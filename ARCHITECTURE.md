<!-- REWRITTEN ARCHITECTURE (2025) -->
# Architecture

This document splits the platform into the open‑core C++ Scanner and the proprietary Intelligence Layer contained in `agent/`. The design goal: a narrow, deterministic telemetry core with a pluggable, additive enrichment layer that can evolve (rules, correlations, baseline analytics, reasoning) without destabilizing the base schema.

---
## 1. Core Scanner (Open‑Core)
### Responsibilities
* Enumerate host hygiene & security surface (processes, network sockets, kernel params, modules, world‑writable paths, SUID/SGID, MAC status, optional compliance & rules) under tight performance and determinism constraints.
* Emit stable JSON (Schema v2) whose canonical form is reproducible bit‑for‑bit (ordering, formatting, optional timestamp zeroing env `SYS_SCAN_CANON_TIME_ZERO=1`).
* Provide minimal policy / filtering primitives (min severity, rules-enable) without performing multi-signal reasoning.

### Key Types & Components
| Component | Purpose |
|-----------|---------|
| `Scanner` (interface) | Pure function style `scan(Report&)` producing findings for its domain |
| `ScannerRegistry` | Ordered registration enforcing deterministic emission ordering |
| `Report` | Thread-safe (mutex) append container for future parallelization |
| `Finding` | Lightweight struct with id/title/severity/description + sorted metadata map |
| `JSONWriter` | Canonical builder (stable key ordering, whitespace minimization) + optional pretty printer |
| `Config` | Parsed once (singleton accessor) controlling scanner toggles & thresholds |

### Flow
```
CLI -> Config -> ScannerRegistry (ordered vector)
    -> for each Scanner: start_scanner -> scan -> end_scanner (timings)
    -> Report summary aggregation -> JSONWriter -> stdout/file
```

### Determinism Strategies
* Fixed scanner ordering.
* Sorted metadata keys before serialization.
* Optional canonical mode zeroes volatile fields (timestamps) where feasible.
* Severity filtering applied only after all scanners finish (keeps relative aggregates stable).

### Error & Security Posture
* Non-fatal read / permission errors omitted (future: structured warnings array expansion).
* Module scanner may invoke decompress utilities (`xz`, `gzip`) on root-owned paths; risk minimized by trusted path derivation. Roadmap: native decompression.
* No outbound network activity; pure procfs / filesystem enumeration.

### Extending the Core
1. Implement `<Name>Scanner.{h,cpp}` in `src/scanners/`.
2. Add to CMake library sources.
3. Register in `ScannerRegistry::register_all_default()` (position matters for diff stability).
4. Maintain stable `Finding.id` (avoid transient values such as PIDs unless essential).
5. Keep optional heavy metadata behind flags.

---
## 2. Intelligence Layer (Proprietary)
The Intelligence Layer consumes a raw Core report and produces an enriched artifact with correlations, rarity metrics, calibrated risk, actions, summaries, ATT&CK coverage and performance analytics. It is entirely additive and leaves the original report unchanged.

### Data Model Additions
| Model | Key Fields |
|-------|------------|
| `risk_subscores` | impact, exposure, anomaly, confidence (per finding) |
| `probability_actionable` | Logistic calibration output (0..1) |
| `correlations[]` | Rule & heuristic multi-finding relationships with predicate_hits explain map |
| `reductions` | Summaries: modules, SUID, network, top_findings/top_risks |
| `multi_host_correlation[]` | Cross-host propagation (simultaneous module emergence) |
| `followups[]` | Deterministic tool execution results (hash, package manager query) |
| `actions[]` | Prioritized remediation prompts grounded in correlations/reductions |
| `summaries` | Executive + triage narratives, metrics, ATT&CK coverage, causal hypotheses |
| `enrichment_results` | Auxiliary data: token accounting, perf snapshot, warnings |
| `integrity` | SHA256 & optional signature verification status |

### Pipeline Stages (Sequential Implementation)
1. Load & Validate: size guard, UTF‑8 strict decode, JSON parse, schema (optional).  
2. Augment: host_id & scan_id derivation, tagging, risk subscore seed, host role classification (role rationale added).  
3. Knowledge Enrichment: ports, modules, SUID expectations, org attribution (YAML packs).  
4. Correlate: rule engine merges configured + default rules; exposure bonus for distinct exposure tags.  
5. Baseline Rarity: SQLite (finding first_seen, occurrence counts); anomaly scoring (new/recent/common tagging), calibration observation logging.  
6. Process Novelty: deterministic embedding & cosine distance clustering; anomaly boost for novel clusters.  
7. Temporal Sequence Correlation: e.g. new SUID followed by IP forwarding enabling => synthetic correlation.  
8. Metric Drift: z-score & early delta heuristics produce synthetic drift findings.  
9. Cross-Host Propagation: simultaneous first appearances of a module across ≥ threshold hosts => multi-host correlation & synthetic finding.  
10. Reductions: aggregate module rarity stats, SUID unexpected, network listeners, top findings with redaction.  
11. Follow-Ups & Trust: execute deterministic tool chain (hash, package manager query); downgrade severity if trusted binary hash recognized.  
12. Actions: prioritized list based on correlations/reductions (e.g., routing intent verification).  
13. Summaries: LLM summarization gated by aggregate medium+ risk + newness; redacted inputs; output narratives sanitized.  
14. ATT&CK & Causal Hypotheses: tag mapping to techniques; heuristic chain inferences (speculative).  
15. Performance & Regression: timings & counters, baseline comparison, regression listing.  
16. Canonicalize: stable ordering & JSON cleansing for reproducible hashing.  

### Policy & Governance
* Policy layer escalates severity (and impact subscore) for executables outside approved directories (config/env allowlist + default system dirs).
* Redaction filters user paths (`/home/<user>` etc.) before any LLM or summarization call.
* Risk weights & logistic calibration user-editable via CLI; stored persistently.

### Baseline Database
SQLite schema versions (current v5) track: finding rarity, module observations, metric time series, calibration observations, process clusters. EWMA metrics support smoother drift detection and future predictive heuristics.

### Process Embedding
32-dim vector: token hashed counts plus digit_ratio & token_count features; L2-normalized. Cosine distance threshold (configurable) gates novelty tagging and anomaly boost; cluster centroids derived incrementally via summed vectors.

### Rule Engine
YAML/JSON rule packs + default rule set: condition objects with field / metadata filtering; ANY or ALL logic; exposure bonus by counting unique exposure tags (listening, suid, network_port). Predicate hit labeling improves explainability.

### ATT&CK Mapping & Hypotheses
Tag→technique map in `attack_mapping.yaml`; coverage summary enumerates unique techniques & contributing tags. Hypothesis generator inspects correlation tags (`sequence_anomaly`, `module_propagation`, `metric_drift` + routing) to emit speculative, low confidence causal chains.

### Performance Telemetry
Metrics collector wraps key stages, storing count/total/avg. Regression detection compares current snapshot to saved baseline with an environment threshold (percentage). Snapshot embedded in enriched output and referenced under `meta.analytics.performance`.

### Integrity & Signing
If verification key (`AGENT_VERIFY_KEY_B64`) present, raw report signature verification performed; integrity block records digest, match flags, and errors without aborting enrichment (best-effort). Separate CLI commands for key generation, sign, and verify.

---
## 3. LangGraph DAG & Future Cyclical Reasoning
The `graph_pipeline.py` wraps sequential logic in a LangGraph DAG (current linear chain) enabling:
* Per-node checkpoint JSON snapshots (for audit / regression triage).
* Time-series run index (scan_id, host_id, finding & correlation counts) to power dashboards.
* (Planned) Bounded cyclical reasoning loops: e.g. dynamic rule refinement or summarization refinement passes. Convergence control through max iterations + state hash equality to preserve determinism.
* Tooling integration: follow-up executors are natural “tools” LangGraph can invoke; future loops can conditionally re-run correlation after tool output.

Potential future loop (proposal):
```
reduce -> summarize -> (if summary.metrics.low_confidence && iterations<2) -> refine_rules -> correlate -> reduce -> summarize
```
All loops must remain deterministic under fixed inputs + seed to maintain reproducibility guarantees.

---
## 4. Canonicalization & Reproducibility Guarantees
Enriched output re-serialized into a canonical dict ordering (keys sorted; arrays left in stable constructed order) before final Pydantic model rehydration. This ensures:
* Stable hashes across environments given identical inputs, configs, weights, calibration, rule pack, baseline DB state, and versions.
* Low-noise diffs for CI gating & artifact promotion.

---
## 5. Security & Privacy Considerations
| Concern | Mitigation |
|---------|------------|
| PII leakage in summarization | Redaction of filesystem paths & user tokens; risk gate skip on low materiality |
| Untrusted rule files | Rule loading isolates directories; invalid files skipped; deterministic id hashing for missing ids |
| Novelty false positives | Distance threshold configurable; anomaly boost capped; rationale logged |
| Performance regressions | Baseline snapshot + regression detection; stage timings embedded for transparency |
| Integrity tampering | Optional signature verify; sha256 always included; warnings captured, not silent |

No external network calls by default. Optional corpus enrichment (`AGENT_LOAD_HF_CORPUS=1`) loads local cached datasets if dependencies installed; failure silent but logged as agent warning.

---
## 6. Extensibility Matrix
| Area | Add / Change | Determinism Guard Rails |
|------|--------------|-------------------------|
| New correlation heuristic | Add function before reductions | Keep ordering stable, bounded size arrays |
| New rule pack | Place YAML/JSON & update config rule_dirs | Rule merge order fixed (user then default) |
| New baseline dimension | Add table + migration increment | Schema version bump; migration idempotent |
| New embedding | Update `process_feature_vector` -> embedding hash changes manifest; consumers re-hash |
| New ATT&CK mappings | Extend YAML | Additive; no reorder of existing keys |
| Cyc reasoning loop | Insert bounded LangGraph subgraph | Deterministic convergence criteria |

---
## 7. Roadmap (Architectural)
* Parallel core scanner execution (multi-thread) guarded by deterministic merge ordering.
* Native module decompression (remove shelling to `xz`,`gzip`).
* Structured warning channel in core (separate from findings).
* Bounded LangGraph iterative refinement (rule & action optimization).
* Formal provenance & SBOM correlation linking enriched findings to package metadata.

---
## 8. Diagrams
### Core → Intelligence Layer Data Flow
```
┌─────────────┐   JSON (schema v2)   ┌─────────────────────┐
│ Core Scan   │─────────────────────▶│ Intelligence Layer  │
│ (C++20)     │                      │ (Python)            │
└─────┬───────┘                      └─────┬───────────────┘
    │ timings                             │ enriched JSON
    ▼                                     ▼
  canonical JSON                       canonical enriched JSON
```

### Intelligence Layer Stage Graph (Current Linear)
```
load -> validate -> augment -> correlate -> baseline -> novelty -> sequence -> drift -> multi_host -> reduce -> followups -> actions -> summarize -> output
```

---
## 9. Known Limitations
* Core severity taxonomy still string-based (enum refactor pending).
* Rule engine matching primitive (no regex/DSL in proprietary layer—future safe expansion planned).
* Process embedding intentionally lightweight; not semantic; may miss nuanced novelty.
* ATT&CK mapping subset; coverage counts not weighted by evidentiary strength.
* Cyclical reasoning hooks present conceptually, not yet activated (ensures current determinism baseline).

---
## 10. Contact
Design proposals: open issue tagged `design`. For security disclosures follow `SECURITY.md`.

_End of Architecture Document_
