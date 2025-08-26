# Architecture

## Overview
`sys-scan` is a single-binary host inspection tool composed of pluggable *Scanner* units that populate a shared `Report`. Output is deterministic JSON (schema versioned) containing a summary plus per‑scanner results.

## Core Components
- Scanner interface (`Scanner` in `core/Scanner.h`): name(), description(), scan(Report&).
- Registry (`ScannerRegistry`): Instantiates and runs all default scanners in sequence (currently single‑threaded for predictable ordering & deterministic JSON).
- Report (`Report`): Thread-safe append-only container of `ScanResult` objects (mutex protected) to allow future parallelization.
- Finding model: Plain struct with `id`, `title`, `severity` (string), `description`, and sorted `metadata` map for stable output ordering.
- Config (`Config`): Parsed once in `main.cpp`, stored globally (singleton pattern via `config()` accessor). Provides feature flags & thresholds.
- JSONWriter: Builds canonical string, minifies, then optionally pretty‑prints. Adds `tool_version` and `json_schema_version` for forward compatibility. Emits optional `compliance_summary` and (when gap analysis enabled) `compliance_gaps` with remediation hint scaffolding.

## Scanner Flow
1. `ScannerRegistry::register_all_default()` pushes concrete scanner instances into an internal vector.
2. `run_all` (see implementation) calls `Report::start_scanner`, invokes `scan`, then `Report::end_scanner` capturing duration.
3. `JSONWriter` aggregates global summary (counts, timings, severities) then serializes each `ScanResult` after severity filtering (via `min_severity`).

## Current Scanners
- processes: Enumerates `/proc/*/status` & `cmdline`, optional hashing (`--process-hash`) using OpenSSL (SHA256 first 1MB) if available.
- network: Parses `/proc/net/tcp{,6}`, `/proc/net/udp{,6}` with state / listen / protocol filters; severity heuristic for exposed listeners.
- kernel_params: Snapshots selected hardening sysctls (implementation not shown here for brevity).
- modules: Either enumerates each module or summarizes (`--modules-summary`). Summary collects counts, detects out‑of‑tree signatures, unsigned modules (scans or decompresses `.ko`, `.ko.{xz,gz}`), and compressed stats.
- world_writable: Walks whitelisted directories, reports world‑writable files (exclusions via substrings).
- suid: Aggregates SUID/SGID binaries by inode, collects alternate hardlink paths & escalates severity for unusual locations.
- ioc: Heuristic Indicators of Compromise (deleted executables, execution from temp, suspicious LD_* env usage, ld.so.preload anomalies, SUID in home, temp executables). Aggregates per executable for noise reduction, with allowlist downgrade via `--ioc-allow` / `--ioc-allow-file`.
- mac: Captures SELinux/AppArmor status, complain counts, unconfined critical processes (heuristic).
- compliance (conditional): Aggregates control pass/fail across selected standards (PCI DSS 4.0, HIPAA Security Rule, NIST CSF 2.0) and surfaces per-standard counts + score.

## Determinism & Ordering
- Scanners run sequentially in a fixed registration order to keep JSON ordering stable (facilitates diffing & caching).
- Metadata maps are copied to a vector then key-sorted before emission.

## Error Handling Philosophy
- Prefer silent skip on permission failure (e.g. unreadable `/proc` entries) but still record other findings.
- Symlink or file read issues inside a scanner do not abort the scanner; they simply omit data (future improvement: structured warning channel).

## Security Considerations
- Module scanner uses external decompress utilities (`xz -dc`, `gzip -dc`). Risk: shell invocation with module path. Paths derived from `modules.dep` under `/lib/modules/<release>` (trusted root-owned) mitigating injection risk (no user-controlled input). Future hardening: use liblzma / zlib streaming APIs directly.
- No outbound network connections are made; network scanner only reads procfs.
- Hashing limited to first 1MB for performance to avoid large memory footprint on huge binaries.

## Performance & Concurrency
- Currently single-threaded; `Report` already mutex-protected enabling future parallel scanner execution.
- Potential parallelization targets: processes + network + modules independently.
- IO patterns favor streaming and early caps (`--max-processes`, `--max-sockets`).

## Extensibility Guidelines
1. Create `<Name>Scanner.{h,cpp}` in `src/scanners/` implementing interface.
2. Add source file to `CMakeLists.txt` library list.
3. Register in `ScannerRegistry::register_all_default()` at an appropriate position (ordering impacts JSON diff stability).
4. Use concise, deterministic `Finding.id` (stable key for future suppression/correlation).
5. Keep heavy per-item metadata optional behind a config flag to control output volume.
6. For compliance extensions: isolate standard-specific control logic in dedicated registration helpers; ensure scores remain pure functions of counts (no hidden state) to preserve determinism.

## Future Refactors (Planned)
- Replace severity strings with `enum class Severity` plus central mapping for rank & JSON string emission.
- Introduce a lightweight `Result` / `expected` wrapper for file parsing to differentiate IO error vs absence.
- Structured warning channel (array) to surface non-fatal scanner errors distinct from security findings.
- Externalized remediation hint knowledge base (YAML) merged at JSONWriter layer (current hints are heuristic inline strings).
- Remove shell decompression dependency by embedding minimal xz/gzip readers.

## JSON Schema Versioning
- `json_schema_version`: Starts at "1" (post‑0.1.0). Increment on breaking structural changes (renaming keys, moving arrays, severity encoding shift). Backward-compatible additive fields do not increment.

## Data Flow Diagram (Logical)
```
CLI -> Config -> ScannerRegistry -> [Scanner Loop]
                                   |-> processes   -> Findings
                                   |-> network     -> Findings
                                   |-> modules     -> Findings
                                   |-> ... others  -> Findings
           Report(start/end aggregate timings) -----> JSONWriter -> stdout/file
```

## Known Limitations
- No structured distinction between collection errors and security findings yet.
- Severity taxonomy coarse; lacks numeric risk scoring (planned for Core; Intelligence layer adds risk_subscores & probability modeling).
- Compliance remediation hints currently heuristic; deeper mapping pending external knowledge base.

## Intelligence Layer (Proprietary) Overview
The optional `agent/` Python layer ingests Core JSON, enriches with:
- Baseline rarity & anomaly scoring
- Deterministic correlations & sequence analysis
- Compliance gap normalization & richer remediation mapping
- HTML reporting & diff generation
It is licensed separately (see LICENSE) and not required for Core scanning.

## Licensing Architecture
The project adopts a hybrid model:
- Core scanner: MIT (allows broad reuse & embedding)
- Intelligence layer: Proprietary evaluation license

Design separation is enforced at directory boundaries; no proprietary symbols are required to compile or run the Core binary.
- Pretty printer is bespoke; may not preserve ordering if future nested objects added (evaluate rapidjson or nlohmann/json purely for formatting when pretty enabled).

---
For questions or design proposals, open a GitHub Discussion or Issue tagged `design`.
