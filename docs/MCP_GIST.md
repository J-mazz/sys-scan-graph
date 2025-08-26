# sys-scan MCP Context Gist

## Overview
C++20 Linux host security scanner providing modular system posture & anomaly findings. Builds via CMake; optional OpenSSL for process executable hashing. Current tool_version emitted: 0.1.0.

## Architecture
- Config → ScannerRegistry → individual scanners populate Report.
- Report holds ScanResult objects (findings + timings) plus side-channel collection_warnings & scanner_errors.
- JSONWriter emits: standard JSON (schema v2), canonical JSON (RFC8785 subset), NDJSON stream, SARIF 2.1.0 minimal.
- Deterministic canonical mode used for golden hashing & reproducible pipelines.

## Data Model
Finding fields: id, title, severity(enum), risk_score, description, metadata (string map). Severity enum (info, low, medium, high, critical, error) mapped to consistent risk_score. Report summary adds severity_counts, total_risk_score, timing, slowest scanner.

Side channels: collection_warnings (recoverable acquisition issues), scanner_errors (hard failures – infra present, not widely used yet).

## Output Formats
1. JSON (schema v2 with $schema URL) – includes summary, results, side channels, summary_extension.
2. Canonical JSON – deterministic ordering & formatting (sorted object keys, stable arrays, minimal integers). Environment overrides (SYS_SCAN_META_*) & SYS_SCAN_CANON_TIME_ZERO for reproducibility.
3. NDJSON – lines: meta, summary_extension, findings (streaming ingestion friendly).
4. SARIF – minimal run/results (enhancement for rules & level mapping pending).

## Key Config Flags
Formatting: --pretty, --compact, --canonical, --ndjson, --sarif.
Filtering / thresholds: --min-severity, --fail-on-severity, --fail-on-count.
Process: --all-processes, --process-hash, --process-inventory.
Network: --network-listen-only, --network-proto, --network-state, --max-sockets, --network-debug.
Modules: --modules-summary-only, --modules-anomalies-only.
IOC: --ioc-allow, --ioc-allow-file.
SUID baseline: --suid-expected-file plus additions.
World writable: --world-writable-dir, --world-writable-exclude.
Limits: --max-processes.

## Scanners Implemented
- ProcessScanner (inventory / hashing)
- NetworkScanner (TCP/UDP sockets with severity heuristics)
- KernelParamScanner (ASLR, kptr_restrict, rp_filter, ip_forward)
- ModuleScanner (summary or anomalies: unsigned/out-of-tree/compressed)
- WorldWritableScanner (files in key dirs)
- SuidScanner (aggregation, severity escalation, expected baseline downgrades)
- IOCScanner (process & env heuristics, temp executables, SUID in home, preload anomalies)
- MACScanner (SELinux/AppArmor status synthesis)

## Determinism & Testing
Environment overrides for meta: SYS_SCAN_META_HOSTNAME, KERNEL, ARCH, OS_ID, OS_VERSION, OS_PRETTY, USER, CMDLINE.
SYS_SCAN_CANON_TIME_ZERO zeroes timestamps.
Golden canonical hash test (test_canonical_golden) ensures structural stability.
Other tests: basic, suid_expected, modules_anomalies, json_schema_smoke, sarif_smoke.

## Recent Enhancements
- Severity enum + risk_score.
- Schema v2 + smoke test.
- NDJSON & SARIF output.
- Warning channel populated across scanners.
- Canonical JSON builder (RFC8785 subset) + deterministic golden hash test.

## Pending / Roadmap
- Enrich SARIF (rules, severity level translation, tags).
- ATT&CK / CIS / tag taxonomy per finding.
- Module in-process decompression + signature optimization (remove popen).
- Parallel scanner scheduling & time budget.
- Expand error channel usage with retry/backoff semantics.
- Optionally canonicalize NDJSON line ordering & include deterministic indices.
- Performance profiling & caching (inode map reuse, stat batching).

## Integration Notes (MCP)
Use canonical JSON with overrides for reproducible embeddings or diffing. For streaming ingestion, use NDJSON; treat canonical transform as post-processing if strict determinism required. Golden hash provides guardrail for schema-breaking changes.

---
Generated snapshot for MCP/Gist consumption.
