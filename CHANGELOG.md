# Changelog

All notable changes will be documented in this file.

## [Unreleased]

### Added
- Enhanced LangGraph workflow (Python agent) with async enrichment, summarization, and rule suggestion nodes (`enhanced_*` functions) plus pre-summary `risk_analyzer` & `compliance_checker`.
- Operational tail nodes: `error_handler`, `human_feedback_node`, `cache_manager`, `metrics_collector` producing deterministic `final_metrics` and cache hit rate.
- Environment toggle `AGENT_GRAPH_MODE=enhanced|baseline` and dynamic recovery in `build_workflow()` to ensure enhanced nodes load even after early imports.
- Knowledge signature requirement (`AGENT_KB_REQUIRE_SIGNATURES=1` + `AGENT_KB_PUBKEY`) emitting `SignatureMissing` warnings when `.sig` files absent.
- End-of-workflow routing ensures early END decisions still traverse `metrics_collector` for consistent final metrics.
- Structured collection_warnings entries now emit `code` and optional `detail` fields (replacing prior `message`). Schema v2 updated to accept either legacy `{scanner,message}` objects or new `{scanner,code,detail?}` objects for backward compatibility. Downstream consumers should prefer `code` when present.
### Added
 - Dual metrics & risk scoring: `finding_count_total` vs `finding_count_emitted`, `severity_counts` vs `severity_counts_emitted`, and `emitted_risk_score` in `summary_extension`.
 - Provenance metadata block (`meta.provenance`) with compiler id/version, git commit, cxx standard, cxx flags, build type, SLSA level (baked & runtime override via `--slsa-level`).
 - Reproducibility & determinism flags: `SYS_SCAN_REPRO_BUILD`, `SYS_SCAN_CANON_TIME_ZERO=1`, provenance override env (`SYS_SCAN_PROV_*`), meta overrides (`SYS_SCAN_META_*`).
 - GPG signing: `--sign-gpg <KEYID>` produces detached armored signature (`.asc`).
 - Security hardening: capability drop (`--drop-priv` / `--keep-cap-dac`), seccomp sandbox (`--seccomp`, `--seccomp-strict`).
 - `--write-env FILE` exporting version & binary hash; `--version` flag printing version & provenance summary.
 - NDJSON & SARIF outputs include new emitted risk score (summary_extension & properties).
 - JSON Schema v2 published; schema enumerates emitted vs total metrics.
 - Fuzz harness (`fuzz_rules`) behind `BUILD_FUZZERS=ON`; sanitizer CI job; CodeQL workflow.
 - CONTRIBUTING guide; expanded README sections (Provenance, Schema, Reproducibility, Hardening).
 - Existing feature set: process hashing (`--process-hash`), process inventory (`--process-inventory`), modules anomalies-only mode, IOC allowlist file (`--ioc-allow-file`), SUID expected baseline (`--suid-expected*`), fail-on-count.

### Changed
- Graph state initialization hardened: container fields normalized when LangGraph pre-populates keys with `None` (prevents TypeErrors in async nodes).
 - Canonical JSON now includes provenance & emitted metrics; golden hash updated and stabilized via env overrides.
 - Version string centralized (`APP_VERSION` in `BuildInfo.h`) removing hardcoded literals.
 - Seccomp applied earlier (pre-scan) for improved containment; strict failure mode optional.
 - SELinux absence downgrade logic retained; README & schema expanded.
 - CI workflow formatting corrected and dependency installs clarified.

### Security
 - Added capability dropping and seccomp sandbox (deny-by-default allowlist) with optional strict mode.
 - Embedded provenance improves supply-chain auditability & attestation readiness.

### Fixed
- Missing `_HASHES` in `knowledge` module (restored placeholder) and signature warning expectations in tests.
- Circular import / premature graph assembly resolved by defining `GraphState` prior to node imports; added late import recovery.
 - Canonical hash instability resolved (deterministic environment overrides & timestamp zeroing).
 - CI build failures from malformed YAML indentation & multiline quoting.
 - Minor include / ordering issues (e.g. unordered_set) and robustness of module anomalies-only mode.
 - OpenSSL optional dependency: guarded module hashing (avoids build failure when libssl absent) and CI now installs libssl-dev.

### Removed
 - (None)

## [0.1.0] - Initial Release
- Core scanners (processes, network, kernel params, modules, world_writable, suid_sgid, ioc, mac)
- JSON summary & severity filtering
- Module summary mode & IOC aggregation
