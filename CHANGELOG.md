# Changelog

All notable changes will be documented in this file.

## [Unreleased]
### Added
- (placeholder for future changes)

## [0.2.0] - 2025-08-26
### Added
 - Optional eBPF exec trace collection (ENABLE_EBPF / --ioc-exec-trace integration) with libbpf ring buffer; gracefully degrades when unavailable.
 - Fleet report generation (`fleet-report` CLI) and JSON schema (`schema/fleet_report.schema.json`).
 - Attack coverage summary (MITRE ATT&CK technique mapping) with resilient path resolution for mapping file.
 - Intelligence layer snapshot & reduction tests stabilized; golden canonical hash guard retained.
 - Manifest bundle emission capturing rule pack SHA, weights, embedding model hash.
### Changed
 - Robust `_load_attack_mapping` path search (works when tests run from `agent/` directory).
 - CI workflow expanded: compiler matrix, Python agent tests, libbpf/openssl dependencies.
### Fixed
 - Missing fleet report schema caused test failure when executing from agent directory (added duplicate copy under `agent/schema` for relative path test).
 - Attack coverage test returning zero techniques due to incorrect relative path resolution.
 - Minor determinism edge cases in canonical golden test environment (ensured provenance env overrides stable).
### Security
 - No new security fixes; eBPF feature isolated behind build option.
### Removed
 - (None)
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
 - Canonical JSON now includes provenance & emitted metrics; golden hash updated and stabilized via env overrides.
 - Version string centralized (`APP_VERSION` in `BuildInfo.h`) removing hardcoded literals.
 - Seccomp applied earlier (pre-scan) for improved containment; strict failure mode optional.
 - SELinux absence downgrade logic retained; README & schema expanded.
 - CI workflow formatting corrected and dependency installs clarified.

### Security
 - Added capability dropping and seccomp sandbox (deny-by-default allowlist) with optional strict mode.
 - Embedded provenance improves supply-chain auditability & attestation readiness.

### Fixed
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
