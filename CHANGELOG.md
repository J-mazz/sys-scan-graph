# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [6.0.0] - 2025-09-30

### Added
- **Zero-Trust Local LLM**: Security-first implementation replacing external LLM APIs with local LoRA-fine-tuned Mistral-7B-Instruct model trained on 2.5M security scanner findings. Eliminates data exfiltration risks through fully offline inference.
- Enhanced LangGraph workflow (Python agent) with async enrichment, summarization, and rule suggestion nodes (`enhanced_*` functions).
- Pre-summary analysis nodes: `risk_analyzer` and `compliance_checker` for comprehensive security assessment.
- Operational tail nodes: `error_handler`, `human_feedback_node`, `cache_manager`, `metrics_collector` producing deterministic `final_metrics` and cache hit rate.
- Environment toggle `AGENT_GRAPH_MODE=enhanced|baseline` with dynamic recovery in `build_workflow()` to ensure enhanced nodes load even after early imports.
- Knowledge signature requirement (`AGENT_KB_REQUIRE_SIGNATURES=1` + `AGENT_KB_PUBKEY`) emitting `SignatureMissing` warnings when `.sig` files absent.
- End-of-workflow routing ensures early END decisions still traverse `metrics_collector` for consistent final metrics.
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
- Process hashing (`--process-hash`), process inventory (`--process-inventory`), modules anomalies-only mode, IOC allowlist file (`--ioc-allow-file`), SUID expected baseline.
- Debian packaging support for distribution-ready installation.
- Embedded agent for local inference with full offline capability.

### Changed
- Graph state initialization hardened: container fields normalized when LangGraph pre-populates keys with `None` (prevents TypeErrors in async nodes).
- Canonical JSON now includes provenance & emitted metrics; golden hash updated and stabilized via env overrides.
- Version string centralized (`APP_VERSION` in `BuildInfo.h`) removing hardcoded literals.
- Seccomp applied earlier (pre-scan) for improved containment; strict failure mode optional.
- SELinux absence downgrade logic retained; README & schema expanded.
- CI workflow formatting corrected and dependency installs clarified.
- **Licensing**: Changed entire project licensing from dual MIT/Business Source License to Apache License 2.0 for unified open-source licensing.

### Security
- Added capability dropping and seccomp sandbox (deny-by-default allowlist) with optional strict mode.
- Embedded provenance improves supply-chain auditability & attestation readiness.
- Enhanced provenance metadata tracking and correlation analysis.
- Implemented comprehensive risk assessment in LangGraph analysis pipeline.
- Zero-trust local LLM eliminates all external API dependencies and data transmission.

### Fixed
- Missing `_HASHES` in `knowledge` module (restored placeholder) and signature warning expectations in tests.
- Circular import / premature graph assembly resolved by defining `GraphState` prior to node imports; added late import recovery.
- Canonical hash instability resolved (deterministic environment overrides & timestamp zeroing).
- CI build failures from malformed YAML indentation & multiline quoting.
- Minor include / ordering issues (e.g. unordered_set) and robustness of module anomalies-only mode.
- OpenSSL optional dependency: guarded module hashing (avoids build failure when libssl absent) and CI now installs libssl-dev.
- **Variable Scoping Issues**: Resolved UnboundLocalError in LangGraph analysis pipeline by fixing nested loop variable conflicts in multiple files:
  - `agent/graph_nodes.py`: Fixed `correlate_findings()`, `plan_baseline_queries()`, `should_suggest_rules()`, and `choose_post_summarize()` functions.
  - `agent/graph_nodes_scaffold.py`: Fixed `correlate_findings()`, `enhanced_enrich_findings()`, and `enhanced_summarize_host_state()` functions.
  - `agent/graph_nodes_enhanced.py`: Fixed `_findings_from_graph()`, `enhanced_enrich_findings()`, `enhanced_summarize_host_state()`, `advanced_router()`, `tool_coordinator()`, and `risk_analyzer()` functions.
  - `agent/pipeline.py`: Fixed `augment()` and `baseline_rarity()` functions.
  - `agent/graph_analysis.py`: Fixed fid_to_obj lookup loop.
- **Test Suite Memory Corruption**: Fixed dangling pointer issues in `test_integration.cpp` by replacing temporary `string().c_str()` calls with persistent string variables for file paths used in argument arrays.
- **Config Struct Initialization**: Added default values (`= ""`) to all `std::string` members in `Config.h` to ensure proper initialization and prevent undefined behavior.
- **Argument Parsing Validation**: Corrected argument counts in integration tests to match actual argument array sizes, ensuring deterministic test execution.
- **Workflow Equivalence Testing**: Implemented comprehensive test suite (`test_workflow_equivalence.py`) validating scaffold vs enhanced workflow equivalence with 7 passing tests covering deterministic output, metrics consistency, and state handling.
- **Asyncio Event Loop Conflicts**: Fixed asyncio event loop conflicts in `EnhancedLLMProvider` by implementing fallback to null provider for async test contexts and correcting provider call patterns.
- **Provider Call Corrections**: Fixed tuple unpacking errors and async/sync boundaries in scaffold and enhanced workflow nodes, ensuring proper LLM provider integration.
- **Test Normalization**: Enhanced test result normalization to remove timing and ID fields, ensuring deterministic test outcomes across different execution environments.

### Validation
- **CI/CD**: Verified all GitHub Actions workflows are functioning correctly:
  - Build and test workflows passing for Release/Debug configurations
  - CodeQL security analysis workflow operational
  - Release validation workflow with SBOM generation working
  - Python tests passing (60 passed, 3 skipped)
  - C++ tests passing (12/12 successful)
- **System Scan Integration**: Confirmed full system scan functionality working with 145+ findings generated across multiple scanners (processes, network, kernel_params, modules, suid_sgid, mac, etc.)
- **LangGraph Analysis**: Successfully executed AI-powered security analysis on system scan results, generating enriched reports with correlations, risk scoring, and HTML output.

## [5.0.0] - Pre-release (LangGraph Integration)

### Added
- Structured collection_warnings entries with `code` and optional `detail` fields (replacing prior `message`). Schema v2 updated to accept either legacy `{scanner,message}` objects or new format.
- LangGraph-based security analysis pipeline with multi-stage workflow.
- Basic workflow nodes: `correlate_findings()`, `plan_baseline_queries()`, `should_suggest_rules()`, `choose_post_summarize()`.
- Scaffold workflow implementation for baseline analysis.
- Initial LLM provider integration for security recommendations.

### Changed
- Transitioned from simple processing to graph-based analysis architecture.
- Enhanced finding correlation capabilities with context-aware analysis.

### Fixed
- Initial variable scoping issues in workflow implementation.
- Basic async/sync boundary handling in pipeline.

## [4.0.0] - Pre-release (Security Hardening)

### Added
- Initial provenance metadata tracking.
- Basic security hardening features (capability management, seccomp foundations).
- Process hashing and inventory capabilities.
- IOC allowlist functionality.
- SUID/SGID baseline expectations.

### Changed
- Enhanced security posture with defense-in-depth approach.
- Improved metadata tracking for auditability.

### Security
- Initial capability dropping implementation.
- Foundation for seccomp sandbox.

## [3.0.0] - Pre-release (Extended Scanning)

### Added
- Module anomaly detection.
- Enhanced network scanning capabilities.
- Kernel parameter analysis.
- MAC (Mandatory Access Control) scanner.
- World-writable file detection.

### Changed
- Expanded scanner coverage across system security domains.
- Improved finding categorization and severity scoring.

## [2.0.0] - Pre-release (Output Formats)

### Added
- NDJSON output format support.
- SARIF output format for integration with security tools.
- JSON Schema v1 for output validation.
- Configurable output formatting options.

### Changed
- Standardized output structure across formats.
- Enhanced interoperability with third-party security tools.

## [1.0.0] - Pre-release (Test Infrastructure)

### Added
- Comprehensive C++ test suite (`test_integration.cpp`).
- Python test infrastructure.
- CI/CD pipeline with GitHub Actions.
- Code quality checks and sanitizers.

### Changed
- Established testing standards and practices.
- Automated validation in CI pipeline.

## [0.1.0] - Initial Release

### Added
- Core scanners:
  - Process scanner
  - Network scanner
  - Kernel parameters scanner
  - Kernel modules scanner
  - World-writable files scanner
  - SUID/SGID scanner
  - IOC (Indicators of Compromise) scanner
  - MAC (Mandatory Access Control) scanner
- JSON summary output format.
- Severity filtering capabilities.
- Module summary mode.
- IOC aggregation.
- Basic command-line interface.
- Initial documentation (README).

### Security
- Initial security scanning capabilities for Linux systems.
- Basic finding categorization and reporting.

---

## Version History Summary

- **v6.0.0** (2025-09-30): Zero-trust local LLM, full security hardening, Apache 2.0 license
- **v5.0.0**: LangGraph analysis pipeline integration
- **v4.0.0**: Security hardening and provenance
- **v3.0.0**: Extended scanner coverage
- **v2.0.0**: Multiple output formats
- **v1.0.0**: Test infrastructure
- **v0.1.0**: Initial release with core scanners

[Unreleased]: https://github.com/J-mazz/sys-scan-graph/compare/v6.0.0...HEAD
[6.0.0]: https://github.com/J-mazz/sys-scan-graph/releases/tag/v6.0.0
[5.0.0]: https://github.com/J-mazz/sys-scan-graph/compare/v4.0.0...v5.0.0
[4.0.0]: https://github.com/J-mazz/sys-scan-graph/compare/v3.0.0...v4.0.0
[3.0.0]: https://github.com/J-mazz/sys-scan-graph/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/J-mazz/sys-scan-graph/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/J-mazz/sys-scan-graph/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/J-mazz/sys-scan-graph/releases/tag/v0.1.0
