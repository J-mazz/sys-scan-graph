# Repository Analysis: sys-scan

## Overall Summary
The `sys-scan` repository is a comprehensive host security and hygiene assessment tool for Linux systems (primarily Debian/Ubuntu). It consists of a C++20 core scanner that produces deterministic JSON reports, and an optional Python-based intelligence layer for enrichment, baselining, correlation, and LLM-driven summarization. The project emphasizes reproducibility, determinism, and extensibility via rules and plugins. Key features include multiple scanners (processes, network, kernel modules, etc.), compliance checks, rules engine, and various output formats (JSON, NDJSON, SARIF). The build system uses CMake, with options for tests, fuzzing, and security features like seccomp and capabilities.

Repository structure:
- **Root**: Configuration, documentation, build files.
- **agent/**: Python intelligence layer (Pydantic models, SQLite baseline, LLM integration).
- **src/**: C++ source code (core classes, scanners, eBPF support).
- **rules/**: Declarative rule files for post-processing findings.
- **tests/**: C++ unit tests.
- **docs/**: Documentation and hardening guides.
- **schema/**: JSON schemas for report validation.
- **scripts/**: Demo and release scripts.
- **build/**, **cmake-build-debug/**: Build artifacts.
- **debian/**: Debian packaging.
- **fuzz/**: Fuzz testing harnesses.
- **sanitize/**: Sanitizer builds.
- **evaluation/**: Synthetic attack detection evaluation.
- Other: Artifacts, reports, logs.

## Root Files
- **README.md**: Comprehensive guide to sys-scan, including quick start, features, scanners, output formats, rules, privacy, security model, build/install, usage scenarios, CI integration, examples, and roadmap. Highlights deterministic JSON, high-signal findings, lightweight build, and extensibility.
- **ARCHITECTURE.md**: Detailed architecture overview. Describes core components (Scanner interface, Report, JSONWriter, Config), scanner flow, current scanners (processes, network, modules, etc.), determinism, error handling, security considerations, performance, extensibility guidelines, and future refactors. Includes data flow diagram.
- **CMakeLists.txt**: CMake build configuration. Sets C++20 standard, options for tests, OpenSSL, seccomp, capabilities, fuzzers. Defines sys_scan_core library with sources from src/core/ and src/scanners/. Handles build provenance (git commit), dependencies (Threads, OpenSSL, libseccomp, libcap).
- **config.yaml**: Configuration for the Python agent. Includes weights, thresholds, performance settings, paths, notifications (Slack/webhook), reports (HTML, diff), and bundle manifest.
- **TODO.md**: Local notes on eBPF implementation resume plan, current state (kernel 6.14.0, BTF present), nice-to-haves, troubleshooting, deferred ideas.
- **LICENSE**: MIT license.
- **CHANGELOG.md**: Version history and changes.
- **SECURITY.md**: Security policy and guidelines.
- **rarity.yaml**: Likely configuration for rarity analytics.
- **report.json**, **enriched_report.json**, **fleet_report.json**: Sample or generated reports.
- **agent_baseline.db**, **agent_audit.log**: Agent-specific database and logs.

## Agent Directory
The Python intelligence layer for advanced analysis.
- **README.md**: Explains goals (load JSON, validate, baseline diff, correlate, reduce, summarize via LLM, action plan). Quick start with venv and CLI. Components: models.py (Pydantic), baseline.py (SQLite), rules.py (correlation), reduction.py, llm.py (abstraction), pipeline.py, cli.py.
- **requirements.txt**: Dependencies: pydantic, sqlalchemy, typer, rich, click, pyyaml, langchain, langgraph, orjson, jsonschema, pytest, PyNaCl.
- **cli.py**: Typer-based CLI for analysis.
- **models.py**: Pydantic models for reports, findings, etc.
- **baseline.py**: SQLite-backed baseline store.
- **rules.py**: Correlation rules.
- **reduction.py**: Token/cost reduction.
- **llm.py**: LLM interface with stub.
- **pipeline.py**: Orchestrates analysis pipeline.
- **graph.py**, **graph_analysis.py**, **graph_nodes.py**, **graph_pipeline.py**: LangGraph-based enrichment DAG.
- **hf_loader.py**: Hugging Face model loader.
- **llm_models.py**, **llm_provider.py**: LLM model and provider abstractions.
- **risk.py**: Risk scoring.
- **report_html.py**, **report_diff.py**: HTML and diff report generation.
- **tools.py**: Utilities.
- **config.py**: Configuration handling.
- **audit.py**: Auditing functionality.
- **calibration.py**: Calibration for models.
- **counterfactual.py**: Counterfactual analysis.
- **endpoint_classification.py**: Endpoint classification.
- **evaluation.py**: Evaluation scripts.
- **executors/**: Execution components.
- **fixtures/**: Test fixtures.
- **knowledge/**: Knowledge base.
- **providers/**: Provider integrations.
- **tests/**: Python tests.
- Other files: migration_v3.py, offline_scoring.py, etc.

## Src Directory
C++20 source code for the core scanner.
- **main.cpp**: Entry point.
- **core/**: Core components.
  - Scanner.h/cpp: Interface for scanners.
  - ScannerRegistry.h/cpp: Registers scanners.
  - Report.h/cpp: Thread-safe report container.
  - JSONWriter.h/cpp: Outputs JSON in various formats.
  - Config.h/cpp: Configuration parsing.
  - RuleEngine.h/cpp: Rules processing.
  - Utils.h/cpp: Utilities.
  - JsonUtil.h/cpp: JSON utilities.
  - Logging.h/cpp: Logging.
  - Compliance.h/cpp: Compliance checks.
  - Privilege.h/cpp: Privilege management.
- **scanners/**: Scanner implementations.
  - ProcessScanner: Enumerates processes, optional hashing.
  - NetworkScanner: TCP/UDP sockets.
  - KernelParamScanner: Sysctl hardening params.
  - ModuleScanner: Kernel modules (unsigned, out-of-tree).
  - WorldWritableScanner: World-writable files.
  - SuidScanner: SUID/SGID binaries.
  - IOCScanner: Indicators of compromise.
  - MACScanner: SELinux/AppArmor.
  - MountScanner: Mount points.
  - KernelHardeningScanner: Kernel hardening.
  - SystemdUnitScanner: Systemd units.
  - AuditdScanner: Auditd configuration.
  - ContainerScanner: Container detection.
  - IntegrityScanner: Integrity checks.
  - YaraScanner: YARA rule scanning.
  - EbpfScanner: eBPF-based tracing.
- **bpf/**: BPF programs.
- **ebpf/**: eBPF utilities.

## Rules Directory
Declarative rules for post-processing.
- **SCHEMA.md**: Rule schema v1. Rules have id, scope, logic, severity_override, mitre. Conditions on fields (id, title, description, metadata) with contains, equals, regex.
- **example.rule**, **example_env.rule**: Example rule files.
- **yara/**: YARA rules subdirectory.

## Tests Directory
C++ unit tests.
- test_basic.cpp: Basic functionality.
- test_canonical_golden.cpp: Canonical output hashing.
- test_canonical_ordering.cpp: Ordering determinism.
- test_json_schema_smoke.cpp: Schema validation.
- test_meta_suppression.cpp: Meta suppression.
- test_modules_anomalies.cpp: Module anomalies.
- test_ndjson_mitre.cpp: NDJSON with MITRE.
- test_rules_engine.cpp: Rules engine.
- test_rules_engine_unit.cpp: Unit tests for rules.
- test_rules_engine_warnings_structured.cpp: Warnings.
- test_rules_mitre_dedup.cpp: MITRE deduplication.
- test_sarif_smoke.cpp: SARIF output.
- test_scanner_scope.cpp: Scanner scoping.
- test_suid_expected.cpp: SUID expected.

## Docs Directory
Documentation.
- **MCP_GIST.md**: Summary for Model Context Protocol, overview, architecture, data model, formats, config, scanners, determinism.
- **hardening/**: Hardening guides.

## Schema Directory
JSON schemas.
- **v2.json**: Schema for report v2 (meta, summary, results, warnings, errors, summary_extension).
- **v3.json**: Likely updated schema.
- **fleet_report.schema.json**: Fleet report schema.

## Scripts Directory
Utility scripts.
- **demo_phase10.sh**: Demo script.
- **release_validate.py**: Release validation.

## Other Directories
- **build/**, **cmake-build-debug/**: CMake build outputs.
- **debian/**: Debian packaging files (changelog, control, etc.).
- **fuzz/**: Fuzz testing (fuzz_rules.cpp).
- **sanitize/**: Sanitizer builds.
- **evaluation/**: Synthetic attack evaluation (README, report.json).
- **artifacts/**: Generated artifacts (report_generation.log).
- **Testing/**: Test outputs.

## Verification Once-Over
- Root files provide comprehensive documentation and configuration.
- Agent/ is well-structured Python layer with clear components.
- Src/ has modular C++ code with core and scanners.
- Rules/ supports declarative enrichment.
- Tests/ cover key functionality.
- Docs/ and schema/ ensure consistency.
- Other dirs support build, packaging, testing, evaluation.
- No major gaps; aligns with README and ARCHITECTURE.

## Reflection and Feedback
This repository is a mature, well-architected security tool with a clear separation between the fast C++ core and the intelligent Python layer. The emphasis on determinism and reproducibility is commendable for CI/CD integration. The extensibility via scanners and rules allows for broad coverage. Potential areas for improvement: more comprehensive eBPF integration (as per TODO), expanded compliance standards, and deeper LLM integration in the agent. The project balances performance, security, and usability effectively. Overall, it's a solid foundation for host security assessments.
