# Architecture — Technical Details 🔧

**Note:** the authoritative report schema is `schema/v4.json`; CLI defaults that referenced `v2` have been updated to `v4` to avoid confusion.

This document describes the implementation and runtime behavior of the project as of this repository snapshot. It is intended for maintainers and contributors who need to understand build-time choices, core runtime components, testing harnesses, and practical debugging tips.

---

## Quick entry points ✅
- Build: `CMakeLists.txt` (top-level) — module file-sets, targets, coverage, and `BUILD_FUZZERS` toggle.
- App entry (C++): `src/main.cpp` — composition root and CLI parsing.
- Core modules: `src/core/modules/*.ixx` — types, config, report, registry.
- Scanners: `src/scanners/modules/*.ixx` — scanner implementations.
- Python agent: `agent/sys_scan_agent/*` — orchestration, LLM/graph, and triage logic.
- Schema & contracts: `schema/v4.json` and `schema/fleet_report.schema.json`.

---

## High-level architecture

The project is split into three cooperating layers:

1. C++ core (fast, platform-level collection and aggregation)
2. Python analysis / orchestration (LLM-driven enrichment, triage, reporting)
3. Dev/infra (tests, fuzz targets, CI — coverage, fuzzing and CodeQL)

Each layer has explicit contracts:
- The C++ core emits a JSON report conforming to **v4 / ground_truth_v1**.
- The Python layer consumes those reports and performs higher-level reasoning and enrichment.

---

## C++ Core: Modules, Types, and Contracts 🔩

### Module layout & build
- `sys_scan_modules` is a C++ module library composed from `.ixx` module units under `src/core/modules/` and `src/scanners/modules/`.
- The project uses CMake with `CMAKE_CXX_SCAN_FOR_MODULES` enabled. **Clang** is the supported compiler for module dependency scanning; you will see a configure-time diagnostic otherwise.
- Key targets:
  - `sys-scan`: the CLI/executable
  - `sys_scan_modules`: archive of modules
  - `sys-scan-tests`: C++ unit tests
  - `fuzz_config` (when `BUILD_FUZZERS=ON`): fuzz harness for config/registry

### Core data models
- `sys_scan.config` — `Config` struct: flags for scanners, concurrency controls, output format and test-root.
- `sys_scan.types` — canonical types: `Finding`, `Severity` enum, helpers like `severity_to_string` and `severity_risk_score`.
- These types are intentionally lightweight and POD-like to make serialization, copying and coroutine yields cheap and predictable.

### Scanner interface and streaming model
- `sys_scan::Scanner` exposes `sys_scan::Generator<Finding> scan()`.
- `Generator` is coroutine-based (`sys_scan.coro`) allowing scanners to `co_yield` findings lazily as they are discovered rather than buffering large results in memory.
- `sys_scan.report::Report::consume()` iterates a scanner's `Generator` and collects findings into a `ScanResult` per scanner. This streaming model helps keep memory bounded even when scans produce many findings.

### Registry and orchestration
- `sys_scan.registry::ScannerRegistry` is responsible for:
  - registering scanner instances
  - determining if a scanner is enabled/disabled per `Config`
  - running enabled scanners either **sequentially** or **in parallel** (bounded by `parallel_max_threads` and a semaphore)
  - catching and recording per-scanner exceptions in `Report` (no process-wide crash)

Design note: the registry intentionally isolates scanner failures (via try/catch) and records errors for downstream triage rather than letting a single faulty scanner break the whole run.

---

## Scanner modules — implementation notes
- Each scanner lives in `src/scanners/modules/*` and is written to be testable via DI (swap in `FakeFileSystem`, `FakeProcessRunner`, etc.).
- Scanners are conservative about resource allocation: they stream results and avoid global state where possible.
- Many scanners use platform-specific probes (`/proc`, system APIs, package manager invocations) and include robust error handling to surface warnings (e.g., missing files, permission errors) in `Report`.

---

## JSON output and schema
- Output format: JSON `ground_truth_v1` compatible with `schema/v4.json`.
- The executable prints to `stdout` by default; `--output PATH` writes to a file. Use `--canonical` flag to produce deterministic output suitable for testing.
- The Python layer and tests rely on the schema for fixture validation and round-trip testing.

---

## Python intelligence & LangGraph integration 🧠
- Located under `agent/` — this is the analysis and orchestration layer (LLM-driven summarization, rule suggestion, triage).
- The `agent` layer consumes the JSON report and constructs `GraphState` objects for LangGraph workflows.
- Key modules:
  - `graph.py`: composes the workflow, wraps async nodes into sync-friendly functions for tests
  - `summarization.py`: normalization + LLM interface
  - `baseline.py`, `enricher.py`, `rules.py`: domain-specific workflows
- Tests use lightweight patches/mocks to isolate LLMs and external dependencies. Long-running "full graph" tests are marked or kept out of default CI.

---

## Testing strategy
- C++: unit tests in `tests/` (compiled into `sys-scan-tests`); `ctest` runs these.
- Python: pytest suite under `agent/tests/` with fixtures and monkeypatch usage to isolate LLMs and external tools.
- Fuzzing: `fuzz/` contains harnesses (e.g., `fuzz_config_module.cpp`) that exercise critical parsing and registry flows with libFuzzer when `BUILD_FUZZERS=ON`.
- Coverage: `-DSYS_SCAN_ENABLE_COVERAGE=ON` produces coverage instrumentation and `ninja coverage` runs `gcovr` to produce reports.

---

## Fuzzing best practices used here
- Module-based fuzz harnesses (C++20/C++23 module imports) leverage `FuzzedDataProvider` to avoid fragile splitters and produce higher-quality, varied inputs.
- Fuzz harnesses are small, bounded (limit arg counts/lengths) and exercise parser and executor paths safely to avoid unbounded memory or CPU usage.

---

## CI / Deployment notes
- CI runs unit tests, coverage, and static analysis. `codeql.yml` is present for security scans; modify with caution.
- The CMake module scanning step requires a modules-aware compiler (Clang) in CI. Provide `CC=clang CXX=clang++` when configuring.

---

## Debugging and performance tips 🔍
- If `ninja` or `cmake` fails with module scanning errors, confirm you’re using Clang (module scanning is not stable on some GCC versions).
- To diagnose memory pressure during scans: look at scanner implementations that allocate large buffers (use streaming where possible) and leverage `Report::consume` streaming behavior.
- For flaky or slow Python graph tests, prefer patched nodes that simulate behavior deterministically and then add a gated integration test for the full LLM path.

---
