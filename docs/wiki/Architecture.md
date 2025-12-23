# Architecture

sys-scan-graph is split into two layers:

1. A **C++ core scanner** that collects host signals (filesystem, procfs, system commands) and emits findings.
2. A **Python intelligence layer** that consumes a *structured scan report* and produces enriched output (correlations, risk summaries, optional artifacts like HTML/diffs, and optional metrics export). The default LLM provider is **local-qwen** with deterministic heuristic fallback; cloud LLM APIs are not used **unless you explicitly opt in**.

This page is intentionally **comprehensive but code-backed**: every major behavior described below is present in the current source tree.

## 🧩 Core scanner (C++)

### What it is

The core is implemented as **C++20 modules** (built with a **C++23 toolchain**) under `src/core/modules/` and scanner modules under `src/scanners/modules/`.

Key modules to start with:

- `sys_scan.scanner` (scanner interface)
- `sys_scan.types` (finding/severity types)
- `sys_scan.report` (aggregation of scanner results)
- `sys_scan.registry` (scanner registration + execution orchestration)
- `sys_scan.interfaces` / `sys_scan.system_services` (DI-friendly system abstractions)
- `sys_scan.config` (feature toggles and execution/output options)

### How scanners produce findings

Each scanner implements a common interface and returns a coroutine-backed generator of `Finding` values (see `sys_scan.scanner` and `sys_scan.coro`). The report aggregator consumes each scanner’s generator and records per-scanner results (see `sys_scan.report`).

### Execution model

Scanners are registered into a `ScannerRegistry` and executed via `ScannerRegistry::run_all(report, cfg)` (see `sys_scan.registry`).

- **Sequential execution** is the default.
- **Parallel execution** is supported by the registry when `cfg.parallel` is enabled (bounded by `cfg.parallel_max_threads`).

### Current CLI status

`src/main.cpp` includes a minimal argument parser and emits a **v4 (ground_truth_v1 compatible) JSON report** to stdout by default, or to a file via `--output`.

Supported CLI flags are intentionally small and code-backed:

- `--output FILE` — write JSON to a file (otherwise stdout)
- `--canonical` — stable ordering of scanners/findings
- `--enable NAME` / `--disable NAME` — include/exclude scanners by name
- `--test-root PATH` — scan against an alternate root (fixtures)

For the full list of currently wired toggles, see **[CLI Guide](CLI-Guide.md)**.

## 🧠 Intelligence layer (Python)

### What it is

The intelligence layer lives under `agent/sys_scan_agent/` and is packaged as `sys-scan-agent` (see `agent/pyproject.toml`). It exposes Typer-based CLIs:

- `sys-scan-graph`
- `sys-scan-intelligence`

### What it consumes

The primary entrypoint is `sys-scan-graph analyze`, which expects a **sys-scan JSON report** and can optionally validate it against the v4 JSON schema:

- schema: `schema/v4.json`
- validator: `sys-scan-graph validate-report` (see `agent/sys_scan_agent/cli.py`)

### What it produces

The analysis workflow reads the raw report, runs enrichment/correlation/risk steps, then writes `enriched_report.json` (default). The output is canonicalized for stable ordering (see `agent/sys_scan_agent/canonicalize.py`, used by `cli.py`).

Optional outputs (controlled by config and CLI flags) include:

- per-node metrics export (`--metrics-out` supports `.json`, `.csv`, `.prom`)
- HTML report and markdown diffs (see `agent/sys_scan_agent/report_html.py` and `report_diff.py` usage in `cli.py`)

## 📦 Data contract between layers

The intended contract between the core scanner and the intelligence layer is a versioned JSON schema (`schema/v4.json`).

This repository includes sample report fixtures (for example, `agent/report.json` and `evaluation/report.json`) that illustrate the v4 ground-truth-compatible shape.

## Design principles (as implemented)

- **Separation of concerns**: the C++ layer collects signals; the Python layer reasons over them.
- **Testability by design**: the C++ core uses explicit interfaces (`sys_scan.interfaces`) to make scanners mockable.
- **Least surprise**: scanners report structured findings and attach metadata, rather than hiding logic in side effects.
- **Operational safety**: the core is oriented around local inspection (filesystem, procfs, system commands) and does not include network-based enrichment.

## Where to go next

- **[Architecture (Technical Details)](Architecture-Technical-Details.md)**
- **[Core Scanners](Core-Scanners.md)**
- **[CLI Guide](CLI-Guide.md)**
- **[Intelligence Layer](Intelligence-Layer.md)**
