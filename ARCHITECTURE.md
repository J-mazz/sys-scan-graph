╔══════════════════════════════════╗
║             MazzLabs             ║
╟──────────────────────────────────╢
║           Joseph Mazzini         ║
╚══════════════════════════════════╝

# Architecture Overview

`sys-scan-graph` has two cooperating layers:

1. **Core scanner (C++23 toolchain, C++20 modules)** — deterministic host scanner that enumerates security surfaces and emits structured findings.
2. **Intelligence layer (Python, optional)** — the `sys-scan-agent` package that enriches, correlates, and summarizes the core report.

```mermaid
flowchart LR
	A[sys-scan (C++)] -->|report.json| B[sys-scan-graph analyze (Python)]
	B -->|enriched_report.json| C[Analysts / pipelines]
	B -->|HTML / SARIF / metrics| D[Dashboards / CI]
```

## Core scanner (C++23 with C++20 modules)

- Built with the C++23 standard, using C++20 modules (`src/core/modules/`) plus scanner modules (`src/scanners/modules/*.ixx`).
- Dependency injection via a scan context (no global config); deterministic registration order.
- Outputs: JSON, NDJSON, SARIF, and HTML when wired via CLI/config (see `Config` in `src/core/modules/config.ixx`).

## Intelligence layer (Python)

- Packaged as `sys-scan-agent`; entrypoint CLIs: `sys-scan-graph` and `sys-scan-intelligence`.
- Default provider: **local-qwen** (offline). Heuristic fallback remains available if models are absent.
- Optional extras (`sys-scan-agent[ai]`) enable local model loading; no outbound LLM calls.

## Data contract

- Primary schema: `schema/v4.json` (sample `report.json` in repo root).
- Canonicalization for stable ordering lives in `agent/sys_scan_agent/canonicalize.py` and is invoked by the CLI.

## Pointers for contributors

- Coverage & testing: `docs/TEST_COVERAGE.md`
- Architecture deep dive: `docs/wiki/Architecture.md`
- Scanner registry and execution: `src/core/modules/registry.ixx` and `src/main.cpp` (composition root)
