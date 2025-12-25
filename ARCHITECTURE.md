# Architecture — Overview

A compact explanation of responsibilities and how the system works.

```mermaid
flowchart LR
  subgraph Core [C++ core]
    direction TB
    SCANNERS[scanners: process, network, kernel, mount, fs-perms, module, ebpf, yara, integrity]
    REG[ScannerRegistry]
    REPORT[Report (json, schema/v4.json)]
    SCANNERS --> REG --> REPORT
  end

  subgraph Agent [Python agent (optional)]
    direction TB
    AGENT[sys-scan-agent]\n(enrichment, correlation, routing)
    GRAPH[LangGraph workflow]\n(enrich -> reflect -> summarize -> risk/compliance)
    AGENT --> GRAPH --> ENR[enriched_report.json / HTML / metrics]
  end

  REPORT --> AGENT
  AGENT -.->|IPC socket| UI[UI / Investigation Director (optional)]
  AGENT -.->|artifacts| CI[CI / analysts / pipelines]
```

How it accomplishes the goal (brief)

- Scanners are modular C++ components that `co_yield` `Finding` objects; `Report::consume()` streams those findings into per-scanner `ScanResult` objects to keep memory bounded.
- `ScannerRegistry` composes and runs scanners (sequential or bounded parallel), captures per-scanner warnings/errors, and prevents a single faulty scanner from crashing the run.
- The executable writes `schema/v4.json`-compatible JSON; use `--canonical` to produce deterministic ordering for tests and CI.
- The Python agent assembles a LangGraph-like workflow (`agent/sys_scan_agent/graph.py`) to enrich, correlate, and triage findings; local providers (e.g., `local-qwen`) are default and networked providers are opt-in.
- CMake enforces a Clang compiler for module scanning; fuzz harnesses and coverage modes are provided for robustness.

Where to find details

- Core implementation: `src/core/modules/`, `src/scanners/modules/` (scanner logic), `src/main.cpp` (composition root).
- Agent: `agent/sys_scan_agent/` (CLI, graph orchestration, providers, models).
- Schemas & fixtures: `schema/v4.json`, `schema/fleet_report.schema.json`.
- Tests & CI: `tests/` (C++), `agent/tests/` (Python), `docs/TEST_COVERAGE.md`.

Design choices in one line:

- Determinism, local-first intelligence, bounded resources, testability, and minimal external dependencies.