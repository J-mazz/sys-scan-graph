# sys-scan-graph

![sys-scan-graph Logo](assets/sys-scan-graph_badge.jpg)

## System Security Scanner & Intelligence Graph

[![CI](https://github.com/J-mazz/sys-scan-graph/actions/workflows/ci.yml/badge.svg)](https://github.com/J-mazz/sys-scan-graph/actions/workflows/ci.yml)
[![CodeQL](https://github.com/J-mazz/sys-scan-graph/actions/workflows/codeql.yml/badge.svg)](https://github.com/J-mazz/sys-scan-graph/actions/workflows/codeql.yml)
[![CodeScene Analysis](https://codescene.io/images/analyzed-by-codescene-badge.svg)](https://codescene.io/projects/71206)
[![CodeScene Average Code Health](https://codescene.io/projects/72512/status-badges/average-code-health)](https://codescene.io/projects/72512)
[![CodeScene System Mastery](https://codescene.io/projects/72512/status-badges/system-mastery)](https://codescene.io/projects/72512)
[![Coverage](https://img.shields.io/badge/coverage-%3E=85%25-brightgreen.svg)](docs/TEST_COVERAGE.md)

**Sys-Scan-Graph** turns host signals into concise, actionable findings and analyst-friendly summaries — designed to run offline and at scale.

It pairs a deterministic, high-performance C++ core (strict schema, streaming collectors) with an optional Python intelligence agent that enriches and triages results locally (default provider: `local-qwen`). The project is optimized for reproducibility, CI, and air-gapped deployments.

```mermaid
flowchart LR
  subgraph Core [C++ core]
    direction TB
    SCANNERS[Scanners\n(process, net, kernel, mounts, fs perms, modules, eBPF, YARA, integrity)]
    REG[ScannerRegistry]\n(streaming orchestration)
    SCANNERS --> REG --> REPORT[Report (json, schema/v4.json)]
  end

  subgraph Agent [Python agent (optional)]
    direction TB
    AGENT[sys-scan-agent]\n(LangGraph workflows, enrichment)
    AGENT --> ENR[enriched_report.json / HTML / metrics]
    AGENT -->|socket IPC| UI[UI (optional)]
  end

  REPORT --> AGENT
  AGENT -.->|artifacts| CI[CI / analysts / pipelines]
```

Highlights — in one line each

- Deterministic, schema-validated JSON: `schema/v4.json` and `--canonical` for stable ordering.
- Memory-bounded scanners: coroutine-based `Generator<Finding>` and streaming collection via `Report::consume()`.
- Local-first intelligence: `local-qwen` provider (weights not included; set `AGENT_LOCAL_QWEN_MODEL_DIR`); external providers are opt-in.
- Safe operation: scanner failures are recorded (no process-wide crash) and the registry runs scanners with bounded parallelism.
- Developer ergonomics: packaged CLI entrypoints (`sys-scan`, `sys-scan-graph`, `sys-scan-intelligence`), clear CMake flags (Clang required for modules), and an optional UI.

---

Quick start (minimal)

Build core and run (Linux/Clang suggested):

```bash
cmake -B build -S . -G Ninja -DCMAKE_CXX_STANDARD=23 && cmake --build build -j$(nproc)
./build/sys-scan --canonical --output report.json
```

Enrich with the agent (optional):

```bash
python -m venv .venv && source .venv/bin/activate
pip install sys-scan-agent
AGENT_LLM_PROVIDER=local-qwen TRANSFORMERS_OFFLINE=1 HF_HUB_OFFLINE=1 \
  sys-scan-graph analyze --report report.json --out enriched_report.json
```

For developer details and deep dives, see `docs/wiki/` (Architecture, CLI Guide, Core Scanners).

---

## Documentation

Front door (you are here): a quick orientation for all audiences.

Deep dives live in `docs/wiki/`:

- **[Architecture Overview](docs/wiki/Architecture.md)** — core vs. intelligence responsibilities
- **[Core Scanners](docs/wiki/Core-Scanners.md)** — signals, outputs, schemas
- **[Intelligence Layer](docs/wiki/Intelligence-Layer.md)** — pipeline, providers, data governance
- **[CLI Guide](docs/wiki/CLI-Guide.md)** — full command reference
- **[Rules Engine](docs/wiki/Rules-Engine.md)** — formats, MITRE mapping, validation

---

## Repository at a glance

- **Core scanner (C++)**: `src/`, `CMakeLists.txt`
- **Intelligence layer (Python)**: `agent/` (published as `sys-scan-agent`)
- **Rules**: `rules/`
- **Schemas**: `schema/`
- **Docs (deep dives)**: `docs/wiki/`
- **Tests**: `tests/` (C++) and `agent/tests/` (Python)

### Why the split architecture?

- **C++ core**: maximizes speed, determinism, and operational portability (scan without Python)
- **Python intelligence**: fast iteration for enrichment, correlation, reporting, and policy logic

---

## Design ethos

- Deterministic, reproducible outputs (canonical JSON, stable ordering)
- Local-first, zero-trust AI (no outbound LLM APIs by default; optional external inference is explicit opt-in)
- Bounded resources by default (thread caps, batch processing, caching)
- Extensible and testable (DI-friendly scanners; pluggable providers; high coverage)

---

## Licensing & Support

- License: Apache License 2.0 (see [`LICENSE`](LICENSE))
- Issues: [GitHub Issues](https://github.com/J-mazz/sys-scan-graph/issues)
- Discussions: [GitHub Discussions](https://github.com/J-mazz/sys-scan-graph/discussions)
- Security: see [`SECURITY.md`](SECURITY.md)

![Mazzlabs Logo](assets/Mazzlabs.png)
