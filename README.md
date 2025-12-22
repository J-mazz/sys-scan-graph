# sys-scan-graph

![sys-scan-graph Logo](assets/sys-scan-graph_badge.jpg)

## System Security Scanner & Intelligence Graph

[![CI](https://github.com/J-mazz/sys-scan-graph/actions/workflows/ci.yml/badge.svg)](https://github.com/J-mazz/sys-scan-graph/actions/workflows/ci.yml)
[![CodeQL](https://github.com/J-mazz/sys-scan-graph/actions/workflows/codeql.yml/badge.svg)](https://github.com/J-mazz/sys-scan-graph/actions/workflows/codeql.yml)
[![CodeScene Analysis](https://codescene.io/images/analyzed-by-codescene-badge.svg)](https://codescene.io/projects/71206)
[![CodeScene Average Code Health](https://codescene.io/projects/72512/status-badges/average-code-health)](https://codescene.io/projects/72512)
[![CodeScene System Mastery](https://codescene.io/projects/72512/status-badges/system-mastery)](https://codescene.io/projects/72512)
[![Coverage](https://img.shields.io/badge/coverage-%3E=85%25-brightgreen.svg)](docs/TEST_COVERAGE.md)

**Sys-Scan-Graph** turns raw host signals from multiple security surfaces into a concise, actionable security report.

It combines a **high-performance C++ core** (built with a C++23 toolchain, using C++20 modules) with an **optional local intelligence layer** (Python) that enriches and summarizes results without sending data off-host.

```mermaid
flowchart LR
  A[Core scan (C++)] -->|report.json| B[Python intelligence]
  B -->|enriched_report.json| C[Analysts & pipelines]
  B -->|HTML / metrics| D[Dashboards & CI]
```

### Highlights

- **Deterministic scans**: canonical JSON output with stable ordering
- **Local intelligence**: default `local-qwen` provider (offline), with heuristic fallback
- **Performance-aware**: bounded parallelism, batch processing, cache primitives, and memory-safe defaults
- **Composable**: DI-friendly scanners and pluggable rule/LLM providers
- **Secure by design**: zero outbound LLM calls; works air-gapped after model download

---

## Quick Start

### Core scanner (C++)

```bash
git clone https://github.com/J-mazz/sys-scan-graph.git
cd sys-scan-graph

cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

### Intelligence layer (Python, optional)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install sys-scan-agent

# Optional: local model + orchestration dependencies (torch/transformers/etc.)
# Note: model weights are NOT shipped with the PyPI package. Provide weights locally via
# AGENT_LOCAL_QWEN_MODEL_DIR (see agent/sys_scan_agent/models/local_qwen/MODEL_CARD.md).
pip install \
  langgraph langchain-core \
  torch transformers peft accelerate safetensors huggingface_hub

# Optional: external inference via LangChain (networked, opt-in)
# IMPORTANT: You must provide your own provider credentials for your chosen inference provider.
pip install langchain langchain-openai langchain-anthropic
```

### Optional Dashboard (Interactive UI) ✅

We provide an optional Qt/QML dashboard (`UI/`) that can run the Agent interactively and display investigation summaries. The UI build is controlled from the root CMake **master** using the `BUILD_UI` option.

- Enable UI build:

```bash
cmake -B build -S . -DBUILD_UI=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

- Requirements: Qt6 (install platform packages e.g. `qt6-base-dev`, `qt6-declarative-dev` on Debian/Ubuntu) or let CMake disable the UI when Qt6 is not found.

- Running options:
  - UI-first (recommended for interactive sessions): run the UI binary (`sys-scan-ui`). If the UI cannot find an existing agent IPC socket it will attempt to spawn the Agent as a worker subprocess using the default socket (`/tmp/sys-scan-ui.sock`).

```bash
# Launch UI; it will try to start the agent if needed
./build/UI/sys-scan-ui
```

  - Agent-first: run the Agent with the `--interactive` flag which starts an IPC server and enables the Investigation Director node in the graph. The Agent exposes a `--socket` option to set the socket path.

```bash
sys-scan-graph analyze --report report.json --out enriched_report.json --interactive --socket /tmp/sys-scan-ui.sock
```

- Developer notes:
  - Integration code for the Investigation Director and IPC lives inside the Agent package (`agent/sys_scan_agent/graph_nodes_ui.py` and `agent/sys_scan_agent/ipc_server.py`).
  - Unit tests for the Investigation Director node are in `tests/test_graph_nodes_ui.py`.

For full developer details and troubleshooting, see `docs/wiki/Interactive-UI.md`.

### Run (memory-safe defaults)

```bash
# 1) Core scan
./build/sys-scan --canonical --output report.json

# 2) Enrich locally (offline, bounded threads)
AGENT_LLM_PROVIDER=local-qwen \
AGENT_GRAPH_APP_ENABLED=0 \
OMP_NUM_THREADS=4 MKL_NUM_THREADS=4 \
sys-scan-graph analyze --report report.json --out enriched_report.json
```

Tips: use `--metrics-out metrics.json` to capture node timings. HTML output is controlled by `config.yaml` (see `reports.html_enabled` and `reports.html_path`). Set `TRANSFORMERS_OFFLINE=1 HF_HUB_OFFLINE=1` to avoid network calls.

### Common workflows

1. **Scan only (fastest path):**

```bash
./build/sys-scan --canonical --output report.json
```

1. **Scan + enrich locally (recommended):**

```bash
./build/sys-scan --canonical --output report.json

AGENT_LLM_PROVIDER=local-qwen \
AGENT_GRAPH_APP_ENABLED=0 \
TRANSFORMERS_OFFLINE=1 HF_HUB_OFFLINE=1 \
OMP_NUM_THREADS=4 MKL_NUM_THREADS=4 \
sys-scan-graph analyze --report report.json --out enriched_report.json
```

1. **CI-friendly output (artifacts):**

Persist `report.json` (and optionally `enriched_report.json`) as CI artifacts for review and trend analysis.

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
