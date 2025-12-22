# CLI guide

This page documents the CLIs that exist in this repository today.

## Core scanner (C++): `sys-scan`

Build:

```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

Run:

```bash
./build/sys-scan
```

`src/main.cpp` now includes a minimal flag parser and emits JSON that conforms to `schema/v4.json` (ground_truth_v1 compatible). Canonical ordering is available when requested.

Common flags:

- `--output FILE` — write JSON to a file (otherwise stdout)
- `--canonical` — stable ordering of scanners/findings
- `--enable NAME` / `--disable NAME` — run only selected scanners
- `--test-root PATH` — run against an alternate root (fixtures)

Scanner toggles (per-code-path and wired today):

- `--no-hardening` (off by default? no, hardening defaults on)
- `--no-process-inventory` / `--all-processes`
- `--no-user-meta`
- `--listen-only` (network scanner)
- `--fast-scan` (skips heavier checks in some scanners)
- `--modules-summary-only`
- `--containers`
- `--integrity`
- `--ioc-trace` [`--ioc-trace-seconds N`]
- `--rules-enable` [`--yara-root PATH`]

Example:

```bash
./build/sys-scan \
  --canonical \
  --enable processes --enable network \
  --output report.json
```

## Intelligence layer (Python): `sys-scan-graph`

The intelligence layer is optional and is shipped as the `sys-scan-agent` Python package (source: `agent/`).

Install:

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install -U pip
pip install sys-scan-agent
```

Run analysis:

```bash
sys-scan-graph analyze --report report.json --out enriched_report.json
```

The `--report` input must be a JSON report. This repository includes sample reports you can use for experimentation (for example, `report.json`).

### Metrics export

`analyze` can export node telemetry to a file via `--metrics-out`:

```bash
sys-scan-graph analyze \
  --report report.json \
  --out enriched_report.json \
  --metrics-out metrics.json
```

Supported extensions: `.json`, `.csv`, `.prom`.

### Interactive / UI mode

The Agent supports an interactive mode that enables IPC with a UI dashboard. These options are intended for local, interactive workflows (not CI). There are two common ways to use the UI: **UI-first** (launch the GUI and let it spawn or connect to an agent) and **Agent-first** (start the agent and then run the GUI).

- `--interactive` — start the Agent's IPC server and enable the Investigation Director node at the end of the pipeline.
- `--socket <path>` — path for the Unix domain socket used for UI↔Agent communication (default: `/tmp/sys-scan-ui.sock`).

1) UI-first (recommended for interactive sessions): build and launch the UI binary. If the agent socket is missing the UI will attempt to spawn the Agent subprocess (ensure the `sys-scan-graph` CLI is on PATH or install the Agent into your venv).

```bash
# Build UI (if not already built)
cmake -B build -S . -DBUILD_UI=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc) --target sys-scan-ui

# Run UI (repo-built binary)
./build/UI/sys-scan-ui
# (the UI will try to spawn 'sys-scan-graph' or 'python3 -m sys_scan_agent.cli' if the socket is missing)
```

2) Agent-first (recommended when iterating on the Agent): start the Agent in interactive mode, then run the UI which will connect to the socket.

```bash
# Activate venv and install editable package if needed
python3 -m venv .venv
source .venv/bin/activate
pip install -e ./agent

# Start the agent (it will start the IPC server on the socket)
sys-scan-graph analyze --report report.json --out enriched_report.json --interactive --socket /tmp/sys-scan-ui.sock

# Start the UI and it will connect to the agent
./build/UI/sys-scan-ui
```

Troubleshooting:
- If the UI prints errors like "module 'QtQuick.Window' is not installed", install the Qt Quick runtime and required QML modules (see Installation Guide).
- If the UI reports "Main QML not found" or fails to load QML, confirm `build/UI/resources/qml/Main.qml` exists (re-run CMake configure/build after enabling `BUILD_UI`).
- If the UI cannot spawn the agent, ensure `sys-scan-graph` is available on PATH (install the Agent into your venv or system) or start the Agent first using the Agent-first flow above.

Note: When `--interactive` is set, the Agent will attempt to start the IPC server (via `agent.sys_scan_agent.ipc_server.start_ipc_thread`).

### Environment variables (optional)

The agent supports several `AGENT_*` environment variables. Common ones include:

- `AGENT_LLM_PROVIDER=local-qwen` (default): local Qwen provider (when available)
- `AGENT_LLM_PROVIDER=local`: deterministic local heuristic provider
- `AGENT_LLM_PROVIDER=null`: deterministic no-LLM provider
- `AGENT_LLM_PROVIDER=langchain-api`: external inference via LangChain (**requires** `AGENT_EXTERNAL_LLM_ENABLED=1` and your own provider credentials)
- `AGENT_EXTERNAL_LLM_ENABLED=1`: explicit opt-in gate for external inference
- `AGENT_LANGCHAIN_PROVIDER=openai|anthropic`
- `AGENT_LANGCHAIN_MODEL=<provider-model-name>`
- `AGENT_BASELINE_DB=agent_baseline.db`
- `AGENT_MAX_SUMMARY_ITERS=3`

For the full command list, run `sys-scan-graph --help`.
