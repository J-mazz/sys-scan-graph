# Interactive UI (Qt/QML) — Design & Usage

This page documents the interactive dashboard (UI) and how it integrates with the Python Agent.

Status
- The UI is optional; it is built when `BUILD_UI` is enabled in the root `CMakeLists.txt`.
- Integration pieces (Investigation Director + IPC) were promoted into the Agent package so interactive features are first-class and importable from `agent/sys_scan_agent`.

Key files
- `UI/` — Qt/QML Dashboard sources and assets (C++ / QML) and packaging helpers
- `agent/sys_scan_agent/graph_nodes_ui.py` — Investigation Director node (post-analysis summary)
- `agent/sys_scan_agent/ipc_server.py` — IPC utilities (`FeedbackChannel`, `GraphCommunicator`, `start_ipc_thread`)
- `tests/test_graph_nodes_ui.py` — Unit tests validating Investigation Director behavior and IPC send logic

Build & run

1) Build the entire project (UI enabled by default in local dev branches):

```bash
cmake -B build -S . -DBUILD_UI=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

2) Two ways to run interactively:

- UI-first (recommended for interactive sessions):
  - Launch the UI binary. If it does not detect an existing IPC socket it will try to spawn the Agent subprocess and wait for a connection.

```bash
./build/UI/sys-scan-ui
# or installed system-wide as `sys-scan-ui`
```

- Agent-first:
  - Start the agent with `--interactive` and specify the socket path if needed (default: `/tmp/sys-scan-ui.sock`).

```bash
sys-scan-graph analyze --report report.json --out enriched_report.json --interactive --socket /tmp/sys-scan-ui.sock
```

Design notes

- The C++ UI uses a Unix domain socket for IPC by default; the socket path can be overridden by the Agent CLI `--socket` option.
- The Agent provides `start_ipc_thread()` which starts an IPC server and returns a `GraphCommunicator` instance that can be closed when the run finishes.
- The Investigation Director node constructs a concise, factual payload (summary + areas) and attempts a best-effort send to any connected UI. The payload now includes `report_path` (from the agent `output_path` state key) so the UI can trigger a reload of an enriched report when analysis completes. This is non-blocking and failures are logged; the node still completes the pipeline when the UI is unavailable.
- The UI's `AgentService::ask` generator has been implemented to use the local `llama.cpp` backend when available; otherwise it falls back to mock streaming. The implementation tokenizes the prompt, runs decode steps, and yields generated text pieces incrementally.

Developer guidance

- Prefer starting the Agent with `--interactive` for long-lived interactive sessions (avoids repeated connect attempts from nodes).
- For quick integration tests, the UI will spawn a short-lived Agent subprocess when the socket is missing — this is intended for usability and local demos.
- If you need persistent IPC, consider creating a singleton communicator on process start and passing it into graph nodes via state, instead of per-node connect attempts.

Troubleshooting

- If UI cannot connect, check socket permissions and that the socket file exists (`ls -l /tmp/sys-scan-ui.sock`).
- To debug IPC: set `LOGLEVEL=DEBUG` (or adjust logging config) to see `GraphCommunicator` and `FeedbackChannel` logs.
- If the UI is not starting due to missing Qt libraries, CMake will print a warning and skip the UI build — install Qt6 and rerun CMake.

Testing

- Unit tests for the Investigation Director are in `tests/test_graph_nodes_ui.py`. They mock the communicator to avoid network/socket usage.
- Integration tests that exercise the UI would require either a lightweight mocked UI socket server or an automated UI session; these are good candidates for future e2e tests.

Security & sandboxing

- IPC uses Unix domain sockets by default and stays local to the host. The Agent and UI should be run under the same user account when possible to avoid permission issues.
- The integration follows the repository's zero-outbound model: the UI only displays data and can request human feedback; no automatic outbound LLM calls are introduced by the UI.

Questions / follow-ups

- Want me to add an integration test that spawns a fake UI socket and validates message exchange? (I can add a pytest-based fixture to simulate the UI side.)
- Want the README to document how to package the UI and Agent together into a single distribution (deb/package instructions)?
