# sys-scan-UI

<div align="center">
  <img src="resources/sys-scan-graph_primary_logo.png" alt="sys-scan-UI Logo" width="400"/>
</div>

Interactive native GTK4 dashboard for [sys-scan-graph](https://github.com/J-mazz/sys-scan-graph) security reports with LangGraph human-in-the-loop integration.

## Features

### Native GTK4 Dashboard
- **Interactive Findings Browser**: Browse security findings with rich detail views
- **Real-time Filtering**: Filter by severity, search by keywords
- **Correlation Visualization**: View relationships between findings
- **Zero External Dependencies**: Only uses Debian repository packages

### LangGraph Integration (NEW)
- **Investigation Director**: Post-analysis node that presents concise, factual summaries
- **Non-Intrusive Design**: Runs at END of pipeline, doesn't interrupt automated analysis
- **IPC Communication**: Unix domain sockets for UI<->Graph interaction
- **Concrete Investigation Areas**: Precise findings, not vague suggestions

### Agent Query Interface
- Ask natural language questions to the embedded security agent
- Asynchronous processing with callback-based UI updates
- Integration with sys-scan-graph Python intelligence layer

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              sys-scan-UI (C++ GTK4)                     │
│  ┌────────────────────────────────────────────────────┐ │
│  │  Dashboard │ FindingView │ FeedbackPanel          │ │
│  └────────┬───────────────────────────┬───────────────┘ │
└───────────┼───────────────────────────┼─────────────────┘
            │   Unix Socket IPC         │
┌───────────┼───────────────────────────┼─────────────────┐
│           ▼                           ▼                 │
│  GraphCommunicator ◄──► Investigation Director         │
│         │                      ▲                        │
│         └──────────────────────┘                        │
│              LangGraph Pipeline                         │
│  enrich → memory → reflection → ... → metrics          │
│                                         │               │
│                        Investigation Director           │
│                     (Concise Summary Node)              │
└─────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

```bash
sudo apt-get install -y \
    cmake \
    pkg-config \
    libgtk-4-dev \
    libjson-glib-dev \
    debhelper
```

### Building

```bash
# Clone the repository
git clone https://github.com/J-mazz/sys-scan-UI.git
cd sys-scan-UI

# Build
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

### Installing

```bash
# Option 1: Install locally (from build directory)
sudo make install

# Option 2: Build Debian package
# Clone the packaging repository
git clone https://github.com/J-mazz/sys-scan-ui-debian.git debian
# Then build the package
dpkg-buildpackage -us -uc -b
sudo dpkg -i ../sys-scan-ui_1.0.0-1_amd64.deb
```

### Running

```bash
# Launch UI
sys-scan-ui

# Or with specific report
sys-scan-ui /path/to/enriched_report.json
```

## LangGraph Integration

**Note:** The human-in-the-loop integration code previously shipped under `UI/integration/` has been consolidated into the Python Agent package so interactive features work reliably as a first-class capability.

### Where the integration lives now

- `agent/sys_scan_agent/graph_nodes_ui.py` — **Investigation Director** node (concise post-analysis summaries and investigation areas)
- `agent/sys_scan_agent/ipc_server.py` — IPC utilities and `GraphCommunicator`

### Investigation Director Node

Runs at the END of automated analysis to produce:
- Concise findings summary (total, by severity, novel count)
- Specific correlations discovered
- Concrete investigation areas with exact finding IDs
- Attack patterns detected (e.g., privilege escalation chains)

Example payload sent to the UI (or stored in state):
```json
{
  "type": "investigation_summary",
  "summary": { "findings": {"total": 45, ... }, ... },
  "areas": [ ... ]
}
```

### How to run (two options)

- **UI-first (recommended):** Launch the UI binary; if no IPC socket exists the UI will attempt to spawn the Agent subprocess and wait for the socket (`/tmp/sys-scan-ui.sock` by default):

```bash
./build/dist/bin/sys-scan-ui
```

- **Agent-first:** Run the Agent with the `--interactive` flag to start its IPC server and expose the Investigation Director node to incoming UI connections:

```bash
sys-scan-graph analyze --report report.json --out enriched_report.json --interactive --socket /tmp/sys-scan-ui.sock
```

### Developer notes
- Tests for the Agent-side integration live in `tests/test_graph_nodes_ui.py`.
- The Agent tries a best-effort send from the Investigation Director node when a UI is available; when starting long-running interactive services consider creating a persistent communicator (see `agent/sys_scan_agent/ipc_server.py`).

For more design details and troubleshooting steps, see `docs/wiki/Interactive-UI.md`.

## Project Structure

```
sys-scan-UI/
├── src/                      # C++ source files
│   ├── main.cpp
│   ├── report_parser.cpp
│   ├── dashboard_window.cpp
│   ├── finding_view.cpp
│   ├── agent_interface.cpp
│   └── feedback_panel.cpp
├── include/                  # C++ headers
├── tests/                    # Unit tests (Google Test)
│   ├── test_main.cpp
│   └── test_report_parser.cpp
├── integration/              # LangGraph integration (Python)
│   ├── nodes/               # Custom nodes
│   │   └── investigation_director.py
│   ├── ipc/                 # IPC communication
│   │   └── communication.py
│   └── workflow_extension.py
├── resources/               # Desktop files, icons
│   ├── sys-scan-ui.desktop      # Desktop entry
│   ├── sys-scan-graph_logo1.png # Primary application icon
│   ├── sys-scan-graph_logo2.png # Alternative application icon
│   └── sys-scan-graph_primary_logo.png # Logo for documentation
└── CMakeLists.txt
```

## Documentation

- [`README.md`](README.md) - This file
- [`BUILD.md`](BUILD.md) - Detailed build instructions
- [`USAGE.md`](USAGE.md) - User guide
- [`PROJECT_SUMMARY.md`](PROJECT_SUMMARY.md) - Architecture overview
- [`INTEGRATION_SUMMARY.md`](INTEGRATION_SUMMARY.md) - LangGraph integration details
- [`integration/README.md`](integration/README.md) - Integration layer documentation
- [sys-scan-ui-debian](https://github.com/J-mazz/sys-scan-ui-debian) - Debian packaging repository

## Dependencies

### Runtime
- libgtk-4-1 (GTK4 runtime)
- libjson-glib-1.0-0 (JSON parsing)
- sys-scan-graph (recommended, for agent functionality)

### Build
- cmake (>= 3.16)
- pkg-config
- libgtk-4-dev
- libjson-glib-dev
- debhelper-compat (= 13)

## Statistics

- **~1,079 lines** of C++20 code
- **~1,040 lines** of Python integration code
- **Zero external dependencies** (beyond GTK4/json-glib in Debian)
- **Fully packagable** with dpkg-buildpackage

## Debian Policy Compliance

- Uses only packages from Debian main repository
- Follows FHS (Filesystem Hierarchy Standard)
- Proper dependency declarations
- No embedded library copies
- debhelper 13 compatibility level
- Standards-Version 4.6.0

## Integration with sys-scan-graph

Designed to work seamlessly with sys-scan-graph:
- Reads enriched JSON from `sys-scan-graph analyze`
- Can invoke agent for interactive queries
- Displays MITRE ATT&CK mappings and compliance data
- Visualizes correlations discovered by intelligence layer
- **NEW**: Investigation Director node for post-analysis interaction

## License

Apache License 2.0 - See [`debian/copyright`](debian/copyright) for full text.

## Contributing

See the main [sys-scan-graph](https://github.com/J-mazz/sys-scan-graph) repository for contribution guidelines.

## Support

- Issues: [GitHub Issues](https://github.com/J-mazz/sys-scan-UI/issues)
- Documentation: See docs in this repository
- sys-scan-graph: [Main Repository](https://github.com/J-mazz/sys-scan-graph)
