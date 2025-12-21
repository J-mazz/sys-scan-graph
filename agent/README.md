# sys-scan-graph

![sys-scan-graph Logo](../assets/sys-scan-graph_badge.jpg)

## System Security Scanner & Intelligence Graph

**Sys-Scan-Graph** is a high-speed security analysis tool that transforms raw data from multiple security surfaces into a unified, actionable report.

[![CodeScene Analysis](https://codescene.io/images/analyzed-by-codescene-badge.svg)](https://codescene.io/projects/75070)
[![CodeScene Average Code Health](https://codescene.io/projects/71206/status-badges/average-code-health)](https://codescene.io/projects/75070)
[![CodeScene System Mastery](https://codescene.io/projects/71206/status-badges/system-mastery)](https://codescene.io/projects/75070)

This directory contains the optional **Python intelligence layer**, published as the `sys-scan-agent` package. It consumes JSON produced by the C++ core scanner and enriches/summarizes results locally.

### Key Features

- **Local-first analysis** of `sys-scan` JSON reports
- **CLI entry points** provided by the package (`sys-scan-graph`, `sys-scan-intelligence`)
- **Deterministic outputs** via canonicalization and stable ordering
- **Optional artifacts** such as HTML reports (configured via `config.yaml`) and metrics export (`--metrics-out`)

---

## Quick Start

### Installation

The intelligence layer is installed separately from the C++ core.

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install -U pip
pip install sys-scan-agent
```

Optional local-LLM dependencies:

```bash
pip install \
  langgraph langchain-core \
  torch transformers peft accelerate safetensors huggingface_hub
```

Optional external inference dependencies (LangChain API provider):

```bash
# IMPORTANT: You must provide your own provider credentials (not bundled with this project).
pip install langchain langchain-openai langchain-anthropic
```

### Basic Usage

```bash
# Run the C++ core scanner (from the repo root)
./build/sys-scan --canonical --output report.json

# Analyze/enrich with the Python layer
source .venv/bin/activate
sys-scan-graph analyze --report report.json --out enriched_report.json
```

### Generate HTML Report

```bash
# Enable HTML generation in ./config.yaml, then run:
sys-scan-graph analyze --report report.json --out enriched_report.json
```

---

## Documentation

For detailed documentation, see our [comprehensive wiki](../docs/wiki/_index.md):

- **[Architecture Overview](../docs/wiki/Architecture.md)** - High-level system architecture, core vs intelligence layer responsibilities
- **[Core Scanners](../docs/wiki/Core-Scanners.md)** - Scanner implementations, signals, output formats, and schemas
- **[Intelligence Layer](../docs/wiki/Intelligence-Layer.md)** - Pipeline stages, LangGraph orchestration, LLM providers, data governance

### Additional Resources

- **[Rules Engine](../docs/wiki/Rules-Engine.md)** - Rule file formats, MITRE aggregation, severity overrides, validation
- **[CLI Guide](../docs/wiki/CLI-Guide.md)** - Complete command reference
- **[Extensibility](../docs/wiki/Extensibility.md)** - Adding custom scanners and rules

---

## Repository Structure

This repository contains:

- **Core Scanner** (`src/`, `CMakeLists.txt`) - High-performance C++ scanning engine
- **Intelligence Layer** (`agent/`) - Python package (`sys-scan-agent`) for analysis and enrichment
- **Rules** (`rules/`) - Security rules and MITRE ATT&CK mappings
- **Documentation** (`docs/wiki/`) - Comprehensive project documentation
- **Tests** (`tests/`, `agent/tests/`) - Test suites for both components

---

## Key Design Principles

- **Type-safe architecture** with a C++23 toolchain using C++20 modules and dependency injection via ScanContext
- **Deterministic, reproducible results** with stable ordering and canonicalization in the Python layer
- **Local-first security posture**: no outbound LLM API calls by default; optional external inference is explicit opt-in
- **Thread-safe parallelization** with mutex-protected report aggregation
- **Extensible plugin system** supporting custom scanners, rules, and LLM providers
- **Comprehensive testing** via CTest (C++) and pytest (Python)

---

## Licensing

This project is licensed under the **Apache License 2.0**. See [`LICENSE`](../LICENSE) for complete licensing details.

---

## Support & Community

- **Documentation**: [Wiki](../docs/wiki/_index.md)
- **Issues**: [GitHub Issues](https://github.com/J-mazz/sys-scan-graph/issues)
- **Discussions**: [GitHub Discussions](https://github.com/J-mazz/sys-scan-graph/discussions)
- **Security**: See [`SECURITY.md`](../SECURITY.md) for vulnerability disclosure

---

![Mazzlabs Logo](../assets/Mazzlabs.png)

