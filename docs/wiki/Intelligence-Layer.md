# Intelligence layer

This page is intentionally **minimal and code-aligned**.

The intelligence layer is an optional Python component (package: `sys-scan-agent`, source: `agent/`) that consumes JSON produced by the C++ core scanner and produces enriched artifacts.

## Install (optional)

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install -U pip
pip install sys-scan-agent
```

Optional local model dependencies:

```bash
pip install 'sys-scan-agent[ai]'
```

## Run

```bash
# 1) Create a raw report with the core scanner
./build/sys-scan --canonical --output report.json

# 2) Enrich/analyze the report
sys-scan-graph analyze --report report.json --out enriched_report.json
```

## Orchestration

The workflow code lives under `agent/sys_scan_agent/graph/`.

## LLM providers (local-only)

Provider selection is implemented in `agent/sys_scan_agent/llm_provider.py`.

The shipped provider factory is **local-only** (no cloud APIs). Supported values:

- `AGENT_LLM_PROVIDER=local-qwen` (default): attempts to initialize `LocalQwenLLMProvider`.
- `AGENT_LLM_PROVIDER=local`: deterministic local heuristic provider (`LocalLLMProvider`).
- `AGENT_LLM_PROVIDER=null`: deterministic no-LLM provider (`NullLLMProvider`).

If a requested local provider cannot be loaded, the code falls back to a deterministic provider.

## Metrics export

The `analyze` command supports writing node telemetry to a file via `--metrics-out`.

- `--metrics-out metrics.json`
- `--metrics-out metrics.csv`
- `--metrics-out metrics.prom`

Implementation: `agent/sys_scan_agent/metrics_exporter.py`.

## Other commands

The `sys-scan-graph` CLI includes additional subcommands (risk weights, calibration, baseline helpers, fleet reports, etc.).
Use `sys-scan-graph --help` to discover what is available in the current version.

## Related Documentation

- **[Architecture](Architecture.md)** - System architecture overview
- **[Rules Engine](Rules-Engine.md)** - Correlation rule configuration
- **[Risk Model](Risk-Model.md)** - Risk assessment and calibration
- **[CLI Guide](CLI-Guide.md)** - Command-line interface usage
- **[Architecture (Technical Details)](Architecture-Technical-Details.md)** - Implementation notes

---

*For questions about the Intelligence Layer implementation or configuration, see the [Contributing Guide](../../CONTRIBUTING.md) or open a [GitHub Discussion](https://github.com/J-mazz/sys-scan-graph/discussions).*
