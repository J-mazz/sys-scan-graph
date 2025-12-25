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
pip install \
	langgraph langchain-core \
	torch transformers peft accelerate safetensors huggingface_hub
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

## LLM providers (local-first)

Provider selection is implemented in `agent/sys_scan_agent/llm_provider.py`.

By default, the project is **local-first** (no cloud LLM API calls unless you explicitly opt in). Supported values:

- `AGENT_LLM_PROVIDER=local-qwen` (default): attempts to initialize `LocalQwenLLMProvider`.
  - See `agent/sys_scan_agent/models/local_qwen/MODEL_CARD.md` for local-QWEN model files and usage notes.
- `AGENT_LLM_PROVIDER=local`: deterministic local heuristic provider (`LocalLLMProvider`).
- `AGENT_LLM_PROVIDER=null`: deterministic no-LLM provider (`NullLLMProvider`).
- `AGENT_LLM_PROVIDER=langchain-api`: **external inference via LangChain** (opt-in).

### LangChain API provider (opt-in)

This mode enables an external inference API via LangChain integrations.

Requirements:

- Install external inference dependencies:

	`pip install langchain langchain-openai langchain-anthropic`
- Explicitly opt in by setting `AGENT_EXTERNAL_LLM_ENABLED=1`
- Provide your own credentials for your chosen inference provider (not bundled with this project)

Common configuration:

- `AGENT_EXTERNAL_LLM_ENABLED=1`
- `AGENT_LANGCHAIN_PROVIDER=openai|anthropic`
- `AGENT_LANGCHAIN_MODEL=<provider-model-name>`
- `AGENT_LANGCHAIN_TEMPERATURE=0.1`

Note: this mode may transmit analysis content to your provider and may incur cost.

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
