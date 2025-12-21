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
