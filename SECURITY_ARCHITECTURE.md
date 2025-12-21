# Security Architecture

## Zero-Trust AI Posture

**Core principle (default):** no external LLM APIs. All intelligence runs locally using the default **local-qwen** provider; deterministic heuristic fallback remains available.

```mermaid
flowchart TD
  A[sys-scan (C++)] --> B[report.json]
  B --> C[sys-scan-graph (Python)]
  C -->|local-qwen| D[Local inference]
  C -->|fallback| E[Heuristic engine]
  D --> F[Enriched outputs]
  E --> F[Enriched outputs]
```

## Guarantees

### ✅ What we do
- Local inference only (default `AGENT_LLM_PROVIDER=local-qwen`); heuristic fallback if models are absent.
- Deterministic settings: low-temperature generation, canonical ordering, reproducible outputs.
- Offline-capable: set `TRANSFORMERS_OFFLINE=1 HF_HUB_OFFLINE=1` to avoid network calls; models load from disk.
- Data stays on-host by default: outputs are written locally; the project does not ship built-in telemetry, metering, or remote logging.
- Bounded resources: thread caps and batch processing to avoid OOM in default configs.

### ❌ What we never do
- No cloud LLM API calls **by default**.
- No built-in outbound telemetry or remote logging.
- No project-managed API keys: if you opt into an external provider, you must supply and manage your own credentials.

## Optional external inference (LangChain API provider)

If you explicitly opt in, the intelligence layer can call an external inference API through LangChain.

**Important:** This may transmit analysis content to your chosen provider, may incur cost, and requires outbound network access.

Enable it explicitly:

```bash
AGENT_EXTERNAL_LLM_ENABLED=1 \
AGENT_LLM_PROVIDER=langchain-api \
AGENT_LANGCHAIN_PROVIDER=openai \
AGENT_LANGCHAIN_MODEL=<your-model-name> \
sys-scan-graph analyze --report report.json --out enriched_report.json
```

Credentials are **not** bundled with this project. You must provide your own credentials for the provider you choose.
For example, OpenAI and Anthropic integrations typically use environment variables like `OPENAI_API_KEY` or
`ANTHROPIC_API_KEY` (see your provider’s documentation).

## Dependency stance

Safe (local-first default): `langgraph`, `langchain-core`, `pydantic`, `sqlalchemy`, `torch`, `transformers`, `peft`, `accelerate`, `huggingface_hub` (for local model loading/caching).

Optional (external inference; only installed/used if you opt in): `langchain`, `langchain-openai`, `langchain-anthropic` and their underlying provider SDKs.

## Quick audit steps

```bash
# Check for cloud LLM imports (expected only for the optional LangChain API provider)
grep -R "openai\|anthropic\|ChatOpenAI\|ChatAnthropic" agent/sys_scan_agent || true

# Check for HTTP clients
grep -R "requests\|httpx\|urllib" agent/sys_scan_agent || true

# Confirm provider selection and offline flags at runtime
AGENT_LLM_PROVIDER=local-qwen TRANSFORMERS_OFFLINE=1 HF_HUB_OFFLINE=1 \
python - <<'PY'
import os
from sys_scan_agent.llm_provider import get_llm_provider
provider = get_llm_provider()
print(provider.__class__.__name__)
assert 'local' in os.environ['AGENT_LLM_PROVIDER']
PY
```

## Threat model (summarized)

Mitigated: data exfiltration, API key leakage, network sniffing of LLM traffic, third-party logging. Residual: one-time model download supply-chain risk (mitigate by pre-seeding `HUGGINGFACE_HUB_CACHE` in a trusted environment), general PyTorch/CUDA CVEs (mitigate via pinning/vendor and CVE monitoring).

## Maintainer commitment

- Keep intelligence local-first by default; any external inference stays opt-in and gated.
- Audit PRs for networked AI dependencies.
- Document any new network dependency explicitly and conservatively.
- Preserve deterministic, offline-friendly defaults.

If you spot an external API call, please report it as a security vulnerability immediately.

