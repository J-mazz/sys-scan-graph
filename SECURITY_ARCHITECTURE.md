# Security Architecture

## Zero-Trust AI Posture

**Core principle:** no external LLM APIs. All intelligence runs locally using the default **local-qwen** provider; deterministic heuristic fallback remains available. No outbound network calls are made during analysis when offline flags are set.

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
- Data stays on-host: no telemetry, metering, or remote logging.
- Bounded resources: thread caps and batch processing to avoid OOM in default configs.

### ❌ What we never do
- No OpenAI/Anthropic/Cohere/Together/Groq or any cloud LLM APIs.
- No API keys required, stored, or transmitted.
- No outbound telemetry or data exfiltration.

## Dependency stance

Safe (local-only): `langgraph`, `langchain-core`, `pydantic`, `sqlalchemy`, `torch`, `transformers`, `peft`, `accelerate`, `huggingface_hub` (for local model loading/caching). Explicitly excluded: `openai`, `anthropic`, `langchain-openai`, `langchain-anthropic`, `cohere`, `together`, or any cloud LLM client.

## Quick audit steps

```bash
# Check for cloud LLM imports
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

- Keep intelligence local-first; no cloud LLM APIs.
- Audit PRs for networked AI dependencies.
- Document any new network dependency explicitly and conservatively.
- Preserve deterministic, offline-friendly defaults.

If you spot an external API call, please report it as a security vulnerability immediately.

