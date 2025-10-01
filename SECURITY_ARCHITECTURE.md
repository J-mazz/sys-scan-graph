# Security Architecture

## Zero-Trust AI Security Posture

### Core Principle: No External API Dependencies

This project maintains a **zero-trust security architecture** with **absolute prohibition of external LLM API calls**. All intelligence processing occurs locally using embedded models with no outbound network dependencies for AI operations.

## Security Guarantees

### ✅ What We Do

1. **Local Model Inference Only**
   - Mistral-7B-Instruct-v0.3 with 168MB LoRA adapters runs entirely on-device
   - PyTorch inference with no cloud dependencies
   - All model weights stored locally or downloaded once from HuggingFace (optional)

2. **Deterministic Processing**
   - `LLMClient` class provides structured analysis without external calls
   - All "LLM" operations are deterministic heuristics and rule-based transformations
   - Simulated token counts for observability, no actual API metering

3. **Workflow Orchestration Without APIs**
   - LangGraph/LangChain-core used solely for state machine orchestration
   - No `ChatOpenAI`, `ChatAnthropic`, or any cloud LLM provider imports
   - `langchain_core.messages` used only for local data structures

4. **Air-Gapped Capable**
   - Can operate in completely offline environments
   - No internet connectivity required after initial model download
   - All dependencies can be vendored/cached

### ❌ What We Never Do

1. **No External LLM APIs**
   - No OpenAI API calls
   - No Anthropic Claude API calls
   - No Together AI, Groq, Cohere, or any cloud LLM services
   - No API keys required or accepted

2. **No Telemetry**
   - No usage analytics sent externally
   - No phone-home behavior
   - No cloud logging or monitoring integrations

3. **No Data Exfiltration**
   - Security findings never leave the host
   - All analysis occurs in-process
   - No external endpoints for data transmission

## Architecture Components

### Local Intelligence Stack

```
┌─────────────────────────────────────────┐
│  Sys-Scan C++ Core (Native Scanning)   │
│  ✓ Process/Module/Network/File scans   │
│  ✓ SUID/Capabilities/Mount inspection  │
│  ✓ JSON output with no external deps   │
└──────────────┬──────────────────────────┘
               │ JSON findings
               ↓
┌─────────────────────────────────────────┐
│  Python Intelligence Layer (Local AI)   │
│  ✓ Mistral-7B inference (torch)        │
│  ✓ LangGraph orchestration (no APIs)   │
│  ✓ Rule correlation engine              │
│  ✓ SQLite baseline storage              │
└─────────────────────────────────────────┘
               ↓
         Enriched Reports
```

### Dependency Audit

**Safe Dependencies (No API Calls):**
- `langgraph>=0.2,<1` - Workflow state machine (local only)
- `langchain-core>=0.3,<1` - Message types and tool decorators (no APIs)
- `torch>=2.0.0` - Local tensor operations
- `transformers>=4.40.0` - Model loading and inference
- `peft>=0.10.0` - LoRA adapter loading
- `huggingface_hub>=0.20.0` - Optional for model download only

**Explicitly Excluded:**
- ❌ `openai` - OpenAI API client
- ❌ `anthropic` - Anthropic API client
- ❌ `langchain-openai` - OpenAI LangChain integration
- ❌ `langchain-anthropic` - Anthropic LangChain integration
- ❌ `cohere` - Cohere API client
- ❌ `together` - Together AI client
- ❌ Any package containing "api", "client", "cloud" for LLM services

## Verification Protocol

### Audit Commands

```bash
# Verify no external API imports
grep -r "openai\|anthropic\|ChatOpenAI\|ChatAnthropic" agent/sys_scan_graph_agent/*.py
# Expected: No matches (only local LangChain-core imports)

# Check for HTTP clients
grep -r "import requests\|import httpx\|import urllib" agent/sys_scan_graph_agent/*.py
# Expected: Only unused import in cli.py

# Verify requirements.txt
grep -E "openai|anthropic|cohere|together" agent/requirements.txt
# Expected: No matches
```

### Runtime Verification

```python
# Test local-only operation
import sys
sys.path.insert(0, 'agent')
from sys_scan_graph_agent.graph import build_workflow

# Build workflow - should succeed without network
workflow, app = build_workflow(enhanced=True)
assert app is not None, "Workflow must compile without external dependencies"

# Verify no API keys in environment
import os
assert 'OPENAI_API_KEY' not in os.environ
assert 'ANTHROPIC_API_KEY' not in os.environ
```

## Threat Model

### Mitigated Threats

1. **Data Exfiltration** - No findings leave host memory
2. **API Key Compromise** - No API keys exist or are required
3. **Supply Chain Attack** - All dependencies audit-able and vendorable
4. **Network Sniffing** - No LLM traffic to intercept
5. **Third-Party Logging** - No external services with data access

### Residual Risks

1. **HuggingFace Model Download** - One-time download if model not cached
   - Mitigation: Download models in trusted environment, distribute offline
   - Optional: Use `HUGGINGFACE_HUB_CACHE` to pre-populate models

2. **PyTorch Vulnerabilities** - Standard software supply chain risk
   - Mitigation: Pin versions, vendor dependencies, regular CVE monitoring

## Compliance Notes

- **GDPR/Privacy:** All PII stays on-device, no cloud processing
- **Air-Gapped:** Fully operational without internet after model download
- **Zero-Trust:** No trust in external services required or granted
- **Audit Trail:** All processing is deterministic and reproducible

## Maintainer Commitment

We commit to:
1. Never adding external LLM API dependencies
2. Auditing all PRs for external API calls
3. Maintaining local-first architecture
4. Documenting any new network dependencies explicitly

**If you discover any external API calls, please report immediately as a security vulnerability.**

---

Last Updated: 2025-09-30  
Maintainer: Joseph Mazzini <joseph@mazzlabs.works>
