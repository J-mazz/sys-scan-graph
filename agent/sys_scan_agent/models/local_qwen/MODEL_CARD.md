# Qwen3 Security Agent (local)

**Model name:** local-qwen — Qwen3 Security Agent / Security Analyst (Qwen3-4B-Instruct-2507 fine-tuned)  \
**Provider aliases:** `local-qwen`, `local_agent`, `local-llm`, `local_llm`  \
**Domain:** host security scan summarization, triage, and rule refinement  \
**Deployment:** on-box / air-gapped; no external calls

## Overview
A locally runnable Qwen3-based model fine-tuned for security scan reasoning. It is wired into the sys-scan agent DAG via the `LocalQwenLLMProvider` and is the default provider when `AGENT_LLM_PROVIDER` is unset or set to a local alias. All inference is offline and zero-trust.

## Base & Training Data
- **Base model:** [`unsloth/Qwen3-4B-Instruct-2507`](https://huggingface.co/unsloth/Qwen3-4B-Instruct-2507)
- **Fine-tune dataset:** [`jmazz/sys-scan_synthetic_dataset_v2`](https://huggingface.co/datasets/jmazz/sys-scan_synthetic_dataset_v2)
- **Training pipeline:** see notebook `notebooks/Qwen3_Security_Agent_Pipeline.ipynb` (SFT then GRPO phases)

## Task & Capabilities
- Summarize enriched security findings with correlations and actions
- Triage findings and surface top issues
- Refine rules with deterministic structure, optionally augmented by generation
- Preserves schema-aligned outputs for downstream ingestion

## Intended Use
- On-device, offline inference inside the sys-scan graph pipeline
- Zero external network dependency; suitable for restricted environments

## Limitations
- Falls back to heuristic summaries if model weights are missing or fail to load
- Generation is trimmed to concise summaries; long-form reasoning is not guaranteed
- Relies on local GPU/CPU resources; quantization/throughput depend on hardware

## Files & Layout
- Model directory: `agent/sys_scan_agent/models/local_qwen/`
  - Place safetensor shards and config here; `shards/` is provided for split weights
  - Example expected files: `config.json`, `tokenizer.json`, `tokenizer.model`, `generation_config.json`, `model.safetensors` (or shards under `shards/`)

## Usage
- Environment variables:
  - `AGENT_LLM_PROVIDER` (default: `local-qwen`) — selects this provider
  - `AGENT_LOCAL_QWEN_MODEL_DIR` — override path to the local Qwen weights
- Provider entrypoint: `LocalQwenLLMProvider` (loaded via `get_llm_provider()`)

## Inference Notes
- Deterministic-first: starts from heuristic outputs, then overwrites summary if generation succeeds
- Temperature defaults to 0 for consistency; no external APIs are called

## Safety & Governance
- Offline-only; no telemetry or data egress
- Schema and redaction routines still apply upstream/downstream

## Evaluation
- Alignment and reasoning tuned via SFT + GRPO on the synthetic dataset; for production, validate against your own ground-truth findings.
