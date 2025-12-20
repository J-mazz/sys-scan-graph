from __future__ import annotations
"""Local Qwen provider for zero-trust, offline inference.

This provider is designed for deterministic, on-box usage of Qwen weights
stored as safetensor shards. It attempts to load a local model directory
and gracefully falls back to the heuristic provider when weights or
dependencies are unavailable. No remote calls are made.
"""
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime
import os
from pathlib import Path
import logging

from ..llm_provider import ILLMProvider, ProviderMetadata, NullLLMProvider
from .. import models

logger = logging.getLogger(__name__)

Reductions = models.Reductions
Correlation = models.Correlation
Summaries = models.Summaries
ActionItem = models.ActionItem


class LocalQwenLLMProvider(ILLMProvider):
    """Local Qwen model wrapper with safe fallbacks.

    The provider lazily loads the tokenizer/model from a local directory.
    If the model cannot be loaded, it falls back to the deterministic
    heuristic provider while keeping the provider metadata tagged as Qwen.
    """

    def __init__(self, *, model_dir: Optional[str] = None, device: str = "auto"):
        self.device = device
        self.model_dir = self._resolve_model_dir(model_dir)
        self._tokenizer = None
        self._model = None
        self._delegate = NullLLMProvider()
        self._load_error: Optional[Exception] = None
        self.model_name = "qwen-local"
        self.provider_name = "local-agent"
        # lazy load to avoid import errors when deps are missing
        self._model_initialized = False

    # ----------------- internal helpers -----------------
    def _resolve_model_dir(self, override: Optional[str]) -> Path:
        if override:
            return Path(override)
        env_dir = os.environ.get("AGENT_LOCAL_QWEN_MODEL_DIR")
        if env_dir:
            return Path(env_dir)
        # packaged default for shards (prefer shards/ if present)
        base = Path(__file__).parent / "models" / "local_qwen"
        shards = base / "shards"
        return shards if shards.exists() else base

    def _lazy_load(self) -> None:
        if self._model_initialized:
            return
        self._model_initialized = True
        try:
            from transformers import AutoTokenizer, AutoModelForCausalLM
            import torch  # noqa: F401 - imported for side effects / device mapping

            if not self.model_dir.exists():
                raise FileNotFoundError(
                    f"Local Qwen model directory not found: {self.model_dir}. "
                    "Place safetensor shards and config here."
                )

            self._tokenizer = AutoTokenizer.from_pretrained(
                str(self.model_dir),
                trust_remote_code=True,
            )
            if self._tokenizer.pad_token is None:
                self._tokenizer.pad_token = self._tokenizer.eos_token

            self._model = AutoModelForCausalLM.from_pretrained(
                str(self.model_dir),
                device_map=self.device,
                trust_remote_code=True,
            )
            logger.info("✓ Loaded local Qwen model from %s", self.model_dir)
        except Exception as exc:  # pragma: no cover - defensive path
            self._load_error = exc
            self._tokenizer = None
            self._model = None
            logger.warning("Local Qwen load failed, using heuristic fallback: %s", exc)

    def _retag_metadata(self, metadata: ProviderMetadata) -> ProviderMetadata:
        data = metadata._asdict()
        data.update({
            "model_name": self.model_name,
            "provider_name": self.provider_name,
            "timestamp": data.get("timestamp") or datetime.now().isoformat(),
            "error_message": self._load_error and str(self._load_error),
        })
        return ProviderMetadata(**data)

    def _maybe_generate(self, prompt: str, *, max_new_tokens: int = 256, temperature: float = 0.0) -> Optional[str]:
        self._lazy_load()
        if not self._model or not self._tokenizer:
            return None
        try:
            inputs = self._tokenizer(prompt, return_tensors="pt").to(self._model.device)
            outputs = self._model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                temperature=temperature,
                do_sample=temperature > 0,
            )
            return self._tokenizer.decode(outputs[0], skip_special_tokens=True)
        except Exception as exc:  # pragma: no cover - inference errors
            logger.warning("Local Qwen generation failed, falling back: %s", exc)
            return None

    def _summary_prompt(self, reductions: Reductions, correlations: List[Correlation], actions: List[ActionItem]) -> str:
        return (
            "You are a local security analyst model (Qwen). "
            "Summarize key findings, correlations, and recommended actions in a concise executive summary. "
            f"Findings: {reductions.get('top_findings', []) if isinstance(reductions, dict) else getattr(reductions, 'top_findings', [])}. "
            f"Correlations: {[c.id for c in correlations]}. "
            f"Actions: {[a.action for a in actions]}"
        )

    # ----------------- interface implementations -----------------
    def summarize(self, reductions: Reductions, correlations: List[Correlation], actions: List[ActionItem], *,
                  skip: bool = False, previous: Optional[Summaries] = None,
                  skip_reason: Optional[str] = None, baseline_context: Optional[Dict[str, Any]] = None) -> Tuple[Summaries, ProviderMetadata]:
        # Start from heuristic baseline for deterministic structure
        result, metadata = self._delegate.summarize(
            reductions, correlations, actions,
            skip=skip, previous=previous, skip_reason=skip_reason,
            baseline_context=baseline_context
        )
        generated = None if skip else self._maybe_generate(self._summary_prompt(reductions, correlations, actions))
        if generated:
            result.executive_summary = generated
        return result, self._retag_metadata(metadata)

    def refine_rules(self, suggestions: List[Dict[str, Any]],
                     examples: Optional[Dict[str, List[str]]] = None) -> Tuple[List[Dict[str, Any]], ProviderMetadata]:
        result, metadata = self._delegate.refine_rules(suggestions, examples)
        # Optional: future rule-refinement generation could be added here
        return result, self._retag_metadata(metadata)

    def triage(self, reductions: Reductions, correlations: List[Correlation]) -> Tuple[Dict[str, Any], ProviderMetadata]:
        result, metadata = self._delegate.triage(reductions, correlations)
        return result, self._retag_metadata(metadata)


__all__ = ["LocalQwenLLMProvider"]
