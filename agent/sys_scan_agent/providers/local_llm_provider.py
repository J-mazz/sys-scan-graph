from __future__ import annotations
"""Local LLM provider shim for zero-trust, offline inference.

This provider delegates to the deterministic ``NullLLMProvider`` but is
exposed as a "local" provider to allow future upgrades to a true offline
model without changing the public interface. No remote calls or LoRA
artifacts are used.
"""
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime

from ..llm_provider import ILLMProvider, ProviderMetadata, NullLLMProvider
from .. import models

Reductions = models.Reductions
Correlation = models.Correlation
Summaries = models.Summaries
ActionItem = models.ActionItem


class LocalLLMProvider(ILLMProvider):
    """Local, deterministic provider using in-process heuristics only."""

    def __init__(self, *, model_name: str = "local-heuristic", provider_name: str = "local-llm"):
        self._delegate = NullLLMProvider()
        self.model_name = model_name
        self.provider_name = provider_name

    def _retag_metadata(self, metadata: ProviderMetadata) -> ProviderMetadata:
        data = metadata._asdict()
        data.update({
            "model_name": self.model_name,
            "provider_name": self.provider_name,
            "timestamp": data.get("timestamp") or datetime.now().isoformat()
        })
        return ProviderMetadata(**data)

    def summarize(self, reductions: Reductions, correlations: List[Correlation], actions: List[ActionItem], *,
                  skip: bool = False, previous: Optional[Summaries] = None,
                  skip_reason: Optional[str] = None, baseline_context: Optional[Dict[str, Any]] = None) -> Tuple[Summaries, ProviderMetadata]:
        result, metadata = self._delegate.summarize(
            reductions, correlations, actions,
            skip=skip, previous=previous, skip_reason=skip_reason,
            baseline_context=baseline_context
        )
        return result, self._retag_metadata(metadata)

    def refine_rules(self, suggestions: List[Dict[str, Any]],
                     examples: Optional[Dict[str, List[str]]] = None) -> Tuple[List[Dict[str, Any]], ProviderMetadata]:
        result, metadata = self._delegate.refine_rules(suggestions, examples)
        return result, self._retag_metadata(metadata)

    def triage(self, reductions: Reductions, correlations: List[Correlation]) -> Tuple[Dict[str, Any], ProviderMetadata]:
        result, metadata = self._delegate.triage(reductions, correlations)
        return result, self._retag_metadata(metadata)


__all__ = ["LocalLLMProvider"]
