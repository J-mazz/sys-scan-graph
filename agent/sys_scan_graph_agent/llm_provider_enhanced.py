from __future__ import annotations
"""Enhanced LLM Provider with local Mistral model support.

This module provides a simplified provider that uses only the local Mistral
model with LoRA adapters for zero-trust deterministic analysis.
"""

from typing import Protocol, List, Optional, Dict, Any, Tuple
import logging

from . import llm_provider
from .providers.local_mistral_provider import LocalMistralLLMProvider
ILLMProvider = llm_provider.ILLMProvider
ProviderMetadata = llm_provider.ProviderMetadata

logger = logging.getLogger(__name__)

class EnhancedLLMProvider(ILLMProvider):
    """Enhanced LLM provider using only local Mistral model for zero-trust analysis."""

    def __init__(self, model_path: Optional[str] = None, device: str = "auto"):
        """Initialize with local Mistral provider only."""
        self.local_provider = LocalMistralLLMProvider(model_path=model_path, device=device)
        self.metrics = {
            'calls_made': 0,
            'errors': 0,
        }

    def summarize(self, reductions, correlations, actions, *,
                  skip: bool = False, previous=None,
                  skip_reason: Optional[str] = None,
                  baseline_context: Optional[Dict[str, Any]] = None):
        """Summarize using local Mistral model."""
        try:
            result, metadata = self.local_provider.summarize(
                reductions, correlations, actions,
                skip=skip, previous=previous, skip_reason=skip_reason,
                baseline_context=baseline_context
            )
            self.metrics['calls_made'] += 1
            return result, metadata
        except Exception as e:
            logger.error(f"Local Mistral provider failed: {e}")
            self.metrics['errors'] += 1
            # Fallback to null provider if local model fails
            from .llm_provider import NullLLMProvider
            null_provider = NullLLMProvider()
            return null_provider.summarize(
                reductions, correlations, actions,
                skip=skip, previous=previous, skip_reason=skip_reason,
                baseline_context=baseline_context
            )

    def refine_rules(self, suggestions: List[Dict[str, Any]],
                     examples: Optional[Dict[str, List[str]]] = None):
        """Refine rules using local Mistral model."""
        try:
            result, metadata = self.local_provider.refine_rules(suggestions, examples)
            self.metrics['calls_made'] += 1
            return result, metadata
        except Exception as e:
            logger.error(f"Local Mistral provider failed: {e}")
            self.metrics['errors'] += 1
            # Fallback to null provider
            from .llm_provider import NullLLMProvider
            null_provider = NullLLMProvider()
            return null_provider.refine_rules(suggestions, examples)

    def triage(self, reductions, correlations):
        """Triage using local Mistral model."""
        try:
            result, metadata = self.local_provider.triage(reductions, correlations)
            self.metrics['calls_made'] += 1
            return result, metadata
        except Exception as e:
            logger.error(f"Local Mistral provider failed: {e}")
            self.metrics['errors'] += 1
            # Fallback to null provider
            from .llm_provider import NullLLMProvider
            null_provider = NullLLMProvider()
            return null_provider.triage(reductions, correlations)

    def get_metrics(self) -> Dict[str, Any]:
        """Get provider metrics."""
        return self.metrics.copy()

# Global enhanced provider instance
_enhanced_provider: Optional[EnhancedLLMProvider] = None

def get_enhanced_llm_provider() -> EnhancedLLMProvider:
    """Get the enhanced LLM provider instance (local Mistral only)."""
    global _enhanced_provider
    if _enhanced_provider is None:
        _enhanced_provider = EnhancedLLMProvider()
    return _enhanced_provider

def set_enhanced_llm_provider(provider: EnhancedLLMProvider) -> None:
    """Set the enhanced LLM provider instance."""
    global _enhanced_provider
    _enhanced_provider = provider

__all__ = [
    'EnhancedLLMProvider',
    'get_enhanced_llm_provider',
    'set_enhanced_llm_provider'
]
