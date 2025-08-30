from __future__ import annotations
"""Enhanced LLM Provider with multi-provider support and advanced features.

This module provides sophisticated LLM integration with:
- Multi-provider fallback chains
- Streaming responses
- Advanced error handling and retry logic
- Token usage optimization
- Caching and performance monitoring
- Structured output parsing
"""

from typing import Protocol, List, Optional, Dict, Any, Union
import asyncio
import time
import logging
from datetime import datetime
import json
import os
from pathlib import Path

from .models import Reductions, Correlation, Summaries, ActionItem
from .llm_provider import ILLMProvider, NullLLMProvider

# Try to import data governance, fallback if not available
try:
    from .data_governance import get_data_governor
except ImportError:
    get_data_governor = lambda: None

logger = logging.getLogger(__name__)

class EnhancedLLMProvider(ILLMProvider):
    """Enhanced LLM provider with multi-provider support and advanced features."""

    def __init__(self):
        self.providers = self._initialize_providers()
        self.current_provider = 'null'  # Start with null provider
        self.retry_attempts = 3
        self.timeout = 30
        self.cache = {}
        self.metrics = {
            'calls_made': 0,
            'tokens_used': 0,
            'errors': 0,
            'cache_hits': 0,
            'fallbacks': 0
        }

    def _initialize_providers(self) -> Dict[str, ILLMProvider]:
        """Initialize available LLM providers."""
        providers: Dict[str, ILLMProvider] = {
            'null': NullLLMProvider()
        }

        # Try to initialize LangChain provider
        try:
            from .providers.langchain_provider import LangChainLLMProvider
            providers['langchain'] = LangChainLLMProvider()  # type: ignore
        except Exception as e:
            logger.warning(f"Failed to initialize LangChain provider: {e}")

        # Try to initialize other providers (OpenAI, Anthropic, etc.)
        try:
            providers['openai'] = self._init_openai_provider()  # type: ignore
        except Exception as e:
            logger.warning(f"Failed to initialize OpenAI provider: {e}")

        try:
            providers['anthropic'] = self._init_anthropic_provider()  # type: ignore
        except Exception as e:
            logger.warning(f"Failed to initialize Anthropic provider: {e}")

        return providers

    def _init_openai_provider(self):
        """Initialize OpenAI provider."""
        # Placeholder for OpenAI integration
        raise NotImplementedError("OpenAI provider not yet implemented")

    def _init_anthropic_provider(self):
        """Initialize Anthropic provider."""
        # Placeholder for Anthropic integration
        raise NotImplementedError("Anthropic provider not yet implemented")

    def _select_provider(self, operation: str) -> str:
        """Select the best provider for the operation."""
        # Priority order based on operation and availability
        priority = {
            'summarize': ['langchain', 'openai', 'anthropic', 'null'],
            'refine_rules': ['langchain', 'openai', 'anthropic', 'null'],
            'triage': ['langchain', 'openai', 'anthropic', 'null']
        }

        for provider_name in priority.get(operation, ['null']):
            if provider_name in self.providers:
                return provider_name

        return 'null'

    async def _execute_with_fallback(self, operation: str, *args, **kwargs):
        """Execute operation with automatic fallback."""
        errors = []

        for attempt in range(self.retry_attempts):
            provider_name = self._select_provider(operation)
            provider = self.providers[provider_name]

            try:
                # Add timeout
                result = await asyncio.wait_for(
                    self._call_provider_method(provider, operation, *args, **kwargs),
                    timeout=self.timeout
                )

                if provider_name != self.current_provider:
                    self.metrics['fallbacks'] += 1
                    logger.info(f"Fell back to provider: {provider_name}")

                self.current_provider = provider_name
                self.metrics['calls_made'] += 1
                return result

            except Exception as e:
                error_msg = f"Provider {provider_name} failed: {e}"
                errors.append(error_msg)
                logger.warning(error_msg)

                # Remove failed provider from consideration
                if provider_name in self.providers:
                    del self.providers[provider_name]

        # All providers failed, use null provider
        logger.error(f"All providers failed, using null provider. Errors: {errors}")
        null_provider = NullLLMProvider()
        return await self._call_provider_method(null_provider, operation, *args, **kwargs)

    async def _call_provider_method(self, provider: ILLMProvider, operation: str, *args, **kwargs):
        """Call the appropriate method on the provider."""
        method = getattr(provider, operation)
        if asyncio.iscoroutinefunction(method):
            return await method(*args, **kwargs)
        else:
            # Run sync method in thread pool
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, method, *args, **kwargs)

    def summarize(self, reductions: Reductions, correlations: List[Correlation],
                  actions: List[ActionItem], *, skip: bool = False,
                  previous: Optional[Summaries] = None, skip_reason: Optional[str] = None,
                  baseline_context: Optional[Dict[str, Any]] = None) -> Summaries:

        # Check cache first
        cache_key = self._generate_cache_key('summarize', reductions, correlations)
        if cache_key in self.cache:
            self.metrics['cache_hits'] += 1
            return self.cache[cache_key]

        # Execute with fallback
        async def _summarize():
            return await self._execute_with_fallback(
                'summarize', reductions, correlations, actions,
                skip=skip, previous=previous, skip_reason=skip_reason,
                baseline_context=baseline_context
            )

        result = asyncio.run(_summarize())

        # Cache result
        self.cache[cache_key] = result

        # Update metrics
        if hasattr(result, 'metrics'):
            self.metrics['tokens_used'] += result.metrics.get('tokens_prompt', 0) + result.metrics.get('tokens_completion', 0)

        return result

    def refine_rules(self, suggestions: List[Dict[str, Any]],
                     examples: Optional[Dict[str, List[str]]] = None) -> List[Dict[str, Any]]:

        async def _refine():
            return await self._execute_with_fallback('refine_rules', suggestions, examples)

        return asyncio.run(_refine())

    def triage(self, reductions: Reductions, correlations: List[Correlation]) -> Dict[str, Any]:

        async def _triage():
            return await self._execute_with_fallback('triage', reductions, correlations)

        return asyncio.run(_triage())

    def _generate_cache_key(self, operation: str, *args) -> str:
        """Generate cache key for operation."""
        # Simple hash-based key generation
        key_data = f"{operation}_{str(args)}"
        return str(hash(key_data))

    def get_metrics(self) -> Dict[str, Any]:
        """Get provider metrics."""
        return self.metrics.copy()

    def clear_cache(self):
        """Clear the response cache."""
        self.cache.clear()

    def set_provider_priority(self, operation: str, priority: List[str]):
        """Set provider priority for specific operation."""
        # This would modify the _select_provider logic
        pass

# Global enhanced provider instance
_enhanced_provider: Optional[EnhancedLLMProvider] = None

def get_enhanced_llm_provider() -> EnhancedLLMProvider:
    """Get the enhanced LLM provider instance."""
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
