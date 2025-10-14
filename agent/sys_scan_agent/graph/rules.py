"""Rules module for graph nodes.

This module contains functions for rule suggestion and gap mining.
"""

from __future__ import annotations
import asyncio
import logging
import time
import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING

# Forward reference / safe import for GraphState to avoid circular import at module import time.
# Use Dict[str, Any] directly to avoid circular import issues during module initialization.
GraphState = Dict[str, Any]  # type: ignore

# Core provider & helper imports (existing project modules)
from .. import llm_provider
from .. import pipeline
from .. import knowledge
from .. import reduction
from .. import rule_gap_miner
from .. import graph_state
from .. import util_hash
from .. import util_normalization
from .. import models
from .. import rules

# Import specific functions for re-export
from ..llm_provider import get_llm_provider

# Pydantic model imports (data structures used across node logic)
Finding = models.Finding
ScannerResult = models.ScannerResult
Report = models.Report
Meta = models.Meta
Summary = models.Summary
SummaryExtension = models.SummaryExtension
AgentState = models.AgentState

logger = logging.getLogger(__name__)

# Parameter object for warning encapsulation
from dataclasses import dataclass

@dataclass
class WarningInfo:
    """Encapsulates warning information to reduce function argument count."""
    module: str
    stage: str
    error: str
    hint: Optional[str] = None

# Optimization: Pre-compile environment variable access
_ENV_CACHE = {}

def _get_env_var(key: str, default: Any = None) -> Any:
    """Cache environment variable lookups for performance."""
    if key not in _ENV_CACHE:
        _ENV_CACHE[key] = __import__('os').environ.get(key, default)
    return _ENV_CACHE[key]

def _build_finding_models(findings_dicts: List[Dict[str, Any]]) -> List[models.Finding]:
    """Optimized conversion of finding dicts to Pydantic models with error handling."""
    models_list = []
    for finding_dict in findings_dicts:
        try:
            # Use only valid fields to avoid validation errors
            valid_fields = {k: v for k, v in finding_dict.items()
                          if k in models.Finding.model_fields}
            models_list.append(models.Finding(**valid_fields))
        except Exception:  # pragma: no cover
            continue
    return models_list

# Type alias for better readability
StateType = Dict[str, Any]  # type: ignore

def _extract_findings_from_state(state: StateType, key: str) -> List[Dict[str, Any]]:
    """Safely extract findings from state with fallback chain."""
    return (state.get(key) or
            state.get('correlated_findings') or
            state.get('enriched_findings') or
            state.get('raw_findings') or [])

def _initialize_state_fields(state: StateType, *fields: str) -> None:
    """Initialize state fields to avoid None checks throughout."""
    for field in fields:
        if state.get(field) is None:
            if field in ('warnings', 'cache_keys'):
                state[field] = []
            elif field in ('metrics', 'cache', 'enrich_cache'):
                state[field] = {}
            else:
                state[field] = []

def _update_metrics_duration(state: StateType, metric_key: str, start_time: float) -> None:
    """Standardized metrics duration update."""
    duration = time.monotonic() - start_time
    state.setdefault('metrics', {})[metric_key] = duration

def _append_warning(state: StateType, warning_info: WarningInfo) -> None:
    """Append a warning to the state using encapsulated warning information."""
    wl = state.setdefault('warnings', [])
    wl.append({
        'module': warning_info.module,
        'stage': warning_info.stage,
        'error': warning_info.error,
        'hint': warning_info.hint
    })

def _update_metrics_counter(state: StateType, counter_key: str, increment: int = 1) -> None:
    """Standardized metrics counter update."""
    metrics = state.setdefault('metrics', {})
    metrics[counter_key] = metrics.get(counter_key, 0) + increment

def _build_suggestion_context(state: StateType) -> str:
    """Build context string from state for rule suggestions."""
    context_parts = []
    if state.get('summary'):
        context_parts.append(f"Summary: {state['summary']}")
    if state.get('correlations'):
        context_parts.append(f"Correlations: {len(state['correlations'])} items")
    if state.get('baseline_results'):
        context_parts.append(f"Baseline: {state['baseline_results']}")
    return '\n'.join(context_parts) if context_parts else 'No additional context'


def _refine_suggestions_with_provider(provider: Any, suggestions: List[Any]) -> List[Any]:
    """Refine suggestions using provider's refine_rules method if available."""
    try:
        refine_fn = getattr(provider, 'refine_rules', None)
        if callable(refine_fn) and suggestions:
            refined = refine_fn(suggestions, examples=None)
            return refined if isinstance(refined, list) else suggestions
    except Exception:  # pragma: no cover - refinement fallback
        pass
    return suggestions


def _prepare_suggestion_data(state: StateType) -> Tuple[Any, List[models.Finding], str]:
    """Prepare data needed for rule suggestions."""
    provider = get_enhanced_llm_provider()
    findings_src = _extract_findings_from_state(state, 'correlated_findings')
    findings_models = _build_finding_models(findings_src)
    context = _build_suggestion_context(state)
    return provider, findings_models, context


def _execute_gap_mining(findings_models: List[models.Finding]) -> Dict[str, Any]:
    """Execute gap mining to get rule suggestions."""
    import tempfile, json as _json
    from pathlib import Path

    tf_path = None
    try:
        findings_data = {'enriched_findings': [f.model_dump() for f in findings_models]}

        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.json') as tf:
            tf_path = tf.name
            _json.dump(findings_data, tf)
            tf.flush()
            # Use slightly permissive thresholds to increase suggestion probability
            result = rule_gap_miner.mine_gap_candidates([Path(tf.name)], risk_threshold=10, min_support=2)

        return result
    finally:
        if tf_path:
            try:
                import os
                os.unlink(tf_path)
            except Exception:
                pass


def _process_suggestions(suggestions: List[Any], provider: Any) -> List[Any]:
    """Process and refine suggestions."""
    # Optional refinement with provider
    suggestions = _refine_suggestions_with_provider(provider, suggestions)

    # Ensure suggestions is a list
    try:
        if not isinstance(suggestions, list):
            suggestions = [suggestions] if suggestions else []
    except Exception:
        suggestions = []

    return suggestions


def _update_suggestion_state(state: StateType, suggestions: List[Any]) -> None:
    """Update state with processed suggestions."""
    state['suggested_rules'] = suggestions

    # Apply unified normalization
    state = util_normalization.normalize_rule_suggestions(state)
    state = util_normalization.ensure_monotonic_timing(state)
    state = util_normalization.add_metrics_version(state)

    # Metrics with helper
    _update_metrics_counter(state, 'rule_suggest_calls')
    metrics = state.setdefault('metrics', {})
    metrics['rule_suggest_count'] = len(suggestions) if hasattr(suggestions, '__len__') else 0


async def enhanced_suggest_rules(state: StateType) -> StateType:
    """Advanced async rule suggestion node with temp file optimization.

    Optimized: Uses helper functions, cached env vars, and eliminates temp file usage.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    start = time.monotonic()
    try:
        provider, findings_models, context = _prepare_suggestion_data(state)

        # Use cached env var for max suggestions (though not used in current logic)
        max_suggestions = int(_get_env_var('AGENT_MAX_RULE_SUGGESTIONS', '10'))

        result = _execute_gap_mining(findings_models)
        raw_suggestions = result.get('suggestions', [])
        suggestions = _process_suggestions(raw_suggestions, provider)
        _update_suggestion_state(state, suggestions)
    except Exception as e:  # pragma: no cover
        logger.exception('enhanced_suggest_rules failed: %s', e)
        _append_warning(state, WarningInfo('graph', 'enhanced_suggest_rules', f"{type(e).__name__}: {e}"))  # type: ignore
    finally:
        _update_metrics_duration(state, 'rule_suggest_duration', start)
    return state


def get_enhanced_llm_provider():
    """Multi-provider selection wrapper.

    Currently returns the default provider; placeholder for future logic that
    could select alternate providers based on:
      - state['summary_strategy']
      - environment variables (AGENT_LLM_PROVIDER / AGENT_LLM_PROVIDER_ALT)
      - risk / finding volume thresholds
    Deterministic by design (no randomness).
    """
    # Basic strategy: prefer primary; optionally allow alternate env variable if set and distinct
    primary = llm_provider.get_llm_provider()
    alt_env = __import__('os').environ.get('AGENT_LLM_PROVIDER_ALT')
    if alt_env and alt_env == '__use_null__':  # explicit override to force Null provider
        try:
            return llm_provider.NullLLMProvider()
        except Exception:  # pragma: no cover
            return primary
    return primary