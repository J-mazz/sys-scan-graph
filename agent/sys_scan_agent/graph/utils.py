"""Utilities module for graph nodes.

This module re-exports shared utility functions from base.py for backward compatibility
and provides any utils-specific functionality not covered by base.py.

All common utilities are now consolidated in base.py to eliminate code duplication.
"""

from __future__ import annotations
import asyncio
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple, TypeVar

# Import graph_state for backward compatibility with tests that patch it
from .. import graph_state

# Import all shared utilities from base module - single source of truth
from .base import (
    # Type definitions
    GraphState,
    StateType,
    
    # Dataclasses
    WarningInfo,
    SummarizationContext,
    
    # Environment utilities
    get_env_var as _get_env_var,
    clear_env_cache,
    _ENV_CACHE,  # Re-exported for backward compatibility with tests
    
    # Compliance utilities
    normalize_compliance_standard as _normalize_compliance_standard,
    
    # State management
    extract_findings_from_state as _extract_findings_from_state,
    initialize_state_fields as _initialize_state_fields,
    normalize_state as _normalize_state,
    ensure_monotonic_timing,
    
    # Metrics utilities
    update_metrics_duration as _update_metrics_duration,
    update_metrics_counter as _update_metrics_counter,
    
    # Warning management
    append_warning as _append_warning,
    
    # Model building
    build_finding_models as _build_finding_models,
    build_agent_state as _build_agent_state,
    findings_from_graph as _findings_from_graph,
    
    # Batch processing
    batch_extract_finding_fields as _batch_extract_finding_fields,
    batch_filter_findings_by_severity as _batch_filter_findings_by_severity,
    batch_check_baseline_status as _batch_check_baseline_status,
    is_compliance_related as _is_compliance_related,
    batch_check_compliance_indicators as _batch_check_compliance_indicators,
    
    # Risk calculations
    count_severities as _count_severities,
    calculate_risk_totals as _calculate_risk_totals,
    determine_qualitative_risk as _determine_qualitative_risk,
    batch_calculate_risk_metrics as _batch_calculate_risk_metrics,
    batch_get_top_findings_by_risk as _batch_get_top_findings_by_risk,
    count_findings_by_severity as _count_findings_by_severity,
    
    # LLM utilities
    get_enhanced_llm_provider,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Type Variables for Generic Async Wrapper
# =============================================================================

T = TypeVar('T')


# =============================================================================
# Generic Async Node Wrapper
# =============================================================================

def run_async_node(async_fn: Callable[[T], Awaitable[T]]) -> Callable[[T], T]:
    """Create a synchronous wrapper for an async node function.
    
    This utility eliminates boilerplate sync wrapper code by providing a generic
    factory that converts async graph node functions to sync functions suitable
    for LangGraph StateGraph integration.
    
    Args:
        async_fn: An async function that takes state and returns updated state.
        
    Returns:
        A synchronous wrapper function with the same signature.
        
    Example:
        # Instead of:
        def summarize_findings(state: GraphState) -> GraphState:
            '''Sync wrapper for async summarize_findings_async.'''
            return asyncio.get_event_loop().run_until_complete(
                summarize_findings_async(state)
            )
        
        # Use:
        summarize_findings = run_async_node(summarize_findings_async)
    """
    def sync_wrapper(state: T) -> T:
        """Synchronous wrapper for async node function."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running loop, create new one
            return asyncio.run(async_fn(state))
        
        if loop.is_running():
            # Already in async context, create new loop in thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, async_fn(state))
                return future.result()
        else:
            return loop.run_until_complete(async_fn(state))
    
    # Preserve function metadata for introspection
    sync_wrapper.__name__ = async_fn.__name__.replace('_async', '')
    sync_wrapper.__doc__ = f"Sync wrapper for {async_fn.__name__}"
    
    return sync_wrapper


# =============================================================================
# Utils-Specific Functions (not in base.py)
# =============================================================================

def _requires_external_data(tags: List[str], metadata: Dict[str, Any]) -> bool:
    """Check if a finding requires external data based on tags and metadata."""
    return (bool('external_required' in tags) or
            bool(metadata.get('requires_external')) or
            bool(metadata.get('threat_feed_lookup')))


def _batch_check_external_requirements(fields: Dict[str, List[Any]]) -> List[int]:
    """Batch check for findings requiring external data."""
    external_indices = []
    for i, (tags, metadata) in enumerate(zip(fields['tags_list'], fields['metadata_list'])):
        if _requires_external_data(tags, metadata):
            external_indices.append(i)
    return external_indices


def _extract_metadata_standards(metadata: Dict[str, Any]) -> Set[str]:
    """Extract compliance standards from finding metadata."""
    candidates: Set[str] = set()
    ms = metadata.get('compliance_standard')
    if isinstance(ms, str):
        norm_meta = _normalize_compliance_standard(ms) or ms
        candidates.add(norm_meta)
    return candidates


def _extract_tag_standards(tags: List[str]) -> Set[str]:
    """Extract compliance standards from finding tags."""
    candidates: Set[str] = set()
    for tag in tags:
        norm = _normalize_compliance_standard(tag)
        if norm:
            candidates.add(norm)
    return candidates


def _map_findings_to_standards(candidates: Set[str], std_map: Dict[str, List[int]], index: int) -> None:
    """Map finding index to compliance standards."""
    for std in candidates:
        std_map.setdefault(std, []).append(index)


def _batch_normalize_compliance_standards(fields: Dict[str, List[Any]]) -> Dict[str, List[int]]:
    """Batch normalize compliance standards and return standard -> finding_indices mapping."""
    std_map: Dict[str, List[int]] = {}

    for i, (metadata, tags) in enumerate(zip(fields['metadata_list'], fields['tags_list'])):
        candidates = _extract_metadata_standards(metadata)
        tag_candidates = _extract_tag_standards(tags)
        candidates.update(tag_candidates)
        _map_findings_to_standards(candidates, std_map, i)

    return std_map