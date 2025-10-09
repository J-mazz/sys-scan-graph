"""Baseline module for graph nodes.

This module contains functions for baseline query planning and result integration.
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

# Batch processing helpers for finding loops optimization
def _batch_check_baseline_status(findings: List[Dict[str, Any]]) -> List[int]:
    """Batch check which findings are missing baseline status."""
    missing_indices = []
    for i, finding in enumerate(findings):
        baseline_status = finding.get('baseline_status')
        if baseline_status is None or 'baseline_status' not in finding:
            missing_indices.append(i)
    return missing_indices

def _derive_pending_tool_calls_on_demand(state: StateType) -> Optional[List[Dict[str, Any]]]:
    """Derive pending tool calls from enriched findings if not already present."""
    enriched = state.get('enriched_findings') or []
    if not enriched:
        return None

    # Batch check baseline status
    missing_indices = _batch_check_baseline_status(enriched)
    if not missing_indices:
        return None

    # Batch extract fields for missing findings
    missing_findings = [enriched[i] for i in missing_indices]
    fields = _batch_extract_finding_fields(missing_findings)

    # Build tool calls using batched data
    return _build_baseline_tool_calls(fields)


def _batch_extract_finding_fields(findings: List[Dict[str, Any]]) -> Dict[str, List[Any]]:
    """Batch extract commonly used fields from findings to avoid repeated dict lookups."""
    ids = []
    titles = []
    severities = []
    tags_list = []
    categories = []
    metadata_list = []
    risk_scores = []

    for finding in findings:
        ids.append(finding.get('id'))
        titles.append(finding.get('title', ''))
        severities.append(str(finding.get('severity', 'unknown')).lower())
        tags_list.append([t.lower() for t in (finding.get('tags') or [])])
        categories.append(str(finding.get('category', '')).lower())
        metadata_list.append(finding.get('metadata', {}) or {})
        # Extract risk score with fallback
        risk_score = finding.get('risk_score')
        if risk_score is None:
            risk_score = finding.get('risk_total', 0)
        try:
            risk_scores.append(int(risk_score) if risk_score is not None else 0)
        except (ValueError, TypeError):
            risk_scores.append(0)

    return {
        'ids': ids,
        'titles': titles,
        'severities': severities,
        'tags_list': tags_list,
        'categories': categories,
        'metadata_list': metadata_list,
        'risk_scores': risk_scores,
    }


def _build_baseline_tool_calls(fields: Dict[str, List[Any]]) -> List[Dict[str, Any]]:
    """Build baseline query tool calls from finding fields."""
    host_id = _get_env_var('AGENT_GRAPH_HOST_ID', 'graph_host')
    pending = []

    for i, (fid, title, severity, scanner) in enumerate(zip(
        fields['ids'], fields['titles'], fields['severities'], fields['metadata_list']
    )):
        scanner_name = _extract_scanner_name_from_metadata(scanner)

        pending.append({
            'id': f"call_{fid or f'unknown_{i}'}",
            'name': 'query_baseline',
            'args': {
                'finding_id': fid or f'unknown_{i}',
                'title': title or '',
                'severity': severity or '',
                'scanner': scanner_name,
                'host_id': host_id,
            }
        })

    return pending


def _extract_scanner_name_from_metadata(scanner: Any) -> str:
    """Extract scanner name from metadata, defaulting to 'mixed'."""
    if isinstance(scanner, dict):
        return scanner.get('scanner', 'mixed')
    return 'mixed'


def _check_dependencies_available() -> bool:
    """Check if required dependencies for baseline planning are available."""
    return AIMessage is not None


def _get_or_derive_pending_tool_calls(state: StateType) -> Optional[List[Dict[str, Any]]]:
    """Get pending tool calls from state or derive them on-demand."""
    pending = state.get('pending_tool_calls')
    if not pending:  # derive on-demand if empty or None
        pending = _derive_pending_tool_calls_on_demand(state)
    return pending


def _construct_baseline_message(pending: List[Dict[str, Any]]) -> Any:
    """Construct AIMessage with tool calls for baseline queries."""
    return AIMessage(content="Baseline context required", tool_calls=pending)  # type: ignore[arg-type]


def _update_messages_with_baseline_query(state: StateType, pending: List[Dict[str, Any]]) -> None:
    """Update state messages with baseline query message."""
    msgs = state.get('messages') or []
    msgs.append(_construct_baseline_message(pending))
    state['messages'] = msgs


try:  # Optional: message classes for planning/integration if langchain present
    from langchain_core.messages import AIMessage, ToolMessage  # type: ignore
except Exception:  # pragma: no cover
    AIMessage = ToolMessage = None  # type: ignore


def plan_baseline_queries(state: StateType) -> StateType:
    """Construct AIMessage with tool_calls for baseline queries with optimized batch processing.

    Optimized: Uses batch processing to eliminate redundant finding iterations.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    # Ensure monotonic timing is initialized for accurate duration calculations
    state = util_normalization.ensure_monotonic_timing(state)

    try:
        if not _check_dependencies_available():  # dependency not available
            return state

        pending = _get_or_derive_pending_tool_calls(state)
        if not pending:
            _update_metrics_counter(state, 'baseline_plan_calls')
            return state

        _update_messages_with_baseline_query(state, pending)
        _update_metrics_counter(state, 'baseline_plan_calls')
    except Exception as e:  # pragma: no cover
        logger.exception('plan_baseline_queries (scaffold) failed: %s', e)
        _append_warning(state, WarningInfo('graph', 'plan_baseline', f"{type(e).__name__}: {e}"))  # type: ignore
    return state


def _extract_message_payload(message) -> Any:
    """Extract payload from ToolMessage or dict message."""
    if ToolMessage is not None and isinstance(message, ToolMessage):
        return getattr(message, 'content', None)
    elif isinstance(message, dict) and message.get('type') == 'tool':
        return message.get('content')
    return None


def _parse_payload_to_data_obj(payload) -> Optional[Dict[str, Any]]:
    """Parse payload to data object, handling dict or JSON string."""
    if isinstance(payload, dict):
        return payload
    elif isinstance(payload, str):
        try:
            import json as _json  # local import
            return _json.loads(payload)
        except Exception:  # pragma: no cover
            pass
    return None


def _integrate_finding_data(data_obj: Dict[str, Any], results: Dict[str, Any]) -> None:
    """Integrate finding data into results if it has a valid finding_id."""
    fid = data_obj.get('finding_id')
    if isinstance(fid, str):
        results[fid] = data_obj  # type: ignore[index]


def integrate_baseline_results(state: StateType) -> StateType:
    """Integrate ToolMessage outputs into baseline_results & mark cycle done.

    Compatible with legacy implementation but also tolerant to absent ToolMessage
    class. Any dict content under a ToolMessage with a 'finding_id' key is added.
    Sets baseline_cycle_done = True always (conservative to avoid infinite loops).
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    # Ensure monotonic timing is initialized for accurate duration calculations
    state = util_normalization.ensure_monotonic_timing(state)

    try:
        if ToolMessage is None:
            state['baseline_cycle_done'] = True
            return state
        msgs = state.get('messages') or []
        results = state.get('baseline_results') or {}

        for m in msgs:
            try:
                payload = _extract_message_payload(m)
                if payload is None:
                    continue

                data_obj = _parse_payload_to_data_obj(payload)
                if data_obj is None:
                    continue

                _integrate_finding_data(data_obj, results)
            except Exception:  # pragma: no cover
                continue
        state['baseline_results'] = results
    except Exception as e:  # pragma: no cover
        logger.exception('integrate_baseline_results (scaffold) failed: %s', e)
        _append_warning(state, WarningInfo('graph', 'integrate_baseline', f"{type(e).__name__}: {e}"))  # type: ignore
    finally:
        state['baseline_cycle_done'] = True
    return state