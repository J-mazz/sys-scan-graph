"""Routing module for graph nodes.

This module contains functions for routing decisions in the graph workflow.
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

# Optimization: Pre-compile compliance standard mappings
_COMPLIANCE_ALIASES = {
    'pci': 'PCI DSS',
    'pcidss': 'PCI DSS',
    'hipaa': 'HIPAA',
    'soc2': 'SOC 2',
    'soc': 'SOC 2',
    'iso27001': 'ISO 27001',
    'cis': 'CIS Benchmark',
}

def _normalize_compliance_standard(raw: str) -> Optional[str]:
    """Normalize compliance standard names to canonical forms."""
    if not raw:
        return None
    key = raw.lower().replace(' ', '')
    return _COMPLIANCE_ALIASES.get(key)

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

def _batch_filter_findings_by_severity(fields: Dict[str, List[Any]], severity_levels: set) -> List[int]:
    """Batch filter finding indices by severity levels."""
    return [i for i, sev in enumerate(fields['severities']) if sev in severity_levels]

def _is_compliance_related(tags: List[str], category: str, metadata: Dict[str, Any]) -> bool:
    """Check if a finding is compliance-related based on tags, category, and metadata."""
    return (bool('compliance' in tags) or
            bool(category == 'compliance') or
            bool(metadata.get('compliance_standard')) or
            bool(_normalize_compliance_standard(category)))


def _batch_check_compliance_indicators(fields: Dict[str, List[Any]]) -> List[int]:
    """Batch check for compliance-related findings."""
    compliance_indices = []
    for i, (tags, category, metadata) in enumerate(zip(
        fields['tags_list'], fields['categories'], fields['metadata_list']
    )):
        if _is_compliance_related(tags, category, metadata):
            compliance_indices.append(i)
    return compliance_indices


def _batch_check_baseline_status(findings: List[Dict[str, Any]]) -> List[int]:
    """Batch check which findings are missing baseline status."""
    missing_indices = []
    for i, finding in enumerate(findings):
        baseline_status = finding.get('baseline_status')
        if baseline_status is None or 'baseline_status' not in finding:
            missing_indices.append(i)
    return missing_indices

def _check_human_feedback_gate(state: StateType) -> Optional[str]:
    """Check if human feedback is pending and return routing decision."""
    if state.get('human_feedback_pending'):
        return 'human_feedback'
    return None


def _get_findings_for_routing(state: StateType) -> List[Dict[str, Any]]:
    """Get findings from state for routing decisions."""
    return state.get('correlated_findings') or state.get('enriched_findings') or state.get('raw_findings') or []


def _check_compliance_routing(fields: Dict[str, List[Any]]) -> Optional[str]:
    """Check for compliance-related findings and return routing decision."""
    compliance_indices = _batch_check_compliance_indicators(fields)
    if compliance_indices:
        return 'compliance'
    return None


def _check_baseline_routing(fields: Dict[str, List[Any]], state: StateType) -> Optional[str]:
    """Check for high severity findings missing baseline and return routing decision."""
    high_severity_indices = _batch_filter_findings_by_severity(fields, {'high', 'critical'})
    if high_severity_indices:
        baseline = state.get('baseline_results') or {}
        # Check if any high-sev finding is missing baseline
        for idx in high_severity_indices:
            fid = fields['ids'][idx]
            if fid and fid not in baseline:
                return 'baseline'
    return None


def _check_risk_routing(fields: Dict[str, List[Any]]) -> Optional[str]:
    """Check for findings requiring external risk assessment."""
    metadata_list = fields.get('metadata_list', [])
    for metadata in metadata_list:
        if isinstance(metadata, dict) and metadata.get('requires_external'):
            return 'risk'
    return None


def advanced_router(state: StateType) -> str:
    """Priority-based routing decision with optimized batch processing.

    Optimized: Uses batch processing to eliminate redundant finding iterations.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    try:
        # Ensure monotonic timing is initialized for accurate duration calculations
        state = util_normalization.ensure_monotonic_timing(state)

        # 1. Human feedback gate
        route = _check_human_feedback_gate(state)
        if route:
            return route

        # Choose findings source preference
        findings = _get_findings_for_routing(state)
        if not findings:
            return 'summarize'

        # Batch extract all needed fields once
        fields = _batch_extract_finding_fields(findings)

        # 2. Compliance detection (batch check)
        route = _check_compliance_routing(fields)
        if route:
            return route

        # 3. High severity missing baseline (batch check)
        route = _check_baseline_routing(fields, state)
        if route:
            return route

        # 4. External requirements (batch check)
        route = _check_risk_routing(fields)
        if route:
            return route

        # 5. Default path
        return 'summarize'
    except Exception:  # pragma: no cover
        return 'error'


def should_suggest_rules(state: StateType) -> str:
    """Router: decide whether to run rule suggestion with optimized batch processing.

    Optimized: Uses batch processing to eliminate redundant finding iterations.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    # Ensure monotonic timing is initialized for accurate duration calculations
    state = util_normalization.ensure_monotonic_timing(state)

    try:
        enriched = state.get('enriched_findings') or []
        if not enriched:
            try:  # pragma: no cover - library optional
                from langgraph.graph import END  # type: ignore
                return END  # type: ignore
            except Exception:
                return '__end__'

        # Batch check for high severity findings
        fields = _batch_extract_finding_fields(enriched)
        high_severity_indices = _batch_filter_findings_by_severity(fields, {'high'})

        if high_severity_indices:
            return 'suggest_rules'

        try:  # pragma: no cover - library optional
            from langgraph.graph import END  # type: ignore
            return END  # type: ignore
        except Exception:
            return '__end__'
    except Exception:  # pragma: no cover
        return 'suggest_rules'  # fail open to ensure progress


def choose_post_summarize(state: StateType) -> str:
    """Router after summarization with optimized batch processing.

    Optimized: Uses batch processing to eliminate redundant finding iterations.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    # Ensure monotonic timing is initialized for accurate duration calculations
    state = util_normalization.ensure_monotonic_timing(state)

    try:
        if not state.get('baseline_cycle_done'):
            enriched = state.get('enriched_findings') or []
            if not enriched:
                return should_suggest_rules(state)

            # Batch check for missing baseline status
            missing_indices = _batch_check_baseline_status(enriched)
            if missing_indices:
                return 'plan_baseline'

        return should_suggest_rules(state)
    except Exception:  # pragma: no cover
        return 'suggest_rules'


def _prepare_tool_coordination_data(state: StateType) -> Tuple[List[Dict[str, Any]], bool]:
    """Prepare data for tool coordination and check if coordination is needed."""
    findings = state.get('correlated_findings') or state.get('enriched_findings') or []
    if not findings:
        state['pending_tool_calls'] = []
        _update_metrics_counter(state, 'tool_coordinator_calls')
        return [], False

    # Batch check baseline status
    missing_indices = _batch_check_baseline_status(findings)
    if not missing_indices:
        state['pending_tool_calls'] = []
        _update_metrics_counter(state, 'tool_coordinator_calls')
        return [], False

    # Batch extract fields for missing findings
    missing_findings = [findings[i] for i in missing_indices]
    return missing_findings, True


def _build_tool_calls_from_findings(missing_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build tool calls from missing findings."""
    fields = _batch_extract_finding_fields(missing_findings)
    pending: List[Dict[str, Any]] = []
    host_id = _get_env_var('AGENT_GRAPH_HOST_ID', 'graph_host')

    for i, (fid, title, severity, scanner) in enumerate(zip(
        fields['ids'], fields['titles'], fields['severities'], fields['metadata_list']
    )):
        # Extract scanner from metadata if available
        scanner_name = _extract_scanner_name_from_metadata(scanner)

        pending.append({
            'id': f'call_{fid or f"unknown_{i}"}',
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


def _update_tool_coordination_state(state: StateType, pending: List[Dict[str, Any]]) -> None:
    """Update state with tool coordination results."""
    state['pending_tool_calls'] = pending
    _update_metrics_counter(state, 'tool_coordinator_calls')


async def tool_coordinator(state: StateType) -> StateType:
    """Analyze enriched/correlated findings and plan external tool needs with optimized batch processing.

    Optimized: Uses batch processing to eliminate redundant finding iterations.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    # Ensure monotonic timing is initialized for accurate duration calculations
    state = util_normalization.ensure_monotonic_timing(state)

    start = time.monotonic()
    try:
        missing_findings, needs_coordination = _prepare_tool_coordination_data(state)
        if not needs_coordination:
            return state

        pending = _build_tool_calls_from_findings(missing_findings)
        _update_tool_coordination_state(state, pending)
    except Exception as e:  # pragma: no cover
        logger.exception('tool_coordinator failed: %s', e)
        _append_warning(state, WarningInfo('graph', 'tool_coordinator', f"{type(e).__name__}: {e}"))  # type: ignore
    finally:
        _update_metrics_duration(state, 'tool_coordinator_duration', start)
    return state