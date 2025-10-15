"""Summarization module for graph nodes.

This module contains functions for summarizing security findings and host state.
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

@dataclass
class SummarizationContext:
    """Encapsulates summarization parameters to reduce function argument count."""
    provider: Any
    reductions: Any
    correlations: List[Any]
    actions: List[Any]
    baseline_context: Dict[str, Any]

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

def _build_agent_state(findings: List[models.Finding], scanner_name: str = "mixed") -> models.AgentState:
    """Optimized construction of AgentState from findings."""
    sr = models.ScannerResult(
        scanner=scanner_name,
        finding_count=len(findings),
        findings=findings,
    )
    report = models.Report(
        meta=models.Meta(),
        summary=models.Summary(
            finding_count_total=len(findings),
            finding_count_emitted=len(findings),
        ),
        results=[sr],
        collection_warnings=[],
        scanner_errors=[],
        summary_extension=models.SummaryExtension(total_risk_score=0),
    )
    return models.AgentState(report=report)

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


async def streaming_summarizer(context: SummarizationContext) -> Any:
    """Deterministic streaming facade using encapsulated context.

    For now this simply delegates to _call_summarize once (no incremental
    token emission) to maintain determinism. Later this could yield partial
    chunks and assemble them into a final Summaries object.
    """
    return await _call_summarize(context)


async def _call_summarize(context: SummarizationContext) -> Any:
    """Helper to normalize async/sync summarize calls using encapsulated context."""
    import inspect
    res = context.provider.summarize(context.reductions, context.correlations, context.actions, baseline_context=context.baseline_context)
    if inspect.isawaitable(res):
        return await res
    return res


def _check_iteration_limit(state: StateType) -> bool:
    """Check if iteration limit has been reached and append warning if so."""
    max_iter = int(_get_env_var('AGENT_MAX_SUMMARY_ITERS', '3'))
    iters = int(state.get('iteration_count', 0) or 0)
    if iters >= max_iter:
        _append_warning(state, WarningInfo('graph', 'enhanced_summarize', 'iteration_limit_reached'))  # type: ignore
        return True
    return False


def _prepare_summarization_data(state: StateType) -> Tuple[Any, List[Any], Dict[str, Any], bool]:
    """Prepare data needed for summarization."""
    provider = get_enhanced_llm_provider()
    findings_src = _extract_findings_from_state(state, 'correlated_findings')
    findings_models = _build_finding_models(findings_src)

    reductions = reduction.reduce_all(findings_models)
    corr_objs = []
    for c in state.get('correlations', []) or []:
        try:
            corr_objs.append(models.Correlation(**c))
        except Exception:  # pragma: no cover
            continue

    baseline_context = state.get('baseline_results') or {}
    streaming = bool(state.get('streaming_enabled'))

    return provider, corr_objs, baseline_context, streaming


async def _execute_summarization(provider: Any, reductions: Any, corr_objs: List[Any], baseline_context: Dict[str, Any], streaming: bool) -> Tuple[Any, Any]:
    """Execute summarization using appropriate method."""
    context = SummarizationContext(
        provider=provider,
        reductions=reductions,
        correlations=corr_objs,
        actions=[],
        baseline_context=baseline_context
    )
    if streaming:
        return await streaming_summarizer(context)
    else:
        return await _call_summarize(context)


def _update_summarization_state(state: StateType, summaries: Any, iters: int) -> None:
    """Update state with summarization results."""
    summary_dict = summaries.model_dump()
    if 'metrics' not in summary_dict or summary_dict['metrics'] is None:
        summary_dict['metrics'] = {}
    state['summary'] = summary_dict
    state['iteration_count'] = iters + 1


def _extract_summarization_metrics(state: StateType, summaries: Any) -> None:
    """Extract and update metrics from summarization results."""
    sm = summaries.metrics or {}
    metrics = state.setdefault('metrics', {})
    if 'tokens_prompt' in sm:
        metrics['tokens_prompt'] = sm['tokens_prompt']
    if 'tokens_completion' in sm:
        metrics['tokens_completion'] = sm['tokens_completion']
    _update_metrics_counter(state, 'summarize_calls')


async def enhanced_summarize_host_state(state: StateType) -> StateType:
    """Advanced async summarization node with streaming + metrics.

    Optimized: Uses helper functions and cached environment variables.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    start = time.monotonic()
    try:
        if _check_iteration_limit(state):
            return state

        provider, corr_objs, baseline_context, streaming = _prepare_summarization_data(state)
        reductions = reduction.reduce_all(_build_finding_models(_extract_findings_from_state(state, 'correlated_findings')))

        summaries, metadata = await _execute_summarization(provider, reductions, corr_objs, baseline_context, streaming)

        iters = int(state.get('iteration_count', 0) or 0)
        _update_summarization_state(state, summaries, iters)
        _extract_summarization_metrics(state, summaries)
    except Exception as e:  # pragma: no cover
        logger.exception('enhanced_summarize_host_state failed: %s', e)
        _append_warning(state, WarningInfo('graph', 'enhanced_summarize', f"{type(e).__name__}: {e}"))  # type: ignore
        # Create fallback summary when LLM fails
        enriched_findings = _extract_findings_from_state(state, 'correlated_findings')
        correlations = [models.Correlation(**c) for c in state.get('correlations', []) or [] if isinstance(c, dict)]
        risk_assessment = state.get('risk_assessment', {})
        
        fallback_summary = _generate_executive_summary(enriched_findings, correlations, risk_assessment)
        fallback_reductions = _create_reductions(enriched_findings)
        
        fallback_summaries = models.Summaries(
            executive_summary=fallback_summary,
            analyst={"finding_count": len(enriched_findings), "correlation_count": len(correlations)},
            consistency_findings=[],
            triage_summary={"top_findings": fallback_reductions.get('top_findings', []), "correlation_count": len(correlations)},
            action_narrative="Analysis completed with fallback summarization",
            metrics={"findings_count": len(enriched_findings), "fallback_mode": True}
        )
        
        iters = int(state.get('iteration_count', 0) or 0)
        _update_summarization_state(state, fallback_summaries, iters)
        _extract_summarization_metrics(state, fallback_summaries)
    finally:
        _update_metrics_duration(state, 'summarize_duration', start)
    return state


def _generate_executive_summary(enriched_findings: List[Dict[str, Any]], correlations: List[models.Correlation], risk_assessment: Dict[str, Any]) -> str:
    """Generate an executive summary of the security assessment."""
    finding_count = len(enriched_findings)
    high_severity = sum(1 for f in enriched_findings if f['severity'].lower() in ['high', 'critical'])
    correlation_count = len(correlations)
    risk_level = risk_assessment.get('risk_level', 'unknown')

    summary_parts = []

    if finding_count == 0:
        return "Security assessment completed with no findings detected. System appears to be in a secure state."
    
    summary_parts.append(f"Security assessment identified {finding_count} security findings")
    
    if high_severity > 0:
        summary_parts.append(f"including {high_severity} high/critical severity issues")

    if correlation_count > 0:
        summary_parts.append(f"and {correlation_count} correlated patterns of concern")

    summary_parts.append(f"Overall risk level assessed as: {risk_level.upper()}")

    # Add key insights
    if risk_level in ['critical', 'high']:
        summary_parts.append("Immediate attention required for critical security vulnerabilities")
    elif risk_level == 'medium':
        summary_parts.append("Moderate security concerns identified requiring planned remediation")
    else:
        summary_parts.append("System security posture is acceptable with minor areas for improvement")
    
    return ". ".join(summary_parts) + "."


def _count_findings_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count findings by severity level."""
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'unknown': 0}
    for finding in findings:
        severity = finding['severity'].lower()
        if severity in counts:
            counts[severity] += 1
        else:
            counts['unknown'] += 1
    return counts


def _create_reductions(enriched_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate reductions/summaries by category."""
    # Group findings by category
    by_category = {}
    for finding in enriched_findings:
        category = "unknown"
        if 'suid' in finding['title'].lower():
            category = "Privilege Escalation"
        elif 'network' in finding['title'].lower():
            category = "Network Security"
        elif 'file' in finding['title'].lower() or 'permission' in finding['title'].lower():
            category = "File System Security"
        elif 'process' in finding['title'].lower():
            category = "Process Security"

        if category not in by_category:
            by_category[category] = []
        by_category[category].append(finding)

    # Create reductions
    reductions = {}
    for category, findings in by_category.items():
        reductions[category.lower().replace(' ', '_') + '_summary'] = {
            'count': len(findings),
            'severity_breakdown': _count_findings_by_severity(findings),
            'highest_severity': max((f['severity'].lower() for f in findings), default='info'),
            'sample_findings': [f['title'] for f in findings[:3]]  # First 3 as examples
        }

    # Top findings by risk score
    top_findings = sorted(enriched_findings, key=lambda f: f['risk_score'], reverse=True)[:10]
    reductions['top_findings'] = [
        {
            'id': f['id'],
            'title': f['title'],
            'severity': f['severity'],
            'risk_score': f['risk_score'],
            'probability_actionable': f.get('probability_actionable', 0)
        } for f in top_findings
    ]

    return reductions