"""Analysis module for graph nodes.

This module contains functions for risk analysis, compliance checking, and metrics collection.
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

def _batch_calculate_risk_metrics(fields: Dict[str, List[Any]]) -> Dict[str, Any]:
    """Batch calculate risk assessment metrics."""
    sev_counters = _count_severities(fields['severities'])
    total_risk, avg_risk, risk_values = _calculate_risk_totals(fields['risk_scores'])
    qualitative_risk = _determine_qualitative_risk(sev_counters)

    return {
        'sev_counters': sev_counters,
        'total_risk': total_risk,
        'avg_risk': avg_risk,
        'qualitative_risk': qualitative_risk,
        'risk_values': risk_values,
    }

def _count_severities(severities: List[str]) -> Dict[str, int]:
    """Count findings by severity level."""
    sev_counters = {k: 0 for k in ['critical', 'high', 'medium', 'low', 'info', 'unknown']}
    for sev in severities:
        sev = sev if sev in sev_counters else 'unknown'
        sev_counters[sev] += 1
    return sev_counters


def _calculate_risk_totals(risk_scores: List[int]) -> Tuple[int, float, List[int]]:
    """Calculate total and average risk scores."""
    total_risk = sum(risk_scores)
    avg_risk = (total_risk / len(risk_scores)) if risk_scores else 0.0
    return total_risk, avg_risk, risk_scores


def _determine_qualitative_risk(sev_counters: Dict[str, int]) -> str:
    """Determine overall qualitative risk level."""
    qualitative = 'info'
    order = ['critical', 'high', 'medium', 'low', 'info']
    for level in order:
        if sev_counters.get(level):
            qualitative = level
            break
    return qualitative


def _batch_get_top_findings_by_risk(fields: Dict[str, List[Any]], top_n: int = 3) -> List[Dict[str, Any]]:
    """Batch get top N findings by risk score."""
    finding_risks = []
    for i, (fid, title, risk_score, sev) in enumerate(zip(
        fields['ids'], fields['titles'], fields['risk_scores'], fields['severities']
    )):
        finding_risks.append({
            'index': i,
            'id': fid,
            'title': title,
            'risk_score': risk_score,
            'severity': sev,
        })

    # Sort by risk score descending and take top N
    top_findings = sorted(finding_risks, key=lambda x: x['risk_score'], reverse=True)[:top_n]

    # Remove index field for final output
    for finding in top_findings:
        del finding['index']

    return top_findings

def _get_top_findings_by_risk(findings: List[Dict[str, Any]], top_n: int = 5) -> List[Dict[str, Any]]:
    """Get top findings by risk score."""
    fields = _batch_extract_finding_fields(findings)
    return _batch_get_top_findings_by_risk(fields, top_n)


def _analyze_risk_trends(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze risk trends and patterns."""
    high_priority = [f for f in findings if (f.get('probability_actionable') or 0) > 0.7]
    return {
        'high_priority_count': len(high_priority),
        'new_findings_count': sum(1 for f in findings if f.get('baseline_status') == 'new'),
        'trending_up': len(high_priority) > len(findings) * 0.3
    }


async def risk_analyzer(state: GraphState) -> GraphState:
    """Analyze overall risk profile of the system."""
    start = time.monotonic()
    enriched_findings = state.get('enriched_findings', [])
    correlations = state.get('correlations', [])

    # Calculate aggregate risk metrics
    total_risk = sum(f['risk_score'] for f in enriched_findings)
    high_severity_count = sum(1 for f in enriched_findings if f['severity'].lower() in ['high', 'critical'])
    correlation_bonus = sum(c.risk_score_delta for c in correlations)

    # Calculate risk metrics using batch processing
    fields = _batch_extract_finding_fields(enriched_findings)
    risk_metrics = _batch_calculate_risk_metrics(fields)
    sev_counters = risk_metrics['sev_counters']
    avg_risk = risk_metrics['avg_risk']
    qualitative_risk = risk_metrics['qualitative_risk']

    risk_assessment = {
        'overall_risk_level': qualitative_risk,
        'overall_risk': qualitative_risk,  # Unified field - use qualitative risk based on highest severity
        'risk_factors': [],  # Placeholder
        'recommendations': [],  # Placeholder
        'confidence_score': 0.8,  # Placeholder
        'counts': sev_counters,
        'total_risk_score': total_risk + correlation_bonus,
        'average_risk_score': avg_risk,
        'finding_count': len(enriched_findings),
        'top_findings': _get_top_findings_by_risk(enriched_findings),
        # Legacy fields for backward compatibility
        'risk_level': qualitative_risk,
        'risk_trends': _analyze_risk_trends(enriched_findings),
        'high_severity_count': high_severity_count,
        'correlation_count': len(correlations)
    }

    state['risk_assessment'] = risk_assessment
    _update_metrics_counter(state, 'risk_analyzer_calls')
    _update_metrics_duration(state, 'risk_analyzer_duration', start)
    return state


async def compliance_checker(state: GraphState) -> GraphState:
    """Check compliance against security standards."""
    start = time.monotonic()
    enriched_findings = state.get('enriched_findings', [])

    # Build standards structure
    standards = {}

    # PCI DSS compliance
    pci_violations = []
    for finding in enriched_findings:
        if 'suid' in finding['title'].lower():
            pci_violations.append(finding['id'])
        if 'network' in finding['title'].lower() and 'unencrypted' in finding['title'].lower():
            pci_violations.append(finding['id'])
        # Also check for explicit PCI DSS mentions in title, tags, or metadata
        title_lower = finding['title'].lower()
        tags = finding.get('tags', [])
        metadata = finding.get('metadata', {})
        if ('pci' in title_lower or
            any('pci' in tag.lower() for tag in tags) or
            metadata.get('compliance_standard', '').upper() == 'PCI'):
            pci_violations.append(finding['id'])

    standards['PCI DSS'] = {
        'finding_ids': pci_violations,
        'count': len(pci_violations)
    }

    # HIPAA compliance
    hipaa_violations = []
    for finding in enriched_findings:
        if 'readable' in finding['title'].lower() and 'world' in str(finding.get('metadata', {})).lower():
            hipaa_violations.append(finding['id'])
        # Also check for explicit HIPAA mentions in title, tags, or metadata
        title_lower = finding['title'].lower()
        tags = finding.get('tags', [])
        metadata = finding.get('metadata', {})
        if ('hipaa' in title_lower or
            any('hipaa' in tag.lower() for tag in tags) or
            metadata.get('compliance_standard', '').upper() == 'HIPAA'):
            hipaa_violations.append(finding['id'])

    standards['HIPAA'] = {
        'finding_ids': hipaa_violations,
        'count': len(hipaa_violations)
    }

    # ISO 27001 compliance
    iso_violations = []
    for finding in enriched_findings:
        if 'permission' in finding['title'].lower():
            iso_violations.append(finding['id'])

    standards['ISO27001'] = {
        'finding_ids': iso_violations,
        'count': len(iso_violations)
    }

    compliance_check = {
        'standards': standards,
        'total_compliance_findings': len(pci_violations) + len(hipaa_violations) + len(iso_violations),
        # Legacy fields for backward compatibility
        'pci_dss_compliant': len(pci_violations) == 0,
        'hipaa_compliant': len(hipaa_violations) == 0,
        'iso27001_compliant': len(iso_violations) == 0,
        'compliance_gaps': _identify_compliance_gaps(enriched_findings),
        'remediation_priority': _calculate_remediation_priority(enriched_findings)
    }

    state['compliance_check'] = compliance_check
    _update_metrics_counter(state, 'compliance_checker_calls')
    _update_metrics_duration(state, 'compliance_checker_duration', start)
    return state


async def metrics_collector(state: GraphState) -> GraphState:
    """Collect performance and operational metrics."""
    start = time.monotonic()
    enriched_findings = state.get('enriched_findings', [])
    correlations = state.get('correlations', [])
    risk_assessment = state.get('risk_assessment', {})

    metrics = {
        'processing_timestamp': int(__import__('time').time()),
        'findings_processed': len(enriched_findings),
        'correlations_found': len(correlations),
        'enrichment_duration_ms': 1500,  # Mock duration
        'memory_usage_mb': 45.2,  # Mock memory usage
        'cpu_usage_percent': 12.5,  # Mock CPU usage
        'findings_by_severity': _count_findings_by_severity(enriched_findings),
        'findings_by_category': _count_findings_by_category(enriched_findings),
        'correlation_effectiveness': _calculate_correlation_effectiveness(correlations),
        'overall_risk': risk_assessment.get('overall_risk', 'unknown'),
        'cache_entries': len(state.get('cache', {})) + len(state.get('enrich_cache', {}))
    }

    state['final_metrics'] = metrics
    _update_metrics_duration(state, 'metrics_collector_duration', start)
    return state


def _identify_compliance_gaps(findings: List[Dict[str, Any]]) -> List[str]:
    """Identify specific compliance gaps."""
    gaps = []
    for finding in findings:
        if finding['severity'].lower() in ['high', 'critical']:
            if 'suid' in finding['title'].lower():
                gaps.append('PCI_DSS_2.2.4')
            if 'network' in finding['title'].lower():
                gaps.append('ISO27001_A.13.2.1')
    return gaps


def _calculate_remediation_priority(findings: List[Dict[str, Any]]) -> str:
    """Calculate overall remediation priority."""
    critical_count = sum(1 for f in findings if f['severity'].lower() == 'critical')
    high_count = sum(1 for f in findings if f['severity'].lower() == 'high')

    if critical_count > 0:
        return "immediate"
    elif high_count > 2:
        return "high"
    elif high_count > 0:
        return "medium"
    else:
        return "low"


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


def _count_findings_by_category(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count findings by category."""
    counts = {}
    for finding in findings:
        category = "unknown"
        if 'suid' in finding['title'].lower():
            category = "privilege_escalation"
        elif 'network' in finding['title'].lower():
            category = "network_security"
        elif 'file' in finding['title'].lower() or 'permission' in finding['title'].lower():
            category = "filesystem"
        elif 'process' in finding['title'].lower():
            category = "process_security"

        counts[category] = counts.get(category, 0) + 1
    return counts


def _calculate_correlation_effectiveness(correlations: List[models.Correlation]) -> float:
    """Calculate how effective correlations are at identifying patterns."""
    if not correlations:
        return 0.0

    total_related = sum(len(c.related_finding_ids) for c in correlations)
    return min(total_related / len(correlations), 5.0) # Cap at 5.0