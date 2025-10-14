"""Utilities module for graph nodes.

This module contains shared utility functions and helpers used across graph nodes.
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


def _findings_from_graph(state: StateType) -> List[models.Finding]:
    out: List[models.Finding] = []
    for finding_dict in state.get('raw_findings', []) or []:
        try:
            # Extract risk score with fallback and error handling
            risk_score_raw = finding_dict.get('risk_score')
            if risk_score_raw is None:
                risk_score_raw = finding_dict.get('risk_total', 0)
            try:
                risk_score = int(risk_score_raw) if risk_score_raw is not None else 0
            except (ValueError, TypeError):
                risk_score = 0

            # Provide minimal required fields; defaults for missing
            out.append(models.Finding(
                id=finding_dict.get('id','unknown'),
                title=finding_dict.get('title','(no title)'),
                severity=finding_dict.get('severity','info'),
                risk_score=risk_score,
                metadata=finding_dict.get('metadata', {})
            ))
        except Exception:  # pragma: no cover - defensive
            continue
    return out


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

def _batch_check_baseline_status(findings: List[Dict[str, Any]]) -> List[int]:
    """Batch check which findings are missing baseline status."""
    missing_indices = []
    for i, finding in enumerate(findings):
        baseline_status = finding.get('baseline_status')
        if baseline_status is None or 'baseline_status' not in finding:
            missing_indices.append(i)
    return missing_indices

def _extract_metadata_standards(metadata: Dict[str, Any]) -> Set[str]:
    """Extract compliance standards from finding metadata."""
    candidates = set()
    ms = metadata.get('compliance_standard')
    if isinstance(ms, str):
        norm_meta = _normalize_compliance_standard(ms) or ms
        candidates.add(norm_meta)
    return candidates


def _extract_tag_standards(tags: List[str]) -> Set[str]:
    """Extract compliance standards from finding tags."""
    candidates = set()
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

def _normalize_state(state: StateType) -> StateType:
    """Normalize state to ensure all mandatory keys exist."""
    return graph_state.normalize_graph_state(state)