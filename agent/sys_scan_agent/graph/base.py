"""Base module for graph nodes - shared utilities and helpers.

This module consolidates all common utilities, type definitions, and helper functions
used across graph nodes to eliminate code duplication. All graph node modules should
import from this base module instead of re-defining these utilities.

Design Principles:
- Single source of truth for shared functionality
- Lazy imports to avoid circular dependencies
- Cached lookups for performance optimization
- Type-safe abstractions with proper error handling
"""

from __future__ import annotations
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING

# Import GraphState from dedicated state module (single source of truth)
from .state import GraphState

# Lazy module imports to avoid circular dependencies
_models = None
_graph_state = None
_util_hash = None
_util_normalization = None
_llm_provider = None
_pipeline = None
_knowledge = None
_reduction = None
_rule_gap_miner = None
_rules = None

logger = logging.getLogger(__name__)

# =============================================================================
# Type Definitions
# =============================================================================

# Type alias for backward compatibility
StateType = Dict[str, Any]


# =============================================================================
# Lazy Import Accessors
# =============================================================================

def _get_models():
    """Lazy import of models module."""
    global _models
    if _models is None:
        from .. import models as m
        _models = m
    return _models


def _get_graph_state():
    """Lazy import of graph_state module."""
    global _graph_state
    if _graph_state is None:
        from .. import graph_state as gs
        _graph_state = gs
    return _graph_state


def _get_util_hash():
    """Lazy import of util_hash module."""
    global _util_hash
    if _util_hash is None:
        from .. import util_hash as uh
        _util_hash = uh
    return _util_hash


def _get_util_normalization():
    """Lazy import of util_normalization module."""
    global _util_normalization
    if _util_normalization is None:
        from .. import util_normalization as un
        _util_normalization = un
    return _util_normalization


def _get_llm_provider():
    """Lazy import of llm_provider module."""
    global _llm_provider
    if _llm_provider is None:
        from .. import llm_provider as lp
        _llm_provider = lp
    return _llm_provider


def _get_pipeline():
    """Lazy import of pipeline module."""
    global _pipeline
    if _pipeline is None:
        from .. import pipeline as p
        _pipeline = p
    return _pipeline


def _get_knowledge():
    """Lazy import of knowledge module."""
    global _knowledge
    if _knowledge is None:
        from .. import knowledge as k
        _knowledge = k
    return _knowledge


def _get_reduction():
    """Lazy import of reduction module."""
    global _reduction
    if _reduction is None:
        from .. import reduction as r
        _reduction = r
    return _reduction


def _get_rule_gap_miner():
    """Lazy import of rule_gap_miner module."""
    global _rule_gap_miner
    if _rule_gap_miner is None:
        from .. import rule_gap_miner as rgm
        _rule_gap_miner = rgm
    return _rule_gap_miner


def _get_rules():
    """Lazy import of rules module."""
    global _rules
    if _rules is None:
        from .. import rules as r
        _rules = r
    return _rules


# =============================================================================
# Parameter Objects (Dataclasses)
# =============================================================================

@dataclass
class WarningInfo:
    """Encapsulates warning information to reduce function argument count.
    
    Attributes:
        module: The module where the warning originated
        stage: The processing stage where the warning occurred
        error: The error message or description
        hint: Optional hint for resolution
    """
    module: str
    stage: str
    error: str
    hint: Optional[str] = None


@dataclass
class SummarizationContext:
    """Encapsulates summarization parameters to reduce function argument count.
    
    Attributes:
        provider: The LLM provider instance
        reductions: The reduction results from findings
        correlations: List of correlation objects
        actions: List of action recommendations
        baseline_context: Baseline query results
    """
    provider: Any
    reductions: Any
    correlations: List[Any]
    actions: List[Any]
    baseline_context: Dict[str, Any]


# =============================================================================
# Environment Variable Caching
# =============================================================================

_ENV_CACHE: Dict[str, Any] = {}


def get_env_var(key: str, default: Any = None) -> Any:
    """Cache environment variable lookups for performance.
    
    Args:
        key: Environment variable name
        default: Default value if not set
        
    Returns:
        The environment variable value or default
    """
    if key not in _ENV_CACHE:
        _ENV_CACHE[key] = __import__('os').environ.get(key, default)
    return _ENV_CACHE[key]


def clear_env_cache() -> None:
    """Clear the environment variable cache (useful for testing)."""
    global _ENV_CACHE
    _ENV_CACHE = {}


# =============================================================================
# Compliance Standard Normalization
# =============================================================================

_COMPLIANCE_ALIASES: Dict[str, str] = {
    'pci': 'PCI DSS',
    'pcidss': 'PCI DSS',
    'hipaa': 'HIPAA',
    'soc2': 'SOC 2',
    'soc': 'SOC 2',
    'iso27001': 'ISO 27001',
    'cis': 'CIS Benchmark',
}


def normalize_compliance_standard(raw: str) -> Optional[str]:
    """Normalize compliance standard names to canonical forms.
    
    Args:
        raw: Raw compliance standard name
        
    Returns:
        Canonical form of the standard name, or None if not recognized
    """
    if not raw:
        return None
    key = raw.lower().replace(' ', '')
    return _COMPLIANCE_ALIASES.get(key)


# =============================================================================
# State Management Utilities
# =============================================================================

def extract_findings_from_state(state: StateType, key: str) -> List[Dict[str, Any]]:
    """Safely extract findings from state with fallback chain.
    
    Args:
        state: The graph state dictionary
        key: Primary key to look for findings
        
    Returns:
        List of finding dictionaries (empty list if none found)
    """
    return (state.get(key) or
            state.get('correlated_findings') or
            state.get('enriched_findings') or
            state.get('raw_findings') or [])


def initialize_state_fields(state: StateType, *fields: str) -> None:
    """Initialize state fields to avoid None checks throughout.
    
    Args:
        state: The graph state dictionary to modify
        *fields: Field names to initialize
    """
    for field in fields:
        if state.get(field) is None:
            if field in ('warnings', 'cache_keys'):
                state[field] = []
            elif field in ('metrics', 'cache', 'enrich_cache'):
                state[field] = {}
            else:
                state[field] = []


def normalize_state(state: StateType) -> StateType:
    """Normalize state to ensure all mandatory keys exist.
    
    Args:
        state: The graph state dictionary
        
    Returns:
        Normalized state dictionary
    """
    return _get_graph_state().normalize_graph_state(state)


def ensure_monotonic_timing(state: StateType) -> StateType:
    """Ensure monotonic timing is initialized for accurate duration calculations.
    
    Args:
        state: The graph state dictionary
        
    Returns:
        State with monotonic timing initialized
    """
    return _get_util_normalization().ensure_monotonic_timing(state)


# =============================================================================
# Metrics Utilities
# =============================================================================

def update_metrics_duration(state: StateType, metric_key: str, start_time: float) -> None:
    """Standardized metrics duration update.
    
    Args:
        state: The graph state dictionary
        metric_key: Key for the duration metric
        start_time: Monotonic start time from time.monotonic()
    """
    duration = time.monotonic() - start_time
    state.setdefault('metrics', {})[metric_key] = duration


def update_metrics_counter(state: StateType, counter_key: str, increment: int = 1) -> None:
    """Standardized metrics counter update.
    
    Args:
        state: The graph state dictionary
        counter_key: Key for the counter metric
        increment: Amount to increment (default 1)
    """
    metrics = state.setdefault('metrics', {})
    metrics[counter_key] = metrics.get(counter_key, 0) + increment


# =============================================================================
# Warning Management
# =============================================================================

def append_warning(state: StateType, warning_info: WarningInfo) -> None:
    """Append a warning to the state using encapsulated warning information.
    
    Args:
        state: The graph state dictionary
        warning_info: WarningInfo dataclass instance
    """
    wl = state.setdefault('warnings', [])
    wl.append({
        'module': warning_info.module,
        'stage': warning_info.stage,
        'error': warning_info.error,
        'hint': warning_info.hint
    })


# =============================================================================
# Model Building Utilities
# =============================================================================

def build_finding_models(findings_dicts: List[Dict[str, Any]]) -> List[Any]:
    """Optimized conversion of finding dicts to Pydantic models with error handling.
    
    Args:
        findings_dicts: List of finding dictionaries
        
    Returns:
        List of Finding model instances
    """
    models = _get_models()
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


def build_agent_state(findings: List[Any], scanner_name: str = "mixed") -> Any:
    """Optimized construction of AgentState from findings.
    
    Args:
        findings: List of Finding model instances
        scanner_name: Name of the scanner (default "mixed")
        
    Returns:
        AgentState model instance
    """
    models = _get_models()
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


def findings_from_graph(state: StateType) -> List[Any]:
    """Extract findings from graph state and convert to models.
    
    Args:
        state: The graph state dictionary
        
    Returns:
        List of Finding model instances
    """
    models = _get_models()
    out = []
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
                id=finding_dict.get('id', 'unknown'),
                title=finding_dict.get('title', '(no title)'),
                severity=finding_dict.get('severity', 'info'),
                risk_score=risk_score,
                metadata=finding_dict.get('metadata', {})
            ))
        except Exception:  # pragma: no cover - defensive
            continue
    return out


# =============================================================================
# Batch Processing Helpers
# =============================================================================

def batch_extract_finding_fields(findings: List[Dict[str, Any]]) -> Dict[str, List[Any]]:
    """Batch extract commonly used fields from findings to avoid repeated dict lookups.
    
    Args:
        findings: List of finding dictionaries
        
    Returns:
        Dictionary with lists of extracted field values
    """
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


def batch_filter_findings_by_severity(fields: Dict[str, List[Any]], severity_levels: set) -> List[int]:
    """Batch filter finding indices by severity levels.
    
    Args:
        fields: Batched finding fields from batch_extract_finding_fields()
        severity_levels: Set of severity level strings to filter by
        
    Returns:
        List of indices matching the severity levels
    """
    return [i for i, sev in enumerate(fields['severities']) if sev in severity_levels]


def batch_check_baseline_status(findings: List[Dict[str, Any]]) -> List[int]:
    """Batch check which findings are missing baseline status.
    
    Args:
        findings: List of finding dictionaries
        
    Returns:
        List of indices for findings missing baseline status
    """
    missing_indices = []
    for i, finding in enumerate(findings):
        baseline_status = finding.get('baseline_status')
        if baseline_status is None or 'baseline_status' not in finding:
            missing_indices.append(i)
    return missing_indices


def is_compliance_related(tags: List[str], category: str, metadata: Dict[str, Any]) -> bool:
    """Check if a finding is compliance-related based on tags, category, and metadata.
    
    Args:
        tags: List of tags (lowercase)
        category: Category string (lowercase)
        metadata: Metadata dictionary
        
    Returns:
        True if compliance-related, False otherwise
    """
    return (bool('compliance' in tags) or
            bool(category == 'compliance') or
            bool(metadata.get('compliance_standard')) or
            bool(normalize_compliance_standard(category)))


def batch_check_compliance_indicators(fields: Dict[str, List[Any]]) -> List[int]:
    """Batch check for compliance-related findings.
    
    Args:
        fields: Batched finding fields from batch_extract_finding_fields()
        
    Returns:
        List of indices for compliance-related findings
    """
    compliance_indices = []
    for i, (tags, category, metadata) in enumerate(zip(
        fields['tags_list'], fields['categories'], fields['metadata_list']
    )):
        if is_compliance_related(tags, category, metadata):
            compliance_indices.append(i)
    return compliance_indices


# =============================================================================
# Risk Calculation Utilities
# =============================================================================

def count_severities(severities: List[str]) -> Dict[str, int]:
    """Count findings by severity level.
    
    Args:
        severities: List of severity strings (lowercase)
        
    Returns:
        Dictionary with counts per severity level
    """
    sev_counters = {k: 0 for k in ['critical', 'high', 'medium', 'low', 'info', 'unknown']}
    for sev in severities:
        sev = sev if sev in sev_counters else 'unknown'
        sev_counters[sev] += 1
    return sev_counters


def calculate_risk_totals(risk_scores: List[int]) -> Tuple[int, float, List[int]]:
    """Calculate total and average risk scores.
    
    Args:
        risk_scores: List of risk score integers
        
    Returns:
        Tuple of (total_risk, average_risk, risk_scores_list)
    """
    total_risk = sum(risk_scores)
    avg_risk = (total_risk / len(risk_scores)) if risk_scores else 0.0
    return total_risk, avg_risk, risk_scores


def determine_qualitative_risk(sev_counters: Dict[str, int]) -> str:
    """Determine overall qualitative risk level from severity counts.
    
    Args:
        sev_counters: Dictionary of severity counts
        
    Returns:
        Qualitative risk level string
    """
    qualitative = 'info'
    order = ['critical', 'high', 'medium', 'low', 'info']
    for level in order:
        if sev_counters.get(level):
            qualitative = level
            break
    return qualitative


def batch_calculate_risk_metrics(fields: Dict[str, List[Any]]) -> Dict[str, Any]:
    """Batch calculate risk assessment metrics.
    
    Args:
        fields: Batched finding fields from batch_extract_finding_fields()
        
    Returns:
        Dictionary with calculated risk metrics
    """
    sev_counters = count_severities(fields['severities'])
    total_risk, avg_risk, risk_values = calculate_risk_totals(fields['risk_scores'])
    qualitative_risk = determine_qualitative_risk(sev_counters)

    return {
        'sev_counters': sev_counters,
        'total_risk': total_risk,
        'avg_risk': avg_risk,
        'qualitative_risk': qualitative_risk,
        'risk_values': risk_values,
    }


def batch_get_top_findings_by_risk(fields: Dict[str, List[Any]], top_n: int = 3) -> List[Dict[str, Any]]:
    """Batch get top N findings by risk score.
    
    Args:
        fields: Batched finding fields from batch_extract_finding_fields()
        top_n: Number of top findings to return
        
    Returns:
        List of top findings with id, title, risk_score, severity
    """
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


def count_findings_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count findings by severity level (convenience function).
    
    Args:
        findings: List of finding dictionaries
        
    Returns:
        Dictionary with counts per severity level
    """
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'unknown': 0}
    for finding in findings:
        severity = finding.get('severity', 'unknown')
        if isinstance(severity, str):
            severity = severity.lower()
        if severity in counts:
            counts[severity] += 1
        else:
            counts['unknown'] += 1
    return counts


# =============================================================================
# LLM Provider Utilities
# =============================================================================

def get_enhanced_llm_provider() -> Any:
    """Multi-provider selection wrapper.

    Currently returns the default provider; placeholder for future logic that
    could select alternate providers based on:
      - state['summary_strategy']
      - environment variables (AGENT_LLM_PROVIDER / AGENT_LLM_PROVIDER_ALT)
      - risk / finding volume thresholds
    Deterministic by design (no randomness).
    
    Returns:
        LLM provider instance
    """
    llm_provider = _get_llm_provider()
    primary = llm_provider.get_llm_provider()
    alt_env = __import__('os').environ.get('AGENT_LLM_PROVIDER_ALT')
    if alt_env and alt_env == '__use_null__':
        try:
            return llm_provider.NullLLMProvider()
        except Exception:  # pragma: no cover
            return primary
    return primary


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Type definitions
    'GraphState',
    'StateType',
    
    # Dataclasses
    'WarningInfo',
    'SummarizationContext',
    
    # Environment utilities
    'get_env_var',
    'clear_env_cache',
    
    # Compliance utilities
    'normalize_compliance_standard',
    
    # State management
    'extract_findings_from_state',
    'initialize_state_fields',
    'normalize_state',
    'ensure_monotonic_timing',
    
    # Metrics utilities
    'update_metrics_duration',
    'update_metrics_counter',
    
    # Warning management
    'append_warning',
    
    # Model building
    'build_finding_models',
    'build_agent_state',
    'findings_from_graph',
    
    # Batch processing
    'batch_extract_finding_fields',
    'batch_filter_findings_by_severity',
    'batch_check_baseline_status',
    'is_compliance_related',
    'batch_check_compliance_indicators',
    
    # Risk calculations
    'count_severities',
    'calculate_risk_totals',
    'determine_qualitative_risk',
    'batch_calculate_risk_metrics',
    'batch_get_top_findings_by_risk',
    'count_findings_by_severity',
    
    # LLM utilities
    'get_enhanced_llm_provider',
    
    # Lazy accessors
    '_get_models',
    '_get_graph_state',
    '_get_util_hash',
    '_get_util_normalization',
    '_get_llm_provider',
    '_get_pipeline',
    '_get_knowledge',
    '_get_reduction',
    '_get_rule_gap_miner',
    '_get_rules',
]
