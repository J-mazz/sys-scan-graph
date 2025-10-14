"""Enrichment module for graph nodes.

This module contains functions for enriching and correlating security findings.
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
            # Provide minimal required fields; defaults for missing
            out.append(models.Finding(
                id=finding_dict.get('id','unknown'),
                title=finding_dict.get('title','(no title)'),
                severity=finding_dict.get('severity','info'),
                risk_score=int(finding_dict.get('risk_score', finding_dict.get('risk_total', 0)) or 0),
                metadata=finding_dict.get('metadata', {})
            ))
        except Exception:  # pragma: no cover - defensive
            continue
    return out


def _update_metrics_counter(state: StateType, counter_key: str, increment: int = 1) -> None:
    """Standardized metrics counter update."""
    metrics = state.setdefault('metrics', {})
    metrics[counter_key] = metrics.get(counter_key, 0) + increment

def enrich_findings(state: GraphState) -> GraphState:
    """Enrich raw findings with additional metadata, risk analysis, and intelligence."""
    raw_findings = state.get('raw_findings', [])
    enriched_findings = []

    for finding_dict in raw_findings:
        try:
            # Normalize raw finding data before creating model
            normalized_dict = finding_dict.copy()

            # Convert base_severity_score to risk_score if needed
            if 'base_severity_score' in normalized_dict and 'risk_score' not in normalized_dict:
                try:
                    # Convert string to int, defaulting to 0 if conversion fails
                    normalized_dict['risk_score'] = int(float(normalized_dict['base_severity_score']))
                except (ValueError, TypeError):
                    normalized_dict['risk_score'] = 0

            # Ensure risk_score is present
            if 'risk_score' not in normalized_dict:
                normalized_dict['risk_score'] = 0

            # Provide defaults for required fields to handle incomplete data gracefully
            if 'title' not in normalized_dict:
                normalized_dict['title'] = f"Finding {normalized_dict.get('id', 'unknown')}"
            if 'severity' not in normalized_dict:
                normalized_dict['severity'] = 'info'
            if 'metadata' not in normalized_dict:
                normalized_dict['metadata'] = {}

            # Convert dict to Finding model if needed
            if isinstance(finding_dict, dict):
                finding = models.Finding(**normalized_dict)
            else:
                finding = finding_dict

            # Add risk subscores based on severity and metadata
            risk_subscores = _calculate_risk_subscores(finding)

            # Determine baseline status (simplified - in real implementation would check baseline DB)
            baseline_status = _determine_baseline_status(finding)

            # Calculate probability actionable
            probability_actionable = _calculate_probability_actionable(finding, risk_subscores)

            # Add enrichment metadata
            finding.risk_subscores = risk_subscores
            finding.baseline_status = baseline_status
            finding.probability_actionable = probability_actionable
            finding.risk_total = finding.risk_score  # Ensure consistency

            # Add tags based on analysis
            finding.tags = _generate_tags(finding)

            if finding.severity.lower() != 'info':
                enriched_findings.append(finding)
        except Exception as e:  # pragma: no cover
            # Log validation errors but continue processing other findings
            logger.warning(f"Skipping invalid finding {finding_dict.get('id', 'unknown')}: {e}")
            _append_warning(state, WarningInfo('graph', 'enrich_findings', f"Invalid finding {finding_dict.get('id', 'unknown')}: {e}"))  # type: ignore
            continue

    state['enriched_findings'] = [finding.model_dump() for finding in enriched_findings]
    return state

def _calculate_risk_subscores(finding: models.Finding) -> Dict[str, float]:
    """Calculate risk subscores for impact, exposure, anomaly, and confidence."""
    # Base scores from severity
    severity_base = {
        'critical': 1.0,
        'high': 0.8,
        'medium': 0.6,
        'low': 0.4,
        'info': 0.2
    }.get(finding.severity.lower(), 0.3)

    # Impact score based on finding type and metadata
    impact = severity_base
    if 'suid' in finding.title.lower() or 'suid' in str(finding.metadata):
        impact *= 1.3  # SUID files are high impact
    if 'network' in finding.title.lower():
        impact *= 1.2  # Network exposures increase impact

    # Exposure score based on accessibility
    exposure = severity_base
    if 'world' in str(finding.metadata).lower() or 'readable' in finding.title.lower():
        exposure *= 1.4  # World-readable increases exposure
    if 'executable' in finding.title.lower():
        exposure *= 1.2  # Executable files increase exposure

    # Anomaly score based on deviation from baseline
    anomaly = severity_base
    if finding.baseline_status == 'new':
        anomaly *= 1.5  # New findings are more anomalous

    # Confidence score based on data quality
    confidence = 0.8  # Base confidence
    if finding.metadata and len(finding.metadata) > 2:
        confidence *= 1.1  # More metadata increases confidence

    return {
        'impact': min(impact, 1.0),
        'exposure': min(exposure, 1.0),
        'anomaly': min(anomaly, 1.0),
        'confidence': min(confidence, 1.0)
    }

def _determine_baseline_status(finding: models.Finding) -> str:
    """Determine if finding is new, existing, or unknown in baseline."""
    # Use deterministic hash-based assignment instead of random for test reliability
    import hashlib

    # Create a deterministic hash from finding properties
    hash_input = f"{finding.id or ''}:{finding.title}:{finding.severity}"
    hash_value = int(hashlib.md5(hash_input.encode()).hexdigest(), 16)

    # Use hash to deterministically select status with same weights as before
    # 30% new, 60% existing, 10% unknown
    normalized_hash = hash_value % 100
    if normalized_hash < 30:
        return 'new'
    elif normalized_hash < 90:  # 30 + 60 = 90
        return 'existing'
    else:
        return 'unknown'

def _calculate_probability_actionable(finding: models.Finding, subscores: Dict[str, float]) -> float:
    """Calculate probability that this finding requires action."""
    # Weighted combination of subscores
    weights = {'impact': 0.4, 'exposure': 0.3, 'anomaly': 0.2, 'confidence': 0.1}
    score = sum(subscores.get(k, 0) * w for k, w in weights.items())

    # Adjust based on severity
    severity_multiplier = {
        'critical': 1.2,
        'high': 1.1,
        'medium': 1.0,
        'low': 0.9,
        'info': 0.7
    }.get(finding.severity.lower(), 0.8)

    return min(score * severity_multiplier, 1.0)

def _generate_tags(finding: models.Finding) -> List[str]:
    """Generate relevant tags for the finding."""
    tags = []

    # Severity-based tags
    if finding.severity.lower() in ['critical', 'high']:
        tags.append('high_priority')

    # Content-based tags
    title_lower = finding.title.lower()
    if 'suid' in title_lower:
        tags.append('suid')
        tags.append('privilege_escalation')
    if 'network' in title_lower or 'port' in title_lower:
        tags.append('network')
    if 'file' in title_lower or 'permission' in title_lower:
        tags.append('filesystem')
    if 'process' in title_lower:
        tags.append('process')

    # Baseline tags
    if finding.baseline_status:
        tags.append(f'baseline:{finding.baseline_status}')

    return tags


def _validate_correlation_inputs(findings_dicts: List[Dict[str, Any]], findings_models: List[models.Finding]) -> bool:
    """Validate inputs for correlation processing."""
    return bool(findings_dicts and findings_models)


def _initialize_correlation_results() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Initialize empty correlation results."""
    return [], []


def _apply_correlation_rules(findings_models: List[models.Finding]) -> Tuple[List[Any], Dict[str, Any]]:
    """Apply correlation rules and return correlations with lookup map."""
    try:
        correlator = rules.Correlator(rules.DEFAULT_RULES)
        correlations = correlator.apply(findings_models)
        corr_map = {c.id: c for c in correlations}
        return correlations, corr_map
    except Exception:  # pragma: no cover
        return [], {}


def _attach_correlations_to_findings(findings_models: List[models.Finding], corr_map: Dict[str, Any]) -> None:
    """Attach correlation references to findings."""
    for finding in findings_models:
        for corr_id in corr_map.keys():
            if finding.id in corr_map[corr_id].related_finding_ids:
                if corr_id not in finding.correlation_refs:
                    finding.correlation_refs.append(corr_id)


def _prepare_correlation_data(state: StateType) -> Tuple[List[Dict[str, Any]], List[models.Finding], bool]:
    """Prepare data for correlation processing and check if correlation is needed."""
    findings_dicts = _extract_findings_from_state(state, 'enriched_findings')
    if not findings_dicts:
        state['correlated_findings'], state['correlations'] = _initialize_correlation_results()
        return [], [], False

    findings_models = _build_finding_models(findings_dicts)
    if not _validate_correlation_inputs(findings_dicts, findings_models):
        state['correlated_findings'], state['correlations'] = _initialize_correlation_results()
        return [], [], False

    return findings_dicts, findings_models, True


def _execute_correlation_processing(findings_models: List[models.Finding]) -> Tuple[List[Any], Dict[str, Any]]:
    """Execute correlation rules and attach correlations to findings."""
    astate = _build_agent_state(findings_models, "mixed")
    correlations, corr_map = _apply_correlation_rules(findings_models)
    _attach_correlations_to_findings(findings_models, corr_map)
    return correlations, corr_map


def _update_correlation_state(state: StateType, findings_models: List[models.Finding], correlations: List[Any]) -> None:
    """Update state with correlation results."""
    state['correlated_findings'] = [finding.model_dump() for finding in findings_models]
    state['correlations'] = [c.model_dump() for c in correlations]


def correlate_findings(state: StateType) -> StateType:
    """Apply correlation rules to enriched findings and attach correlation references.

    Optimized: Uses helper functions and reduces redundant operations.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    # Ensure monotonic timing is initialized for accurate duration calculations
    state = util_normalization.ensure_monotonic_timing(state)

    try:
        findings_dicts, findings_models, needs_correlation = _prepare_correlation_data(state)
        if not needs_correlation:
            return state

        correlations, corr_map = _execute_correlation_processing(findings_models)
        _update_correlation_state(state, findings_models, correlations)
    except Exception as e:  # pragma: no cover
        logger.exception("correlate_findings failed: %s", e)
        _append_warning(state, WarningInfo('graph', 'correlate', str(e)))  # type: ignore
        if 'correlated_findings' not in state:
            state['correlated_findings'] = state.get('enriched_findings', [])
    return state


def _generate_cache_key(raw_list: List[Dict[str, Any]]) -> str:
    """Generate deterministic cache key from raw findings."""
    try:
        return util_hash.stable_hash(raw_list, "enrich")
    except Exception:  # pragma: no cover - extremely unlikely
        return "enrich:invalid_key"


def _check_cache_hit(cache: Dict[str, Any], cache_key: str) -> bool:
    """Check if cache key exists in cache."""
    return cache_key in cache


def _handle_cache_hit(state: StateType, cache: Dict[str, Any], cache_key: str, start: float) -> StateType:
    """Handle cache hit by rehydrating from cache and updating metrics."""
    logger.debug("enhanced_enrich_findings cache hit key=%s", cache_key)
    _update_metrics_counter(state, "cache_hits")
    # Rehydrate enriched findings from cache
    state["enriched_findings"] = cache[cache_key]
    # Still record very small duration for observability
    _update_metrics_duration(state, "enrich_duration", start)
    ck_list = state["cache_keys"]
    if cache_key not in ck_list:
        ck_list.append(cache_key)
    return state


def _perform_enrichment_pipeline(state: StateType) -> List[Dict[str, Any]]:
    """Perform the enrichment pipeline and return enriched findings."""
    findings = _findings_from_graph(state)
    astate = _build_agent_state(findings, "mixed")
    # Run enrichment pipeline pieces (sync) inside async context
    astate = pipeline.augment(astate)
    astate = knowledge.apply_external_knowledge(astate)

    enriched: List[Dict[str, Any]] = []
    if astate.report and astate.report.results:
        for result in astate.report.results:
            for finding in result.findings:
                try:
                    enriched.append(finding.model_dump())
                except Exception:  # pragma: no cover
                    continue
    return enriched


def _update_cache_and_keys(state: StateType, cache: Dict[str, Any], cache_key: str, enriched: List[Dict[str, Any]]) -> None:
    """Update cache and cache keys with enriched findings."""
    cache[cache_key] = enriched
    ck_list = state["cache_keys"]
    if cache_key not in ck_list:
        ck_list.append(cache_key)


def _prepare_enrichment_state(state: StateType) -> Tuple[str, Dict[str, Any]]:
    """Prepare state for enrichment processing."""
    raw_list = state.get("raw_findings") or []
    _initialize_state_fields(state, 'warnings', 'metrics', 'cache_keys', 'enrich_cache')
    cache_key = _generate_cache_key(raw_list)
    cache: Dict[str, Any] = state["enrich_cache"]
    return cache_key, cache


def _handle_enrichment_cache_hit(state: StateType, cache: Dict[str, Any], cache_key: str, start: float) -> Optional[StateType]:
    """Handle cache hit scenario for enrichment."""
    if _check_cache_hit(cache, cache_key):
        return _handle_cache_hit(state, cache, cache_key, start)
    return None


def _execute_enrichment_pipeline(state: StateType, cache: Dict[str, Any], cache_key: str) -> None:
    """Execute enrichment pipeline and update cache."""
    enriched = _perform_enrichment_pipeline(state)
    state["enriched_findings"] = enriched
    _update_cache_and_keys(state, cache, cache_key, enriched)


def _handle_enrichment_error(state: StateType, cache_key: str, error: Exception) -> None:
    """Handle enrichment errors with fallback logic."""
    logger.exception("enhanced_enrich_findings failed key=%s error=%s", cache_key, error)
    _append_warning(state, WarningInfo("graph", "enhanced_enrich", f"{type(error).__name__}: {error}"))  # type: ignore
    if "enriched_findings" not in state:
        state["enriched_findings"] = state.get("raw_findings", [])


async def enhanced_enrich_findings(state: StateType) -> StateType:
    """Advanced async enrichment node with caching & metrics.

    Optimized: Uses helper functions for state initialization and metrics.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    start = time.monotonic()
    try:
        cache_key, cache = _prepare_enrichment_state(state)

        # Check for cache hit
        cached_result = _handle_enrichment_cache_hit(state, cache, cache_key, start)
        if cached_result is not None:
            return cached_result

        # Cache miss -> perform enrichment
        _execute_enrichment_pipeline(state, cache, cache_key)
    except Exception as e:  # pragma: no cover
        _handle_enrichment_error(state, cache_key, e)
    finally:
        _update_metrics_duration(state, "enrich_duration", start)
    return state