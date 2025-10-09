"""Correlation module for finding correlation analysis and rule-based pattern detection."""

from typing import List

from . import models
from . import rules
from . import metrics
from .utils import _log_error

# Re-export for backward compatibility
Correlation = models.Correlation
Correlator = rules.Correlator


def _enrich_knowledge_before_correlation(state) -> None:
    """Apply external knowledge enrichment before correlation processing."""
    try:
        from .metrics import get_metrics_collector
        mc = get_metrics_collector()
        with mc.time_stage('knowledge.enrichment'):
            from .knowledge import apply_external_knowledge
            apply_external_knowledge(state)
    except ImportError:
        # Skip if knowledge module not available
        pass


def _collect_findings_for_correlation(state) -> List:
    """Collect all findings from the report for correlation processing."""
    all_findings = []
    if not state.report:
        return all_findings
    for r in state.report.results:
        for finding in r.findings:
            all_findings.append(finding)
    return all_findings


def _load_correlation_config_and_rules() -> tuple:
    """Load configuration and merge correlation rules."""
    try:
        from .config import load_config
        from .rules import load_rules_dir, DEFAULT_RULES
        cfg = load_config()
        merged = _merge_correlation_rules(cfg)
        return cfg, merged
    except ImportError:
        return None, []


def _merge_correlation_rules(cfg) -> list:
    """Merge correlation rules from config directories and defaults with deduplication."""
    try:
        from .rules import load_rules_dir, DEFAULT_RULES
        merged = []
        seen = set()
        for rd in (cfg.paths.rule_dirs or []):
            for rule in load_rules_dir(rd):
                rid = rule.get('id')
                if rid and rid in seen: continue
                merged.append(rule); seen.add(rid)
        for rule in DEFAULT_RULES:
            rid = rule.get('id')
            if rid and rid in seen: continue
            merged.append(rule); seen.add(rid)
        return merged
    except ImportError:
        return []


def _apply_correlation_rules_and_metrics(all_findings: List, merged: list, mc) -> list:
    """Apply correlation rules to findings and update metrics."""
    try:
        from .rules import Correlator
        correlator = Correlator(merged)
        with mc.time_stage('correlate.apply_rules'):
            correlations = correlator.apply(all_findings)
        mc.incr('correlate.rules_loaded', len(merged))
        mc.incr('correlate.correlations', len(correlations))
        return correlations
    except ImportError:
        return []


def _build_correlation_reference_map(correlations: list) -> dict:
    """Build a map of finding IDs to their correlation references."""
    corr_map = {}
    for c in correlations:
        for fid in c.related_finding_ids:
            corr_map.setdefault(fid, []).append(c.id)
    return corr_map


def _assign_correlation_refs_to_findings(all_findings: List, corr_map: dict) -> None:
    """Assign correlation references to findings."""
    for finding in all_findings:
        finding.correlation_refs = corr_map.get(finding.id, [])


def correlate(state) -> None:
    """Apply correlation rules to findings and build correlation references."""
    # Enrich with external knowledge first
    _enrich_knowledge_before_correlation(state)

    # Collect all findings for processing
    all_findings = _collect_findings_for_correlation(state)
    if not all_findings:
        return

    # Load configuration and merge rules
    cfg, merged = _load_correlation_config_and_rules()

    # Apply correlation rules and update metrics
    try:
        from .metrics import get_metrics_collector
        mc = get_metrics_collector()
        state.correlations = _apply_correlation_rules_and_metrics(all_findings, merged, mc)
    except ImportError:
        state.correlations = []

    # Build and assign correlation references
    corr_map = _build_correlation_reference_map(state.correlations)
    _assign_correlation_refs_to_findings(all_findings, corr_map)


def _flatten_findings(state) -> List:
    """Flatten all findings from report results preserving order."""
    ordered = []
    if state.report and state.report.results:
        for r in state.report.results:
            ordered.extend(r.findings)
    return ordered


def _collect_suid_indices(ordered: List) -> List[tuple]:
    """Collect indices of new SUID findings."""
    suid_indices = []
    for idx, f in enumerate(ordered):
        if 'suid' in (f.tags or []) and any(t == 'baseline:new' for t in (f.tags or [])):
            suid_indices.append((idx, f))
    return suid_indices


def _collect_ip_forward_indices(ordered: List) -> List[tuple]:
    """Collect indices of IP forwarding enabled findings."""
    ip_forward_indices = []
    for idx, f in enumerate(ordered):
        if f.category == 'kernel_param' and f.metadata.get('sysctl_key') == 'net.ipv4.ip_forward':
            val = str(f.metadata.get('value') or f.metadata.get('desired') or f.metadata.get('current') or '')
            if val in {'1','true','enabled'}:
                ip_forward_indices.append((idx, f))
    return ip_forward_indices


def _check_sequence_trigger(suid_indices: List[tuple], ip_forward_indices: List[tuple]) -> bool:
    """Check if any SUID precedes any IP forwarding finding."""
    if not suid_indices or not ip_forward_indices:
        return False
    trigger_pairs = [(s,i) for (s,_) in suid_indices for (i,_) in ip_forward_indices if s < i]
    return bool(trigger_pairs)


def _build_related_finding_ids(suid_indices: List[tuple], ip_forward_indices: List[tuple]) -> List[str]:
    """Build list of related finding IDs for correlation."""
    related = []
    for (s_idx, s_f) in suid_indices[:3]:
        related.append(s_f.id)
    for (i_idx, i_f) in ip_forward_indices[:2]:
        related.append(i_f.id)
    return related


def _create_sequence_correlation(related: List[str], existing_count: int):
    """Create a sequence anomaly correlation."""
    # Deterministic ID: sequence_anom_<n>
    corr_id = f'sequence_anom_{existing_count + 1}'
    corr = Correlation(
        id=corr_id,
        title='Suspicious Sequence: New SUID followed by IP forwarding enabled',
        rationale='Heuristic: newly introduced SUID binary preceded enabling IP forwarding in same scan',
        related_finding_ids=related,
        risk_score_delta=8,
        tags=['sequence_anomaly','routing','privilege_escalation_surface'],
        severity='high'
    )
    return corr


def _add_correlation_refs(state, corr, ordered: List) -> None:
    """Add correlation references to related findings."""
    for f in ordered:
        if f.id in corr.related_finding_ids:
            if corr.id not in (f.correlation_refs or []):
                if f.correlation_refs is None:
                    f.correlation_refs = []
                f.correlation_refs.append(corr.id)


def sequence_correlation(state) -> None:
    """Detect suspicious temporal sequences inside a single scan.
    Current heuristic pattern:
      1. New SUID binary (tag baseline:new + suid) appears
      2. net.ipv4.ip_forward kernel param enabled (value=1) in same scan after the SUID finding order.
    If both occur, emit synthetic correlation with tag sequence_anomaly.
    Ordering proxy: we use appearance order in report results since per-scanner timestamps absent.
    """
    if not state.report:
        return

    # Flatten findings preserving order
    ordered = _flatten_findings(state)

    # Collect relevant finding indices
    suid_indices = _collect_suid_indices(ordered)
    ip_forward_indices = _collect_ip_forward_indices(ordered)

    # Check for sequence trigger
    if _check_sequence_trigger(suid_indices, ip_forward_indices):
        # Build correlation referencing the involved findings
        related = _build_related_finding_ids(suid_indices, ip_forward_indices)

        # Avoid duplicate correlation creation
        already = any(c.related_finding_ids == related and 'sequence_anomaly' in (c.tags or []) for c in state.correlations)
        if not already:
            # Count existing sequence anomalies
            existing_count = len([c for c in state.correlations if 'sequence_anomaly' in (c.tags or []) and c.id.startswith('sequence_anom_')])
            corr = _create_sequence_correlation(related, existing_count)
            state.correlations.append(corr)

            # Back-reference on findings
            _add_correlation_refs(state, corr, ordered)