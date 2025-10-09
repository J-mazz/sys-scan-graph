"""Enrichment module for finding augmentation with metadata, categories, and risk scores."""

import hashlib
import uuid
from pathlib import Path
from typing import Optional

from .utils import _log_error, _recompute_finding_risk, CAT_MAP, POLICY_MULTIPLIER, SEVERITY_BASE


def _compute_finding_tags(metadata: dict, scanner: str) -> set[str]:
    """Compute base tags for a finding based on its metadata and scanner."""
    base_tags = {f"scanner:{scanner}", f"severity:{metadata.get('severity', 'unknown')}"}

    # Heuristic tags
    if metadata.get("port"):
        base_tags.add("network_port")
    if metadata.get("state") == "LISTEN":
        base_tags.add("listening")
    if metadata.get("suid") == "true":
        base_tags.add("suid")
    if metadata.get("module"):
        base_tags.add("module")
    if metadata.get("sysctl_key"):
        base_tags.add("kernel_param")

    return base_tags


def _merge_finding_tags(finding, base_tags: set[str]) -> None:
    """Merge base tags with existing finding tags, preserving order."""
    if not finding.tags:
        finding.tags = list(sorted(base_tags))
        return

    existing = set(finding.tags)
    for t in sorted(base_tags):
        if t not in existing:
            finding.tags.append(t)


def _initialize_finding_risk(finding, severity_base: dict, policy_multiplier: dict, inferred_cat: str) -> None:
    """Initialize risk subscores for a finding."""
    if not finding.risk_subscores:
        exposure = 0.0
        if any(t in (finding.tags or []) for t in ["listening","suid","routing","nat"]):
            if "listening" in (finding.tags or []): exposure += 1.0
            if "suid" in (finding.tags or []): exposure += 1.0
            if any(t.startswith("network_port") for t in (finding.tags or [])): exposure += 0.5
            if "routing" in (finding.tags or []): exposure += 0.5
            if "nat" in (finding.tags or []): exposure += 0.5

        cat_key = finding.category or inferred_cat or "unknown"
        impact = float(severity_base.get(finding.severity,1)) * policy_multiplier.get(cat_key,1.0)

        finding.risk_subscores = {
            "impact": round(impact,2),
            "exposure": round(min(exposure,3.0),2),
            "anomaly": 0.0,  # baseline stage will add weights
            "confidence": 1.0  # default; heuristic rules may lower
        }


def _process_finding_enrichment(sr, inferred_cat: Optional[str], severity_base: dict, policy_multiplier: dict) -> None:
    """Process enrichment for all findings in a scanner result."""
    if inferred_cat is None:
        inferred_cat = "unknown"
    for finding in sr.findings:
        if not finding.category:
            finding.category = inferred_cat

        # Base tags
        base_tags = _compute_finding_tags(finding.metadata or {}, sr.scanner)
        _merge_finding_tags(finding, base_tags)

        # Structured risk subscores initialization
        _initialize_finding_risk(finding, severity_base, policy_multiplier, inferred_cat)


def _derive_host_metadata(state) -> None:
    """Derive host_id and scan_id from raw report metadata."""
    if not state.report:
        return

    meta_raw = state.raw_report.get("meta", {}) if state.raw_report else {}
    hostname = meta_raw.get("hostname", "unknown")
    kernel = meta_raw.get("kernel", "")

    # Derive host_id if absent
    if not state.report.meta.host_id:
        h = hashlib.sha256()
        h.update(hostname.encode())
        h.update(b"|")
        h.update(kernel.encode())
        state.report.meta.host_id = h.hexdigest()[:32]

    # Always assign a fresh scan_id
    state.report.meta.scan_id = uuid.uuid4().hex


def _apply_host_role_adjustments(state) -> None:
    """Apply host role-based adjustments to finding risk scores."""
    if not state.report:
        return

    # Try to import classify_host_role, skip if not available
    try:
        from . import audit
        classify_host_role = getattr(audit, 'classify_host_role', None)
        if classify_host_role is None:
            return
    except (ImportError, AttributeError):
        return  # Skip if audit module not available
    
    host_id = state.report.meta.host_id
    for sr in state.report.results:
        for f in sr.findings:
            try:
                role, rationale = classify_host_role(host_id, f.category, f.metadata)
                f.host_role = role
                f.host_role_rationale = rationale
                if f.category == 'kernel_param' and f.metadata.get('sysctl_key') == 'net.ipv4.ip_forward' and f.risk_subscores:
                    impact_changed = False
                    if role in {'lightweight_router','container_host'}:
                        new_imp = round(max(0.5, f.risk_subscores['impact'] * 0.6),2)
                        if new_imp != f.risk_subscores['impact']:
                            f.risk_subscores['impact'] = new_imp; impact_changed = True
                        note = f"host_role {role} => ip_forward normalized (impact adjusted)"
                    elif role in {'workstation','dev_workstation'}:
                        new_imp = round(min(10.0, f.risk_subscores['impact'] * 1.2 + 0.5),2)
                        if new_imp != f.risk_subscores['impact']:
                            f.risk_subscores['impact'] = new_imp; impact_changed = True
                        note = f"host_role {role} => ip_forward unusual (impact raised)"
                    else:
                        note = None
                    if note:
                        if f.rationale:
                            f.rationale.append(note)
                        else:
                            f.rationale = [note]
                    if impact_changed:
                        _recompute_finding_risk(f)
            except Exception as e:
                _log_error('host_role_classification', e, state)


def _perform_initial_risk_recomputation(state) -> None:
    """Perform initial risk recomputation for findings lacking risk_score."""
    if not state.report:
        return

    from .metrics import get_metrics_collector
    mc = get_metrics_collector()
    with mc.time_stage('augment.risk_recompute_initial'):
        for sr in state.report.results:
            for finding in sr.findings:
                if finding.risk_subscores and finding.risk_score is None:
                    _recompute_finding_risk(finding)


def augment(state):
    """Derive host_id, scan_id, finding categories & basic tags without modifying core C++ schema."""
    if not state.report:
        return state

    # Derive host metadata
    _derive_host_metadata(state)

    # Iterate findings to enrich
    if not state.report or not state.report.results:
        return state

    from .metrics import get_metrics_collector
    mc = get_metrics_collector()
    with mc.time_stage('augment.iter_findings'):
        for sr in state.report.results:
            inferred_cat = CAT_MAP.get(sr.scanner.lower(), sr.scanner.lower())
            _process_finding_enrichment(sr, inferred_cat, SEVERITY_BASE, POLICY_MULTIPLIER)

    # Host role classification and adjustments
    _apply_host_role_adjustments(state)

    # Initial risk computation for findings lacking risk_score
    _perform_initial_risk_recomputation(state)

    return state