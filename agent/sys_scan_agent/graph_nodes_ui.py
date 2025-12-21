"""
Investigation Director Node for the Agent package.

This was moved from UI/integration/nodes/investigation_director.py so the Agent can
import it directly when running in interactive mode.
"""
from __future__ import annotations
from typing import Dict, Any, List
from dataclasses import dataclass
import time
import logging

logger = logging.getLogger(__name__)


@dataclass
class InvestigationArea:
    """Concrete area identified for potential investigation."""

    area_id: str
    title: str  # Concise, factual title
    what_was_found: str  # Precise statement of findings
    finding_ids: List[str]  # Exact findings involved
    correlation_ids: List[str]  # Exact correlations involved
    impact: str  # "critical", "high", "medium", "low"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "area_id": self.area_id,
            "title": self.title,
            "what_was_found": self.what_was_found,
            "finding_ids": self.finding_ids,
            "correlation_ids": self.correlation_ids,
            "impact": self.impact
        }


from .ipc_server import GraphCommunicator

def investigation_director_node(state: Dict[str, Any]) -> Dict[str, Any]:
    logger.info("Investigation Director: Generating final summary")

    summary = _generate_concise_summary(state)
    state['investigation_summary'] = summary

    areas = _identify_investigation_areas(state)
    if areas:
        state['investigation_areas'] = [a.to_dict() for a in areas]
        logger.info(f"Identified {len(areas)} concrete investigation areas")
    else:
        state['investigation_areas'] = []
        logger.info("No specific investigation areas identified")

    # Attempt to send the concise summary to any UI over IPC (best-effort)
    try:
        comm = GraphCommunicator()
        # Try to connect as client (UI may be acting as server) — best-effort
        if comm.connect_as_client():
            payload = {
                "type": "investigation_summary",
                "summary": summary,
                "areas": state.get('investigation_areas', [])
            }
            sent = comm.send_graph_state(payload)
            if sent:
                logger.info("Sent investigation summary to UI via IPC")
            else:
                logger.warning("Failed to send investigation summary to UI")
            comm.close()
        else:
            logger.debug("No UI IPC endpoint available (client connect failed); skipping send")
    except Exception as e:  # pragma: no cover - best-effort IPC
        logger.warning(f"IPC send attempt failed: {e}")

    state['investigation_complete'] = True

    return state


# (helper functions retained verbatim)

def _generate_concise_summary(state: Dict[str, Any]) -> Dict[str, Any]:
    enriched_findings = state.get('enriched_findings', [])
    correlations = state.get('correlations', [])
    risk_assessment = state.get('risk_assessment', {})

    by_severity = {}
    for f in enriched_findings:
        sev = f.get('severity', 'unknown')
        by_severity[sev] = by_severity.get(sev, 0) + 1

    novel_count = sum(1 for f in enriched_findings if f.get('baseline_status') == 'novel')

    correlation_details = []
    for corr in correlations:
        correlation_details.append({
            "id": corr.get('id', ''),
            "title": corr.get('title', ''),
            "finding_count": len(corr.get('related_finding_ids', [])),
            "tags": corr.get('tags', [])
        })

    summary = {
        "findings": {
            "total": len(enriched_findings),
            "by_severity": by_severity,
            "novel": novel_count
        },
        "correlations": {
            "total": len(correlations),
            "details": correlation_details
        },
        "risk": {
            "level": risk_assessment.get('risk_level', 'unknown'),
            "score": risk_assessment.get('risk_score', 0)
        }
    }

    return summary


def _identify_investigation_areas(state: Dict[str, Any]) -> List[InvestigationArea]:
    areas = []

    enriched_findings = state.get('enriched_findings', [])
    correlations = state.get('correlations', [])

    for corr in correlations:
        finding_ids = corr.get('related_finding_ids', [])
        if len(finding_ids) >= 4:
            areas.append(InvestigationArea(
                area_id=f"corr_{corr.get('id', 'unknown')}",
                title=corr.get('title', 'Complex correlation'),
                what_was_found=f"{len(finding_ids)} findings correlate: {corr.get('rationale', 'See findings')}",
                finding_ids=finding_ids,
                correlation_ids=[corr.get('id', '')],
                impact="high" if len(finding_ids) >= 6 else "medium"
            ))

    novel_high = [
        f for f in enriched_findings
        if f.get('baseline_status') == 'novel' and f.get('severity') in ['critical', 'high']
    ]

    if len(novel_high) >= 3:
        finding_ids = [f.get('id', '') for f in novel_high]
        areas.append(InvestigationArea(
            area_id=f"novel_high_{int(time.time())}",
            title=f"{len(novel_high)} novel high-severity findings",
            what_was_found=f"Found {len(novel_high)} new high-severity issues not in baseline",
            finding_ids=finding_ids,
            correlation_ids=[],
            impact="critical"
        ))

    attack_patterns = _detect_attack_patterns(enriched_findings, correlations)
    for pattern in attack_patterns:
        areas.append(InvestigationArea(
            area_id=pattern['id'],
            title=pattern['title'],
            what_was_found=pattern['description'],
            finding_ids=pattern['finding_ids'],
            correlation_ids=pattern['correlation_ids'],
            impact=pattern['impact']
        ))

    impact_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    areas.sort(key=lambda a: impact_order.get(a.impact, 0), reverse=True)

    return areas


def _detect_attack_patterns(
    findings: List[Dict[str, Any]],
    correlations: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    patterns = []

    priv_esc_findings = [
        f for f in findings
        if 'privilege_escalation' in f.get('tags', []) or 'suid' in f.get('tags', [])
    ]

    if len(priv_esc_findings) >= 2:
        linking_corrs = [
            c for c in correlations
            if any(f.get('id') in c.get('related_finding_ids', []) for f in priv_esc_findings)
        ]

        if linking_corrs:
            patterns.append({
                'id': f'priv_esc_chain_{int(time.time())}',
                'title': 'Privilege escalation chain detected',
                'description': f'{len(priv_esc_findings)} privilege escalation vectors found, {len(linking_corrs)} correlations',
                'finding_ids': [f.get('id', '') for f in priv_esc_findings],
                'correlation_ids': [c.get('id', '') for c in linking_corrs],
                'impact': 'critical'
            })

    network_findings = [f for f in findings if 'network' in f.get('tags', [])]
    process_findings = [f for f in findings if 'process' in f.get('tags', [])]

    if network_findings and process_findings:
        combined_corrs = [
            c for c in correlations
            if any(f.get('id') in c.get('related_finding_ids', []) for f in network_findings)
            and any(f.get('id') in c.get('related_finding_ids', []) for f in process_findings)
        ]

        if combined_corrs:
            patterns.append({
                'id': f'network_process_{int(time.time())}',
                'title': 'Network and process activity correlated',
                'description': f'{len(network_findings)} network + {len(process_findings)} process findings linked',
                'finding_ids': [f.get('id', '') for f in network_findings + process_findings],
                'correlation_ids': [c.get('id', '') for c in combined_corrs],
                'impact': 'high'
            })

    return patterns


__all__ = [
    "investigation_director_node",
    "InvestigationArea",
]
