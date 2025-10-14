from __future__ import annotations
import json
from pathlib import Path
from sys_scan_agent.pipeline import load_report, augment, correlate, baseline_rarity, sequence_correlation
from sys_scan_agent.models import AgentState


def build_report():
    findings = []
    # New SUID binary
    findings.append({
        'id': 'suid1', 'title': 'New suspicious SUID binary', 'severity': 'high', 'risk_score': 50,
        'metadata': {'path': '/usr/local/bin/suspicious'}, 'tags': ['suid','baseline:new']
    })
    # Kernel param enabling ip_forward (value=1)
    findings.append({
        'id': 'ipfwd', 'title': 'Enable IP forwarding', 'severity': 'medium', 'risk_score': 20,
        'metadata': {'sysctl_key': 'net.ipv4.ip_forward', 'value': '1'}, 'tags': ['kernel_param']
    })
    report = {
        'meta': {'hostname': 'hostZ'},
        'summary': {'finding_count_total': len(findings), 'finding_count_emitted': len(findings), 'severity_counts': {'high':1,'medium':1}},
        'results': [
            {'scanner': 'suid', 'finding_count': 1, 'findings': [findings[0]]},
            {'scanner': 'kernel_params', 'finding_count': 1, 'findings': [findings[1]]}
        ],
        'collection_warnings': [],
        'scanner_errors': [],
        'summary_extension': {'total_risk_score': 0}
    }
    return report


def test_sequence_correlation(tmp_path):
    rpt = build_report()
    p = tmp_path / 'r.json'
    p.write_text(json.dumps(rpt))
    st = AgentState()
    st = load_report(st, p)
    st = augment(st)
    st = correlate(st)
    st = sequence_correlation(st)
    ids = [c.id for c in st.correlations]
    assert 'sequence_anom_1' in ids, 'Expected sequence anomaly correlation created'
    seq_corr = [c for c in st.correlations if c.id=='sequence_anom_1'][0]
    assert 'sequence_anomaly' in seq_corr.tags
    # Ensure finding back-references
    assert st.report and st.report.results
    suid_ref = any('sequence_anom_1' in f.correlation_refs for r in st.report.results for f in r.findings if f.id=='suid1')
    assert suid_ref
