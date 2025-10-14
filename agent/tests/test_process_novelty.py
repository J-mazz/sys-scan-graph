from __future__ import annotations
import json, tempfile
from pathlib import Path
from sys_scan_agent.pipeline import load_report, augment, baseline_rarity, process_novelty
from sys_scan_agent.models import AgentState, Report


def build_report(cmds):
    findings = []
    for i,cmd in enumerate(cmds):
        findings.append({
            'id': f'p{i}',
            'title': cmd,
            'severity': 'medium',
            'risk_score': 10,
            'metadata': {'cmdline': cmd}
        })
    report = {
        'meta': {'hostname': 'hostA'},
        'summary': {'finding_count_total': len(findings), 'finding_count_emitted': len(findings), 'severity_counts': {'medium': len(findings)}},
        'results': [
            {'scanner': 'process', 'finding_count': len(findings), 'findings': findings}
        ],
        'collection_warnings': [],
        'scanner_errors': [],
        'summary_extension': {'total_risk_score': 0}
    }
    return report


def test_process_novelty(tmp_path, monkeypatch):
    # First scan establishes clusters
    r1 = build_report(['bash','sshd','python /opt/app/server.py'])
    p1 = tmp_path / 'r1.json'
    p1.write_text(json.dumps(r1))
    state = AgentState()
    state = load_report(state, p1)
    state = augment(state)
    state = baseline_rarity(state, baseline_path=tmp_path/'baseline.db')
    state = process_novelty(state, baseline_path=tmp_path/'novelty.json')
    assert state.report and state.report.results
    first_tags = [f.tags for r in state.report.results for f in r.findings]
    # Second scan introduces novel process
    r2 = build_report(['bash','sshd','weird_malware_process_xyz'])
    p2 = tmp_path / 'r2.json'
    p2.write_text(json.dumps(r2))
    state2 = AgentState()
    state2 = load_report(state2, p2)
    state2 = augment(state2)
    state2 = baseline_rarity(state2, baseline_path=tmp_path/'baseline.db')
    state2 = process_novelty(state2, baseline_path=tmp_path/'novelty.json')
    assert state2.report and state2.report.results
    novel = [f for r in state2.report.results for f in r.findings if 'process_novel' in f.tags]
    assert novel, 'Expected at least one novel process finding tagged'
    # Ensure weird process got tag
    assert any('weird_malware_process_xyz' in f.title for f in novel)
