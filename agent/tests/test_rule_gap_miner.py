from __future__ import annotations
import json
from pathlib import Path
from sys_scan_agent.rule_gap_miner import mine_gap_candidates


def make_enriched(fpath: Path, titles, severity='high', risk=80):
    findings = []
    for i,t in enumerate(titles):
        findings.append({
            'id': f'f{i}',
            'title': t,
            'severity': severity,
            'risk_total': risk,
            'risk_score': risk,
            'tags': []
        })
    obj = {'enriched_findings': findings}
    fpath.write_text(json.dumps(obj))


def test_gap_miner_basic(tmp_path):
    # Three similar high-risk uncorrrelated findings repeating across files
    titles = ["Suspicious tool execution alpha", "Suspicious tool execution beta", "Suspicious tool execution gamma"]
    for i in range(3):
        make_enriched(tmp_path / f'e{i}.json', titles)
    res = mine_gap_candidates(list(tmp_path.glob('*.json')), risk_threshold=50, min_support=2)
    assert res['selected'] >= 1
    assert res['suggestions']
    skel = res['suggestions'][0]
    assert 'conditions' in skel and skel['conditions']
    assert any('contains' in c for c in skel['conditions'])
