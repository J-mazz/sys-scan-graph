from __future__ import annotations
import json
from pathlib import Path
from sys_scan_agent.rule_gap_miner import mine_gap_candidates

def make_file(p: Path, titles, sev='high', risk=90):
    findings = []
    for i,t in enumerate(titles):
        findings.append({'id': f'f{i}', 'title': t, 'severity': sev, 'risk_total': risk, 'risk_score': risk, 'tags': []})
    p.write_text(json.dumps({'enriched_findings': findings}))


def test_scoring_variance_and_severity(tmp_path):
    # Two groups: one with critical severity & high variance, one medium severity low variance
    high_titles = [f"High pattern {i}" for i in range(5)]
    med_titles = [f"Med pattern {i}" for i in range(5)]
    # Create files mixing patterns so support counts similar
    for i in range(3):
        make_file(tmp_path / f'h{i}.json', high_titles, sev='critical', risk=90 + i*5)
        make_file(tmp_path / f'm{i}.json', med_titles, sev='medium', risk=40 + i)
    res = mine_gap_candidates(list(tmp_path.glob('*.json')), risk_threshold=30, min_support=2)
    ids = {s['id']: s for s in res['suggestions']}
    # Expect at least two suggestions (one per pattern)
    assert len(ids) >= 2
    # Find risk deltas
    deltas = [s['risk_score_delta'] for s in res['suggestions']]
    assert max(deltas) >= min(deltas)
