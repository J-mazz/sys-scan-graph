from __future__ import annotations
import json, tempfile
from pathlib import Path
from sys_scan_agent.rule_suggest import suggest_rules

def make_report(path: Path, titles):
    findings = []
    for i,t in enumerate(titles):
        findings.append({'id': f'f{i}', 'title': t, 'severity': 'high', 'risk_total': 90, 'risk_score': 90, 'tags': []})
    path.write_text(json.dumps({'enriched_findings': findings}))


def test_rule_suggest_basic(tmp_path, monkeypatch, capsys):
    # Prepare synthetic enriched report
    titles = [
        'Suspicious persistence mechanism detected alpha',
        'Suspicious persistence mechanism detected beta',
        'Suspicious persistence mechanism detected gamma'
    ]
    rpt = tmp_path / 'enriched.json'
    make_report(rpt, titles)
    suggest_rules(['--input', str(rpt), '--min-risk', '0.5'])
    out = capsys.readouterr().out
    obj = json.loads(out)
    assert obj['candidate_count'] >= 1
    assert obj['candidates']
    first = obj['candidates'][0]
    assert 'conditions' in first and first['conditions']
