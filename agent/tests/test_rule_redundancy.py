from __future__ import annotations
import json
from pathlib import Path
from sys_scan_agent.rule_redundancy import compute_redundancy

def make_corr_report(path: Path, corrs):
    path.write_text(json.dumps({'correlations': corrs}))


def test_rule_redundancy_simple(tmp_path):
    # Two correlations with high overlap
    c1 = {'id': 'r1', 'related_finding_ids': ['a','b','c','d']}
    c2 = {'id': 'r2', 'related_finding_ids': ['b','c','d','e']}
    c3 = {'id': 'r3', 'related_finding_ids': ['x']}
    make_corr_report(tmp_path/'rpt1.json', [c1,c2,c3])
    res = compute_redundancy(list(tmp_path.glob('*.json')), threshold=0.6)
    assert res['redundant_pairs']
    pair = res['redundant_pairs'][0]
    assert {'rule_a','rule_b','overlap'} <= pair.keys()
