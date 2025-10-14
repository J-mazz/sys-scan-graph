from __future__ import annotations
import json, os
from pathlib import Path
from sys_scan_agent.rule_gap_miner import mine_gap_candidates, refine_with_llm


def test_refine_with_llm_layers(tmp_path, monkeypatch):
    # Build enriched files with repeated pattern
    titles = ["Unknown binary dropped temp", "Unknown binary dropped tmp", "Unknown binary dropped cache"]
    for i in range(3):
        findings = []
        for j,t in enumerate(titles):
            findings.append({'id': f'f{i}_{j}', 'title': t, 'severity': 'high', 'risk_total': 90, 'risk_score': 90, 'tags': []})
        (tmp_path / f'e{i}.json').write_text(json.dumps({'enriched_findings': findings}))
    res = mine_gap_candidates(list(tmp_path.glob('*.json')), risk_threshold=50, min_support=2)
    assert res['suggestions']
    # Heuristic refinement
    ex_map = {}
    for c in res['candidates']:
        rid_guess = f"gap_{c['key'][:40]}"
        ex_map[rid_guess] = c['example_titles']
    refined = refine_with_llm(res['suggestions'], examples=ex_map)
    assert any('refined tokens' in s.get('rationale','') for s in refined)
    # Enable LLM second layer
    monkeypatch.setenv('AGENT_RULE_REFINER_USE_LLM','1')
    refined2 = refine_with_llm(res['suggestions'], examples=ex_map)
    assert any('LLM refined' in s.get('rationale','') for s in refined2)
