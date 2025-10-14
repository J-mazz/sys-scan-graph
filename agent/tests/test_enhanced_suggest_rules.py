from __future__ import annotations
import asyncio
import copy
from sys_scan_agent.graph import enhanced_enrich_findings, enhanced_suggest_rules


def test_enhanced_suggest_rules_monkeypatch(monkeypatch):
    # Provide minimal findings that would normally maybe not produce suggestions
    state = {"raw_findings": [
        {"id":"f1","title":"Suspicious process name","severity":"high","risk_score":70,"metadata":{},"tags":["process"]},
        {"id":"f2","title":"Another anomalous process","severity":"medium","risk_score":40,"metadata":{},"tags":["process"]}
    ]}

    # Monkeypatch miner to deterministically return one suggestion
    def fake_mine(paths, risk_threshold=10, min_support=2):
        return {"suggestions": [
            {"id":"rule1","title":"Process pattern","conditions":[{"field":"title","contains":"process"}],"rationale":"test rationale","tags":["candidate"]}
        ]}
    import sys_scan_agent.rule_gap_miner as miner
    orig = miner.mine_gap_candidates
    monkeypatch.setattr(miner, 'mine_gap_candidates', fake_mine)

    try:
        state = asyncio.run(enhanced_enrich_findings(state))
        state = asyncio.run(enhanced_suggest_rules(state))
    finally:
        # Restore (defensive)
        monkeypatch.setattr(miner, 'mine_gap_candidates', orig)

    suggestions = state.get('suggested_rules') or []
    assert suggestions, 'Expected at least one suggestion'
    # If refinement added 'refined' tag (depends on provider), allow either but metrics must exist
    metrics = state.get('metrics', {})
    assert 'rule_suggest_duration' in metrics
    assert metrics.get('rule_suggest_count') == len(suggestions)
