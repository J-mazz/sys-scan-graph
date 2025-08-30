from __future__ import annotations
from agent.graph_nodes_scaffold import advanced_router


def test_router_human_feedback():
    state = {"human_feedback_pending": True}
    assert advanced_router(state) == 'human_feedback'


def test_router_compliance():
    state = {"enriched_findings": [{"id":"a","severity":"low","tags":["compliance"],"metadata":{}}]}
    assert advanced_router(state) == 'compliance'


def test_router_high_sev_missing_baseline():
    state = {"enriched_findings": [
        {"id":"h1","severity":"high","metadata":{}},
        {"id":"m1","severity":"medium","metadata":{}}
    ], "baseline_results": {}}
    assert advanced_router(state) == 'baseline'


def test_router_external_requirement():
    state = {"enriched_findings": [
        {"id":"x","severity":"low","metadata":{"requires_external": True}}
    ], "baseline_results": {"dummy":"val"}}
    assert advanced_router(state) == 'risk_analysis'


def test_router_default_summarize():
    state = {"enriched_findings": [
        {"id":"x","severity":"low","metadata":{}}
    ], "baseline_results": {"x": {}}}
    assert advanced_router(state) == 'summarize'


def test_router_error_path(monkeypatch):
    # Force an exception inside router by monkeypatching list access
    state = {"enriched_findings": [{"id":"x","severity":"low","metadata":{}}]}
    import agent.graph_nodes_scaffold as scaffold
    orig = scaffold.advanced_router.__code__
    # Monkeypatch not straightforward; instead provoke exception by deleting list after pass
    # We'll monkeypatch state.get to raise
    class BadDict(dict):
        def get(self, *a, **k):
            raise RuntimeError('boom')
    bad_state = BadDict(state)
    assert advanced_router(bad_state) == 'error'
