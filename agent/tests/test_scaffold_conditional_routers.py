from __future__ import annotations
from sys_scan_agent.graph import should_suggest_rules, choose_post_summarize


def _end_symbol():
    try:
        from langgraph.graph import END  # type: ignore
        return END  # type: ignore
    except Exception:
        return '__end__'


def test_should_suggest_rules_high():
    state = {"enriched_findings": [
        {"id":"a","severity":"high"},
        {"id":"b","severity":"low"}
    ]}
    assert should_suggest_rules(state) == 'suggest_rules'


def test_should_suggest_rules_no_high():
    state = {"enriched_findings": [
        {"id":"a","severity":"medium"},
        {"id":"b","severity":"low"}
    ]}
    assert should_suggest_rules(state) == _end_symbol()


def test_choose_post_summarize_plan_baseline():
    state = {"baseline_cycle_done": False, "enriched_findings": [
        {"id":"x","severity":"high"},
        {"id":"y","severity":"low"}
    ]}
    # Missing baseline_status triggers plan_baseline
    assert choose_post_summarize(state) == 'plan_baseline'


def test_choose_post_summarize_delegate():
    state = {"baseline_cycle_done": True, "enriched_findings": [
        {"id":"x","severity":"high","baseline_status":"new"}
    ]}
    assert choose_post_summarize(state) == 'suggest_rules'


def test_choose_post_summarize_delegate_no_high():
    state = {"baseline_cycle_done": True, "enriched_findings": [
        {"id":"x","severity":"medium","baseline_status":"existing"}
    ]}
    assert choose_post_summarize(state) == _end_symbol()
