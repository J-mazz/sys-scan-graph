from __future__ import annotations
import pytest
import asyncio
import json

from sys_scan_agent.graph import tool_coordinator, plan_baseline_queries, integrate_baseline_results

try:
    from langchain_core.messages import AIMessage, ToolMessage  # type: ignore
except Exception:  # pragma: no cover
    AIMessage = ToolMessage = None  # type: ignore


def test_tool_coordinator_populates_pending_calls():
    state = {
        'enriched_findings': [
            {'id': 'f1', 'title': 'High missing baseline', 'severity': 'high'},
            {'id': 'f2', 'title': 'Low with baseline', 'severity': 'low', 'baseline_status': 'known'}
        ]
    }
    out = asyncio.run(tool_coordinator(state))
    pending = out.get('pending_tool_calls')
    assert isinstance(pending, list)
    # Only one finding should need a baseline query
    assert len(pending) == 1
    assert pending[0]['args']['finding_id'] == 'f1'
    # Metrics recorded
    metrics = out.get('metrics', {})
    assert metrics.get('tool_coordinator_calls') == 1
    assert 'tool_coordinator_duration' in metrics


def test_plan_baseline_queries_uses_pending(monkeypatch):
    if AIMessage is None:
        pytest.skip('langchain_core not available')
    state = {
        'enriched_findings': [
            {'id': 'f1', 'title': 'A', 'severity': 'low'},
            {'id': 'f2', 'title': 'B', 'severity': 'low'},
        ],
        'pending_tool_calls': [
            {'id': 'call_f1', 'name': 'query_baseline', 'args': {'finding_id': 'f1', 'title': 'A', 'severity': 'low', 'scanner': 'mixed', 'host_id': 'graph_host'}},
        ]
    }
    out = plan_baseline_queries(state)
    msgs = out.get('messages') or []
    # Expect one AIMessage with tool_calls length 1
    assert any(getattr(m, 'tool_calls', None) for m in msgs), f"Messages: {msgs}"
    found = False
    for m in msgs:
        tc = getattr(m, 'tool_calls', None)
        if tc:
            assert len(tc) == 1
            found = True
    assert found
    metrics = out.get('metrics', {})
    assert metrics.get('baseline_plan_calls') == 1


def test_integrate_baseline_results_sets_flag(monkeypatch):
    # Simulate ToolMessage content integration if available
    if ToolMessage is None:
        # Function should still set baseline_cycle_done True
        state = {'messages': []}
        state = integrate_baseline_results(state)
        assert state.get('baseline_cycle_done') is True
        return

    tm = ToolMessage(content=json.dumps({'finding_id': 'f1', 'status': 'baseline_present'}), tool_call_id='x')  # type: ignore
    state = {'messages': [tm]}
    state = integrate_baseline_results(state)
    assert state.get('baseline_cycle_done') is True
    results = state.get('baseline_results', {})
    assert results.get('f1', {}).get('status') == 'baseline_present'
