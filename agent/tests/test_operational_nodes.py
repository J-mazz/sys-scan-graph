from __future__ import annotations
import asyncio
import pytest

from agent.graph_nodes_scaffold import (
    error_handler,
    human_feedback_node,
    cache_manager,
    metrics_collector,
    risk_analyzer,
    compliance_checker,
)


def test_error_handler_degraded_and_fallback():
    state = {
        'errors': [
            {'error': 'Timeout connecting to provider'},
            {'error': 'Model unavailable timeout'},
            {'error': 'Request timeout occurred'},
            {'error': 'Provider rate limit'},
        ]
    }
    asyncio.run(error_handler(state))
    assert state.get('degraded_mode') is True
    assert state.get('llm_provider_mode') == 'fallback'
    metrics = state.get('metrics', {})
    assert metrics.get('timeout_error_count') >= 3
    assert 'error_handler_duration' in metrics


def test_human_feedback_node_clears_flag():
    state = {'human_feedback_pending': True}
    asyncio.run(human_feedback_node(state))
    assert state.get('human_feedback_pending') is False
    assert state.get('human_feedback_processed') is True
    assert 'human_feedback' in state


def test_cache_manager_and_metrics_collector():
    # Build a state with enriched findings, summary, risk/compliance
    state = {
        'enriched_findings': [
            {'id': 'f1', 'title': 'Item', 'severity': 'low', 'risk_score': 5},
            {'id': 'f2', 'title': 'Item2', 'severity': 'high', 'risk_score': 55},
        ],
        'summary': {'executive_summary': 'Example', 'details': {}},
    }
    # Add risk/compliance via their nodes
    asyncio.run(risk_analyzer(state))
    asyncio.run(compliance_checker(state))
    # Run cache manager
    asyncio.run(cache_manager(state))
    cache = state.get('cache') or {}
    assert any(k.startswith('enrich:') for k in cache.keys())
    assert 'risk:latest' in cache
    assert 'compliance:latest' in cache
    # Add metric baseline before metrics_collector
    asyncio.run(metrics_collector(state))
    final = state.get('final_metrics')
    assert final is not None
    assert 'overall_risk' in final
    assert 'cache_entries' in final and final['cache_entries'] >= 3
    assert 'metrics_collector_duration' in state.get('metrics', {})
