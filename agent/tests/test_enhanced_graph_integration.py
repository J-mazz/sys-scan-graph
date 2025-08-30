import os, asyncio

def test_enhanced_workflow_end_to_end(monkeypatch):
    # Force enhanced mode
    monkeypatch.setenv('AGENT_GRAPH_MODE', 'enhanced')
    from agent.graph import build_workflow
    wf, app = build_workflow(enhanced=True)
    assert app is not None, 'Compiled app should not be None in enhanced mode'
    initial_state = {
        'raw_findings': [
            {'id': 'f1', 'title': 'Test Finding', 'severity': 'low', 'description': 'desc', 'risk_score': 1}
        ]
    }
    # Invoke asynchronously because first node may be async
    result = asyncio.run(app.ainvoke(initial_state))
    # Validate analytics & operational tail effects
    assert 'risk_assessment' in result and isinstance(result['risk_assessment'], dict)
    assert 'compliance_check' in result and isinstance(result['compliance_check'], dict)
    # metrics_collector should set final_metrics
    assert 'final_metrics' in result and isinstance(result['final_metrics'], dict)
    # Ensure metrics show at least enrich or metrics_collector duration keys
    metrics = result.get('metrics', {})
    assert any(k.endswith('_duration') for k in metrics.keys()) or 'metrics_collector_duration' in metrics
