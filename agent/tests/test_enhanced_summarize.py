from __future__ import annotations
import asyncio
from sys_scan_agent.graph import enhanced_enrich_findings, enhanced_summarize_host_state

def test_enhanced_summarize_basic():
    state = {"raw_findings": [
        {"id":"f1","title":"Port 22 open","severity":"medium","risk_score":30,"metadata":{"port":"22"}},
        {"id":"f2","title":"New SUID bin","severity":"high","risk_score":60,"metadata":{"path":"/usr/bin/suid"},"tags":["suid","baseline:new"]}
    ]}
    state = asyncio.run(enhanced_enrich_findings(state))
    # Ensure enrichment happened
    assert state.get('enriched_findings')
    # Invoke summarization
    state = asyncio.run(enhanced_summarize_host_state(state))
    assert 'summary' in state
    assert state['summary'].get('metrics') is not None
    # Metrics propagated to state metrics
    m = state.get('metrics', {})
    assert 'summarize_duration' in m
    assert 'summarize_calls' in m and m['summarize_calls'] == 1


def test_enhanced_summarize_streaming_flag():
    state = {"raw_findings": [
        {"id":"f1","title":"Listening port 80","severity":"low","risk_score":5,"metadata":{"port":"80"}}
    ], "streaming_enabled": True}
    state = asyncio.run(enhanced_enrich_findings(state))
    state = asyncio.run(enhanced_summarize_host_state(state))
    assert 'summary' in state
    assert state.get('metrics', {}).get('summarize_calls') == 1
