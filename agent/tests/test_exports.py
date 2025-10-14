from __future__ import annotations

# Star import to validate __all__ content (flake8 ignore in project root if any)
from sys_scan_agent.graph import *  # type: ignore  # noqa: F401,F403

expected_symbols = [
    'enrich_findings', 'enhanced_enrich_findings', 'enhanced_summarize_host_state',
    'enhanced_suggest_rules', 'correlate_findings',
    'advanced_router', 'should_suggest_rules', 'choose_post_summarize',
    'tool_coordinator', 'plan_baseline_queries', 'integrate_baseline_results',
    'risk_analyzer', 'compliance_checker', 'metrics_collector'
]

def test_exports_presence():
    missing = [s for s in expected_symbols if s not in globals()]
    assert not missing, f"Missing expected exported symbols: {missing}"
