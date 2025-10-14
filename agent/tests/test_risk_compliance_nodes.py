from __future__ import annotations
import asyncio
import pytest

from sys_scan_agent.graph import risk_analyzer, compliance_checker


def test_risk_analyzer_basic():
    state = {"enriched_findings": [
        {"id": "f1", "title": "Critical kernel vuln", "severity": "critical", "risk_score": 90},
        {"id": "f2", "title": "High privilege issue", "severity": "high", "risk_score": 70},
        {"id": "f3", "title": "Info banner", "severity": "info", "risk_score": 1},
    ]}
    state = asyncio.run(risk_analyzer(state))
    ra = state.get('risk_assessment')
    assert ra is not None
    assert ra['counts']['critical'] == 1
    assert ra['overall_risk'] == 'critical'
    assert ra['finding_count'] == 3
    assert len(ra['top_findings']) <= 3
    metrics = state.get('metrics', {})
    assert 'risk_analyzer_duration' in metrics
    assert metrics.get('risk_analyzer_calls') == 1


def test_compliance_checker_mapping():
    state = {"enriched_findings": [
        {"id": "f1", "title": "Cardholder data exposure", "severity": "high", "metadata": {"compliance_standard": "PCI"}},
        {"id": "f2", "title": "Healthcare record misconfig", "severity": "medium", "tags": ["hipaa"]},
        {"id": "f3", "title": "Generic issue", "severity": "low"},
        {"id": "f4", "title": "Logging gap", "severity": "low", "tags": ["pci", "hipaa"]},
    ]}
    state = asyncio.run(compliance_checker(state))
    cc = state.get('compliance_check')
    assert cc is not None
    stds = cc['standards']
    # PCI DSS should have f1 and f4
    assert 'PCI DSS' in stds
    assert set(stds['PCI DSS']['finding_ids']) >= {"f1", "f4"}
    # HIPAA should have f2 and f4
    assert 'HIPAA' in stds
    assert set(stds['HIPAA']['finding_ids']) >= {"f2", "f4"}
    metrics = state.get('metrics', {})
    assert 'compliance_checker_duration' in metrics
    assert metrics.get('compliance_checker_calls') == 1
