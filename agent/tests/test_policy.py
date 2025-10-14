from __future__ import annotations
import json
from pathlib import Path
from sys_scan_agent.pipeline import run_pipeline


def test_policy_escalation(tmp_path):
    report = {
        "meta": {"hostname": "h"},
        "summary": {"finding_count_total": 1, "finding_count_emitted": 1},
        "results": [
            {"scanner": "ioc", "finding_count": 1, "findings": [
                {"id": "f1", "title": "Denied exec", "severity": "low", "risk_score": 10, "metadata": {"exe": "/tmp/bad.sh"}}
            ]}
        ],
        "collection_warnings": [],
        "scanner_errors": [],
        "summary_extension": {"total_risk_score": 10}
    }
    rp = tmp_path / 'r.json'
    rp.write_text(json.dumps(report))
    import os
    old_baseline = os.environ.get('AGENT_BASELINE_DB')
    os.environ['AGENT_BASELINE_DB'] = str(tmp_path / 'baseline.db')
    try:
        enriched = run_pipeline(rp)
        assert enriched.enriched_findings is not None
        f = enriched.enriched_findings[0]
        assert f.severity.lower() == 'high'
        assert 'policy:denied_path' in f.tags
        assert f.rationale and any('policy escalation' in r for r in f.rationale)
    finally:
        if old_baseline is not None:
            os.environ['AGENT_BASELINE_DB'] = old_baseline
        else:
            os.environ.pop('AGENT_BASELINE_DB', None)


def test_policy_allowlist(tmp_path, monkeypatch):
    monkeypatch.setenv('AGENT_APPROVED_DIRS', '/bin:/usr/bin')
    monkeypatch.setenv('AGENT_POLICY_ALLOWLIST', '/tmp/ok.sh')
    report = {
        "meta": {"hostname": "h"},
        "summary": {"finding_count_total": 1, "finding_count_emitted": 1},
        "results": [
            {"scanner": "ioc", "finding_count": 1, "findings": [
                {"id": "f1", "title": "Whitelisted exec", "severity": "low", "risk_score": 10, "metadata": {"exe": "/tmp/ok.sh"}}
            ]}
        ],
        "collection_warnings": [],
        "scanner_errors": [],
        "summary_extension": {"total_risk_score": 10}
    }
    rp = tmp_path / 'r.json'
    rp.write_text(json.dumps(report))
    import os
    old_baseline = os.environ.get('AGENT_BASELINE_DB')
    os.environ['AGENT_BASELINE_DB'] = str(tmp_path / 'baseline.db')
    try:
        enriched = run_pipeline(rp)
        assert enriched.enriched_findings is not None
        f = enriched.enriched_findings[0]
        assert f.severity.lower() == 'low'
        assert not any(t == 'policy:denied_path' for t in f.tags)
    finally:
        if old_baseline is not None:
            os.environ['AGENT_BASELINE_DB'] = old_baseline
        else:
            os.environ.pop('AGENT_BASELINE_DB', None)
