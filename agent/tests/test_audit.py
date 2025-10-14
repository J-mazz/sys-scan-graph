from __future__ import annotations
from pathlib import Path
import json
from sys_scan_agent.pipeline import run_pipeline
from sys_scan_agent.audit import tail_since

def test_audit_append_and_tail(tmp_path, monkeypatch):
    # Redirect audit log
    monkeypatch.setenv('AGENT_AUDIT_LOG', str(tmp_path / 'audit.log'))
    report = {
        "meta": {"hostname": "h"},
        "summary": {"finding_count_total": 0, "finding_count_emitted": 0},
        "results": [],
        "collection_warnings": [],
        "scanner_errors": [],
        "summary_extension": {"total_risk_score": 0}
    }
    rp = tmp_path / 'raw.json'
    rp.write_text(json.dumps(report))
    run_pipeline(rp)
    recs = tail_since('1h')
    stages = {r.get('stage') for r in recs}
    assert {'load_report','augment','correlate','baseline_rarity','reduce','actions','summarize'} <= stages
