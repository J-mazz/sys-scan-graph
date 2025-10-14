from __future__ import annotations
from pathlib import Path
from sys_scan_agent.pipeline import run_pipeline
import json

def test_home_dir_redaction(tmp_path):
    # Craft minimal report with a finding containing a home path in title
    report = {
        "meta": {"hostname": "host1"},
        "summary": {"finding_count_total": 1, "finding_count_emitted": 1},
        "results": [
            {"scanner": "ioc", "finding_count": 1, "findings": [
                {"id": "f1", "title": "Suspicious binary in /home/alice/.cache/tool", "severity": "high", "risk_score": 80, "metadata": {"path": "/home/alice/.cache/tool"}}
            ]}
        ],
        "collection_warnings": [],
        "scanner_errors": [],
        "summary_extension": {"total_risk_score": 80, "emitted_risk_score": 80}
    }
    rp = tmp_path / 'report.json'
    rp.write_text(json.dumps(report))
    enriched = run_pipeline(rp)
    # Check reductions top findings redaction
    titles = [t['title'] for t in (enriched.reductions.get('top_risks') or [])]
    assert any('/home/<user>/.cache/tool' in t for t in titles), titles
    # Ensure original raw finding still retains full path (raw data untouched) for internal reference
    raw_titles = [f.title for f in enriched.enriched_findings or []]
    assert any('/home/alice/.cache/tool' in t for t in raw_titles)
