import json, os, tempfile, shutil
from pathlib import Path
from sys_scan_agent.pipeline import run_pipeline

SAMPLE_REPORT_BASE = {
    "meta": {"hostname": "host1", "tool_version": "1.0", "json_schema_version": "v2"},
    "summary": {"finding_count_total": 0, "finding_count_emitted": 0, "severity_counts": {}},
    "results": [],
    "collection_warnings": [],
    "scanner_errors": [],
    "summary_extension": {"total_risk_score": 0}
}

def make_report(fcount_high=0, fcount_total=0):
    findings = []
    for i in range(fcount_total):
        sev = 'high' if i < fcount_high else 'low'
        findings.append({
            "id": f"f{i}",
            "title": "Synthetic",
            "severity": sev,
            "risk_score": 0,
            "metadata": {}
        })
    return {
        **SAMPLE_REPORT_BASE,
        "results": [
            {"scanner": "ioc", "finding_count": len(findings), "findings": findings}
        ],
        "summary": {"finding_count_total": len(findings), "finding_count_emitted": len(findings), "severity_counts": {"high": fcount_high, "low": max(0, fcount_total-fcount_high)}}
    }

def run_with_history(values, workdir):
    db_path = Path(workdir)/"baseline.db"
    os.environ['AGENT_BASELINE_DB'] = str(db_path)
    last = None
    for idx, (total, high) in enumerate(values):
        rpt = make_report(fcount_high=high, fcount_total=total)
        rpt_path = Path(workdir)/f"report_{idx}.json"
        with rpt_path.open('w') as f:
            json.dump(rpt, f)
        last = run_pipeline(rpt_path)
    return last

def test_metric_drift_trigger():
    tmp = tempfile.mkdtemp(prefix="metric_drift_")
    try:
        history = [(5,1),(6,1),(5,1),(6,1)]
        spike = (20,10)
        enriched = run_with_history(history + [spike], tmp)
        assert enriched is not None
        findings = list(enriched.enriched_findings or [])
        drift = [f for f in findings if 'metric_drift' in (f.tags or [])]
        assert drift, "Expected metric drift finding after spike"
        assert any('drift' in ' '.join(f.rationale or []) for f in drift)
    finally:
        os.environ.pop('AGENT_BASELINE_DB', None)
        shutil.rmtree(tmp, ignore_errors=True)
