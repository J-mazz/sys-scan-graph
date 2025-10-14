from __future__ import annotations
import json, tempfile, textwrap, pathlib
from sys_scan_agent.pipeline import run_pipeline

def make_report(compliance_summary=None, compliance_gaps=None):
    base = {
        "meta": {"hostname": "host1"},
        "summary": {"finding_count_total": 0, "finding_count_emitted": 0, "severity_counts": {}},
    "summary_extension": {"total_risk_score": 0, "emitted_risk_score": 0},
        "results": [],
        "collection_warnings": [],
        "scanner_errors": []
    }
    if compliance_summary:
        base["compliance_summary"] = compliance_summary
    if compliance_gaps:
        base["compliance_gaps"] = compliance_gaps
    return base


def test_compliance_metrics_extracted_basic(tmp_path):
    report = make_report(
        compliance_summary={
            "pci_dss_4_0": {"passed": 10, "failed": 2, "score": 83.3, "total_controls": 12, "not_applicable": 0},
            "hipaa_security_rule": {"passed": 5, "failed": 5, "score": 50.0, "total_controls": 10}
        },
        compliance_gaps=[{"standard": "pci_dss_4_0", "control_id": "2.2.4", "remediation_hint": "Baseline & harden services"}]
    )
    p = tmp_path/"report.json"
    p.write_text(json.dumps(report))
    enriched = run_pipeline(p)
    metrics = enriched.summaries.metrics
    assert metrics is not None
    assert 'compliance_summary' in metrics
    assert metrics['compliance_summary']['pci_dss_4_0']['failed'] == 2
    assert metrics['compliance_summary']['hipaa_security_rule']['score'] == 50.0
    assert metrics['compliance_gap_count'] == 1
    assert metrics['compliance_gaps'][0]['control_id'] == '2.2.4'


def test_compliance_absent_safe(tmp_path):
    p = tmp_path/"report.json"
    p.write_text(json.dumps(make_report()))
    enriched = run_pipeline(p)
    metrics = enriched.summaries.metrics
    # Should not create compliance keys when absent
    assert metrics is None or 'compliance_summary' not in metrics

