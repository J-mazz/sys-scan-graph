from __future__ import annotations
import json
from pathlib import Path
from sys_scan_agent.pipeline import load_report, augment, correlate, summarize
from sys_scan_agent.models import AgentState


def build_report():
    # Include findings with tags mapping to ATT&CK techniques plus correlation tags
    findings = [
        {'id':'f1','title':'SUID binary','severity':'high','risk_score':40,'metadata':{},'tags':['suid','baseline:new']},
        {'id':'f2','title':'Novel process observed','severity':'medium','risk_score':20,'metadata':{'cmdline':'/tmp/weird'},'tags':['process_novel']}
    ]
    report = {
        'meta': {'hostname':'hostAttack'},
        'summary': {'finding_count_total':2,'finding_count_emitted':2,'severity_counts':{'high':1,'medium':1}},
        'results': [
            {'scanner':'suid','finding_count':1,'findings':[findings[0]]},
            {'scanner':'process','finding_count':1,'findings':[findings[1]]}
        ],
        'collection_warnings': [],
        'scanner_errors': [],
        'summary_extension': {'total_risk_score':0}
    }
    return report


def test_attack_coverage(tmp_path):
    rpt = build_report()
    p = tmp_path / 'r.json'
    p.write_text(json.dumps(rpt))
    st = AgentState()
    st = load_report(st, p)
    st = augment(st)
    st = correlate(st)
    st = summarize(st)
    assert st.summaries and st.summaries.attack_coverage
    cov = st.summaries.attack_coverage
    print(f"DEBUG: attack_coverage = {cov}")
    print(f"DEBUG: findings tags = {[f.tags for r in st.report.results for f in r.findings] if st.report else 'no report'}")
    print(f"DEBUG: correlations tags = {[c.tags for c in st.correlations] if st.correlations else 'no correlations'}")
    assert cov['technique_count'] >= 1
    assert 'T1548' in cov['techniques']  # suid
