from __future__ import annotations
import json
from pathlib import Path
from sys_scan_agent.pipeline import load_report, augment, correlate, sequence_correlation, summarize
from sys_scan_agent.models import AgentState


def build_report():
    findings = []
    findings.append({'id':'suid1','title':'New SUID binary','severity':'high','risk_score':50,'metadata':{'path':'/usr/bin/new_suid'},'tags':['suid','baseline:new']})
    findings.append({'id':'ipfwd','title':'Enable IP forwarding','severity':'medium','risk_score':20,'metadata':{'sysctl_key':'net.ipv4.ip_forward','value':'1'},'tags':['kernel_param']})
    report = {
        'meta': {'hostname':'hostC'},
        'summary': {'finding_count_total':2,'finding_count_emitted':2,'severity_counts':{'high':1,'medium':1}},
        'results': [
            {'scanner':'suid','finding_count':1,'findings':[findings[0]]},
            {'scanner':'kernel_params','finding_count':1,'findings':[findings[1]]}
        ],
        'collection_warnings': [],
        'scanner_errors': [],
        'summary_extension': {'total_risk_score':0}
    }
    return report


def test_causal_hypotheses(tmp_path):
    rpt = build_report()
    p = tmp_path / 'r.json'
    p.write_text(json.dumps(rpt))
    st = AgentState()
    st = load_report(st, p)
    st = augment(st)
    st = correlate(st)
    st = sequence_correlation(st)
    st = summarize(st)
    assert st.summaries and st.summaries.causal_hypotheses
    hyp = st.summaries.causal_hypotheses[0]
    assert hyp['speculative'] is True
    assert hyp['confidence'] == 'low'
