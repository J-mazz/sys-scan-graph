from __future__ import annotations
import json
from pathlib import Path
from agent.models import AgentState
from agent.pipeline import load_report, augment, correlate, baseline_rarity, process_novelty, sequence_correlation, reduce, summarize
from agent.counterfactual import what_if


def build_report():
    findings = []
    # ip_forward enabled
    findings.append({'id':'ipf','title':'Enable IP forwarding','severity':'medium','risk_score':30,'metadata':{'sysctl_key':'net.ipv4.ip_forward','value':'1'},'tags':['kernel_param']})
    # Odd binary path (novelty expected)
    findings.append({'id':'proc1','title':'/tmp/.weird_hidden_binary_xyz','severity':'medium','risk_score':20,'metadata':{'cmdline':'/tmp/.weird_hidden_binary_xyz'},'tags':[]})
    report = {
        'meta': {'hostname':'hostCF'},
        'summary': {'finding_count_total':2,'finding_count_emitted':2,'severity_counts':{'medium':2}},
        'results': [
            {'scanner':'kernel_params','finding_count':1,'findings':[findings[0]]},
            {'scanner':'process','finding_count':1,'findings':[findings[1]]}
        ],
        'collection_warnings': [],
        'scanner_errors': [],
        'summary_extension': {'total_risk_score':0}
    }
    return report


def test_counterfactual_and_novelty(tmp_path):
    rpt = build_report()
    p = tmp_path/'r.json'
    p.write_text(json.dumps(rpt))
    st = AgentState()
    st = load_report(st, p)
    st = augment(st)
    st = correlate(st)
    st = baseline_rarity(st, baseline_path=tmp_path/'db.sqlite')
    st = process_novelty(st, baseline_path=tmp_path/'db.sqlite')
    # Ensure novelty detection fires
    assert st.report and st.report.results
    novel = [f for r in st.report.results for f in r.findings if 'process_novel' in f.tags]
    assert novel, 'Novelty detection did not fire for odd binary path'
    st = sequence_correlation(st)
    st = reduce(st)
    st.actions = []
    st = summarize(st)
    # Serialize enriched output for counterfactual
    assert st.report and st.report.results
    enriched = {
        'correlations': [c.model_dump() for c in st.correlations],
        'reductions': st.reductions.model_dump(),
        'summaries': st.summaries.model_dump() if st.summaries else {},
        'actions': [a.model_dump() for a in st.actions],
        'enriched_findings': [f.model_dump() for r in st.report.results for f in r.findings]
    }
    enriched_path = tmp_path / 'enriched.json'
    enriched_path.write_text(json.dumps(enriched))
    cf = what_if(enriched_path, ip_forward_disabled=True)
    assert cf['scenario']['ip_forward_disabled'] is True
    assert any(d['delta'] <= 0 for d in cf['changed_findings'])
    # ATT&CK coverage should be present (even if subset)
    if cf['technique_coverage']:
        assert 'technique_count' in cf['technique_coverage']
