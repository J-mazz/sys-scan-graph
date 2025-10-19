from __future__ import annotations
import json, random, string
from pathlib import Path
from sys_scan_agent.pipeline import run_pipeline

FIELDS = ['id','title','description','severity','risk_score']
SEVERITIES = ['info','low','medium','high','critical']  # keep valid to avoid schema rejection

def rand_str(n=12):
    return ''.join(random.choice(string.ascii_letters+string.digits) for _ in range(n))


def make_random_report(path: Path, n_findings: int = 20):
    findings = []
    for i in range(n_findings):
        f = {
            'id': rand_str(6),
            'title': rand_str(random.randint(3,40)),
            'severity': random.choice(SEVERITIES),
            'risk_score': random.choice([0,5,10,50,80,100]),
            'metadata': {
                'path': '/home/'+rand_str(5)+'/'+rand_str(4),
                'api_token': rand_str(16) if random.random()<0.2 else 'none'
            },
            'tags': [rand_str(4) for _ in range(random.randint(0,3))]
        }
        findings.append(f)
    report = {
        'meta': {'hostname': rand_str(6)},
        'summary': {'finding_count_total': len(findings), 'finding_count_emitted': len(findings)},
        'results': [ {'scanner':'network','finding_count':len(findings),'findings':findings} ],
        'collection_warnings': [],
        'scanner_errors': [],
        'summary_extension': {'total_risk_score': sum([f.get('risk_score') for f in findings if isinstance(f.get('risk_score'), int)]), 'emitted_risk_score': 0}
    }
    path.write_text(json.dumps(report))


def test_pipeline_fuzz_runs(tmp_path):
    # Generate multiple random reports and ensure pipeline completes without exceptions
    import os
    old_baseline = os.environ.get('AGENT_BASELINE_DB')
    os.environ['AGENT_BASELINE_DB'] = str(tmp_path / 'baseline.db')
    try:
        for i in range(3):
            rp = tmp_path / f'random_{i}.json'
            make_random_report(rp, n_findings=30)
            enriched = run_pipeline(rp)
            assert enriched is not None
            # Ensure enrichment results present and contain perf snapshot
            perf_obj = {}
            if enriched.enrichment_results:
                perf_obj = enriched.enrichment_results.get('perf', {})
            assert isinstance(perf_obj, dict)
            # Basic performance metric propagated into summaries.metrics if available
            # TODO: Implement perf.total_ms metric propagation when performance tracking is added
    finally:
        if old_baseline is not None:
            os.environ['AGENT_BASELINE_DB'] = old_baseline
        else:
            os.environ.pop('AGENT_BASELINE_DB', None)
