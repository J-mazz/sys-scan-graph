from __future__ import annotations
from pathlib import Path
from sys_scan_agent.integrity import generate_keypair, sign_file, verify_file
from sys_scan_agent.pipeline import run_pipeline
import json

def test_sign_and_verify(tmp_path):
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
    sk, vk = generate_keypair()
    digest, sig_b64 = sign_file(rp, sk)
    status = verify_file(rp, vk)
    assert status['digest_match'] is True
    assert status['signature_valid'] is True
    # Pipeline includes integrity sha automatically - use temp baseline DB
    import os
    old_baseline = os.environ.get('AGENT_BASELINE_DB')
    os.environ['AGENT_BASELINE_DB'] = str(tmp_path / 'baseline.db')
    try:
        enriched = run_pipeline(rp)
        assert enriched.integrity is not None
        assert enriched.integrity.get('sha256_actual') == digest
    finally:
        if old_baseline is not None:
            os.environ['AGENT_BASELINE_DB'] = old_baseline
        else:
            os.environ.pop('AGENT_BASELINE_DB', None)
