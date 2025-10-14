from __future__ import annotations
import json, hashlib
from pathlib import Path
from sys_scan_agent.models import Finding
from sys_scan_agent.reduction import reduce_all

# Load the malicious compromised dev host raw fixture (pre-enrichment) and build a snapshot of reductions
FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "malicious" / "compromised_dev_host.json"
GOLDEN_PATH = Path(__file__).parent / "golden_compromised_dev_host_reductions.json"


def _load_findings():
    raw = json.loads(FIXTURE_PATH.read_text())
    findings = []
    for block in raw.get("results", []):
        for f in block.get("findings", []):
            findings.append(
                Finding(
                    id=f["id"],
                    title=f["title"],
                    severity=f.get("severity", "info"),
                    risk_score=int(f.get("risk_score", 0)),
                    metadata=f.get("metadata", {}),
                )
            )
    return findings


def test_compromised_dev_host_reduction_snapshot():
    findings = _load_findings()
    reductions = reduce_all(findings)
    data = json.loads(reductions.model_dump_json())
    if not GOLDEN_PATH.exists():
        GOLDEN_PATH.write_text(json.dumps(data, indent=2, sort_keys=True))
    golden = json.loads(GOLDEN_PATH.read_text())
    # Backward compatibility: some versions may not have top_risks alias; normalize before compare
    if 'top_risks' not in golden and 'top_risks' in data:
        golden['top_risks'] = golden.get('top_findings')
    assert data == golden, "Compromised dev host reduction output drifted from golden snapshot"


def test_compromised_dev_host_token_size_upper_bound():
    findings = _load_findings()
    reductions = reduce_all(findings)
    serialized = reductions.model_dump_json()
    approx_tokens = len(serialized) / 4
    assert approx_tokens < 400, f"Reductions payload too large (approx {approx_tokens} tokens)"
