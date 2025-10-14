from __future__ import annotations
import json, hashlib
from pathlib import Path
from sys_scan_agent.models import Finding
from sys_scan_agent.reduction import reduce_all

FIXTURE = {
    "findings": [
        {"id":"mod1","title":"Kernel module br_netfilter","severity":"info","risk_score":10,"metadata":{"module":"br_netfilter"}},
        {"id":"mod2","title":"Kernel module xt_MASQUERADE","severity":"info","risk_score":10,"metadata":{"module":"xt_MASQUERADE"}},
        {"id":"mod3","title":"Kernel module uncommonX","severity":"info","risk_score":10,"metadata":{"module":"uncommonX"}},
        {"id":"suid1","title":"SUID binary /usr/bin/pppd","severity":"medium","risk_score":50,"metadata":{"suid":"true","path":"/usr/bin/pppd"}},
        {"id":"net1","title":"TCP 53 listening","severity":"info","risk_score":10,"metadata":{"state":"LISTEN","port":"53"}},
        {"id":"net2","title":"TCP 22 listening","severity":"info","risk_score":10,"metadata":{"state":"LISTEN","port":"22"}},
    ]
}

GOLDEN_PATH = Path(__file__).parent / "golden_reductions.json"


def test_reduction_snapshot():
    findings = [Finding(id=o['id'], title=o['title'], severity=o['severity'], risk_score=o['risk_score'], metadata=o['metadata']) for o in FIXTURE['findings']]
    reductions = reduce_all(findings)
    data = json.loads(reductions.model_dump_json())
    if not GOLDEN_PATH.exists():
        # First run create golden (intentionally) - in real CI you'd fail instead
        GOLDEN_PATH.write_text(json.dumps(data, indent=2, sort_keys=True))
    golden = json.loads(GOLDEN_PATH.read_text())
    assert data == golden, "Reduction output drifted from golden snapshot"


def test_token_size_upper_bound():
    findings = [Finding(id=o['id'], title=o['title'], severity=o['severity'], risk_score=o['risk_score'], metadata=o['metadata']) for o in FIXTURE['findings']]
    reductions = reduce_all(findings)
    serialized = reductions.model_dump_json()
    # Approx token estimate: 1 token ~4 chars (rough heuristic for stability guard)
    approx_tokens = len(serialized) / 4
    assert approx_tokens < 400, f"Reductions payload too large (approx {approx_tokens} tokens)"
