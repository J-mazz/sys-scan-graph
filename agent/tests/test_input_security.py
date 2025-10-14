from __future__ import annotations
import json, os
from pathlib import Path
import pytest
from sys_scan_agent.pipeline import load_report, AgentState


def write_temp(tmp_path: Path, obj, newline_variant: str = "\n") -> Path:
    text = json.dumps(obj)
    if newline_variant == "crlf":
        text = text.replace("\n", "\r\n")
    elif newline_variant == "cr":
        text = text.replace("\n", "\r")
    p = tmp_path / "report.json"
    p.write_text(text)
    return p


def test_load_report_size_limit(tmp_path, monkeypatch):
    obj = {"meta": {"hostname": "h"}, "summary": {}, "results": [], "summary_extension": {"total_risk_score": 0}}
    p = write_temp(tmp_path, obj)
    # Create an over-sized file by repeating content
    big = tmp_path / "big.json"
    big.write_text("{" + "\n".join(["\"k%d\":%d" % (i, i) for i in range(400000)]) + "}")
    monkeypatch.setenv('AGENT_MAX_REPORT_MB', '1')
    # small file loads
    state = AgentState()
    load_report(state, p)
    # big file rejected
    with pytest.raises(ValueError):
        load_report(AgentState(), big)


def test_load_report_newline_canonicalization(tmp_path):
    obj = {"meta": {"hostname": "h"}, "summary": {}, "results": [], "summary_extension": {"total_risk_score": 0}}
    for variant in ["crlf", "cr"]:
        p = write_temp(tmp_path, obj, newline_variant=variant)
    st = AgentState()
    load_report(st, p)
    assert st.report is not None
    assert st.report.meta.hostname == 'h'


def test_load_report_invalid_utf8(tmp_path):
    p = tmp_path / "bad.json"
    # Invalid continuation byte sequence
    bad_bytes = b'{"a":"' + bytes([0xf0, 0x28, 0x8c, 0x28]) + b'"}'
    p.write_bytes(bad_bytes)
    with pytest.raises(ValueError):
        load_report(AgentState(), p)
