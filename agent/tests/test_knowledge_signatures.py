from __future__ import annotations
import os, tempfile, textwrap, subprocess, json, shutil
from pathlib import Path
import pytest
from sys_scan_agent import knowledge as K
from sys_scan_agent.models import AgentState, Report, Meta, ScannerResult, Summary, SummaryExtension


def _write_yaml(dirp: Path, name: str, content: str):
    (dirp / name).write_text(content)

@pytest.mark.skipif(not shutil.which('minisign'), reason='minisign not installed')
def test_signature_verification(tmp_path, monkeypatch):
    import shutil
    # Create temp knowledge dir
    kd = tmp_path / 'knowledge'
    kd.mkdir()
    _write_yaml(kd, 'ports.yaml', 'ports: {"22": {"service": "ssh", "tags": ["remote"]}}')
    # Generate minisign key pair
    subprocess.run(['minisign', '-G', '-p', str(tmp_path/'pub.key'), '-s', str(tmp_path/'sec.key')], check=True)
    # Sign file
    subprocess.run(['minisign', '-S', '-s', str(tmp_path/'sec.key'), '-m', str(kd/'ports.yaml')], check=True)
    pub = (tmp_path/'pub.key').read_text()
    monkeypatch.setenv('AGENT_KB_PUBKEY', pub)
    monkeypatch.setenv('AGENT_KB_REQUIRE_SIGNATURES','1')
    # Point module to temp dir
    monkeypatch.setattr(K, 'KNOWLEDGE_DIR', kd)
    state = AgentState(agent_warnings=[], report=Report(
        meta=Meta(),
        summary=Summary(finding_count_total=0, finding_count_emitted=0),
        results=[ScannerResult(scanner='network', finding_count=0, findings=[])],
        collection_warnings=[], scanner_errors=[],
        summary_extension=SummaryExtension(total_risk_score=0, emitted_risk_score=0)
    ))
    K.apply_external_knowledge(state)
    # Ensure no signature warnings
    assert not any(w for w in state.agent_warnings if w.get('stage')=='signature')
