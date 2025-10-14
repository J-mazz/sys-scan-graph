from __future__ import annotations
import textwrap, os, shutil
from pathlib import Path
from sys_scan_agent import knowledge as K
from sys_scan_agent.models import AgentState, Report, Meta, Summary, SummaryExtension, ScannerResult, Finding

def _state():
    # Provide one network finding so ports.yaml is actually loaded
    dummy_finding = Finding(id='f1', title='Port 22 open', severity='info', risk_score=1, metadata={'port':'22'})
    return AgentState(agent_warnings=[], report=Report(meta=Meta(), summary=Summary(finding_count_total=1, finding_count_emitted=1), results=[ScannerResult(scanner='network', finding_count=1, findings=[dummy_finding])], collection_warnings=[], scanner_errors=[], summary_extension=SummaryExtension(total_risk_score=1, emitted_risk_score=1)))


def test_yaml_corruption_warning(tmp_path, monkeypatch):
    # Prepare temp knowledge dir with corrupted YAML
    kd = tmp_path / 'knowledge'
    kd.mkdir()
    # Intentionally malformed YAML (will parse to scalar / unexpected structure)
    (kd / 'ports.yaml').write_text('ports: [ this: is: invalid')
    monkeypatch.setattr(K, 'KNOWLEDGE_DIR', kd)
    # Clear knowledge caches
    K._CACHE.clear(); K._HASHES.clear();
    st = _state()
    K.apply_external_knowledge(st)
    # Corruption => no enrichment fields (service_name) added
    assert st.report and st.report.results
    f = st.report.results[0].findings[0]
    assert 'service_name' not in f.metadata


def test_yaml_missing_signature_required(tmp_path, monkeypatch):
    kd = tmp_path / 'knowledge'
    kd.mkdir()
    (kd / 'ports.yaml').write_text('ports: {"22": {"service": "ssh"}}')
    # Create a dummy pubkey file
    pubkey_file = tmp_path / 'dummy_pubkey'
    pubkey_file.write_text('dummy_pubkey_contents')
    monkeypatch.setattr(K, 'KNOWLEDGE_DIR', kd)
    monkeypatch.setenv('AGENT_KB_REQUIRE_SIGNATURES','1')
    monkeypatch.setenv('AGENT_KB_PUBKEY', str(pubkey_file))
    K._CACHE.clear(); K._HASHES.clear();
    st = _state()
    K.apply_external_knowledge(st)
    assert any(w for w in st.agent_warnings if w.get('error_type')=='SignatureMissing')
