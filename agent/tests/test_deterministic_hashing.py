from __future__ import annotations
import os
from sys_scan_agent.data_governance import _hash, _get_salt

def test_hash_determinism_env_salt(monkeypatch):
    monkeypatch.setenv('AGENT_HASH_SALT','cafebabe1234')
    h1 = _hash('secret-token-123')
    h2 = _hash('secret-token-123')
    assert h1 == h2
    # Different value different hash
    h3 = _hash('secret-token-124')
    assert h1 != h3


def test_hash_host_derivation(monkeypatch):
    # Clear env forcing host-derived salt (simulate by unsetting variable)
    if 'AGENT_HASH_SALT' in os.environ:
        monkeypatch.delenv('AGENT_HASH_SALT', raising=False)
    # Reset module global
    from sys_scan_agent import data_governance as dg
    dg._GLOBAL_SALT = None
    h1 = dg._hash('abc')
    dg._GLOBAL_SALT = None
    h2 = dg._hash('abc')
    # Host based should match across resets within same host
    assert h1 == h2
