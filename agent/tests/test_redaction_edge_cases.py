from __future__ import annotations
import os, random, string
from sys_scan_agent.data_governance import get_data_governor
from sys_scan_agent.models import Finding

# Helper to build random metadata containing secrets and paths

def rand_str(n=12):
    return ''.join(random.choice(string.ascii_letters+string.digits) for _ in range(n))

def test_secret_key_drop(monkeypatch):
    monkeypatch.setenv('AGENT_HASH_SALT','deadbeefcafebabe')
    gov = get_data_governor()
    f = Finding(id='f1', title='User password exposure', severity='high', risk_score=10, risk_total=10,
                description='Contains password secret token', metadata={'api_token':'ABC123SECRET','nested':{'password':'supersecret'}}, tags=['test'], rationale=['r'], host_role_rationale=None)
    red = gov.redact_for_llm(f)
    # Redactor may return model or dict; normalize
    if hasattr(red,'metadata'):
        md = red.metadata
    else:
        md = red.get('metadata')
    assert md['api_token'] == '[REDACTED]'
    assert md['nested']['password'] == '[REDACTED]'


def test_long_string_hash(monkeypatch):
    monkeypatch.setenv('AGENT_HASH_SALT','abcd')
    gov = get_data_governor()
    longval = 'A'*200
    f = Finding(id='f2', title='Long value test', severity='low', risk_score=1, risk_total=1,
                description=longval, metadata={'payload':longval}, tags=[], rationale=['r'], host_role_rationale=None)
    red = gov.redact_for_llm(f)
    if hasattr(red,'description'):
        desc = red.description
        md = red.metadata
    else:
        desc = red.get('description')
        md = red.get('metadata')
    assert desc.startswith('h:') and len(desc) > 2
    assert md['payload'].startswith('h:')


def test_title_mask_buckets(monkeypatch):
    monkeypatch.setenv('AGENT_HASH_SALT','abcd')
    gov = get_data_governor()
    f_short = Finding(id='s', title='abcd', severity='low', risk_score=1, risk_total=1, description='d', metadata={}, tags=[], rationale=['r'], host_role_rationale=None)
    f_mid = Finding(id='m', title='abcdefghij', severity='low', risk_score=1, risk_total=1, description='d', metadata={}, tags=[], rationale=['r'], host_role_rationale=None)
    f_long = Finding(id='l', title='a'*40, severity='low', risk_score=1, risk_total=1, description='d', metadata={}, tags=[], rationale=['r'], host_role_rationale=None)
    rs = []
    for f in (f_short,f_mid,f_long):
        r = gov.redact_for_llm(f)
        if hasattr(r,'title'):
            rs.append(r.title)
        else:
            rs.append(r.get('title'))
    # Expect masking with bucket sizes (4,8,32)
    assert rs[0] == '****'
    assert len(rs[1]) == 8 and set(rs[1]) == {'*'}
    assert len(rs[2]) == 32 and set(rs[2]) == {'*'}


def test_list_and_nested_recursion(monkeypatch):
    monkeypatch.setenv('AGENT_HASH_SALT','abcd')
    gov = get_data_governor()
    metadata = {'items':[{'token':'abc123secret','path':'/opt/app/config.yaml'}]}
    f = Finding(id='f3', title='Path leak', severity='medium', risk_score=5, risk_total=5, description='d', metadata=metadata, tags=[], rationale=['r'], host_role_rationale=None)
    red = gov.redact_for_llm(f)
    if hasattr(red,'metadata'):
        md = red.metadata
    else:
        md = red.get('metadata')
    assert md['items'][0]['token'] == '[REDACTED]'
    assert md['items'][0]['path'].startswith('h:')
