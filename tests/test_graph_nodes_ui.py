import sys
import pathlib
import pytest

# Ensure repo root is on sys.path for imports during tests
ROOT = pathlib.Path(__file__).parent.parent.resolve()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.sys_scan_agent import graph_nodes_ui


def minimal_state():
    return {
        'enriched_findings': [],
        'correlations': [],
        'risk_assessment': {},
    }


def test_investigation_director_sets_summary(monkeypatch):
    # Force GraphCommunicator.connect_as_client to return False to avoid network
    class FakeComm:
        def connect_as_client(self):
            return False
        def close(self):
            pass

    monkeypatch.setattr(graph_nodes_ui, 'GraphCommunicator', lambda: FakeComm())

    s = minimal_state()
    out = graph_nodes_ui.investigation_director_node(s)
    assert out.get('investigation_summary') is not None
    assert out.get('investigation_complete') is True


def test_investigation_director_sends_when_connected(monkeypatch):
    sent = {}

    class FakeComm:
        def connect_as_client(self):
            return True
        def send_graph_state(self, payload):
            sent['payload'] = payload
            return True
        def close(self):
            pass

    monkeypatch.setattr(graph_nodes_ui, 'GraphCommunicator', lambda: FakeComm())

    s = minimal_state()
    out = graph_nodes_ui.investigation_director_node(s)
    assert out.get('investigation_summary') is not None
    assert 'payload' in sent
    assert sent['payload']['type'] == 'investigation_summary'