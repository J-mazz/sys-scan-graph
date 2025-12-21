import sys
import pathlib
import pytest
import time

ROOT = pathlib.Path(__file__).parent.parent.parent.resolve()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.sys_scan_agent.graph_nodes_ui import investigation_director_node
from agent.sys_scan_agent.ipc_server import GraphCommunicator, FeedbackChannel


def test_investigation_director_no_ui():
    state = {'enriched_findings': [], 'correlations': [], 'risk_assessment': {}}
    out = investigation_director_node(state)
    assert out.get('investigation_complete') is True
    assert 'investigation_summary' in out


def test_investigation_director_sends_when_ui_available(tmp_path):
    sock = str(tmp_path / 'graph_ui.sock')
    # Start server (agent side)
    comm = GraphCommunicator(channel=FeedbackChannel(socket_path=sock))
    assert comm.start_as_server()

    # Start a fake UI client to receive graph_state
    client = GraphCommunicator(channel=FeedbackChannel(socket_path=sock))
    assert client.connect_as_client()

    # Replace communicator usage inside node by monkeypatching GraphCommunicator to return our client
    class FakeComm:
        def connect_as_client(self):
            return True
        def send_graph_state(self, payload):
            # Accept any payload
            self.payload = payload
            return True
        def close(self):
            pass

    # Monkeypatch GraphCommunicator in module
    import agent.sys_scan_agent.graph_nodes_ui as gnu
    orig = gnu.GraphCommunicator
    gnu.GraphCommunicator = lambda: FakeComm()

    try:
        state = {'enriched_findings': [], 'correlations': [], 'risk_assessment': {}}
        out = investigation_director_node(state)
        assert out['investigation_complete'] is True
    finally:
        gnu.GraphCommunicator = orig
        client.close()
        comm.close()
