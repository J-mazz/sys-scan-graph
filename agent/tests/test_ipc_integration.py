import sys
import pathlib
import os
import time
import json
import threading
from pathlib import Path
import pytest

# Ensure repo root is on sys.path when running tests from the repository root
ROOT = pathlib.Path(__file__).parent.parent.parent.resolve()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.sys_scan_agent.ipc_server import FeedbackChannel, GraphCommunicator, FileFeedbackChannel, Message


def test_feedback_channel_server_client_exchange(tmp_path):
    sock = str(tmp_path / "test.sock")

    # Start server
    server_channel = FeedbackChannel(socket_path=sock)
    assert server_channel.start_server() is True

    # Client connects
    client_channel = FeedbackChannel(socket_path=sock)
    connected = False
    for _ in range(10):
        if client_channel.connect_client(timeout=1):
            connected = True
            break
        time.sleep(0.1)
    assert connected

    # Wrap in communicators
    server_comm = GraphCommunicator(channel=server_channel)
    client_comm = GraphCommunicator(channel=client_channel)

    # Server registers a simple handler via polling thread
    received = {}

    def server_process():
        # Wait for a message from client
        for _ in range(50):
            msg = server_channel.get_message(timeout=0.2)
            if msg and msg.msg_type == 'graph_state':
                received['msg'] = msg
                # Respond (as feedback_response) to ensure send_and_wait_response is exercised elsewhere
                resp = Message(msg_type='feedback_response', msg_id=msg.msg_id, data={'ok': True}, timestamp=time.time())
                server_channel.send_message(resp)
                return
        pytest.skip("Server did not receive message in time")

    t = threading.Thread(target=server_process, daemon=True)
    t.start()

    # Client sends a graph_state message
    payload = Message(msg_type='graph_state', msg_id='state_1', data={'state': 'ok'}, timestamp=time.time())
    assert client_channel.send_message(payload) is True

    t.join(timeout=5)
    assert 'msg' in received
    assert received['msg'].data.get('state') == 'ok'

    # Cleanup
    client_channel.close()
    server_channel.close()


def test_send_and_wait_response_roundtrip(tmp_path):
    sock = str(tmp_path / "test2.sock")
    server = FeedbackChannel(socket_path=sock)
    assert server.start_server()

    client = FeedbackChannel(socket_path=sock)
    assert client.connect_client()

    # Use GraphCommunicator convenience wrappers
    server_comm = GraphCommunicator(channel=server)
    client_comm = GraphCommunicator(channel=client)

    # Server side: wait for request then respond
    def server_worker():
        m = server.get_message(timeout=5)
        if not m:
            return
        # send response with same msg_id
        resp = Message(msg_type='feedback_response', msg_id=m.msg_id, data={'accepted': True}, timestamp=time.time())
        server.send_message(resp)

    th = threading.Thread(target=server_worker, daemon=True)
    th.start()

    msg = Message(msg_type='feedback_request', msg_id='req-42', data={'question': 'ok?'}, timestamp=time.time())
    resp = client.send_and_wait_response(msg, timeout=3)
    assert resp is not None
    assert resp.data.get('accepted') is True

    client.close()
    server.close()


def test_file_feedback_channel_roundtrip(tmp_path):
    base = str(tmp_path / "ipc")
    fch = FileFeedbackChannel(base_dir=base)

    req_id = 'req-file-1'
    data = {'a': 1}
    assert fch.write_request(req_id, data) is True

    # Spawn a reader in background
    def reader():
        val = fch.read_response(req_id, timeout=1)
        return val

    # Respond
    assert fch.write_response(req_id, {'answer': 'ok'}) is True

    res = fch.read_response(req_id, timeout=1)
    # Since write_response writes responses, read_response will find it
    assert res is not None
    assert res.get('answer') == 'ok'


def test_register_feedback_callback_invokes_callback(tmp_path):
    sock = str(tmp_path / "test3.sock")
    server_channel = FeedbackChannel(socket_path=sock)
    assert server_channel.start_server()

    client_channel = FeedbackChannel(socket_path=sock)
    assert client_channel.connect_client()

    client_comm = GraphCommunicator(channel=client_channel)
    server_comm = GraphCommunicator(channel=server_channel)

    invoked = {}

    def cb(data):
        invoked['data'] = data

    # register a callback that processes feedback_request
    server_comm.register_feedback_callback(cb)

    # Send a request from client
    msg = Message(msg_type='feedback_request', msg_id='cb-1', data={'q': 1}, timestamp=time.time())
    client_channel.send_message(msg)

    # Wait for callback to be invoked
    for _ in range(20):
        if invoked:
            break
        time.sleep(0.1)

    assert invoked
    assert invoked['data'].get('q') == 1

    client_channel.close()
    server_channel.close()
