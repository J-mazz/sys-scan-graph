"""
IPC server utilities for the Agent package.

This file was moved from UI/integration/ipc/communication.py and adjusted so the
Agent can start an IPC server (Unix domain socket) to talk to the Qt UI.
"""
from __future__ import annotations
import socket
import json
import threading
import queue
import time
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class Message:
    """Standard message format for IPC."""

    msg_type: str  # "feedback_request", "feedback_response", "status_update", "graph_state"
    msg_id: str
    data: Dict[str, Any]
    timestamp: float

    def to_json(self) -> str:
        """Serialize to JSON."""
        return json.dumps({
            "msg_type": self.msg_type,
            "msg_id": self.msg_id,
            "data": self.data,
            "timestamp": self.timestamp
        })

    @classmethod
    def from_json(cls, json_str: str) -> Message:
        """Deserialize from JSON."""
        data = json.loads(json_str)
        return cls(**data)


class FeedbackChannel:
    """
    Bidirectional communication channel for human-in-the-loop feedback.

    Uses Unix domain sockets for efficient IPC on Linux systems.
    """

    def __init__(self, socket_path: str = "/tmp/sys-scan-ui.sock"):
        self.socket_path = socket_path
        self.socket: Optional[socket.socket] = None
        self.is_server = False
        self.running = False
        self.message_queue: queue.Queue = queue.Queue()
        self.response_handlers: Dict[str, Callable] = {}
        self.listen_thread: Optional[threading.Thread] = None

    def start_server(self) -> bool:
        """Start as server (graph side)."""
        try:
            # Remove existing socket if present
            Path(self.socket_path).unlink(missing_ok=True)

            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.socket.bind(self.socket_path)
            self.socket.listen(1)
            self.is_server = True
            self.running = True

            logger.info(f"IPC server started on {self.socket_path}")

            # Start listening thread
            self.listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.listen_thread.start()

            return True
        except Exception as e:
            logger.error(f"Failed to start IPC server: {e}")
            return False

    def connect_client(self, timeout: int = 5) -> bool:
        """Connect as client (UI side)."""
        try:
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.socket.settimeout(timeout)
            self.socket.connect(self.socket_path)
            self.socket.settimeout(None)  # Remove timeout after connection
            self.is_server = False
            self.running = True

            logger.info(f"IPC client connected to {self.socket_path}")

            # Start listening thread
            self.listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.listen_thread.start()

            return True
        except Exception as e:
            logger.error(f"Failed to connect IPC client: {e}")
            return False

    def _listen_loop(self):
        """Listen for incoming messages."""
        if not self.socket:
            return

        if self.is_server:
            # Accept connection
            try:
                conn, _ = self.socket.accept()
                logger.info("Client connected")
            except Exception as e:
                logger.error(f"Failed to accept connection: {e}")
                return
        else:
            conn = self.socket

        buffer = ""
        while self.running:
            try:
                data = conn.recv(4096).decode('utf-8')
                if not data:
                    logger.warning("Connection closed by peer")
                    break

                buffer += data

                # Process complete messages (newline-delimited)
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    if line.strip():
                        try:
                            msg = Message.from_json(line)
                            self._handle_message(msg)
                        except json.JSONDecodeError as e:
                            logger.error(f"Invalid JSON received: {e}")

            except Exception as e:
                logger.error(f"Error in listen loop: {e}")
                break

        if not self.is_server:
            conn.close()

    def _handle_message(self, msg: Message):
        """Handle incoming message."""
        logger.debug(f"Received message: {msg.msg_type} (ID: {msg.msg_id})")

        # Check for registered handler
        if msg.msg_id in self.response_handlers:
            handler = self.response_handlers[msg.msg_id]
            handler(msg)
            del self.response_handlers[msg.msg_id]
        else:
            # Put in queue for polling
            self.message_queue.put(msg)

    def send_message(self, msg: Message) -> bool:
        """Send a message through the channel."""
        if not self.socket or not self.running:
            logger.error("Cannot send message: channel not active")
            return False

        try:
            # Send message with newline delimiter
            data = msg.to_json() + '\n'
            self.socket.sendall(data.encode('utf-8'))
            logger.debug(f"Sent message: {msg.msg_type} (ID: {msg.msg_id})")
            return True
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            return False

    def send_and_wait_response(
        self,
        msg: Message,
        timeout: Optional[float] = None
    ) -> Optional[Message]:
        """Send message and wait for response."""
        response_event = threading.Event()
        response_holder = {'msg': None}

        def response_handler(response_msg: Message):
            response_holder['msg'] = response_msg
            response_event.set()

        # Register response handler
        self.response_handlers[msg.msg_id] = response_handler

        # Send message
        if not self.send_message(msg):
            del self.response_handlers[msg.msg_id]
            return None

        # Wait for response
        if response_event.wait(timeout=timeout):
            return response_holder['msg']
        else:
            # Timeout
            if msg.msg_id in self.response_handlers:
                del self.response_handlers[msg.msg_id]
            logger.warning(f"Timeout waiting for response to {msg.msg_id}")
            return None

    def get_message(self, timeout: Optional[float] = None) -> Optional[Message]:
        """Get next message from queue (polling interface)."""
        try:
            return self.message_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self):
        """Close the channel."""
        self.running = False

        if self.listen_thread:
            self.listen_thread.join(timeout=2)

        if self.socket:
            self.socket.close()

        if self.is_server:
            Path(self.socket_path).unlink(missing_ok=True)

        logger.info("IPC channel closed")


class GraphCommunicator:
    """
    High-level interface for UI<->Graph communication.
    """

    def __init__(self, channel: Optional[FeedbackChannel] = None):
        self.channel = channel or FeedbackChannel()
        self.feedback_callbacks: Dict[str, Callable] = {}

    def start_as_server(self) -> bool:
        """Start as server (graph side)."""
        return self.channel.start_server()

    def connect_as_client(self) -> bool:
        """Connect as client (UI side)."""
        return self.channel.connect_client()

    def request_feedback(
        self,
        request_id: str,
        request_data: Dict[str, Any],
        timeout: Optional[float] = 300.0
    ) -> Optional[Dict[str, Any]]:
        msg = Message(
            msg_type="feedback_request",
            msg_id=request_id,
            data=request_data,
            timestamp=time.time()
        )

        response_msg = self.channel.send_and_wait_response(msg, timeout=timeout)

        if response_msg:
            return response_msg.data
        return None

    def send_feedback_response(
        self,
        request_id: str,
        response_data: Dict[str, Any]
    ) -> bool:
        msg = Message(
            msg_type="feedback_response",
            msg_id=request_id,
            data=response_data,
            timestamp=time.time()
        )

        return self.channel.send_message(msg)

    def send_graph_state(self, state_data: Dict[str, Any]) -> bool:
        msg = Message(
            msg_type="graph_state",
            msg_id=f"state_{int(time.time())}",
            data=state_data,
            timestamp=time.time()
        )

        return self.channel.send_message(msg)

    def register_feedback_callback(
        self,
        callback: Callable[[Dict[str, Any]], None]
    ):
        def process_messages():
            while self.channel.running:
                msg = self.channel.get_message(timeout=1.0)
                if msg and msg.msg_type == "feedback_request":
                    callback(msg.data)

        thread = threading.Thread(target=process_messages, daemon=True)
        thread.start()

    def close(self):
        """Close the communicator."""
        self.channel.close()


# Convenience wrapper to start the IPC server for the Agent
def start_ipc_thread(socket_path: str = "/tmp/sys-scan-ui.sock"):
    """Start the IPC server and return the communicator instance.

    The communicator's channel runs its own listener thread; this function simply
    returns the communicator so the caller can close it when done.
    """
    channel = FeedbackChannel(socket_path)
    comm = GraphCommunicator(channel=channel)
    success = comm.start_as_server()
    if not success:
        logger.warning("Failed to start IPC server")
    return comm


__all__ = ["Message", "FeedbackChannel", "GraphCommunicator", "start_ipc_thread"]