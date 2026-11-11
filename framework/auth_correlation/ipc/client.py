"""
Phase 21: Isolated Execution Dispatcher IPC Client.

Provides the secure, strongly typed IPC client interface used by the BugBounty-Agent
correlation engine to communicate with the isolated execution authority.
Translates local requests into length-prefixed JSON frames, manages nonces,
enforces timeouts, and fails closed when the dispatcher is unavailable.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import secrets
import socket
import sys
import time
from typing import Any, Dict, Optional, Tuple

from framework.auth_correlation.ipc.protocol import (
    PROTOCOL_VERSION,
    DispatcherUnavailableError,
    IPCTimeoutError,
    IPCValidationError,
    pack_message,
    read_framed_message,
    validate_request_frame,
    validate_response_frame,
)


DEFAULT_SOCKET_NAME = "dispatcher.sock"
DEFAULT_PIPE_NAME = r"\\.\pipe\bugbounty_dispatcher"


def get_default_ipc_endpoint(workspace_root: Optional[str] = None) -> Tuple[str, str]:
    """
    Returns (endpoint_type: 'unix' | 'pipe', address: str).
    Prefers user configuration directory or workspace directory.
    """
    if os.name == "nt":
        # Windows Named Pipe
        pipe_env = os.environ.get("BUGBOUNTY_DISPATCHER_PIPE")
        if pipe_env:
            return "pipe", pipe_env
        return "pipe", DEFAULT_PIPE_NAME
    else:
        # Linux / POSIX Unix Domain Socket
        sock_env = os.environ.get("BUGBOUNTY_DISPATCHER_SOCKET")
        if sock_env:
            return "unix", sock_env
        run_sock = "/run/bugbounty/dispatcher.sock"
        if os.path.exists(run_sock):
            return "unix", run_sock
        # Fall back to user config directory
        user_config_dir = os.path.expanduser("~/.config/bugbounty-agent")
        os.makedirs(user_config_dir, exist_ok=True)
        return "unix", os.path.join(user_config_dir, DEFAULT_SOCKET_NAME)


class IsolatedDispatcherClient:
    """
    Client for the Isolated Execution Dispatcher Service.
    Connects over Unix Domain Sockets (Linux) or Named Pipes (Windows).
    """

    def __init__(
        self,
        endpoint_type: Optional[str] = None,
        address: Optional[str] = None,
        timeout: float = 10.0,
    ):
        self.timeout = timeout
        if endpoint_type and address:
            self.endpoint_type = endpoint_type
            self.address = address
        else:
            self.endpoint_type, self.address = get_default_ipc_endpoint()

    def _connect(self) -> Any:
        """Establishes an active connection or raises DispatcherUnavailableError."""
        if self.endpoint_type == "unix":
            if not os.path.exists(self.address):
                raise DispatcherUnavailableError(
                    f"Dispatcher Unix domain socket '{self.address}' does not exist. Is the dispatcher service running?"
                )
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect(self.address)
                return sock
            except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
                raise DispatcherUnavailableError(
                    f"Failed to connect to dispatcher at '{self.address}': {e}"
                )
        elif self.endpoint_type == "pipe":
            try:
                from multiprocessing.connection import Client
                # Windows Named Pipe connection using stdlib Client with AF_PIPE
                conn = Client(self.address, family="AF_PIPE")
                return conn
            except Exception as e:
                raise DispatcherUnavailableError(
                    f"Failed to connect to dispatcher named pipe '{self.address}': {e}"
                )
        else:
            raise DispatcherUnavailableError(f"Unsupported IPC endpoint type: '{self.endpoint_type}'")

    def _send_and_receive(self, request_frame: Dict[str, Any]) -> Dict[str, Any]:
        """Sends an IPC request frame and reads the corresponding response frame."""
        validate_request_frame(request_frame)
        raw_msg = pack_message(request_frame)
        expected_req_id = request_frame["request_id"]

        conn = self._connect()
        try:
            if hasattr(conn, "send_bytes"):
                # multiprocessing Connection (AF_PIPE)
                conn.send_bytes(raw_msg)
                # Read raw bytes response
                resp_bytes = conn.recv_bytes(65536)
                # Unpack: length prefix (4 bytes) + json
                if len(resp_bytes) < 4:
                    raise IPCValidationError("Received undersized response from dispatcher")
                resp_json = json.loads(resp_bytes[4:].decode("utf-8"))
            else:
                # Raw socket (AF_UNIX)
                conn.sendall(raw_msg)
                resp_json = read_framed_message(conn)

            validate_response_frame(resp_json, expected_req_id=expected_req_id)
            return resp_json
        except socket.timeout:
            raise IPCTimeoutError(f"Dispatcher IPC request timed out after {self.timeout}s")
        except Exception as e:
            if isinstance(e, (DispatcherUnavailableError, IPCTimeoutError, IPCValidationError)):
                raise
            raise DispatcherUnavailableError(f"Dispatcher IPC communication error: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def ping(self) -> bool:
        """Pings the dispatcher service to check availability."""
        req_id = f"REQ-{secrets.token_hex(16).upper()}"
        nonce = f"NONCE-{secrets.token_hex(16).upper()}"
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        req = {
            "version": PROTOCOL_VERSION,
            "request_id": req_id,
            "nonce": nonce,
            "timestamp": now_iso,
            "action": "PING",
            "payload": {},
        }
        try:
            resp = self._send_and_receive(req)
            return resp.get("status") == "SUCCESS"
        except DispatcherUnavailableError:
            return False

    def get_status(self) -> Dict[str, Any]:
        """Queries the dispatcher service for status and diagnostic information."""
        req_id = f"REQ-{secrets.token_hex(16).upper()}"
        nonce = f"NONCE-{secrets.token_hex(16).upper()}"
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        req = {
            "version": PROTOCOL_VERSION,
            "request_id": req_id,
            "nonce": nonce,
            "timestamp": now_iso,
            "action": "STATUS",
            "payload": {},
        }
        return self._send_and_receive(req)

    def dispatch_mutation(
        self,
        program_id: str,
        action_id: str,
        action_dossier: Dict[str, Any],
        session_context: Dict[str, Any],
        scope_rules: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Sends an approved Mode B mutation request to the isolated dispatcher.
        Returns the dispatcher response containing the signed ExecutionReceipt.
        """
        req_id = f"REQ-{secrets.token_hex(16).upper()}"
        nonce = f"NONCE-{secrets.token_hex(16).upper()}"
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        req = {
            "version": PROTOCOL_VERSION,
            "request_id": req_id,
            "nonce": nonce,
            "timestamp": now_iso,
            "action": "DISPATCH_MUTATION",
            "payload": {
                "program_id": program_id,
                "action_id": action_id,
                "action_dossier": action_dossier,
                "session_context": session_context,
                "scope_rules": scope_rules or {},
            },
        }

        resp = self._send_and_receive(req)
        return resp
