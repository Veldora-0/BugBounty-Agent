"""
Phase 21: Typed IPC Protocol for Isolated Execution Dispatcher.

Defines wire framing, strict schema validation, request/response models,
and error types for IPC communication between the BugBounty-Agent correlation
engine and the isolated execution dispatcher service.

Constraints:
- Maximum frame size: 65,536 bytes (64 KB).
- Framing: 4-byte big-endian unsigned length prefix + UTF-8 JSON.
- Arbitrary Python object serialization (e.g., pickle) is strictly prohibited.
- Schema violations, oversize payloads, and unknown actions fail closed.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
import struct
from typing import Any, Dict, Optional, Set, Tuple


PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 65536  # 64 KB hard message ceiling

REQUEST_ID_PATTERN = re.compile(r"^REQ-[0-9A-Fa-f]{32}$")
NONCE_PATTERN = re.compile(r"^NONCE-[0-9A-Fa-f]{32}$")
ISO_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$")
ACTION_ID_PATTERN = re.compile(r"^ACT-[0-9A-Fa-f]{64}$")
SESSION_REF_PATTERN = re.compile(r"^sess_[0-9A-Fa-f]{32}$")

ALLOWED_ACTIONS: Set[str] = frozenset({
    "DISPATCH_MUTATION",
    "PING",
    "STATUS",
    "VERIFY_RECEIPT",
})

ALLOWED_DOSSIER_KEYS: Set[str] = frozenset({
    "action_id",
    "action_type",
    "approval_signature",
    "created_at",
    "method",
    "program_id",
    "target_endpoint",
    "test_account",
    "ttl",
    "unique_approval_id",
})

ALLOWED_MUTATION_METHODS: Set[str] = frozenset({"POST", "PUT", "DELETE"})
ALLOWED_ACTION_TYPES: Set[str] = frozenset({"LOGOUT", "ACTION-LOGOUT", "TOKEN_REVOCATION", "PASSWORD_CHANGE"})


class IPCProtocolError(Exception):
    """Base error for all IPC communication faults."""


class IPCValidationError(IPCProtocolError):
    """Raised when an incoming or outgoing IPC frame violates schema or size constraints."""


class IPCTimeoutError(IPCProtocolError):
    """Raised when an IPC request exceeds the configured network/socket timeout."""


class DispatcherUnavailableError(IPCProtocolError):
    """Raised when the isolated dispatcher service is not running or unreachable."""


def pack_message(data: Dict[str, Any]) -> bytes:
    """
    Serializes a dictionary to length-prefixed JSON bytes.
    Enforces maximum payload size ceiling of 64 KB.
    """
    if not isinstance(data, dict):
        raise IPCValidationError("IPC payload must be a dictionary")

    try:
        raw_json = json.dumps(data, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    except Exception as e:
        raise IPCValidationError(f"Failed to serialize IPC message to JSON: {e}")

    payload_len = len(raw_json)
    if payload_len == 0:
        raise IPCValidationError("IPC message payload cannot be empty")
    if payload_len > MAX_MESSAGE_BYTES:
        raise IPCValidationError(
            f"IPC message size ({payload_len} bytes) exceeds maximum ceiling ({MAX_MESSAGE_BYTES} bytes)"
        )

    # 4-byte big-endian unsigned length prefix
    header = struct.pack("!I", payload_len)
    return header + raw_json


def read_framed_message(reader: Any) -> Dict[str, Any]:
    """
    Reads a single length-prefixed message from a stream or socket.
    Fails closed on unexpected EOF, malformed length prefix, or JSON parse errors.
    """
    # Helper to read exact N bytes
    def _read_exact(n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = reader.read(n - len(buf)) if hasattr(reader, "read") else reader.recv(n - len(buf))
            if not chunk:
                raise IPCProtocolError(f"Unexpected connection termination while reading {n} bytes (read {len(buf)})")
            buf.extend(chunk)
        return bytes(buf)

    # 1. Read 4-byte length prefix
    header_bytes = _read_exact(4)
    (payload_len,) = struct.unpack("!I", header_bytes)

    if payload_len == 0:
        raise IPCValidationError("Received empty IPC message length prefix")
    if payload_len > MAX_MESSAGE_BYTES:
        raise IPCValidationError(
            f"Incoming IPC message size ({payload_len} bytes) exceeds maximum ceiling ({MAX_MESSAGE_BYTES} bytes)"
        )

    # 2. Read exact payload bytes
    payload_bytes = _read_exact(payload_len)

    # 3. Decode JSON
    try:
        data = json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        raise IPCValidationError(f"Incoming IPC frame is not valid JSON: {e}")

    if not isinstance(data, dict):
        raise IPCValidationError("Incoming IPC frame must decode to a dictionary")

    return data


def validate_request_frame(req: Dict[str, Any]) -> None:
    """
    Strictly validates the structure and fields of an incoming IPC request.
    Fails closed on missing fields, wrong types, or malformed identifiers.
    """
    if not isinstance(req, dict):
        raise IPCValidationError("Request frame must be a dictionary")

    version = req.get("version")
    if version != PROTOCOL_VERSION:
        raise IPCValidationError(f"Unsupported IPC protocol version: {version} (expected {PROTOCOL_VERSION})")

    req_id = req.get("request_id")
    if not isinstance(req_id, str) or not REQUEST_ID_PATTERN.match(req_id):
        raise IPCValidationError(f"Invalid or malformed request_id: '{req_id}'")

    nonce = req.get("nonce")
    if not isinstance(nonce, str) or not NONCE_PATTERN.match(nonce):
        raise IPCValidationError(f"Invalid or malformed request nonce: '{nonce}'")

    ts = req.get("timestamp")
    if not isinstance(ts, str) or not ISO_TIMESTAMP_PATTERN.match(ts):
        raise IPCValidationError(f"Invalid or malformed timestamp format: '{ts}'")

    action = req.get("action")
    if action not in ALLOWED_ACTIONS:
        raise IPCValidationError(f"Unknown or unsupported IPC action: '{action}'")

    payload = req.get("payload")
    if not isinstance(payload, dict):
        raise IPCValidationError("Request frame 'payload' must be a dictionary")

    if action == "DISPATCH_MUTATION":
        _validate_dispatch_mutation_payload(payload)


def _validate_dispatch_mutation_payload(payload: Dict[str, Any]) -> None:
    """Validates the payload of a DISPATCH_MUTATION action."""
    program_id = payload.get("program_id")
    if not isinstance(program_id, str) or not program_id.strip():
        raise IPCValidationError("DISPATCH_MUTATION requires non-empty string 'program_id'")

    action_id = payload.get("action_id")
    if not isinstance(action_id, str) or not ACTION_ID_PATTERN.match(action_id):
        raise IPCValidationError(f"Invalid action_id format: '{action_id}' (expected ACT-<64-hex>)")

    dossier = payload.get("action_dossier")
    if not isinstance(dossier, dict):
        raise IPCValidationError("DISPATCH_MUTATION requires dictionary 'action_dossier'")

    if set(dossier.keys()) != ALLOWED_DOSSIER_KEYS:
        diff = set(dossier.keys()) ^ ALLOWED_DOSSIER_KEYS
        raise IPCValidationError(f"Action dossier keys do not match approved schema: difference={diff}")

    if dossier.get("action_id") != action_id:
        raise IPCValidationError("Dossier action_id does not match payload action_id")

    method = dossier.get("method")
    if method not in ALLOWED_MUTATION_METHODS:
        raise IPCValidationError(f"Unsupported mutation method: '{method}'")

    action_type = dossier.get("action_type")
    if action_type not in ALLOWED_ACTION_TYPES:
        raise IPCValidationError(f"Unsupported action type: '{action_type}'")

    target = dossier.get("target_endpoint")
    if not isinstance(target, str) or not target.startswith(("http://", "https://")):
        raise IPCValidationError("Invalid target_endpoint scheme: must be http or https")

    sess_ctx = payload.get("session_context")
    if not isinstance(sess_ctx, dict):
        raise IPCValidationError("DISPATCH_MUTATION requires dictionary 'session_context'")

    s_ref = sess_ctx.get("session_ref")
    if not isinstance(s_ref, str) or not SESSION_REF_PATTERN.match(s_ref):
        raise IPCValidationError(f"Invalid session_ref in session_context: '{s_ref}'")

    p_id = sess_ctx.get("principal_id")
    if not isinstance(p_id, str) or not p_id.strip():
        raise IPCValidationError("session_context requires non-empty 'principal_id'")

    if dossier.get("test_account") != p_id:
        raise IPCValidationError(
            f"Dossier test_account '{dossier.get('test_account')}' does not match session principal_id '{p_id}'"
        )


def validate_response_frame(resp: Dict[str, Any], expected_req_id: Optional[str] = None) -> None:
    """
    Strictly validates the structure and fields of an incoming IPC response.
    Fails closed on missing fields, wrong types, or unexpected request_id.
    """
    if not isinstance(resp, dict):
        raise IPCValidationError("Response frame must be a dictionary")

    version = resp.get("version")
    if version != PROTOCOL_VERSION:
        raise IPCValidationError(f"Unsupported IPC response protocol version: {version}")

    req_id = resp.get("request_id")
    if not isinstance(req_id, str) or not REQUEST_ID_PATTERN.match(req_id):
        raise IPCValidationError(f"Invalid response request_id: '{req_id}'")

    if expected_req_id and req_id != expected_req_id:
        raise IPCValidationError(f"Mismatched response request_id: got '{req_id}', expected '{expected_req_id}'")

    status = resp.get("status")
    if status not in ("SUCCESS", "REJECTED", "ERROR"):
        raise IPCValidationError(f"Invalid response status: '{status}'")

    if status == "SUCCESS":
        receipt = resp.get("receipt")
        if receipt is not None and not isinstance(receipt, dict):
            raise IPCValidationError("Receipt must be a dictionary when present in response")
    elif status in ("REJECTED", "ERROR"):
        err_msg = resp.get("error_message")
        if not isinstance(err_msg, str) or not err_msg:
            raise IPCValidationError("Failed response must include a non-empty 'error_message'")
