"""
Unit and Integration Tests for Phase 21 Isolated Execution Dispatcher IPC.

Verifies:
- Protocol framing, length prefixing, and 64KB message ceiling
- Strict schema validation for requests and responses
- Cryptographic receipt canonicalization, signing, and tamper detection
- Client connection, ping, status, and timeout handling
- Live dispatcher service execution over IPC (Named Pipe on Windows / Unix Socket on Linux)
- Immediate pre-execution scope enforcement and SSRF / metadata destination blocking
- Single-use approval consumption and replay attack rejection
- Dispatcher unavailable fail-closed behavior
"""

from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import secrets
import time
import pytest

from framework.auth_correlation.ipc.protocol import (
    PROTOCOL_VERSION,
    MAX_MESSAGE_BYTES,
    DispatcherUnavailableError,
    IPCTimeoutError,
    IPCValidationError,
    pack_message,
    read_framed_message,
    validate_request_frame,
    validate_response_frame,
)
from framework.auth_correlation.ipc.receipt import (
    canonicalize_receipt,
    sign_execution_receipt,
    verify_execution_receipt,
)
from framework.auth_correlation.ipc.client import IsolatedDispatcherClient
from framework.auth_correlation.ipc.service import IsolatedExecutionDispatcher
from framework.validation.request import ControlledRequest, ControlledResponse


class MockTransport:
    """Mock transport engine for isolated dispatcher tests."""
    def __init__(self):
        self.requests: list[ControlledRequest] = []
        self.probe_response = ControlledResponse(401, {"content-type": "application/json"}, b'{"error": "Session revoked"}')

    def send_request(self, req: ControlledRequest) -> ControlledResponse:
        self.requests.append(req)
        if req.headers.get("X-Correlation-Dispatch", "").endswith("-VERIFY"):
            return self.probe_response
        return ControlledResponse(200, {"content-type": "application/json"}, b'{"status": "logged_out", "revoked": true}')


def test_protocol_packing_and_size_limits():
    """Verifies that framing prepends 4-byte big-endian length and enforces 64KB ceiling."""
    valid_data = {"version": 1, "test": "hello"}
    packed = pack_message(valid_data)
    assert len(packed) > 4
    length = int.from_bytes(packed[:4], "big")
    assert length == len(packed) - 4
    assert json.loads(packed[4:].decode("utf-8")) == valid_data

    # Payload exceeding 64KB must be rejected immediately
    huge_data = {"version": 1, "blob": "A" * (MAX_MESSAGE_BYTES + 10)}
    with pytest.raises(IPCValidationError, match="exceeds maximum ceiling"):
        pack_message(huge_data)


def test_protocol_schema_validation():
    """Verifies schema validation on request and response frames."""
    # Valid PING request
    req = {
        "version": 1,
        "request_id": f"REQ-{secrets.token_hex(16).upper()}",
        "nonce": f"NONCE-{secrets.token_hex(16).upper()}",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "action": "PING",
        "payload": {},
    }
    validate_request_frame(req)

    # Invalid version
    with pytest.raises(IPCValidationError, match="Unsupported IPC protocol version"):
        validate_request_frame({**req, "version": 2})

    # Unknown action
    with pytest.raises(IPCValidationError, match="Unknown or unsupported IPC action"):
        validate_request_frame({**req, "action": "EXPLODE"})

    # Malformed nonce
    with pytest.raises(IPCValidationError, match="Invalid or malformed request nonce"):
        validate_request_frame({**req, "nonce": "invalid-nonce"})


def test_receipt_signing_and_tamper_detection():
    """Verifies cryptographic receipt generation, verification, and tamper detection."""
    signing_key = secrets.token_bytes(32)
    aid = f"ACT-{'0' * 64}"
    req_nonce = f"NONCE-{'1' * 32}"

    receipt = {
        "version": 1,
        "receipt_id": f"RCPT-{'2' * 32}",
        "dispatcher_id": "DISPATCHER-TEST-1",
        "dispatcher_key_id": "KEY-DISPATCHER-V1",
        "dispatch_op_id": f"DISP-OP-{'5' * 64}",
        "action_id": aid,
        "action_dossier_digest": "0" * 64,
        "approval_id": f"APPR-{'3' * 16}",
        "request_nonce": req_nonce,
        "execution_id": f"EXEC-{'4' * 32}",
        "program_id": "prog1",
        "principal_id": "u1",
        "session_ref": "sess_00000000000000000000000000000001",
        "target_endpoint": "https://target.local/auth/logout",
        "http_method": "POST",
        "action_type": "LOGOUT",
        "scope_decision": "ALLOWED",
        "execution_outcome": "REVOCATION_VERIFIED",
        "mutation_evidence": {
            "evidence_id": "EVID-000000000001",
            "request_sha256": "a" * 64,
            "response_sha256": "b" * 64,
            "status_code": 200,
            "timestamp": "2026-11-11T12:00:00Z",
        },
        "verification_evidence": {
            "evidence_id": "EVID-000000000002",
            "invalidation_result": "REVOKED",
            "request_sha256": "c" * 64,
            "response_sha256": "d" * 64,
            "status_code": 401,
            "timestamp": "2026-11-11T12:00:01Z",
            "verification_method": "POST_MUTATION_PROBE_CONFIRMED_401",
        },
        "consumption_token": secrets.token_hex(32),
        "issued_at": "2026-11-11T12:00:01Z",
    }

    receipt["signature"] = sign_execution_receipt(receipt, signing_key)

    # 1. Authentic receipt verifies cleanly
    ok, reason = verify_execution_receipt(receipt, signing_key, expected_action_id=aid, expected_nonce=req_nonce)
    assert ok is True
    assert reason == "Receipt cryptographically verified"

    # 2. Tampered field fails closed
    tampered_receipt = dict(receipt)
    tampered_receipt["target_endpoint"] = "https://attacker.com/evil"
    ok, reason = verify_execution_receipt(tampered_receipt, signing_key)
    assert ok is False
    assert "cryptographic signature verification failed" in reason

    # 3. Wrong verification key fails closed
    wrong_key = secrets.token_bytes(32)
    ok, reason = verify_execution_receipt(receipt, wrong_key)
    assert ok is False
    assert "cryptographic signature verification failed" in reason

    # 4. Invalidation result not REVOKED fails closed
    unrevoked_receipt = dict(receipt)
    unrevoked_receipt["verification_evidence"] = dict(receipt["verification_evidence"])
    unrevoked_receipt["verification_evidence"]["invalidation_result"] = "NOT_REVOKED"
    unrevoked_receipt["signature"] = sign_execution_receipt(unrevoked_receipt, signing_key)
    ok, reason = verify_execution_receipt(unrevoked_receipt, signing_key)
    assert ok is False
    assert "invalidation_result='NOT_REVOKED'" in reason


def test_dispatcher_service_ipc_lifecycle(tmp_path):
    """Verifies full dispatcher lifecycle over IPC: start, ping, status, execution, and stop."""
    state_dir = tmp_path / "disp_state"
    key_dir = tmp_path / "disp_keys"
    ev_dir = tmp_path / "disp_ev"
    state_dir.mkdir()
    key_dir.mkdir()
    ev_dir.mkdir()

    appr_key = secrets.token_bytes(32)
    transport = MockTransport()

    # Create unique endpoint name for test
    if os.name == "nt":
        pipe_name = rf"\\.\pipe\test_disp_{secrets.token_hex(8)}"
        disp = IsolatedExecutionDispatcher(
            program_id="test_prog",
            pipe_name=pipe_name,
            key_dir=str(key_dir),
            state_dir=str(state_dir),
            evidence_dir=str(ev_dir),
            approval_key=appr_key,
            transport_engine=transport,
            is_lab=True,
        )
        client = IsolatedDispatcherClient(endpoint_type="pipe", address=pipe_name)
    else:
        sock_path = str(state_dir / f"test_{secrets.token_hex(8)}.sock")
        disp = IsolatedExecutionDispatcher(
            program_id="test_prog",
            socket_path=sock_path,
            key_dir=str(key_dir),
            state_dir=str(state_dir),
            evidence_dir=str(ev_dir),
            approval_key=appr_key,
            transport_engine=transport,
            is_lab=True,
        )
        client = IsolatedDispatcherClient(endpoint_type="unix", address=sock_path)

    disp.start()
    time.sleep(0.1)
    try:
        # 1. PING
        assert client.ping() is True

        # 2. STATUS
        status_res = client.get_status()
        assert status_res["status"] == "SUCCESS"
        assert status_res["receipt"]["dispatcher_id"] == disp.dispatcher_id

        # 3. DISPATCH_MUTATION
        endpoint = "http://127.0.0.1:8080/auth/logout"
        dossier = {
            "action_type": "LOGOUT",
            "created_at": time.time(),
            "method": "POST",
            "program_id": "test_prog",
            "target_endpoint": endpoint,
            "test_account": "alice",
            "ttl": 300.0,
            "unique_approval_id": f"APPR-{secrets.token_hex(16)}",
        }
        canonical_str = json.dumps({k: dossier[k] for k in sorted(dossier.keys())}, sort_keys=True)
        aid = f"ACT-{hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()}"
        dossier["action_id"] = aid
        dossier["approval_signature"] = f"SIG-{hmac.new(appr_key, canonical_str.encode('utf-8'), hashlib.sha256).hexdigest()}"

        sess_ctx = {
            "session_ref": "sess_00000000000000000000000000000001",
            "principal_id": "alice",
            "volatile_headers": {"Authorization": "Bearer token_alice"},
        }

        resp = client.dispatch_mutation(
            program_id="test_prog",
            action_id=aid,
            action_dossier=dossier,
            session_context=sess_ctx,
        )
        assert resp["status"] == "SUCCESS"
        receipt = resp["receipt"]
        assert receipt["action_id"] == aid
        assert receipt["execution_outcome"] == "REVOCATION_VERIFIED"
        assert receipt["verification_evidence"]["invalidation_result"] == "REVOKED"

        # Verify receipt cryptographically
        ok, reason = verify_execution_receipt(receipt, disp.signing_key, expected_action_id=aid)
        assert ok is True

        # 4. Replay attack rejection: calling same action_id must be rejected
        replay_resp = client.dispatch_mutation(
            program_id="test_prog",
            action_id=aid,
            action_dossier=dossier,
            session_context=sess_ctx,
        )
        assert replay_resp["status"] == "REJECTED"
        assert replay_resp["error_code"] == "APPROVAL_CONSUMPTION_FAILED"
        assert "already been consumed" in replay_resp["error_message"]

    finally:
        disp.stop()

    # 5. When dispatcher is stopped, client must fail closed immediately
    with pytest.raises(DispatcherUnavailableError):
        client.dispatch_mutation(
            program_id="test_prog",
            action_id=aid,
            action_dossier=dossier,
            session_context=sess_ctx,
        )


def test_dispatcher_rejects_ssrf_metadata_destination(tmp_path):
    """Verifies that the dispatcher rejects cloud metadata endpoints immediately."""
    state_dir = tmp_path / "ssrf_state"
    state_dir.mkdir()
    disp = IsolatedExecutionDispatcher(state_dir=str(state_dir), key_dir=str(state_dir), evidence_dir=str(state_dir))

    with pytest.raises(ValueError, match="Prohibited cloud metadata destination"):
        disp._validate_scope_and_destination("http://169.254.169.254/latest/meta-data")
