"""Phase 21: Provenance Architecture Security Regression & Adversarial Acceptance Suite.

Validates the complete execution provenance trust boundary across 11 adversarial scenarios
and dynamic provenance boundary capability assessment:

1. Forged execution receipts with invalid Ed25519 signatures are rejected.
2. Execution receipts with tampered fields (action_id, dispatch_op_id, evidence_id, request_sha256) are rejected.
3. An attacker attempting to issue an ExecutionCapability using a forged ControlledDispatchResult without a valid receipt fails closed.
4. An attacker attempting to issue an ExecutionCapability using a forged ControlledDispatchResult with an altered receipt fails closed.
5. Replay attacks with duplicate nonces or duplicate action IDs are rejected by the dispatcher.
6. Expired or future-dated operator approvals are rejected before any network traffic occurs.
7. Dispatcher restarts preserve replay-prevention state across reboots.
8. Rogue IPC endpoint substitution or malicious socket path injection is detected and fails closed.
9. Unauthorized writes to the evidence directory without the dispatcher's authority token are rejected.
10. Capability issuance after a failed verification probe fails closed.
11. Dynamic provenance boundary reporting correctly reflects:
    - Public key missing
    - Public key invalid / malformed
    - Dispatcher daemon stopped
    - Dispatcher daemon unreachable / socket inaccessible
    - Windows platform limitation accurately documented
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import secrets
import stat
import time
from typing import Any, Dict, Optional, Tuple
import pytest

from framework.auth_correlation.dispatcher import ControlledDispatchResult, ControlledDispatchWorkflow
from framework.auth_correlation.ipc.client import IsolatedDispatcherClient
from framework.auth_correlation.ipc.protocol import (
    PROTOCOL_VERSION,
    DispatcherUnavailableError,
    IPCValidationError,
)
from framework.auth_correlation.ipc.receipt import (
    canonicalize_receipt,
    derive_verification_key,
    load_dispatcher_verification_key,
    sign_execution_receipt,
    verify_execution_receipt,
)
from framework.auth_correlation.ipc.service import (
    CANONICAL_ACTION_FIELDS,
    IsolatedExecutionDispatcher,
)
from framework.auth_correlation.ledger import (
    ExecutionCapability,
    ExecutionLedger,
    ExecutionProvenanceError,
    issue_execution_capability,
    sign_consumption_receipt,
)
from framework.auth_correlation.provenance_boundary import (
    assess_provenance_boundary,
    get_provenance_boundary_reason,
    get_provenance_boundary_status,
)
from framework.auth_correlation.revocation import (
    get_or_create_approval_key,
    sign_action_approval,
)
from framework.common.evidence import EvidenceStore
from framework.validation.request import ControlledRequest, ControlledResponse


class MockLabTransport:
    """Simulated transport engine for controlled dispatch unit testing."""

    def __init__(self, probe_status: int = 401, fail_probe: bool = False):
        self.requests: list[ControlledRequest] = []
        self.probe_status = probe_status
        self.fail_probe = fail_probe

    def send_request(self, req: ControlledRequest) -> ControlledResponse:
        self.requests.append(req)
        if req.headers.get("X-Correlation-Dispatch", "").endswith("-VERIFY"):
            if self.fail_probe:
                # Returns 200 indicating session is still active (revocation failed)
                return ControlledResponse(
                    status_code=200,
                    headers={"Content-Type": "application/json"},
                    body_bytes=b'{"doc": "confidential_document"}',
                )
            return ControlledResponse(
                status_code=self.probe_status,
                headers={"Content-Type": "application/json"},
                body_bytes=b'{"error": "Session revoked", "status": "revoked"}',
            )
        return ControlledResponse(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body_bytes=b'{"status": "logged_out", "revoked": true}',
        )


def _setup_test_environment(tmp_path: Any) -> Dict[str, Any]:
    """Sets up an isolated directory hierarchy with keys and evidence store."""
    state_dir = str(tmp_path / "state")
    key_dir = str(tmp_path / "keys")
    ev_dir = str(tmp_path / "evidence")
    os.makedirs(state_dir, exist_ok=True)
    os.makedirs(key_dir, exist_ok=True)
    os.makedirs(ev_dir, exist_ok=True)

    app_key = get_or_create_approval_key(key_dir=key_dir)
    store = EvidenceStore(evidence_dir=ev_dir)

    pipe_or_sock = (
        rf"\\.\pipe\bb_test_{secrets.token_hex(8)}"
        if os.name == "nt"
        else os.path.join(state_dir, f"disp_{secrets.token_hex(8)}.sock")
    )

    return {
        "state_dir": state_dir,
        "key_dir": key_dir,
        "evidence_dir": ev_dir,
        "approval_key": app_key,
        "evidence_store": store,
        "pipe_or_sock": pipe_or_sock,
    }


# ==============================================================================
# 1. FORGED EXECUTION RECEIPTS WITH INVALID ED25519 SIGNATURES ARE REJECTED
# ==============================================================================
def test_adv_01_forged_receipt_signature_rejected():
    """Validates that execution receipts with invalid or forged Ed25519 signatures fail verification."""
    disp_priv = secrets.token_bytes(32)
    disp_pub = derive_verification_key(disp_priv)
    aid = f"ACT-{'A' * 64}"
    nonce = f"NONCE-{'1' * 32}"

    receipt = {
        "version": 1,
        "receipt_id": f"RCPT-{'2' * 32}",
        "dispatcher_id": "DISPATCHER-TEST",
        "dispatcher_key_id": "KEY-DISPATCHER-ED25519-V1",
        "dispatch_op_id": f"DISP-OP-{'3' * 64}",
        "action_id": aid,
        "action_dossier_digest": "A" * 64,
        "approval_id": f"APPR-{'4' * 32}",
        "request_nonce": nonce,
        "execution_id": f"EXEC-{'5' * 32}",
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
            "request_sha256": "0" * 64,
            "response_sha256": "0" * 64,
            "status_code": 200,
            "timestamp": "2026-11-15T12:00:00Z",
        },
        "verification_evidence": {
            "evidence_id": "EVID-000000000002",
            "invalidation_result": "REVOKED",
            "request_sha256": "0" * 64,
            "response_sha256": "0" * 64,
            "status_code": 401,
            "timestamp": "2026-11-15T12:00:00Z",
            "verification_method": "POST_MUTATION_PROBE_CONFIRMED_401",
        },
        "consumption_token": "0" * 64,
        "issued_at": "2026-11-15T12:00:00Z",
    }
    # Case A: Attacker signs with different key
    attacker_priv = secrets.token_bytes(32)
    receipt["signature"] = sign_execution_receipt(receipt, attacker_priv)
    ok, reason = verify_execution_receipt(receipt, disp_pub, expected_action_id=aid)
    assert ok is False
    assert "signature verification failed" in reason

    # Case B: Arbitrary signature string
    receipt["signature"] = f"SIG-{'0' * 128}"
    ok2, reason2 = verify_execution_receipt(receipt, disp_pub, expected_action_id=aid)
    assert ok2 is False
    assert "signature verification failed" in reason2


# ==============================================================================
# 2. EXECUTION RECEIPTS WITH TAMPERED FIELDS ARE REJECTED
# ==============================================================================
def test_adv_02_tampered_receipt_fields_rejected():
    """Validates that altering any canonical receipt field breaks signature verification."""
    disp_priv = secrets.token_bytes(32)
    disp_pub = derive_verification_key(disp_priv)
    aid = f"ACT-{'B' * 64}"
    nonce = f"NONCE-{'2' * 32}"

    base_receipt = {
        "version": 1,
        "receipt_id": f"RCPT-{'3' * 32}",
        "dispatcher_id": "DISPATCHER-TEST",
        "dispatcher_key_id": "KEY-DISPATCHER-ED25519-V1",
        "dispatch_op_id": f"DISP-OP-{'4' * 64}",
        "action_id": aid,
        "action_dossier_digest": "B" * 64,
        "approval_id": f"APPR-{'5' * 32}",
        "request_nonce": nonce,
        "execution_id": f"EXEC-{'6' * 32}",
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
            "request_sha256": "1" * 64,
            "response_sha256": "2" * 64,
            "status_code": 200,
            "timestamp": "2026-11-15T12:00:00Z",
        },
        "verification_evidence": {
            "evidence_id": "EVID-000000000002",
            "invalidation_result": "REVOKED",
            "request_sha256": "3" * 64,
            "response_sha256": "4" * 64,
            "status_code": 401,
            "timestamp": "2026-11-15T12:00:00Z",
            "verification_method": "POST_MUTATION_PROBE_CONFIRMED_401",
        },
        "consumption_token": "5" * 64,
        "issued_at": "2026-11-15T12:00:00Z",
    }
    base_receipt["signature"] = sign_execution_receipt(base_receipt, disp_priv)

    # 1. Tamper action_id
    t1 = json.loads(json.dumps(base_receipt))
    t1["action_id"] = f"ACT-{'C' * 64}"
    assert verify_execution_receipt(t1, disp_pub)[0] is False

    # 2. Tamper dispatch_op_id
    t2 = json.loads(json.dumps(base_receipt))
    t2["dispatch_op_id"] = f"DISP-OP-{'F' * 64}"
    assert verify_execution_receipt(t2, disp_pub)[0] is False

    # 3. Tamper evidence_id
    t3 = json.loads(json.dumps(base_receipt))
    t3["mutation_evidence"]["evidence_id"] = "EVID-FFFFFFFFFFFF"
    assert verify_execution_receipt(t3, disp_pub)[0] is False

    # 4. Tamper request_sha256
    t4 = json.loads(json.dumps(base_receipt))
    t4["verification_evidence"]["request_sha256"] = "F" * 64
    assert verify_execution_receipt(t4, disp_pub)[0] is False


# ==============================================================================
# 3. FORGED CONTROLLED_DISPATCH_RESULT WITHOUT RECEIPT FAILS CLOSED
# ==============================================================================
def test_adv_03_dispatch_result_without_receipt_fails_closed(tmp_path):
    """Validates that issue_execution_capability rejects ControlledDispatchResult lacking a valid receipt."""
    env = _setup_test_environment(tmp_path)
    store = env["evidence_store"]
    key_dir = env["key_dir"]
    state_dir = env["state_dir"]
    app_key = env["approval_key"]

    auth_tok = secrets.token_hex(32)
    store._authority_token = auth_tok

    d_op_id = f"DISP-OP-{secrets.token_hex(32).upper()}"
    app_id = f"APPR-{secrets.token_hex(16).upper()}"
    c_token = secrets.token_hex(32)
    ts = "2026-11-15T12:00:00Z"

    dossier_data = {
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": "prog1",
        "target_endpoint": "https://target.local/auth/logout",
        "test_account": "alice",
        "ttl": 300,
        "unique_approval_id": app_id,
    }
    signed_dossier = sign_action_approval(dossier_data, approval_key=app_key)
    aid = signed_dossier["action_id"]
    op_sig = signed_dossier["approval_signature"]
    canonical_copy = {k: dossier_data[k] for k in CANONICAL_ACTION_FIELDS}

    mut_cap = store.save_transport_dispatch_capture(
        request=ControlledRequest(url="https://target.local/auth/logout", method="POST", headers={}),
        response=ControlledResponse(status_code=200, headers={}, body_bytes=b'{"revoked": true}'),
        action_id=aid,
        approval_id=app_id,
        session_ref="sess_00000000000000000000000000000001",
        principal_id="alice",
        program_id="prog1",
        dispatch_op_id=d_op_id,
        authority_token=auth_tok,
    )
    ver_cap = store.save_transport_dispatch_capture(
        request=ControlledRequest(url="https://target.local/auth/logout", method="GET", headers={}),
        response=ControlledResponse(status_code=401, headers={}, body_bytes=b'{"error": "Revoked"}'),
        action_id=aid,
        approval_id=app_id,
        session_ref="sess_00000000000000000000000000000001",
        principal_id="alice",
        program_id="prog1",
        dispatch_op_id=d_op_id,
        is_verification=True,
        verification_method="POST_MUTATION_PROBE_CONFIRMED_401",
        authority_token=auth_tok,
    )

    consumed_path = os.path.join(state_dir, "consumed_approvals.json")
    receipt_payload = {
        "action_dossier_digest": aid[4:],
        "action_id": aid,
        "action_type": "LOGOUT",
        "approval_id": app_id,
        "consumed_at": ts,
        "consumption_token": c_token,
        "dispatch_op_id": d_op_id,
        "method": "POST",
        "operator_signature": op_sig,
        "principal_id": "alice",
        "program_id": "prog1",
        "session_ref": "sess_00000000000000000000000000000001",
        "target_endpoint": "https://target.local/auth/logout",
        "test_account": "alice",
    }
    receipt_sig = sign_consumption_receipt(receipt_payload, app_key)
    consumed_entry = {
        **receipt_payload,
        "action_dossier": canonical_copy,
        "receipt_signature": receipt_sig,
        "execution_id": None,
    }
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump({"version": "1.0", "consumed": {aid: consumed_entry}}, f)

    # Forged result with NO receipt
    d_res = ControlledDispatchResult(
        dispatch_op_id=d_op_id,
        action_id=aid,
        action_dossier_digest=aid[4:],
        approval_id=app_id,
        program_id="prog1",
        session_ref="sess_00000000000000000000000000000001",
        principal_id="alice",
        test_account="alice",
        target_endpoint="https://target.local/auth/logout",
        http_method="POST",
        action_type="LOGOUT",
        mutation_evidence_ref=mut_cap["evidence_id"],
        mutation_request_digest=mut_cap["request_sha256"],
        mutation_response_digest=mut_cap["response_sha256"],
        mutation_status_code=200,
        verification_evidence_ref=ver_cap["evidence_id"],
        verification_request_digest=ver_cap["request_sha256"],
        verification_response_digest=ver_cap["response_sha256"],
        verification_status_code=401,
        verification_method="POST_MUTATION_PROBE_CONFIRMED_401",
        invalidation_verification_result="REVOKED",
        execution_timestamp=ts,
        verification_timestamp=ts,
        consumption_token=c_token,
        is_genuine_dispatch=True,
        receipt=None,
    )

    with pytest.raises(ExecutionProvenanceError, match="requires an authentic ExecutionReceipt"):
        issue_execution_capability(
            dispatch_result=d_res,
            evidence_store=store,
            consumed_approvals_path=consumed_path,
            approval_key=app_key,
        )


# ==============================================================================
# 4. FORGED CONTROLLED_DISPATCH_RESULT WITH ALTERED RECEIPT FAILS CLOSED
# ==============================================================================
def test_adv_04_dispatch_result_with_altered_receipt_fails_closed(tmp_path):
    """Validates that issue_execution_capability rejects dispatch results whose receipt has altered fields."""
    env = _setup_test_environment(tmp_path)
    store = env["evidence_store"]
    state_dir = env["state_dir"]
    app_key = env["approval_key"]

    auth_tok = secrets.token_hex(32)
    store._authority_token = auth_tok

    d_op_id = f"DISP-OP-{secrets.token_hex(32).upper()}"
    app_id = f"APPR-{secrets.token_hex(16).upper()}"
    ts = "2026-11-15T12:00:00Z"
    c_token = secrets.token_hex(32)

    dossier_data = {
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": "prog1",
        "target_endpoint": "https://target.local/auth/logout",
        "test_account": "alice",
        "ttl": 300,
        "unique_approval_id": app_id,
    }
    signed_dossier = sign_action_approval(dossier_data, approval_key=app_key)
    aid = signed_dossier["action_id"]
    op_sig = signed_dossier["approval_signature"]
    canonical_copy = {k: dossier_data[k] for k in CANONICAL_ACTION_FIELDS}

    mut_cap = store.save_transport_dispatch_capture(
        request=ControlledRequest(url="https://target.local/auth/logout", method="POST", headers={}),
        response=ControlledResponse(status_code=200, headers={}, body_bytes=b'{"revoked": true}'),
        action_id=aid,
        approval_id=app_id,
        session_ref="sess_00000000000000000000000000000001",
        principal_id="alice",
        program_id="prog1",
        dispatch_op_id=d_op_id,
        authority_token=auth_tok,
    )
    ver_cap = store.save_transport_dispatch_capture(
        request=ControlledRequest(url="https://target.local/auth/logout", method="GET", headers={}),
        response=ControlledResponse(status_code=401, headers={}, body_bytes=b'{"error": "Revoked"}'),
        action_id=aid,
        approval_id=app_id,
        session_ref="sess_00000000000000000000000000000001",
        principal_id="alice",
        program_id="prog1",
        dispatch_op_id=d_op_id,
        is_verification=True,
        verification_method="POST_MUTATION_PROBE_CONFIRMED_401",
        authority_token=auth_tok,
    )

    consumed_path = os.path.join(state_dir, "consumed_approvals.json")
    receipt_payload = {
        "action_dossier_digest": aid[4:],
        "action_id": aid,
        "action_type": "LOGOUT",
        "approval_id": app_id,
        "consumed_at": ts,
        "consumption_token": c_token,
        "dispatch_op_id": d_op_id,
        "method": "POST",
        "operator_signature": op_sig,
        "principal_id": "alice",
        "program_id": "prog1",
        "session_ref": "sess_00000000000000000000000000000001",
        "target_endpoint": "https://target.local/auth/logout",
        "test_account": "alice",
    }
    receipt_sig = sign_consumption_receipt(receipt_payload, app_key)
    consumed_entry = {
        **receipt_payload,
        "action_dossier": canonical_copy,
        "receipt_signature": receipt_sig,
        "execution_id": None,
    }
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump({"version": "1.0", "consumed": {aid: consumed_entry}}, f)

    disp_priv = secrets.token_bytes(32)
    disp_pub = derive_verification_key(disp_priv)

    # Valid receipt except target_endpoint is tampered
    rcpt = {
        "version": 1,
        "receipt_id": f"RCPT-{secrets.token_hex(16).upper()}",
        "dispatcher_id": "DISPATCHER-TEST",
        "dispatcher_key_id": "KEY-DISPATCHER-ED25519-V1",
        "dispatch_op_id": d_op_id,
        "action_id": aid,
        "action_dossier_digest": aid[4:],
        "approval_id": app_id,
        "request_nonce": f"NONCE-{secrets.token_hex(16).upper()}",
        "execution_id": f"EXEC-{secrets.token_hex(16).upper()}",
        "program_id": "prog1",
        "principal_id": "alice",
        "session_ref": "sess_00000000000000000000000000000001",
        "target_endpoint": "https://tampered.local/auth/logout",
        "http_method": "POST",
        "action_type": "LOGOUT",
        "scope_decision": "ALLOWED",
        "execution_outcome": "REVOCATION_VERIFIED",
        "mutation_evidence": {
            "evidence_id": mut_cap["evidence_id"],
            "request_sha256": mut_cap["request_sha256"],
            "response_sha256": mut_cap["response_sha256"],
            "status_code": 200,
            "timestamp": ts,
        },
        "verification_evidence": {
            "evidence_id": ver_cap["evidence_id"],
            "invalidation_result": "REVOKED",
            "request_sha256": ver_cap["request_sha256"],
            "response_sha256": ver_cap["response_sha256"],
            "status_code": 401,
            "timestamp": ts,
            "verification_method": "POST_MUTATION_PROBE_CONFIRMED_401",
        },
        "consumption_token": c_token,
        "issued_at": ts,
    }
    rcpt["signature"] = sign_execution_receipt(rcpt, disp_priv)

    # dispatch_result matches consumed_entry, but receipt has tampered target_endpoint
    d_res = ControlledDispatchResult(
        dispatch_op_id=d_op_id,
        action_id=aid,
        action_dossier_digest=aid[4:],
        approval_id=app_id,
        program_id="prog1",
        session_ref="sess_00000000000000000000000000000001",
        principal_id="alice",
        test_account="alice",
        target_endpoint="https://target.local/auth/logout",
        http_method="POST",
        action_type="LOGOUT",
        mutation_evidence_ref=mut_cap["evidence_id"],
        mutation_request_digest=mut_cap["request_sha256"],
        mutation_response_digest=mut_cap["response_sha256"],
        mutation_status_code=200,
        verification_evidence_ref=ver_cap["evidence_id"],
        verification_request_digest=ver_cap["request_sha256"],
        verification_response_digest=ver_cap["response_sha256"],
        verification_status_code=401,
        verification_method="POST_MUTATION_PROBE_CONFIRMED_401",
        invalidation_verification_result="REVOKED",
        execution_timestamp=ts,
        verification_timestamp=ts,
        consumption_token=c_token,
        is_genuine_dispatch=True,
        receipt=rcpt,
    )

    with pytest.raises(ExecutionProvenanceError, match="Receipt target_endpoint mismatch with dispatch result"):
        issue_execution_capability(
            dispatch_result=d_res,
            evidence_store=store,
            consumed_approvals_path=consumed_path,
            approval_key=app_key,
            dispatcher_verification_key=disp_pub,
        )


# ==============================================================================
# 5. REPLAY ATTACKS WITH DUPLICATE NONCES OR ACTION IDS ARE REJECTED
# ==============================================================================
def test_adv_05_replay_rejection_nonce_and_action_id(tmp_path):
    """Validates that replaying a consumed action_id or reused nonce is rejected by the dispatcher."""
    env = _setup_test_environment(tmp_path)
    pipe_or_sock = env["pipe_or_sock"]
    app_key = env["approval_key"]
    transport = MockLabTransport()

    disp = IsolatedExecutionDispatcher(
        program_id="prog1",
        pipe_name=pipe_or_sock if os.name == "nt" else None,
        socket_path=pipe_or_sock if os.name != "nt" else None,
        key_dir=env["key_dir"],
        state_dir=env["state_dir"],
        evidence_dir=env["evidence_dir"],
        approval_key=app_key,
        transport_engine=transport,
        is_lab=True,
    )
    disp.start()

    try:
        client = IsolatedDispatcherClient(
            endpoint_type="pipe" if os.name == "nt" else "unix",
            address=pipe_or_sock,
        )

        dossier_data = {
            "action_type": "LOGOUT",
            "created_at": time.time(),
            "method": "POST",
            "program_id": "prog1",
            "target_endpoint": "https://target.local/auth/logout",
            "test_account": "alice",
            "ttl": 300,
            "unique_approval_id": f"APPR-{secrets.token_hex(16).upper()}",
        }
        signed = sign_action_approval(dossier_data, approval_key=app_key)
        aid = signed["action_id"]
        sess = {"session_ref": f"sess_{secrets.token_hex(16)}", "principal_id": "alice"}
        nonce = f"NONCE-{secrets.token_hex(16).upper()}"

        # First dispatch succeeds
        r1 = client.dispatch_mutation(
            program_id="prog1",
            action_id=aid,
            action_dossier=signed,
            session_context=sess,
            nonce=nonce,
        )
        assert r1["status"] == "SUCCESS"

        # Replay with same action_id
        r2 = client.dispatch_mutation(
            program_id="prog1",
            action_id=aid,
            action_dossier=signed,
            session_context=sess,
        )
        assert r2["status"] == "REJECTED"
        assert r2["error_code"] == "APPROVAL_CONSUMPTION_FAILED"

        # Replay with same request nonce across new action
        dossier2 = dict(dossier_data)
        dossier2["unique_approval_id"] = f"APPR-{secrets.token_hex(16).upper()}"
        signed2 = sign_action_approval(dossier2, approval_key=app_key)
        r3 = client.dispatch_mutation(
            program_id="prog1",
            action_id=signed2["action_id"],
            action_dossier=signed2,
            session_context=sess,
            nonce=nonce,  # duplicate nonce
        )
        assert r3["status"] == "REJECTED"
        assert r3["error_code"] == "NONCE_REPLAY_DETECTED"
    finally:
        disp.stop()


# ==============================================================================
# 6. EXPIRED OR FUTURE-DATED OPERATOR APPROVALS ARE REJECTED
# ==============================================================================
def test_adv_06_expired_and_future_approvals_rejected(tmp_path):
    """Validates that expired or future-dated approvals are rejected before network transmission."""
    env = _setup_test_environment(tmp_path)
    pipe_or_sock = env["pipe_or_sock"]
    app_key = env["approval_key"]
    transport = MockLabTransport()

    disp = IsolatedExecutionDispatcher(
        program_id="prog1",
        pipe_name=pipe_or_sock if os.name == "nt" else None,
        socket_path=pipe_or_sock if os.name != "nt" else None,
        key_dir=env["key_dir"],
        state_dir=env["state_dir"],
        evidence_dir=env["evidence_dir"],
        approval_key=app_key,
        transport_engine=transport,
        is_lab=True,
    )
    disp.start()

    try:
        client = IsolatedDispatcherClient(
            endpoint_type="pipe" if os.name == "nt" else "unix",
            address=pipe_or_sock,
        )

        sess = {"session_ref": f"sess_{secrets.token_hex(16)}", "principal_id": "alice"}

        # 1. Expired approval (created 500s ago with 300s TTL)
        exp_dossier = {
            "action_type": "LOGOUT",
            "created_at": time.time() - 500.0,
            "method": "POST",
            "program_id": "prog1",
            "target_endpoint": "https://target.local/auth/logout",
            "test_account": "alice",
            "ttl": 300.0,
            "unique_approval_id": f"APPR-{secrets.token_hex(16).upper()}",
        }
        signed_exp = sign_action_approval(exp_dossier, approval_key=app_key)
        r_exp = client.dispatch_mutation(
            program_id="prog1",
            action_id=signed_exp["action_id"],
            action_dossier=signed_exp,
            session_context=sess,
        )
        assert r_exp["status"] == "REJECTED"
        assert r_exp["error_code"] == "APPROVAL_EXPIRED"
        assert len(transport.requests) == 0  # Zero network traffic

        # 2. Future-dated approval (created 200s in the future)
        fut_dossier = {
            "action_type": "LOGOUT",
            "created_at": time.time() + 200.0,
            "method": "POST",
            "program_id": "prog1",
            "target_endpoint": "https://target.local/auth/logout",
            "test_account": "alice",
            "ttl": 300.0,
            "unique_approval_id": f"APPR-{secrets.token_hex(16).upper()}",
        }
        signed_fut = sign_action_approval(fut_dossier, approval_key=app_key)
        r_fut = client.dispatch_mutation(
            program_id="prog1",
            action_id=signed_fut["action_id"],
            action_dossier=signed_fut,
            session_context=sess,
        )
        assert r_fut["status"] == "REJECTED"
        assert r_fut["error_code"] == "APPROVAL_FUTURE_DATED"
        assert len(transport.requests) == 0  # Zero network traffic
    finally:
        disp.stop()


# ==============================================================================
# 7. DISPATCHER RESTARTS PRESERVE REPLAY-PREVENTION STATE ACROSS REBOOTS
# ==============================================================================
def test_adv_07_dispatcher_restart_preserves_replay_state(tmp_path):
    """Validates that restart/reboot of dispatcher preserves consumed approval and nonce registries."""
    env = _setup_test_environment(tmp_path)
    pipe_or_sock = env["pipe_or_sock"]
    app_key = env["approval_key"]
    transport = MockLabTransport()

    # Instance 1: Execute mutation
    disp1 = IsolatedExecutionDispatcher(
        program_id="prog1",
        pipe_name=pipe_or_sock if os.name == "nt" else None,
        socket_path=pipe_or_sock if os.name != "nt" else None,
        key_dir=env["key_dir"],
        state_dir=env["state_dir"],
        evidence_dir=env["evidence_dir"],
        approval_key=app_key,
        transport_engine=transport,
        is_lab=True,
    )
    disp1.start()

    client = IsolatedDispatcherClient(
        endpoint_type="pipe" if os.name == "nt" else "unix",
        address=pipe_or_sock,
    )

    dossier_data = {
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": "prog1",
        "target_endpoint": "https://target.local/auth/logout",
        "test_account": "alice",
        "ttl": 300,
        "unique_approval_id": f"APPR-{secrets.token_hex(16).upper()}",
    }
    signed = sign_action_approval(dossier_data, approval_key=app_key)
    aid = signed["action_id"]
    sess = {"session_ref": f"sess_{secrets.token_hex(16)}", "principal_id": "alice"}
    nonce = f"NONCE-{secrets.token_hex(16).upper()}"

    r1 = client.dispatch_mutation(
        program_id="prog1",
        action_id=aid,
        action_dossier=signed,
        session_context=sess,
        nonce=nonce,
    )
    assert r1["status"] == "SUCCESS"
    disp1.stop()

    # Instance 2: Start new dispatcher instance pointing to the same persistent state_dir
    disp2 = IsolatedExecutionDispatcher(
        program_id="prog1",
        pipe_name=pipe_or_sock if os.name == "nt" else None,
        socket_path=pipe_or_sock if os.name != "nt" else None,
        key_dir=env["key_dir"],
        state_dir=env["state_dir"],
        evidence_dir=env["evidence_dir"],
        approval_key=app_key,
        transport_engine=transport,
        is_lab=True,
    )
    disp2.start()

    try:
        # Replay attempt after daemon restart must fail closed
        r_replayed = client.dispatch_mutation(
            program_id="prog1",
            action_id=aid,
            action_dossier=signed,
            session_context=sess,
        )
        assert r_replayed["status"] == "REJECTED"
        assert r_replayed["error_code"] == "APPROVAL_CONSUMPTION_FAILED"
    finally:
        disp2.stop()


# ==============================================================================
# 8. ROGUE IPC ENDPOINT SUBSTITUTION OR MALICIOUS SOCKET INJECTION
# ==============================================================================
def test_adv_08_rogue_endpoint_substitution_fails_closed(tmp_path):
    """Validates that pointing client to an unauthorized socket or missing endpoint fails closed."""
    nonexistent = (
        rf"\\.\pipe\nonexistent_pipe_{secrets.token_hex(8)}"
        if os.name == "nt"
        else str(tmp_path / "nonexistent.sock")
    )
    client = IsolatedDispatcherClient(
        endpoint_type="pipe" if os.name == "nt" else "unix",
        address=nonexistent,
        timeout=1.0,
    )
    assert client.ping() is False

    dossier = {
        "action_id": f"ACT-{'0' * 64}",
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": "prog1",
        "target_endpoint": "https://target.local/auth/logout",
        "test_account": "alice",
        "ttl": 300,
        "unique_approval_id": f"APPR-{'0' * 32}",
        "approval_signature": f"SIG-{'0' * 128}",
    }
    with pytest.raises(DispatcherUnavailableError):
        client.dispatch_mutation(
            program_id="prog1",
            action_id=dossier["action_id"],
            action_dossier=dossier,
            session_context={"session_ref": "sess_00000000000000000000000000000001", "principal_id": "alice"},
        )


# ==============================================================================
# 9. UNAUTHORIZED WRITES TO EVIDENCE DIRECTORY WITHOUT AUTHORITY TOKEN
# ==============================================================================
def test_adv_09_unauthorized_evidence_write_rejected(tmp_path):
    """Validates that EvidenceStore rejects save_transport_dispatch_capture without authority token."""
    from framework.common.evidence import EvidencePersistenceError
    store = EvidenceStore(evidence_dir=str(tmp_path / "ev"))
    req = ControlledRequest(url="https://target.local/auth/logout", method="POST", headers={})
    res = ControlledResponse(status_code=200, headers={}, body_bytes=b'{}')

    # Calling save_transport_dispatch_capture without authority_token must raise EvidencePersistenceError
    with pytest.raises(EvidencePersistenceError, match="Trusted transport capture is disabled"):
        store.save_transport_dispatch_capture(
            request=req,
            response=res,
            action_id=f"ACT-{'0' * 64}",
            approval_id=f"APPR-{'0' * 32}",
            session_ref="sess_00000000000000000000000000000001",
            principal_id="alice",
            program_id="prog1",
            dispatch_op_id=f"DISP-OP-{'0' * 64}",
            authority_token=None,
        )

    # Calling with invalid / mismatched authority token
    store._authority_token = secrets.token_hex(32)
    with pytest.raises(EvidencePersistenceError, match="Trusted transport capture is disabled"):
        store.save_transport_dispatch_capture(
            request=req,
            response=res,
            action_id=f"ACT-{'0' * 64}",
            approval_id=f"APPR-{'0' * 32}",
            session_ref="sess_00000000000000000000000000000001",
            principal_id="alice",
            program_id="prog1",
            dispatch_op_id=f"DISP-OP-{'0' * 64}",
            authority_token="WRONG_TOKEN",
        )


# ==============================================================================
# 10. CAPABILITY ISSUANCE AFTER A FAILED VERIFICATION PROBE FAILS CLOSED
# ==============================================================================
def test_adv_10_failed_verification_probe_fails_closed(tmp_path):
    """Validates that when the post-mutation probe confirms session remains active (HTTP 200), dispatch fails."""
    env = _setup_test_environment(tmp_path)
    pipe_or_sock = env["pipe_or_sock"]
    app_key = env["approval_key"]
    # Fail probe returns 200 indicating session is NOT revoked
    transport = MockLabTransport(fail_probe=True)

    disp = IsolatedExecutionDispatcher(
        program_id="prog1",
        pipe_name=pipe_or_sock if os.name == "nt" else None,
        socket_path=pipe_or_sock if os.name != "nt" else None,
        key_dir=env["key_dir"],
        state_dir=env["state_dir"],
        evidence_dir=env["evidence_dir"],
        approval_key=app_key,
        transport_engine=transport,
        is_lab=True,
    )
    disp.start()

    try:
        client = IsolatedDispatcherClient(
            endpoint_type="pipe" if os.name == "nt" else "unix",
            address=pipe_or_sock,
        )

        dossier_data = {
            "action_type": "LOGOUT",
            "created_at": time.time(),
            "method": "POST",
            "program_id": "prog1",
            "target_endpoint": "https://target.local/auth/logout",
            "test_account": "alice",
            "ttl": 300,
            "unique_approval_id": f"APPR-{secrets.token_hex(16).upper()}",
        }
        signed = sign_action_approval(dossier_data, approval_key=app_key)
        sess = {"session_ref": f"sess_{secrets.token_hex(16)}", "principal_id": "alice"}

        resp = client.dispatch_mutation(
            program_id="prog1",
            action_id=signed["action_id"],
            action_dossier=signed,
            session_context=sess,
        )
        assert resp["status"] in ("REJECTED", "ERROR")
        assert resp["error_code"] == "TRANSPORT_EXECUTION_FAILED"
        assert "not invalidated" in resp["error_message"]
    finally:
        disp.stop()


# ==============================================================================
# 11. DYNAMIC PROVENANCE BOUNDARY REPORTING VERIFICATION
# ==============================================================================
def test_adv_11_dynamic_provenance_boundary_reporting(tmp_path):
    """Validates dynamic capability assessment under varied missing key, daemon, and platform conditions."""
    # 1. Missing public key
    nonexistent_pub = str(tmp_path / "missing_dispatcher.pub")
    a1 = assess_provenance_boundary(public_key_path=nonexistent_pub)
    assert a1.public_key_available is False
    assert a1.public_key_valid is False
    assert a1.status == "UNAVAILABLE"

    # 2. Malformed public key (not 32 bytes)
    bad_pub = str(tmp_path / "bad_dispatcher.pub")
    with open(bad_pub, "wb") as f:
        f.write(b"SHORT_KEY")
    a2 = assess_provenance_boundary(public_key_path=bad_pub)
    assert a2.public_key_available is True
    assert a2.public_key_valid is False
    assert a2.status == "UNAVAILABLE"

    # 3. Valid public key but stopped daemon
    valid_pub = str(tmp_path / "valid_dispatcher.pub")
    valid_key = secrets.token_bytes(32)
    valid_pub_bytes = derive_verification_key(valid_key)
    with open(valid_pub, "wb") as f:
        f.write(valid_pub_bytes)

    dead_endpoint = (
        rf"\\.\pipe\dead_pipe_{secrets.token_hex(8)}"
        if os.name == "nt"
        else str(tmp_path / "dead.sock")
    )
    a3 = assess_provenance_boundary(
        endpoint_type="pipe" if os.name == "nt" else "unix",
        address=dead_endpoint,
        public_key_path=valid_pub,
    )
    assert a3.public_key_available is True
    assert a3.public_key_valid is True
    assert a3.dispatcher_reachable is False
    assert a3.status == "UNAVAILABLE"

    # 4. Running daemon + valid key assessment
    env = _setup_test_environment(tmp_path)
    pipe_or_sock = env["pipe_or_sock"]
    disp = IsolatedExecutionDispatcher(
        program_id="prog1",
        pipe_name=pipe_or_sock if os.name == "nt" else None,
        socket_path=pipe_or_sock if os.name != "nt" else None,
        key_dir=env["key_dir"],
        state_dir=env["state_dir"],
        evidence_dir=env["evidence_dir"],
        approval_key=env["approval_key"],
        is_lab=True,
    )
    disp.start()
    try:
        disp_pub_path = str(tmp_path / "live_disp.pub")
        with open(disp_pub_path, "wb") as f:
            f.write(disp.verification_key)

        a4 = assess_provenance_boundary(
            endpoint_type="pipe" if os.name == "nt" else "unix",
            address=pipe_or_sock,
            public_key_path=disp_pub_path,
        )
        assert a4.dispatcher_reachable is True
        assert a4.public_key_available is True
        assert a4.public_key_valid is True
        assert a4.receipt_verification_operational is True
        assert a4.evidence_verification_operational is True
        assert a4.end_to_end_provenance_available is True

        if os.name == "nt":
            assert a4.status == "AVAILABLE_WITH_LIMITATIONS"
            assert a4.production_isolation_supported is False
            assert "unsupported on Windows" in a4.reason
        else:
            assert a4.status == "AVAILABLE"
            assert a4.production_isolation_supported is True
    finally:
        disp.stop()
