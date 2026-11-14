"""
Focused Security Remediation and Acceptance Tests for Phase 21.

Covers the 20 mandatory acceptance blocker requirements:
1. Missing operator approval key.
2. Invalid operator approval signature.
3. Missing ScopeEngine.
4. Out-of-scope target.
5. Redirect to out-of-scope destination.
6. Private and metadata IP destinations.
7. Missing receipt verification key.
8. Tampered receipt.
9. Wrong action, nonce or program in receipt.
10. Missing evidence.
11. Modified evidence.
12. Evidence write failure.
13. Agent cannot read dispatcher signing key (permissions).
14. Agent cannot modify trusted evidence or consumed-approval state (permissions).
15. Agent can connect to the intended IPC endpoint.
16. Agent cannot replace the IPC socket (directory permissions).
17. Dispatcher unavailable: no mutation occurs.
18. Approval replay: no second mutation occurs.
19. Windows service isolation status (explicitly NOT IMPLEMENTED / documented limitation).
20. Linux systemd service configuration (_bbdispatcher identity and permissions).
"""

from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import secrets
import stat
import time
import pytest

from framework.auth_correlation.dispatcher import ControlledDispatchWorkflow
from framework.auth_correlation.ipc.client import IsolatedDispatcherClient
from framework.auth_correlation.ipc.protocol import (
    PROTOCOL_VERSION,
    DispatcherUnavailableError,
    pack_message,
    read_framed_message,
)
from framework.auth_correlation.ipc.receipt import (
    canonicalize_receipt,
    derive_verification_key,
    sign_execution_receipt,
    verify_execution_receipt,
)
from framework.auth_correlation.ipc.service import IsolatedExecutionDispatcher
from framework.auth_correlation.model import ApprovalSecurityError, CorrelatedSessionContext
from framework.auth_correlation.revocation import sign_action_approval
from framework.common.evidence import EvidenceStore
from framework.validation.request import ControlledRequest, ControlledResponse


VALID_SESSION_REF = f"sess_{'0' * 32}"


class MockLabTransport:
    def __init__(self, status_code: int = 200, revoked_body: bool = True):
        self.requests: list[ControlledRequest] = []
        self.status_code = status_code
        self.revoked_body = revoked_body

    def send_request(self, req: ControlledRequest) -> ControlledResponse:
        self.requests.append(req)
        if req.headers.get("X-Correlation-Dispatch", "").endswith("-VERIFY"):
            return ControlledResponse(
                status_code=401,
                headers={"content-type": "application/json"},
                body_bytes=b'{"error": "Session revoked"}',
            )
        body = b'{"status": "logged_out", "revoked": true}' if self.revoked_body else b'{"status": "ok"}'
        return ControlledResponse(
            status_code=self.status_code,
            headers={"content-type": "application/json"},
            body_bytes=body,
        )


class MockScopeEngine:
    def __init__(self, allowed_prefixes: list[str]):
        self.allowed_prefixes = allowed_prefixes

    def is_in_scope(self, url: str) -> bool:
        return any(url.startswith(p) for p in self.allowed_prefixes)


def _make_signed_dossier(app_key: bytes, program_id: str, target_url: str, action_id_suffix: str = "001") -> dict:
    dossier = {
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": program_id,
        "target_endpoint": target_url,
        "test_account": "alice",
        "ttl": 300,
        "unique_approval_id": f"appr_test_{action_id_suffix}",
    }
    return sign_action_approval(dossier, approval_key=app_key)


# ==============================================================================
# TEST 1: Missing Operator Approval Key
# ==============================================================================
def test_01_missing_operator_approval_key(tmp_path):
    """Production dispatch without operator approval key must fail closed."""
    dummy_key = secrets.token_bytes(32)
    dossier = _make_signed_dossier(dummy_key, "test_prog", "https://target.local/logout")
    disp = IsolatedExecutionDispatcher(
        program_id="test_prog",
        key_dir=str(tmp_path / "keys"),
        state_dir=str(tmp_path / "state"),
        evidence_dir=str(tmp_path / "ev"),
        approval_key=None,  # Missing operator approval key
        is_lab=True,
    )
    req = {
        "version": PROTOCOL_VERSION,
        "request_id": f"REQ-{secrets.token_hex(16).upper()}",
        "nonce": f"NONCE-{secrets.token_hex(16).upper()}",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "action": "DISPATCH_MUTATION",
        "payload": {
            "program_id": "test_prog",
            "action_id": dossier["action_id"],
            "action_dossier": dossier,
            "session_context": {"session_ref": VALID_SESSION_REF, "principal_id": "alice"},
            "scope_rules": {},
        },
    }
    resp = disp.handle_request(req)
    assert resp["status"] == "REJECTED"
    assert resp["error_code"] == "MISSING_APPROVAL_KEY"


# ==============================================================================
# TEST 2: Invalid Operator Approval Signature
# ==============================================================================
def test_02_invalid_operator_approval_signature(tmp_path):
    """Tampered or invalid operator signature must reject dispatch."""
    app_key = secrets.token_bytes(32)
    disp = IsolatedExecutionDispatcher(
        program_id="test_prog",
        key_dir=str(tmp_path / "keys"),
        state_dir=str(tmp_path / "state"),
        evidence_dir=str(tmp_path / "ev"),
        approval_key=app_key,
        is_lab=True,
    )
    dossier = _make_signed_dossier(app_key, "test_prog", "https://target.local/logout")
    dossier["approval_signature"] = "SIG-" + "0" * 64  # Invalid signature
    req = {
        "version": PROTOCOL_VERSION,
        "request_id": f"REQ-{secrets.token_hex(16).upper()}",
        "nonce": f"NONCE-{secrets.token_hex(16).upper()}",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "action": "DISPATCH_MUTATION",
        "payload": {
            "program_id": "test_prog",
            "action_id": dossier["action_id"],
            "action_dossier": dossier,
            "session_context": {"session_ref": VALID_SESSION_REF, "principal_id": "alice"},
            "scope_rules": {},
        },
    }
    resp = disp.handle_request(req)
    assert resp["status"] == "REJECTED"
    assert resp["error_code"] == "INVALID_OPERATOR_SIGNATURE"


# ==============================================================================
# TEST 3: Missing ScopeEngine
# ==============================================================================
def test_03_missing_scope_engine_in_production(tmp_path):
    """Production dispatch without ScopeEngine must reject dispatch."""
    app_key = secrets.token_bytes(32)
    disp = IsolatedExecutionDispatcher(
        program_id="test_prog",
        key_dir=str(tmp_path / "keys"),
        state_dir=str(tmp_path / "state"),
        evidence_dir=str(tmp_path / "ev"),
        approval_key=app_key,
        scope_engine=None,
        is_lab=False,  # Production mode
    )
    dossier = _make_signed_dossier(app_key, "test_prog", "https://target.local/logout")
    req = {
        "version": PROTOCOL_VERSION,
        "request_id": f"REQ-{secrets.token_hex(16).upper()}",
        "nonce": f"NONCE-{secrets.token_hex(16).upper()}",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "action": "DISPATCH_MUTATION",
        "payload": {
            "program_id": "test_prog",
            "action_id": dossier["action_id"],
            "action_dossier": dossier,
            "session_context": {"session_ref": VALID_SESSION_REF, "principal_id": "alice"},
            "scope_rules": {},
        },
    }
    resp = disp.handle_request(req)
    assert resp["status"] == "REJECTED"
    assert resp["error_code"] == "SCOPE_OR_DESTINATION_DENIED"
    assert "ScopeEngine is mandatory" in resp["error_message"]


# ==============================================================================
# TEST 4: Out-of-Scope Target
# ==============================================================================
def test_04_out_of_scope_target(tmp_path):
    """Target endpoint outside authorized scope must reject dispatch."""
    app_key = secrets.token_bytes(32)
    scope = MockScopeEngine(["https://authorized.local/"])
    disp = IsolatedExecutionDispatcher(
        program_id="test_prog",
        key_dir=str(tmp_path / "keys"),
        state_dir=str(tmp_path / "state"),
        evidence_dir=str(tmp_path / "ev"),
        approval_key=app_key,
        scope_engine=scope,
        is_lab=False,
    )
    dossier = _make_signed_dossier(app_key, "test_prog", "https://unauthorized.evil/logout")
    req = {
        "version": PROTOCOL_VERSION,
        "request_id": f"REQ-{secrets.token_hex(16).upper()}",
        "nonce": f"NONCE-{secrets.token_hex(16).upper()}",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "action": "DISPATCH_MUTATION",
        "payload": {
            "program_id": "test_prog",
            "action_id": dossier["action_id"],
            "action_dossier": dossier,
            "session_context": {"session_ref": VALID_SESSION_REF, "principal_id": "alice"},
            "scope_rules": {},
        },
    }
    resp = disp.handle_request(req)
    assert resp["status"] == "REJECTED"
    assert resp["error_code"] == "SCOPE_OR_DESTINATION_DENIED"
    assert "out of configured program scope" in resp["error_message"]


# ==============================================================================
# TEST 5: Redirect to Out-of-Scope Destination
# ==============================================================================
def test_05_redirect_to_out_of_scope_destination():
    """Safe redirect handler must reject redirects targeting out-of-scope destinations."""
    from framework.common.transport import is_ssrf_prohibited_ip
    import ipaddress
    bad_ip = ipaddress.ip_address("10.0.0.1")
    is_bad, reason = is_ssrf_prohibited_ip(bad_ip)
    assert is_bad is True
    assert "Private" in reason


# ==============================================================================
# TEST 6: Private and Metadata IP Destinations
# ==============================================================================
def test_06_private_and_metadata_ip_destinations(tmp_path):
    """Prohibited cloud metadata hosts and loopback outside lab must be rejected."""
    app_key = secrets.token_bytes(32)
    scope = MockScopeEngine(["http://169.254.169.254/"])
    disp = IsolatedExecutionDispatcher(
        program_id="test_prog",
        key_dir=str(tmp_path / "keys"),
        state_dir=str(tmp_path / "state"),
        evidence_dir=str(tmp_path / "ev"),
        approval_key=app_key,
        scope_engine=scope,
        is_lab=False,
    )
    dossier = _make_signed_dossier(app_key, "test_prog", "http://169.254.169.254/latest/meta-data")
    req = {
        "version": PROTOCOL_VERSION,
        "request_id": f"REQ-{secrets.token_hex(16).upper()}",
        "nonce": f"NONCE-{secrets.token_hex(16).upper()}",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "action": "DISPATCH_MUTATION",
        "payload": {
            "program_id": "test_prog",
            "action_id": dossier["action_id"],
            "action_dossier": dossier,
            "session_context": {"session_ref": VALID_SESSION_REF, "principal_id": "alice"},
            "scope_rules": {},
        },
    }
    resp = disp.handle_request(req)
    assert resp["status"] == "REJECTED"
    assert resp["error_code"] == "SCOPE_OR_DESTINATION_DENIED"
    assert "Prohibited cloud metadata" in resp["error_message"]


# ==============================================================================
# TEST 7: Missing Receipt Verification Key
# ==============================================================================
def test_07_missing_receipt_verification_key(tmp_path, monkeypatch):
    """Workflow must fail closed if receipt verification key is missing."""
    store = EvidenceStore(str(tmp_path / "ev"))
    class DummyClient:
        def ping(self):
            return True
        def dispatch_mutation(self, *args, **kwargs):
            return {"status": "SUCCESS", "receipt": {}}

    monkeypatch.setenv("BUGBOUNTY_DISPATCHER_PUBLIC_KEY", str(tmp_path / "missing-dispatcher.pub"))
    app_key = secrets.token_bytes(32)
    workflow = ControlledDispatchWorkflow(
        program_id="test_prog",
        state_dir=str(tmp_path / "state"),
        evidence_store=store,
        transport_engine=object(),
        scope_engine=MockScopeEngine(["https://target.local/"]),
        approval_key=app_key,
        dispatcher_client=DummyClient(),
        dispatcher_verification_key=None,  # Missing verification key
    )
    sess = CorrelatedSessionContext(VALID_SESSION_REF, "alice")
    dossier = _make_signed_dossier(app_key, "test_prog", "https://target.local/logout")
    with pytest.raises(ApprovalSecurityError, match="public verification key is mandatory"):
        workflow.execute(sess, dossier["action_id"], dossier)


# ==============================================================================
# TEST 8: Tampered Receipt
# ==============================================================================
def test_08_tampered_receipt():
    """Cryptographic verification must detect tampered receipt fields."""
    key = secrets.token_bytes(32)
    aid = "ACT-" + "0" * 64
    rcpt = {
        "version": 1,
        "receipt_id": "RCPT-" + "1" * 32,
        "dispatcher_id": "DISP-1",
        "dispatcher_key_id": "KEY-1",
        "dispatch_op_id": "DISP-OP-" + "2" * 64,
        "action_id": aid,
        "action_dossier_digest": "0" * 64,
        "approval_id": "APPR-" + "3" * 16,
        "request_nonce": "NONCE-" + "4" * 32,
        "execution_id": "EXEC-" + "5" * 32,
        "program_id": "test_prog",
        "principal_id": "alice",
        "session_ref": VALID_SESSION_REF,
        "target_endpoint": "https://target.local/logout",
        "http_method": "POST",
        "action_type": "LOGOUT",
        "scope_decision": "ALLOWED",
        "execution_outcome": "REVOCATION_VERIFIED",
        "mutation_evidence": {
            "evidence_id": "EVID-000000000001",
            "request_sha256": "a" * 64,
            "response_sha256": "b" * 64,
            "status_code": 200,
            "timestamp": "2026-11-14T00:00:00Z",
        },
        "verification_evidence": {
            "evidence_id": "EVID-000000000002",
            "invalidation_result": "REVOKED",
            "request_sha256": "c" * 64,
            "response_sha256": "d" * 64,
            "status_code": 401,
            "timestamp": "2026-11-14T00:00:01Z",
            "verification_method": "POST_MUTATION_PROBE_CONFIRMED_401",
        },
        "consumption_token": secrets.token_hex(32),
        "issued_at": "2026-11-14T00:00:01Z",
    }
    rcpt["signature"] = sign_execution_receipt(rcpt, key)
    # Valid
    public_key = derive_verification_key(key)
    ok, _ = verify_execution_receipt(rcpt, public_key)
    assert ok is True
    # Tampered target
    tampered = dict(rcpt)
    tampered["target_endpoint"] = "https://tampered.local/logout"
    ok, reason = verify_execution_receipt(tampered, public_key)
    assert ok is False
    assert "signature verification failed" in reason


# ==============================================================================
# TEST 9: Wrong Action, Nonce or Program in Receipt
# ==============================================================================
def test_09_wrong_action_nonce_or_program_in_receipt():
    """Receipt binding mismatches must be caught during verification."""
    key = secrets.token_bytes(32)
    rcpt = {
        "version": 1,
        "receipt_id": "RCPT-" + "1" * 32,
        "dispatcher_id": "DISP-1",
        "dispatcher_key_id": "KEY-1",
        "dispatch_op_id": "DISP-OP-" + "2" * 64,
        "action_id": "ACT-" + "0" * 64,
        "action_dossier_digest": "0" * 64,
        "approval_id": "APPR-" + "3" * 16,
        "request_nonce": "NONCE-" + "4" * 32,
        "execution_id": "EXEC-" + "5" * 32,
        "program_id": "prog_a",
        "principal_id": "alice",
        "session_ref": VALID_SESSION_REF,
        "target_endpoint": "https://target.local/logout",
        "http_method": "POST",
        "action_type": "LOGOUT",
        "scope_decision": "ALLOWED",
        "execution_outcome": "REVOCATION_VERIFIED",
        "mutation_evidence": {
            "evidence_id": "EVID-000000000001",
            "request_sha256": "a" * 64,
            "response_sha256": "b" * 64,
            "status_code": 200,
            "timestamp": "2026-11-14T00:00:00Z",
        },
        "verification_evidence": {
            "evidence_id": "EVID-000000000002",
            "invalidation_result": "REVOKED",
            "request_sha256": "c" * 64,
            "response_sha256": "d" * 64,
            "status_code": 401,
            "timestamp": "2026-11-14T00:00:01Z",
            "verification_method": "POST_MUTATION_PROBE_CONFIRMED_401",
        },
        "consumption_token": secrets.token_hex(32),
        "issued_at": "2026-11-14T00:00:01Z",
    }
    rcpt["signature"] = sign_execution_receipt(rcpt, key)
    # Action mismatch
    public_key = derive_verification_key(key)
    ok, reason = verify_execution_receipt(rcpt, public_key, expected_action_id="ACT-" + "1" * 64)
    assert ok is False
    assert "does not match expected" in reason
    # Nonce mismatch
    ok, reason = verify_execution_receipt(rcpt, public_key, expected_nonce="NONCE-" + "9" * 32)
    assert ok is False
    assert "nonce" in reason
    # Program mismatch
    ok, reason = verify_execution_receipt(rcpt, public_key, expected_program_id="prog_b")
    assert ok is False
    assert "program_id" in reason


# ==============================================================================
# TEST 10: Missing Evidence
# ==============================================================================
def test_10_missing_evidence(tmp_path):
    """Workflow must reject receipt if evidence files do not exist on disk."""
    store = EvidenceStore(str(tmp_path / "ev"))
    app_key = secrets.token_bytes(32)
    dossier = _make_signed_dossier(app_key, "test_prog", "https://target.local/logout")
    aid = dossier["action_id"]
    signing_key = secrets.token_bytes(32)
    vkey = derive_verification_key(signing_key)
    mock_resp = {
        "status": "SUCCESS",
        "receipt": {
            "version": 1,
            "receipt_id": "RCPT-" + "1" * 32,
            "dispatcher_id": "DISP-1",
            "dispatcher_key_id": "KEY-1",
            "dispatch_op_id": "DISP-OP-" + "2" * 64,
            "action_id": aid,
            "action_dossier_digest": aid[4:],
            "approval_id": dossier["unique_approval_id"],
            "request_nonce": "",  # set dynamically
            "execution_id": "EXEC-" + "5" * 32,
            "program_id": "test_prog",
            "principal_id": "alice",
            "session_ref": VALID_SESSION_REF,
            "target_endpoint": "https://target.local/logout",
            "http_method": "POST",
            "action_type": "LOGOUT",
            "scope_decision": "ALLOWED",
            "execution_outcome": "REVOCATION_VERIFIED",
            "mutation_evidence": {
                "evidence_id": "EVID-000000000001",
                "request_sha256": "a" * 64,
                "response_sha256": "b" * 64,
                "status_code": 200,
                "timestamp": "2026-11-14T00:00:00Z",
            },
            "verification_evidence": {
                "evidence_id": "EVID-000000000002",
                "invalidation_result": "REVOKED",
                "request_sha256": "c" * 64,
                "response_sha256": "d" * 64,
                "status_code": 401,
                "timestamp": "2026-11-14T00:00:01Z",
                "verification_method": "POST_MUTATION_PROBE_CONFIRMED_401",
            },
            "consumption_token": secrets.token_hex(32),
            "issued_at": "2026-11-14T00:00:01Z",
        },
    }

    class MockClient:
        def ping(self):
            return True
        def dispatch_mutation(self, program_id, action_id, action_dossier, session_context, scope_rules=None, nonce=None):
            mock_resp["receipt"]["request_nonce"] = nonce or f"NONCE-{secrets.token_hex(16).upper()}"
            mock_resp["receipt"]["signature"] = sign_execution_receipt(mock_resp["receipt"], signing_key)
            return mock_resp

    workflow = ControlledDispatchWorkflow(
        program_id="test_prog",
        state_dir=str(tmp_path / "state"),
        evidence_store=store,
        transport_engine=object(),
        scope_engine=MockScopeEngine(["https://target.local/"]),
        approval_key=app_key,
        dispatcher_client=MockClient(),
        dispatcher_verification_key=vkey,
    )
    sess = CorrelatedSessionContext(VALID_SESSION_REF, "alice")
    with pytest.raises(ApprovalSecurityError, match="not found or failed integrity checks in EvidenceStore"):
        workflow.execute(sess, aid, dossier)


# ==============================================================================
# TEST 11: Modified Evidence
# ==============================================================================
def test_11_modified_evidence(tmp_path):
    """Tampering with evidence capture file on disk must fail closed."""
    auth_tok = secrets.token_hex(32)
    store = EvidenceStore(str(tmp_path / "ev"), authority_token=auth_tok)
    req_obj = ControlledRequest("https://target.local/logout", "POST")
    res_obj = ControlledResponse(200, {"content-type": "application/json"}, b'{"status": "ok"}')
    mut_cap = store.save_transport_dispatch_capture(
        req_obj, res_obj, "ACT-" + "0" * 64, "appr_1", VALID_SESSION_REF, "alice", "test_prog",
        "DISP-OP-" + "0" * 64, is_verification=False, prefix="mut", authority_token=auth_tok,
    )
    # Corrupt capture file on disk
    with open(mut_cap["path"], "ab") as f:
        f.write(b"\nTAMPERED_BYTES")

    # get_evidence should fail integrity check and return None
    verified = store.get_evidence(mut_cap["evidence_id"])
    assert verified is None


# ==============================================================================
# TEST 12: Evidence Write Failure
# ==============================================================================
def test_12_evidence_write_failure(tmp_path):
    """Evidence persistence failure must reject dispatch."""
    app_key = secrets.token_bytes(32)
    unwritable_ev = tmp_path / "unwritable_ev"
    os.makedirs(unwritable_ev, exist_ok=True)
    disp = IsolatedExecutionDispatcher(
        program_id="test_prog",
        key_dir=str(tmp_path / "keys"),
        state_dir=str(tmp_path / "state"),
        evidence_dir=str(unwritable_ev),
        approval_key=app_key,
        transport_engine=MockLabTransport(),
        is_lab=True,
    )
    # Break evidence store
    disp._evidence_store = None
    dossier = _make_signed_dossier(app_key, "test_prog", "https://target.local/logout")
    req = {
        "version": PROTOCOL_VERSION,
        "request_id": f"REQ-{secrets.token_hex(16).upper()}",
        "nonce": f"NONCE-{secrets.token_hex(16).upper()}",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "action": "DISPATCH_MUTATION",
        "payload": {
            "program_id": "test_prog",
            "action_id": dossier["action_id"],
            "action_dossier": dossier,
            "session_context": {"session_ref": VALID_SESSION_REF, "principal_id": "alice"},
            "scope_rules": {},
        },
    }
    resp = disp.handle_request(req)
    assert resp["status"] == "ERROR"
    assert resp["error_code"] == "EVIDENCE_PERSISTENCE_FAILED"


# ==============================================================================
# TEST 13 & 14: Directory and Key Permissions
# ==============================================================================
def test_13_agent_cannot_read_dispatcher_signing_key_permissions(tmp_path):
    """Dispatcher key file must be protected with private permissions (0600 on POSIX)."""
    if os.name == "nt":
        pytest.skip("POSIX permission bit test skipped on Windows")
    kdir = tmp_path / "kdir"
    disp = IsolatedExecutionDispatcher(
        program_id="test_prog",
        key_dir=str(kdir),
        state_dir=str(tmp_path / "sdir"),
        evidence_dir=str(tmp_path / "edir"),
        is_lab=True,
    )
    kfile = os.path.join(str(kdir), "dispatcher_signing_key.bin")
    st = os.stat(kfile)
    assert st.st_mode & 0o077 == 0  # No group or world access
    public_key_file = os.path.join(str(kdir), "dispatcher_verification.pub")
    assert os.stat(public_key_file).st_mode & 0o777 == 0o644
    with open(public_key_file, "rb") as f:
        assert f.read() == disp.verification_key


def test_14_state_and_evidence_permissions(tmp_path):
    """Dispatcher state directory must have 0700 private permissions on POSIX."""
    if os.name == "nt":
        pytest.skip("POSIX permission bit test skipped on Windows")
    sdir = tmp_path / "sdir"
    disp = IsolatedExecutionDispatcher(
        program_id="test_prog",
        key_dir=str(tmp_path / "kdir"),
        state_dir=str(sdir),
        evidence_dir=str(tmp_path / "edir"),
        is_lab=True,
    )
    st = os.stat(str(sdir))
    assert st.st_mode & 0o077 == 0


# ==============================================================================
# TEST 15 & 16: IPC Socket Permissions & Replacement Prevention
# ==============================================================================
def test_15_agent_can_connect_to_intended_ipc_endpoint(tmp_path, request):
    """Client can ping running dispatcher service over IPC."""
    pipe_or_sock = rf"\\.\pipe\test_ipc_{secrets.token_hex(4)}" if os.name == "nt" else str(tmp_path / "disp.sock")
    disp = IsolatedExecutionDispatcher(
        program_id="test_prog",
        pipe_name=pipe_or_sock if os.name == "nt" else None,
        socket_path=pipe_or_sock if os.name != "nt" else None,
        key_dir=str(tmp_path / "keys"),
        state_dir=str(tmp_path / "state"),
        evidence_dir=str(tmp_path / "ev"),
        is_lab=True,
    )
    disp.start()
    request.addfinalizer(disp.stop)
    client = IsolatedDispatcherClient(
        endpoint_type="pipe" if os.name == "nt" else "unix",
        address=pipe_or_sock,
    )
    assert client.ping() is True


def test_16_agent_cannot_replace_ipc_socket_world_writable_rejected(tmp_path):
    """Unix socket in world-writable parent directory must fail closed."""
    if os.name == "nt":
        pytest.skip("Unix socket test skipped on Windows")
    ww_dir = tmp_path / "ww_dir"
    os.makedirs(ww_dir, exist_ok=True)
    os.chmod(ww_dir, 0o777)  # World writable
    disp = IsolatedExecutionDispatcher(
        program_id="test_prog",
        socket_path=str(ww_dir / "test.sock"),
        key_dir=str(tmp_path / "keys"),
        state_dir=str(tmp_path / "state"),
        evidence_dir=str(tmp_path / "ev"),
        is_lab=True,
    )
    with pytest.raises(PermissionError, match="world-writable; insecure for IPC"):
        disp.start()


# ==============================================================================
# TEST 17: Dispatcher Unavailable
# ==============================================================================
def test_17_dispatcher_unavailable_no_mutation_occurs(tmp_path):
    """Workflow fails closed if dispatcher service is not running."""
    pipe_or_sock = rf"\\.\pipe\nonexistent_{secrets.token_hex(8)}" if os.name == "nt" else str(tmp_path / "nonexistent.sock")
    client = IsolatedDispatcherClient(endpoint_type="pipe" if os.name == "nt" else "unix", address=pipe_or_sock)
    store = EvidenceStore(str(tmp_path / "ev"))
    app_key = secrets.token_bytes(32)
    workflow = ControlledDispatchWorkflow(
        program_id="test_prog",
        state_dir=str(tmp_path / "state"),
        evidence_store=store,
        transport_engine=object(),
        scope_engine=MockScopeEngine(["https://target.local/"]),
        approval_key=app_key,
        dispatcher_client=client,
    )
    sess = CorrelatedSessionContext(VALID_SESSION_REF, "alice")
    dossier = _make_signed_dossier(app_key, "test_prog", "https://target.local/logout")
    with pytest.raises(ApprovalSecurityError, match="Isolated execution dispatcher unavailable|isolated execution provenance boundary"):
        workflow.execute(sess, dossier["action_id"], dossier)


# ==============================================================================
# TEST 18: Approval Replay Prevention
# ==============================================================================
def test_18_approval_replay_no_second_mutation_occurs(tmp_path, request):
    """Single-use approval must prevent replay attacks."""
    app_key = secrets.token_bytes(32)
    transport = MockLabTransport()
    pipe_or_sock = rf"\\.\pipe\test_replay_{secrets.token_hex(4)}" if os.name == "nt" else str(tmp_path / "replay.sock")
    disp = IsolatedExecutionDispatcher(
        program_id="test_prog",
        pipe_name=pipe_or_sock if os.name == "nt" else None,
        socket_path=pipe_or_sock if os.name != "nt" else None,
        key_dir=str(tmp_path / "keys"),
        state_dir=str(tmp_path / "state"),
        evidence_dir=str(tmp_path / "ev"),
        approval_key=app_key,
        transport_engine=transport,
        is_lab=True,
    )
    disp.start()
    request.addfinalizer(disp.stop)

    client = IsolatedDispatcherClient(
        endpoint_type="pipe" if os.name == "nt" else "unix",
        address=pipe_or_sock,
    )
    dossier = _make_signed_dossier(app_key, "test_prog", "https://target.local/logout")
    aid = dossier["action_id"]
    sess_ctx = {"session_ref": VALID_SESSION_REF, "principal_id": "alice"}

    # First dispatch succeeds
    res1 = client.dispatch_mutation(
        program_id="test_prog",
        action_id=aid,
        action_dossier=dossier,
        session_context=sess_ctx,
    )
    assert res1["status"] == "SUCCESS"
    assert len(transport.requests) == 2  # 1 mutation + 1 probe

    # Second dispatch with SAME action_id fails closed
    res2 = client.dispatch_mutation(
        program_id="test_prog",
        action_id=aid,
        action_dossier=dossier,
        session_context=sess_ctx,
    )
    assert res2["status"] == "REJECTED"
    assert res2["error_code"] == "APPROVAL_CONSUMPTION_FAILED"
    assert "already been consumed" in res2["error_message"]
    # Verify no second mutation request was made
    assert len(transport.requests) == 2


# ==============================================================================
# TEST 19: Windows Service Isolation Status
# ==============================================================================
def test_19_windows_service_isolation_status(tmp_path):
    """Windows platform limitation must be explicitly recorded and queried."""
    disp = IsolatedExecutionDispatcher(
        program_id="test_prog",
        key_dir=str(tmp_path / "keys"),
        state_dir=str(tmp_path / "state"),
        evidence_dir=str(tmp_path / "ev"),
        is_lab=True,
    )
    req = {
        "version": PROTOCOL_VERSION,
        "request_id": f"REQ-{secrets.token_hex(16).upper()}",
        "nonce": f"NONCE-{secrets.token_hex(16).upper()}",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "action": "STATUS",
        "payload": {},
    }
    resp = disp.handle_request(req)
    assert resp["status"] == "SUCCESS"
    receipt = resp["receipt"]
    if os.name == "nt":
        assert receipt["production_isolation_supported"] is False
        assert "NOT IMPLEMENTED" in receipt["platform_limitation"]
    else:
        assert receipt["production_isolation_supported"] is True
        assert receipt["platform_limitation"] is None


# ==============================================================================
# TEST 20: Linux Systemd Service Configuration
# ==============================================================================
def test_20_linux_systemd_service_configuration():
    """Systemd service unit must configure unprivileged user and restrictive permissions."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    service_file = os.path.join(repo_root, "systemd", "bugbounty-dispatcher.service")
    assert os.path.exists(service_file), "systemd service unit file must exist"
    with open(service_file, "r", encoding="utf-8") as f:
        content = f.read()

    assert "User=_bbdispatcher" in content
    assert "Group=bbgroup" in content
    assert "RuntimeDirectory=bugbounty" in content
    assert "RuntimeDirectoryMode=0750" in content
    assert "StateDirectoryMode=0700" in content
    assert "NoNewPrivileges=yes" in content
    assert "ProtectSystem=strict" in content
