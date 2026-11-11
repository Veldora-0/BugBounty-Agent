"""
Tests for Phase 21 DualControlPreflightValidator and PostRevocationResourceValidator.

Verifies:
- 6-point preflight verification protocol
- Sequential short-circuiting on probe failure
- False-positive elimination on public landing pages / SPA shells
- Mode A observation-only evidentiary prerequisites
- Mode B controlled mutation approval verification (ACT-<SHA256>)
- Authentic CVSS 3.1 scoring on session persistence findings
"""

import hashlib
import hmac
import json
import os
import secrets
import time
import pytest

from framework.auth_correlation.cvss import CVSS31Calculator
from framework.auth_correlation.ledger import (
    ExecutionLedger,
    ExecutionRecord,
    ExecutionCapability,
    ExecutionProvenanceError,
    issue_execution_capability,
)
from framework.auth_correlation.model import (
    CorrelatedSessionContext,
    ControlledExecutionResult,
    CorrelationLifecycle,
    CorrelationFinding,
    EvidencePersistenceError,
    AttestationSecurityError,
)
from framework.auth_correlation.preflight import DualControlPreflightValidator
from framework.auth_correlation.revocation import (
    PostRevocationResourceValidator,
    ApprovalSecurityError,
    classify_revocation_response,
    create_controlled_invalidation_attestation,
    _create_controlled_invalidation_attestation_from_record,
    _create_controlled_invalidation_attestation_from_result,
    create_operator_invalidation_attestation,
    get_or_create_attestation_key,
    sign_action_approval,
)
from framework.authz.model import ResourceAccessTarget
from framework.common.evidence import EvidenceStore
from framework.validation.request import ControlledRequest, ControlledResponse


class MockValidationEngine:
    """Mock engine allowing scripted responses for sequential probes."""

    def __init__(self, responses_by_url_or_header: Optional[Dict[str, ControlledResponse]] = None):
        self.responses = responses_by_url_or_header or {}
        self.dispatched_requests: list[ControlledRequest] = []

    def send_request(self, req: ControlledRequest) -> ControlledResponse:
        self.dispatched_requests.append(req)
        auth = req.headers.get("Authorization", "ANONYMOUS")
        key = f"{req.url}|{auth}"
        if key in self.responses:
            return self.responses[key]
        if req.url in self.responses:
            return self.responses[req.url]
        return ControlledResponse(status_code=404, headers={}, body_bytes=b"Not Found")


def test_preflight_success_sequential():
    """Verifies that a valid session pair completes all 3 probes and transitions to VERIFIED."""
    preflight_url = "https://target.local/api/v1/profile"
    engine = MockValidationEngine({
        f"{preflight_url}|Bearer token_a": ControlledResponse(200, {"content-type": "application/json"}, b'{"user": "alice", "id": 101}'),
        f"{preflight_url}|Bearer token_b": ControlledResponse(200, {"content-type": "application/json"}, b'{"user": "bob", "id": 102}'),
        f"{preflight_url}|ANONYMOUS": ControlledResponse(401, {"content-type": "application/json"}, b'{"error": "Unauthorized"}'),
    })

    validator = DualControlPreflightValidator(validation_engine=engine)
    sess_a = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="alice", volatile_headers={"Authorization": "Bearer token_a"})
    sess_b = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000002", principal_id="bob", volatile_headers={"Authorization": "Bearer token_b"})

    success, status, details = validator.validate_session_pair(sess_a, sess_b, preflight_url)

    assert success is True
    assert status == "VERIFIED"
    assert sess_a.lifecycle == CorrelationLifecycle.VERIFIED
    assert sess_b.lifecycle == CorrelationLifecycle.VERIFIED
    assert len(engine.dispatched_requests) == 3


def test_preflight_probe1_failure_short_circuits():
    """Verifies that an expired Principal A session aborts Probes 2 and 3 immediately."""
    preflight_url = "https://target.local/api/v1/profile"
    engine = MockValidationEngine({
        f"{preflight_url}|Bearer token_a": ControlledResponse(401, {}, b'{"error": "Session Expired"}'),
    })

    validator = DualControlPreflightValidator(validation_engine=engine)
    sess_a = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="alice", volatile_headers={"Authorization": "Bearer token_a"})
    sess_b = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000002", principal_id="bob", volatile_headers={"Authorization": "Bearer token_b"})

    success, status, details = validator.validate_session_pair(sess_a, sess_b, preflight_url)

    assert success is False
    assert status == "SESSION_HEALTH_FAILED"
    assert sess_a.lifecycle == CorrelationLifecycle.EXPIRED
    assert sess_b.lifecycle == CorrelationLifecycle.FAILED
    # Short-circuit proof: Only Probe 1 was ever sent!
    assert len(engine.dispatched_requests) == 1


def test_preflight_public_endpoint_false_positive_elimination():
    """Verifies that if anonymous control returns matching 200 OK, preflight fails closed."""
    preflight_url = "https://target.local/landing"
    html_shell = b"<html><body>Welcome to Public SPA Shell</body></html>"
    engine = MockValidationEngine({
        f"{preflight_url}|Bearer token_a": ControlledResponse(200, {"content-type": "text/html"}, html_shell),
        f"{preflight_url}|Bearer token_b": ControlledResponse(200, {"content-type": "text/html"}, html_shell),
        f"{preflight_url}|ANONYMOUS": ControlledResponse(200, {"content-type": "text/html"}, html_shell),
    })

    validator = DualControlPreflightValidator(validation_engine=engine)
    sess_a = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="alice", volatile_headers={"Authorization": "Bearer token_a"})
    sess_b = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000002", principal_id="bob", volatile_headers={"Authorization": "Bearer token_b"})

    success, status, details = validator.validate_session_pair(sess_a, sess_b, preflight_url)

    assert success is False
    assert status == "SESSION_HEALTH_FAILED"
    assert sess_a.lifecycle == CorrelationLifecycle.UNKNOWN
    assert sess_b.lifecycle == CorrelationLifecycle.UNKNOWN


def test_revocation_mode_a_missing_prerequisites_fails_inconclusive():
    """Verifies that Mode A requires both baseline and invalidation proof or returns INCONCLUSIVE."""
    validator = PostRevocationResourceValidator()
    target = ResourceAccessTarget(resource_id="res_01", resource_type="DOCUMENT", endpoint="https://target.local/api/v1/docs/1", method="GET")
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1")

    # Case 1: Missing baseline
    status, finding = validator.evaluate_revoked_session(sess, target, pre_revocation_baseline=None, invalidation_evidence_ref="EVID-0123456789ab")
    assert status == "INCONCLUSIVE"
    assert finding is None

    # Case 2: Missing invalidation evidence
    baseline = ControlledResponse(200, {}, b'{"doc": "confidential"}')
    status, finding = validator.evaluate_revoked_session(sess, target, pre_revocation_baseline=baseline, invalidation_evidence_ref=None)
    assert status == "INCONCLUSIVE"
    assert finding is None


def make_valid_invalidation_evidence(
    store: EvidenceStore,
    sess: CorrelatedSessionContext,
    event_type: str = "SESSION_REVOCATION",
    program_id: Optional[str] = None,
    attestation_key: Optional[bytes] = None,
    key_dir: Optional[str] = None,
    execution_ledger: Optional[Any] = None,
    state_dir: Optional[str] = None,
) -> str:
    """Helper to persist a valid, attributable invalidation event with authentic attestation into EvidenceStore."""
    from datetime import datetime, timezone
    from framework.auth_correlation.revocation import get_or_create_approval_key
    from framework.auth_correlation.ledger import (
        sign_consumption_receipt,
        CANONICAL_ACTION_FIELDS,
    )
    prog_id = program_id or "default-program"
    app_key = get_or_create_approval_key(key_dir=key_dir)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    app_id = f"APPR-{secrets.token_hex(16)}"
    c_token = secrets.token_hex(32)

    dossier_data = {
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": prog_id,
        "target_endpoint": "http://127.0.0.1:8080/auth/logout",
        "test_account": sess.principal_id,
        "ttl": 300.0,
        "unique_approval_id": app_id,
    }
    canonical_copy = {k: dossier_data[k] for k in CANONICAL_ACTION_FIELDS}
    canonical_str = json.dumps(canonical_copy, sort_keys=True)
    aid_hex = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
    aid = f"ACT-{aid_hex}"
    op_sig = f"SIG-{hmac.new(app_key, canonical_str.encode('utf-8'), hashlib.sha256).hexdigest()}"

    clean_req = "POST /auth/logout\nAuthorization: Bearer revoked"
    clean_res = 'HTTP 200 OK\n{"status": "logged_out", "revoked": true}'
    res = store.save_controlled_transport_capture(
        request_text=clean_req,
        response_text=clean_res,
        action_id=aid,
        approval_id=app_id,
        session_ref=sess.session_ref,
        principal_id=sess.principal_id,
        program_id=prog_id,
        event_type=event_type,
        prefix="inv_proof",
    )
    ver_req = f"GET /auth/verify\nAuthorization: Bearer {sess.session_ref[:8]}"
    ver_res = 'HTTP 401 Unauthorized\n{"error": "Session revoked"}'
    ver_cap = store.save_controlled_transport_capture(
        request_text=ver_req,
        response_text=ver_res,
        action_id=aid,
        approval_id=app_id,
        session_ref=sess.session_ref,
        principal_id=sess.principal_id,
        program_id=prog_id,
        event_type=event_type,
        verification_method="MUTATION_EXPLICIT_REVOCATION_VERIFIED",
        prefix="inv_ver_proof",
    )

    if state_dir is None:
        state_dir = os.path.join(os.path.dirname(os.path.abspath(store.evidence_dir)), "state")
    os.makedirs(state_dir, exist_ok=True)

    consumed_path = os.path.join(state_dir, "consumed_approvals.json")
    receipt_payload = {
        "action_dossier_digest": aid[4:],
        "action_id": aid,
        "action_type": "LOGOUT",
        "approval_id": app_id,
        "consumed_at": ts,
        "consumption_token": c_token,
        "method": "POST",
        "operator_signature": op_sig,
        "principal_id": sess.principal_id,
        "program_id": prog_id,
        "session_ref": sess.session_ref,
        "target_endpoint": "http://127.0.0.1:8080/auth/logout",
        "test_account": sess.principal_id,
    }
    receipt_sig = sign_consumption_receipt(receipt_payload, app_key)

    consumed_entry = {
        **receipt_payload,
        "action_dossier": canonical_copy,
        "receipt_signature": receipt_sig,
        "execution_id": None,
    }
    consumed_data = {"version": "1.0", "consumed": {}}
    if os.path.exists(consumed_path):
        try:
            with open(consumed_path, "r", encoding="utf-8") as f:
                consumed_data = json.load(f)
        except Exception:
            pass
    if "consumed" not in consumed_data:
        consumed_data["consumed"] = {}
    consumed_data["consumed"][aid] = consumed_entry
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump(consumed_data, f, indent=2)

    ledger = execution_ledger or ExecutionLedger(state_dir=state_dir, key_dir=key_dir, approval_key=app_key)
    k_dir = key_dir or ledger._key_dir
    cap = issue_execution_capability(
        action_id=aid,
        action_dossier_digest=aid[4:],
        approval_id=app_id,
        program_id=prog_id,
        session_ref=sess.session_ref,
        principal_id=sess.principal_id,
        test_account=sess.principal_id,
        target_endpoint="http://127.0.0.1:8080/auth/logout",
        http_method="POST",
        action_type="LOGOUT",
        mutation_evidence_ref=res["evidence_id"],
        mutation_request_digest=res["request_sha256"],
        mutation_response_digest=res["response_sha256"],
        mutation_status_code=200,
        verification_evidence_ref=ver_cap["evidence_id"],
        verification_request_digest=ver_cap["request_sha256"],
        verification_response_digest=ver_cap["response_sha256"],
        verification_status_code=401,
        verification_method="MUTATION_EXPLICIT_REVOCATION_VERIFIED",
        invalidation_verification_result="REVOKED",
        execution_timestamp=ts,
        verification_timestamp=ts,
        consumption_token=c_token,
        approval_key=app_key,
        evidence_store=store,
        consumed_approvals_path=consumed_path,
        key_dir=k_dir,
    )
    exec_rec = ledger.record_execution(
        capability=cap,
        evidence_store=store,
        consumed_approvals_path=consumed_path,
        approval_key=app_key,
    )

    att_rec = _create_controlled_invalidation_attestation_from_record(
        execution_record=exec_rec,
        execution_ledger=ledger,
        evidence_store=store,
        attestation_key=attestation_key,
        key_dir=key_dir,
    )
    return res["evidence_id"]


def test_revocation_mode_a_secure_invalidation(tmp_path):
    """Verifies that 401 with explicit revocation keywords confirms REVOKED when provenance is verified."""
    target_url = "https://target.local/api/v1/docs/1"
    engine = MockValidationEngine({
        target_url: ControlledResponse(401, {}, b'{"error": "Token has been revoked"}'),
    })
    store = EvidenceStore(str(tmp_path / "ev_sec"))
    mock_scope = MockScopeEngine()
    validator = PostRevocationResourceValidator(
        validation_engine=engine,
        evidence_store=store,
        scope_engine=mock_scope,
    )
    target = ResourceAccessTarget(resource_id="res_01", resource_type="DOCUMENT", endpoint=target_url, method="GET")
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1", volatile_headers={"Authorization": "Bearer revoked_token"})
    baseline = ControlledResponse(200, {}, b'{"doc": "confidential"}')

    inv_ref = make_valid_invalidation_evidence(store, sess)

    status, finding = validator.evaluate_revoked_session(sess, target, baseline, inv_ref)
    assert status == "REVOKED"
    assert finding is None


def test_revocation_mode_a_vulnerability_emission(tmp_path):
    """Verifies that 200 OK post-revocation with matching baseline emits SESSION_NOT_INVALIDATED."""
    target_url = "https://target.local/api/v1/docs/1"
    doc_body = b'{"document_id": "1", "sensitive_data": "secret_content_xyz"}'
    engine = MockValidationEngine({
        target_url: ControlledResponse(200, {"content-type": "application/json"}, doc_body),
    })
    ev_dir = tmp_path / "evidence_rev"
    ev_dir.mkdir()
    store = EvidenceStore(str(ev_dir))
    mock_scope = MockScopeEngine()

    target = ResourceAccessTarget(resource_id="res_01", resource_type="DOCUMENT", endpoint=target_url, method="GET")
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1", volatile_headers={"Authorization": "Bearer revoked_token"})
    baseline = ControlledResponse(200, {"content-type": "application/json"}, doc_body)
    inv_ref = make_valid_invalidation_evidence(store, sess)

    # 1. With configured EvidenceStore and verified provenance: finding is emitted
    validator = PostRevocationResourceValidator(validation_engine=engine, evidence_store=store, scope_engine=mock_scope)
    status, finding = validator.evaluate_revoked_session(sess, target, baseline, inv_ref)
    assert status == "SESSION_NOT_INVALIDATED"
    assert finding is not None
    assert finding.category == "SESSION_NOT_INVALIDATED"
    assert finding.severity == "MEDIUM"
    assert finding.cvss_score == 5.4
    assert finding.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
    assert finding.confidence == 0.90
    assert len(finding.evidence_chain) == 1
    assert finding.evidence_chain[0].startswith("EVID-")
    assert "[EVIDENCE_NOT_PERSISTED]" not in finding.description

    # 2. Without EvidenceStore: provenance cannot be verified, fails closed to INCONCLUSIVE without finding
    validator_no_store = PostRevocationResourceValidator(validation_engine=engine, evidence_store=None, scope_engine=mock_scope)
    status_ns, finding_ns = validator_no_store.evaluate_revoked_session(sess, target, baseline, inv_ref)
    assert status_ns == "INCONCLUSIVE"
    assert finding_ns is None

    # 3. Failing EvidenceStore raises EvidencePersistenceError
    class FailingStore:
        evidence_dir = store.evidence_dir
        def get_evidence(self, ref):
            return store.get_evidence(ref)
        def get_invalidation_attestation(self, ref):
            return store.get_invalidation_attestation(ref)
        def save_http_capture(self, *args, **kwargs):
            raise IOError("Simulated disk error during capture")

    validator_fail = PostRevocationResourceValidator(validation_engine=engine, evidence_store=FailingStore(), scope_engine=mock_scope)
    with pytest.raises(EvidencePersistenceError, match="Failed to persist Mode A revocation evidence"):
        validator_fail.evaluate_revoked_session(sess, target, baseline, inv_ref)


def test_revocation_mode_a_provenance_verification_matrix(tmp_path):
    """
    Verifies all 17 negative and positive provenance cases for Mode A invalidation verification:
    1. Ordinary capture with event_type=SESSION_REVOCATION without attestation is rejected.
    2. Arbitrary caller-created metadata is rejected.
    3. A valid trusted event workflow can produce a verifiable attestation.
    4. Invalid signature rejection.
    5. Modified signed payload rejection.
    6. Wrong signing domain rejection.
    7. Wrong session attribution rejection.
    8. Wrong principal attribution rejection.
    9. Wrong program attribution rejection.
    10. Wrong original evidence reference rejection.
    11. Missing original capture rejection.
    12. Modified original capture rejection.
    13. Unknown key identifier rejection.
    14. Missing or unavailable key rejection.
    15. Legacy evidence without attestation returns INCONCLUSIVE.
    16. Mode A observation evidence cannot be reused as invalidation proof.
    17. Operator attestation is distinguishable from independently verified event provenance.
    """
    target_url = "https://target.local/api/v1/docs/1"
    doc_body = b'{"data": "confidential_document_content"}'
    engine = MockValidationEngine({
        target_url: ControlledResponse(200, {"content-type": "application/json"}, doc_body),
    })
    ev_dir = tmp_path / "ev_prov"
    ev_dir.mkdir()
    store = EvidenceStore(str(ev_dir))
    mock_scope = MockScopeEngine()
    key_dir = str(tmp_path / "keys")
    os.makedirs(key_dir, exist_ok=True)
    att_key = get_or_create_attestation_key(key_dir=key_dir)

    validator = PostRevocationResourceValidator(
        validation_engine=engine,
        evidence_store=store,
        scope_engine=mock_scope,
        attestation_key=att_key,
    )

    target = ResourceAccessTarget(resource_id="res_01", resource_type="DOCUMENT", endpoint=target_url, method="GET")
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1")
    baseline = ControlledResponse(200, {"content-type": "application/json"}, doc_body)

    def _make_att(aid, orig_ref, sess_ctx, prog="default-program", ev_type="SESSION_REVOCATION", key=att_key):
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        ledger = validator.ledger
        ev_item = store.get_evidence(orig_ref)
        req_dig = ev_item["request_sha256"] if ev_item else "0"*64
        res_dig = ev_item["response_sha256"] if ev_item else "0"*64
        from framework.auth_correlation.revocation import get_or_create_approval_key, sign_action_approval
        from framework.auth_correlation.ledger import sign_consumption_receipt, CANONICAL_ACTION_FIELDS
        app_key = get_or_create_approval_key(key_dir=ledger.key_dir)

        app_id = f"APPR-{secrets.token_hex(16)}"
        dossier_data = {
            "action_type": "LOGOUT",
            "created_at": time.time(),
            "method": "POST",
            "program_id": prog,
            "target_endpoint": "https://target.local/auth/logout",
            "test_account": sess_ctx.principal_id,
            "ttl": 300.0,
            "unique_approval_id": app_id,
        }
        signed_dossier = sign_action_approval(dossier_data, approval_key=app_key)
        clean_aid = signed_dossier["action_id"]
        op_sig = signed_dossier["approval_signature"]
        canonical_copy = {k: dossier_data[k] for k in CANONICAL_ACTION_FIELDS}

        if ev_item and "meta_path" in ev_item and os.path.exists(ev_item["meta_path"]):
            try:
                with open(ev_item["meta_path"], "r", encoding="utf-8") as mf:
                    mdata = json.load(mf)
                if "metadata" not in mdata:
                    mdata["metadata"] = {}
                mdata["metadata"]["capture_source"] = "CONTROLLED_TRANSPORT_DISPATCH"
                mdata["metadata"]["evidence_class"] = "CONTROLLED_TRANSPORT_DISPATCH"
                mdata["metadata"]["action_id"] = clean_aid
                with open(ev_item["meta_path"], "w", encoding="utf-8") as mf:
                    json.dump(mdata, mf, indent=2)
            except Exception:
                pass

        ver_cap = store.save_controlled_transport_capture(
            request_text=f"GET /auth/verify?aid={clean_aid}\nAuthorization: Bearer {sess_ctx.session_ref[:8]}",
            response_text=f'HTTP 401 Unauthorized\n{{"error": "Session revoked", "action": "{clean_aid}"}}',
            action_id=clean_aid,
            approval_id=app_id,
            session_ref=sess_ctx.session_ref,
            principal_id=sess_ctx.principal_id,
            program_id=prog,
            event_type=ev_type,
            verification_method="MUTATION_EXPLICIT_REVOCATION_VERIFIED",
            prefix=f"ver_{clean_aid[-6:]}",
        )

        c_token = secrets.token_hex(32)
        os.makedirs(ledger.state_dir, exist_ok=True)
        consumed_path = os.path.join(ledger.state_dir, "consumed_approvals.json")

        receipt_payload = {
            "action_dossier_digest": clean_aid[4:],
            "action_id": clean_aid,
            "action_type": "LOGOUT",
            "approval_id": app_id,
            "consumed_at": ts,
            "consumption_token": c_token,
            "method": "POST",
            "operator_signature": op_sig,
            "principal_id": sess_ctx.principal_id,
            "program_id": prog,
            "session_ref": sess_ctx.session_ref,
            "target_endpoint": "https://target.local/auth/logout",
            "test_account": sess_ctx.principal_id,
        }
        receipt_sig = sign_consumption_receipt(receipt_payload, app_key)

        consumed_entry = {
            **receipt_payload,
            "action_dossier": canonical_copy,
            "receipt_signature": receipt_sig,
            "execution_id": None,
        }
        consumed_data = {"version": "1.0", "consumed": {}}
        if os.path.exists(consumed_path):
            try:
                with open(consumed_path, "r", encoding="utf-8") as f:
                    consumed_data = json.load(f)
            except Exception:
                pass
        if "consumed" not in consumed_data:
            consumed_data["consumed"] = {}
        consumed_data["consumed"][clean_aid] = consumed_entry
        with open(consumed_path, "w", encoding="utf-8") as f:
            json.dump(consumed_data, f, indent=2)

        cap = issue_execution_capability(
            action_id=clean_aid,
            action_dossier_digest=clean_aid[4:],
            approval_id=app_id,
            program_id=prog,
            session_ref=sess_ctx.session_ref,
            principal_id=sess_ctx.principal_id,
            test_account=sess_ctx.principal_id,
            target_endpoint="https://target.local/auth/logout",
            http_method="POST",
            action_type="LOGOUT",
            mutation_evidence_ref=orig_ref,
            mutation_request_digest=req_dig,
            mutation_response_digest=res_dig,
            mutation_status_code=200,
            verification_evidence_ref=ver_cap["evidence_id"],
            verification_request_digest=ver_cap["request_sha256"],
            verification_response_digest=ver_cap["response_sha256"],
            verification_status_code=401,
            verification_method="MUTATION_EXPLICIT_REVOCATION_VERIFIED",
            invalidation_verification_result="REVOKED",
            execution_timestamp=ts,
            verification_timestamp=ts,
            consumption_token=c_token,
            approval_key=app_key,
            evidence_store=store,
            consumed_approvals_path=consumed_path,
            key_dir=ledger.key_dir,
        )
        exec_rec = ledger.record_execution(
            capability=cap,
            evidence_store=store,
            consumed_approvals_path=consumed_path,
            approval_key=app_key,
        )
        return _create_controlled_invalidation_attestation_from_record(
            execution_record=exec_rec,
            execution_ledger=ledger,
            evidence_store=store,
            attestation_key=key,
        )

    # 1. Ordinary capture with event_type=SESSION_REVOCATION without attestation is rejected
    res1 = store.save_http_capture(
        request_text="POST /logout", response_text="HTTP 200 OK",
        metadata={"event_type": "SESSION_REVOCATION", "session_ref": sess.session_ref, "principal_id": sess.principal_id, "program_id": "default-program"},
    )
    v1_ok, v1_reason, _ = validator.verify_invalidation_provenance(res1["evidence_id"], sess)
    assert not v1_ok
    assert "authenticated invalidation event attestation" in v1_reason
    s1, f1 = validator.evaluate_revoked_session(sess, target, baseline, res1["evidence_id"])
    assert s1 == "INCONCLUSIVE" and f1 is None

    # 2. Arbitrary caller-created metadata is rejected
    res2 = store.save_http_capture(
        request_text="POST /logout", response_text="HTTP 200 OK",
        metadata={
            "event_type": "SESSION_REVOCATION",
            "session_ref": sess.session_ref,
            "principal_id": sess.principal_id,
            "program_id": "default-program",
            "attestation_verified": True,
            "attestation_id": "ATT-0000000000000000000000000000000000000000000000000000000000000000",
            "signature": "ATT-SIG-0000000000000000000000000000000000000000000000000000000000000000",
        },
    )
    v2_ok, _, _ = validator.verify_invalidation_provenance(res2["evidence_id"], sess)
    assert not v2_ok
    s2, f2 = validator.evaluate_revoked_session(sess, target, baseline, res2["evidence_id"])
    assert s2 == "INCONCLUSIVE" and f2 is None

    # 3. A valid trusted event workflow can produce a verifiable attestation
    res3 = store.save_http_capture(
        request_text="POST /logout\nAuthorization: Bearer valid",
        response_text="HTTP 200 OK\nlogged_out",
        metadata={
            "event_type": "SESSION_REVOCATION",
            "session_ref": sess.session_ref,
            "principal_id": sess.principal_id,
            "program_id": "default-program",
        },
    )
    att3 = _make_att(
        aid="ACT-0000000000000000000000000000000000000000000000000000000000000003",
        orig_ref=res3["evidence_id"],
        sess_ctx=sess,
        prog="default-program",
    )
    v3_ok, v3_reason, v3_rec = validator.verify_invalidation_provenance(res3["evidence_id"], sess)
    assert v3_ok is True
    assert v3_rec["attestation_id"] == att3["attestation_id"]
    s3, f3 = validator.evaluate_revoked_session(sess, target, baseline, res3["evidence_id"])
    assert s3 == "SESSION_NOT_INVALIDATED"
    assert f3 is not None
    assert f3.category == "SESSION_NOT_INVALIDATED"

    # 4. Invalid signature rejection
    res4 = store.save_http_capture(
        request_text="POST /logout\nTest: 4", response_text="HTTP 200 OK",
        metadata={"event_type": "SESSION_REVOCATION", "session_ref": sess.session_ref, "principal_id": sess.principal_id, "program_id": "default-program"},
    )
    att4 = _make_att(
        aid="ACT-0000000000000000000000000000000000000000000000000000000000000004",
        orig_ref=res4["evidence_id"],
        sess_ctx=sess,
        prog="default-program",
    )
    att4_bad = dict(att4)
    att4_bad["signature"] = "ATT-SIG-" + "a" * 64
    store.save_invalidation_attestation(att4_bad)
    v4_ok, v4_reason, _ = validator.verify_invalidation_provenance(res4["evidence_id"], sess)
    assert not v4_ok
    assert "signature verification failed" in v4_reason
    s4, f4 = validator.evaluate_revoked_session(sess, target, baseline, res4["evidence_id"])
    assert s4 == "INCONCLUSIVE" and f4 is None

    # 5. Modified signed payload rejection
    res5 = store.save_http_capture(
        request_text="POST /logout\nTest: 5", response_text="HTTP 200 OK",
        metadata={"event_type": "SESSION_REVOCATION", "session_ref": sess.session_ref, "principal_id": sess.principal_id, "program_id": "default-program"},
    )
    att5 = _make_att(
        aid="ACT-0000000000000000000000000000000000000000000000000000000000000005",
        orig_ref=res5["evidence_id"],
        sess_ctx=sess,
        prog="default-program",
    )
    att5_tamper = dict(att5)
    att5_tamper["event_type"] = "PASSWORD_CHANGE"
    store.save_invalidation_attestation(att5_tamper)
    v5_ok, v5_reason, _ = validator.verify_invalidation_provenance(res5["evidence_id"], sess)
    assert not v5_ok
    assert "digest mismatch" in v5_reason or "signature verification failed" in v5_reason
    s5, f5 = validator.evaluate_revoked_session(sess, target, baseline, res5["evidence_id"])
    assert s5 == "INCONCLUSIVE" and f5 is None

    # 6. Wrong signing domain rejection
    res6 = store.save_http_capture(
        request_text="POST /logout\nTest: 6", response_text="HTTP 200 OK",
        metadata={"event_type": "SESSION_REVOCATION", "session_ref": sess.session_ref, "principal_id": sess.principal_id, "program_id": "default-program"},
    )
    att6 = _make_att(
        aid="ACT-0000000000000000000000000000000000000000000000000000000000000006",
        orig_ref=res6["evidence_id"],
        sess_ctx=sess,
        prog="default-program",
    )
    att6_bad_dom = dict(att6)
    att6_bad_dom["domain"] = "WRONG_DOMAIN_V2"
    store.save_invalidation_attestation(att6_bad_dom)
    v6_ok, v6_reason, _ = validator.verify_invalidation_provenance(res6["evidence_id"], sess)
    assert not v6_ok
    assert "domain" in v6_reason
    s6, f6 = validator.evaluate_revoked_session(sess, target, baseline, res6["evidence_id"])
    assert s6 == "INCONCLUSIVE" and f6 is None

    # 7. Wrong session attribution rejection
    other_sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000999", principal_id="u1")
    res7 = store.save_http_capture(
        request_text="POST /logout\nTest: 7", response_text="HTTP 200 OK",
        metadata={"event_type": "SESSION_REVOCATION", "session_ref": other_sess.session_ref, "principal_id": sess.principal_id, "program_id": "default-program"},
    )
    _make_att(
        aid="ACT-0000000000000000000000000000000000000000000000000000000000000007",
        orig_ref=res7["evidence_id"],
        sess_ctx=other_sess,
        prog="default-program",
    )
    v7_ok, v7_reason, _ = validator.verify_invalidation_provenance(res7["evidence_id"], sess)
    assert not v7_ok
    assert "session_ref" in v7_reason and "mismatch" in v7_reason
    s7, f7 = validator.evaluate_revoked_session(sess, target, baseline, res7["evidence_id"])
    assert s7 == "INCONCLUSIVE" and f7 is None

    # 8. Wrong principal attribution rejection
    sess_foreign = CorrelatedSessionContext(session_ref=sess.session_ref, principal_id="foreign_user")
    res8 = store.save_http_capture(
        request_text="POST /logout\nTest: 8", response_text="HTTP 200 OK",
        metadata={"event_type": "SESSION_REVOCATION", "session_ref": sess.session_ref, "principal_id": "foreign_user", "program_id": "default-program"},
    )
    _make_att(
        aid="ACT-0000000000000000000000000000000000000000000000000000000000000008",
        orig_ref=res8["evidence_id"],
        sess_ctx=sess_foreign,
        prog="default-program",
    )
    v8_ok, v8_reason, _ = validator.verify_invalidation_provenance(res8["evidence_id"], sess)
    assert not v8_ok
    assert "principal_id" in v8_reason and "mismatch" in v8_reason
    s8, f8 = validator.evaluate_revoked_session(sess, target, baseline, res8["evidence_id"])
    assert s8 == "INCONCLUSIVE" and f8 is None

    # 9. Wrong program attribution rejection
    res9 = store.save_http_capture(
        request_text="POST /logout\nTest: 9", response_text="HTTP 200 OK",
        metadata={"event_type": "SESSION_REVOCATION", "session_ref": sess.session_ref, "principal_id": sess.principal_id, "program_id": "foreign_program"},
    )
    _make_att(
        aid="ACT-0000000000000000000000000000000000000000000000000000000000000009",
        orig_ref=res9["evidence_id"],
        sess_ctx=sess,
        prog="foreign_program",
    )
    v9_ok, v9_reason, _ = validator.verify_invalidation_provenance(res9["evidence_id"], sess, program_id="default-program")
    assert not v9_ok
    assert "program_id" in v9_reason and "mismatch" in v9_reason
    s9, f9 = validator.evaluate_revoked_session(sess, target, baseline, res9["evidence_id"])
    assert s9 == "INCONCLUSIVE" and f9 is None

    # 10. Wrong original evidence reference rejection
    dummy_ev = store.save_http_capture(
        "POST /dummy",
        "HTTP 200 OK",
        metadata={
            "event_type": "SESSION_REVOCATION",
            "session_ref": sess.session_ref,
            "principal_id": sess.principal_id,
            "program_id": "default-program",
        },
    )
    att10 = _make_att(
        aid="ACT-0000000000000000000000000000000000000000000000000000000000000010",
        orig_ref=dummy_ev["evidence_id"],
        sess_ctx=sess,
        prog="default-program",
    )
    rec_orig10 = store.get_invalidation_attestation(att10["attestation_id"])
    if rec_orig10 and "att_path" in rec_orig10:
        os.remove(rec_orig10["att_path"])
    att10_bad_ref = dict(att10)
    att10_bad_ref["original_evidence_ref"] = "EVID-FFFFFFFFFFFF"
    store.save_invalidation_attestation(att10_bad_ref)
    v10_ok, v10_reason, _ = validator.verify_invalidation_provenance(att10["attestation_id"], sess)
    assert not v10_ok
    assert "missing from EvidenceStore" in v10_reason or "digest mismatch" in v10_reason
    s10, f10 = validator.evaluate_revoked_session(sess, target, baseline, att10["attestation_id"])
    assert s10 == "INCONCLUSIVE" and f10 is None

    # 11. Missing original capture rejection
    res11 = store.save_http_capture(
        request_text="POST /logout\nTest: 11", response_text="HTTP 200 OK",
        metadata={"event_type": "SESSION_REVOCATION", "session_ref": sess.session_ref, "principal_id": sess.principal_id, "program_id": "default-program"},
    )
    _make_att(
        aid="ACT-0000000000000000000000000000000000000000000000000000000000000011",
        orig_ref=res11["evidence_id"],
        sess_ctx=sess,
        prog="default-program",
    )
    rec11 = store.get_evidence(res11["evidence_id"])
    os.remove(rec11["capture_path"])
    v11_ok, v11_reason, _ = validator.verify_invalidation_provenance(res11["evidence_id"], sess)
    assert not v11_ok
    assert "missing from EvidenceStore" in v11_reason
    s11, f11 = validator.evaluate_revoked_session(sess, target, baseline, res11["evidence_id"])
    assert s11 == "INCONCLUSIVE" and f11 is None

    # 12. Modified original capture rejection
    res12 = store.save_http_capture(
        request_text="POST /logout\nTest: 12", response_text="HTTP 200 OK",
        metadata={"event_type": "SESSION_REVOCATION", "session_ref": sess.session_ref, "principal_id": sess.principal_id, "program_id": "default-program"},
    )
    _make_att(
        aid="ACT-0000000000000000000000000000000000000000000000000000000000000012",
        orig_ref=res12["evidence_id"],
        sess_ctx=sess,
        prog="default-program",
    )
    rec12 = store.get_evidence(res12["evidence_id"])
    with open(rec12["capture_path"], "ab") as f:
        f.write(b"\nTAMPERED_CONTENT_DIGEST_CORRUPTED")
    v12_ok, v12_reason, _ = validator.verify_invalidation_provenance(res12["evidence_id"], sess)
    assert not v12_ok
    assert "digest mismatch" in v12_reason or "missing from EvidenceStore" in v12_reason
    s12, f12 = validator.evaluate_revoked_session(sess, target, baseline, res12["evidence_id"])
    assert s12 == "INCONCLUSIVE" and f12 is None

    # 13. Unknown key identifier rejection
    res13 = store.save_http_capture(
        request_text="POST /logout\nTest: 13", response_text="HTTP 200 OK",
        metadata={"event_type": "SESSION_REVOCATION", "session_ref": sess.session_ref, "principal_id": sess.principal_id, "program_id": "default-program"},
    )
    att13 = _make_att(
        aid="ACT-0000000000000000000000000000000000000000000000000000000000000013",
        orig_ref=res13["evidence_id"],
        sess_ctx=sess,
        prog="default-program",
    )
    att13_bad_k = dict(att13)
    att13_bad_k["key_id"] = "KEY-UNKNOWN-999"
    store.save_invalidation_attestation(att13_bad_k)
    v13_ok, v13_reason, _ = validator.verify_invalidation_provenance(res13["evidence_id"], sess)
    assert not v13_ok
    assert "key_id" in v13_reason
    s13, f13 = validator.evaluate_revoked_session(sess, target, baseline, res13["evidence_id"])
    assert s13 == "INCONCLUSIVE" and f13 is None

    # 14. Missing or unavailable key rejection
    res14 = store.save_http_capture(
        request_text="POST /logout\nTest: 14", response_text="HTTP 200 OK",
        metadata={"event_type": "SESSION_REVOCATION", "session_ref": sess.session_ref, "principal_id": sess.principal_id, "program_id": "default-program"},
    )
    _make_att(
        aid="ACT-0000000000000000000000000000000000000000000000000000000000000014",
        orig_ref=res14["evidence_id"],
        sess_ctx=sess,
        prog="default-program",
    )
    val_wrong_key = PostRevocationResourceValidator(
        validation_engine=engine,
        evidence_store=store,
        scope_engine=mock_scope,
        attestation_key=b"wrong_attestation_key_32_bytes!",
    )
    v14_ok, v14_reason, _ = val_wrong_key.verify_invalidation_provenance(res14["evidence_id"], sess)
    assert not v14_ok
    assert "signature verification failed" in v14_reason
    s14, f14 = val_wrong_key.evaluate_revoked_session(sess, target, baseline, res14["evidence_id"])
    assert s14 == "INCONCLUSIVE" and f14 is None

    # 15. Legacy evidence without attestation returns INCONCLUSIVE
    res15 = store.save_http_capture(
        request_text="POST /legacy_logout", response_text="HTTP 200 OK",
        metadata={"legacy_capture": True, "event_type": "SESSION_REVOCATION"},
    )
    v15_ok, v15_reason, _ = validator.verify_invalidation_provenance(res15["evidence_id"], sess)
    assert not v15_ok
    assert "does not possess an authenticated invalidation event attestation" in v15_reason
    s15, f15 = validator.evaluate_revoked_session(sess, target, baseline, res15["evidence_id"])
    assert s15 == "INCONCLUSIVE" and f15 is None

    # 16. Mode A observation evidence cannot be reused as invalidation proof
    res16 = store.save_http_capture(
        request_text="GET /api/v1/docs/1", response_text="HTTP 200 OK",
        metadata={
            "mode": "MODE_A",
            "category": "SESSION_NOT_INVALIDATED",
            "event_type": "SESSION_REVOCATION",
            "session_ref": sess.session_ref,
            "principal_id": sess.principal_id,
            "program_id": "default-program",
            "invalidation_evidence_ref": "EVID-AABBCCDDEEFF",
        },
    )
    _make_att(
        aid="ACT-0000000000000000000000000000000000000000000000000000000000000016",
        orig_ref=res16["evidence_id"],
        sess_ctx=sess,
        prog="default-program",
    )
    v16_ok, v16_reason, _ = validator.verify_invalidation_provenance(res16["evidence_id"], sess)
    assert not v16_ok
    assert "Mode A observation artifact" in v16_reason
    s16, f16 = validator.evaluate_revoked_session(sess, target, baseline, res16["evidence_id"])
    assert s16 == "INCONCLUSIVE" and f16 is None

    # 17. Operator attestation is distinguishable from independently verified event provenance
    # and operator assertions CANNOT generate confirmed Mode A vulnerability findings (fails closed to INCONCLUSIVE).
    res17 = store.save_http_capture(
        request_text="POST /logout\nAuthorization: Bearer op", response_text="HTTP 200 OK",
        metadata={"event_type": "SESSION_REVOCATION", "session_ref": sess.session_ref, "principal_id": sess.principal_id, "program_id": "default-program"},
    )
    att17 = create_operator_invalidation_attestation(
        evidence_store=store,
        original_evidence_ref=res17["evidence_id"],
        session_ctx=sess,
        program_id="default-program",
        event_type="SESSION_REVOCATION",
        operator_id="security-analyst-01",
        reason="Manually terminated user session via internal admin dashboard",
        attestation_key=att_key,
    )
    v17_ok, v17_reason, v17_rec = validator.verify_invalidation_provenance(res17["evidence_id"], sess)
    assert v17_ok is True
    assert v17_rec["source"] == "OPERATOR_ATTESTATION"
    assert v17_rec["trust_classification"] == "OPERATOR_REPORTED"
    assert "Operator attestation verified" in v17_reason
    assert "security-analyst-01" in v17_reason
    assert v3_rec["source"] == "CONTROLLED_WORKFLOW"
    assert v3_rec["trust_classification"] == "INDEPENDENTLY_VERIFIED_WORKFLOW"
    assert "Invalidation event attestation verified (Source: CONTROLLED_WORKFLOW" in v3_reason
    s17, f17 = validator.evaluate_revoked_session(sess, target, baseline, res17["evidence_id"])
    assert s17 == "INCONCLUSIVE"
    assert f17 is None



def test_revocation_mode_a_scope_authorization_at_dispatch(tmp_path):
    """Verifies that Mode A validates ScopeEngine immediately before request dispatch."""
    target_url = "https://target.local/api/v1/resource"
    engine = MockValidationEngine({
        target_url: ControlledResponse(200, {}, b'{"data": "protected"}'),
    })
    store = EvidenceStore(str(tmp_path / "ev_scope"))
    target = ResourceAccessTarget(resource_id="res_01", resource_type="DOCUMENT", endpoint=target_url, method="GET")
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1")
    baseline = ControlledResponse(200, {}, b'{"data": "protected"}')
    inv_ref = make_valid_invalidation_evidence(store, sess)

    # 1. Missing ScopeEngine fails closed (zero requests dispatched)
    val_no_scope = PostRevocationResourceValidator(validation_engine=engine, evidence_store=store, scope_engine=None)
    s1, f1 = val_no_scope.evaluate_revoked_session(sess, target, baseline, inv_ref)
    assert s1 == "INCONCLUSIVE" and f1 is None
    assert len(engine.dispatched_requests) == 0

    # 2. ScopeEngine returning False (out-of-scope) fails closed (zero requests dispatched)
    class ScopeOut:
        def is_in_scope(self, url):
            return False
    val_scope_out = PostRevocationResourceValidator(validation_engine=engine, evidence_store=store, scope_engine=ScopeOut())
    s2, f2 = val_scope_out.evaluate_revoked_session(sess, target, baseline, inv_ref)
    assert s2 == "INCONCLUSIVE" and f2 is None
    assert len(engine.dispatched_requests) == 0

    # 3. ScopeEngine raising exception fails closed (zero requests dispatched)
    class ScopeErr:
        def is_in_scope(self, url):
            raise RuntimeError("DNS policy resolver unreachable")
    val_scope_err = PostRevocationResourceValidator(validation_engine=engine, evidence_store=store, scope_engine=ScopeErr())
    s3, f3 = val_scope_err.evaluate_revoked_session(sess, target, baseline, inv_ref)
    assert s3 == "INCONCLUSIVE" and f3 is None
    assert len(engine.dispatched_requests) == 0

    # 4. Non-HTTP scheme fails closed
    target_ftp = ResourceAccessTarget(resource_id="res_ftp", resource_type="FILE", endpoint="ftp://target.local/doc", method="GET")
    mock_scope = MockScopeEngine()
    val_valid_scope = PostRevocationResourceValidator(validation_engine=engine, evidence_store=store, scope_engine=mock_scope)
    s4, f4 = val_valid_scope.evaluate_revoked_session(sess, target_ftp, baseline, inv_ref)
    assert s4 == "INCONCLUSIVE" and f4 is None
    assert len(engine.dispatched_requests) == 0


def test_revocation_conservative_response_classifications(tmp_path):
    """Verifies that non-matching, 403, generic 401, redirect, and WAF responses do not emit findings."""
    target_url = "https://target.local/api/v1/docs/1"
    store = EvidenceStore(str(tmp_path / "ev_class"))
    mock_scope = MockScopeEngine()
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1")
    baseline = ControlledResponse(200, {"content-type": "application/json"}, b'{"user": "alice", "doc": "confidential"}')
    target = ResourceAccessTarget(resource_id="res_01", resource_type="DOCUMENT", endpoint=target_url, method="GET")
    inv_ref = make_valid_invalidation_evidence(store, sess)

    cases = [
        # (Response, expected_status)
        (ControlledResponse(403, {}, b'{"error": "Forbidden: access denied"}'), "AUTHORIZATION_DENIED"),
        (ControlledResponse(401, {}, b'{"error": "Invalid authentication credentials"}'), "AUTHENTICATION_FAILED"),
        (ControlledResponse(401, {}, b'{"error": "Session token has expired"}'), "EXPIRED"),
        (ControlledResponse(302, {"Location": "/auth/login"}, b''), "REDIRECT_LOGIN"),
        (ControlledResponse(200, {"content-type": "text/html"}, b'<html><form action="/login"><input type="password"/></form></html>'), "REDIRECT_LOGIN"),
        (ControlledResponse(200, {"Server": "cloudflare"}, b'Attention Required! | Cloudflare Ray ID... Cloudflare security challenge'), "INCONCLUSIVE"),
        (ControlledResponse(200, {"content-type": "text/html"}, b'<html><body>Loading App Shell...</body></html>'), "INCONCLUSIVE"),
        (ControlledResponse(200, {"content-type": "application/json"}, b'{"status": "ok"}'), "INCONCLUSIVE"),
        # Low similarity (< 0.50) against baseline
        (ControlledResponse(200, {"content-type": "application/json"}, b'{"unrelated": "completely different output data"}'), "INCONCLUSIVE"),
    ]

    for resp, exp_status in cases:
        engine = MockValidationEngine({target_url: resp})
        val = PostRevocationResourceValidator(validation_engine=engine, evidence_store=store, scope_engine=mock_scope)
        status, finding = val.evaluate_revoked_session(sess, target, baseline, inv_ref)
        assert status == exp_status, f"Expected status {exp_status} for {resp.status_code}, got {status}"
        assert finding is None, f"Expected no finding for {exp_status}, but finding was emitted"


def test_revocation_mode_a_strictly_read_only(tmp_path):
    """Verifies that Mode A strictly restricts requests to GET or HEAD, never dispatching unsafe mutations."""
    target_url = "https://target.local/api/v1/resource"
    engine = MockValidationEngine({
        target_url: ControlledResponse(401, {}, b'{"error": "Token revoked"}'),
    })
    store = EvidenceStore(str(tmp_path / "ev_ro"))
    mock_scope = MockScopeEngine()
    val = PostRevocationResourceValidator(validation_engine=engine, evidence_store=store, scope_engine=mock_scope)
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1")
    baseline = ControlledResponse(200, {}, b'{"data": "active"}')
    inv_ref = make_valid_invalidation_evidence(store, sess)

    # Even if target defines POST or DELETE, Mode A must downgrade to GET
    target_post = ResourceAccessTarget(resource_id="res_post", resource_type="ITEM", endpoint=target_url, method="POST")
    val.evaluate_revoked_session(sess, target_post, baseline, inv_ref)
    assert len(engine.dispatched_requests) == 1
    assert engine.dispatched_requests[0].method == "GET"

    # HEAD method is preserved
    target_head = ResourceAccessTarget(resource_id="res_head", resource_type="ITEM", endpoint=target_url, method="HEAD")
    val.evaluate_revoked_session(sess, target_head, baseline, inv_ref)
    assert len(engine.dispatched_requests) == 2
    assert engine.dispatched_requests[1].method == "HEAD"


class MockScopeEngine:
    def __init__(self, allowed_prefixes=("https://target.local", "http://target.local")):
        self.allowed_prefixes = allowed_prefixes

    def is_in_scope(self, url: str) -> bool:
        return any(url.startswith(p) for p in self.allowed_prefixes)


def test_revocation_mode_b_controlled_invalidation_approval(tmp_path):
    """Verifies Mode B single-use action-specific approval verification and execution."""
    target_url = "https://target.local/auth/logout"
    engine = MockValidationEngine({
        target_url: ControlledResponse(200, {}, b'{"status": "logged_out"}'),
    })
    test_key = b"A" * 32
    mock_scope = MockScopeEngine()
    store_dir = tmp_path / "ev_store_b_approval"
    store_dir.mkdir()
    store = EvidenceStore(str(store_dir))
    validator = PostRevocationResourceValidator(
        validation_engine=engine,
        state_dir=str(tmp_path),
        scope_engine=mock_scope,
        approval_key=test_key,
        evidence_store=store,
        program_id="test_prog",
    )
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1", volatile_headers={"Authorization": "Bearer active_token"})

    # Build valid dossier and sign with test_key
    from framework.auth_correlation.revocation import sign_action_approval
    dossier_data = {
        "target_endpoint": target_url,
        "method": "POST",
        "test_account": "u1",
        "action_type": "ACTION-LOGOUT",
        "program_id": "test_prog",
        "unique_approval_id": "appr_001",
        "created_at": time.time(),
        "ttl": 300,
    }
    signed_dossier = sign_action_approval(dossier_data, approval_key=test_key)
    action_id = signed_dossier["action_id"]

    # 1. Successful controlled invalidation execution
    res = validator.execute_controlled_invalidation(sess, action_id, signed_dossier)
    assert res is True
    assert sess.lifecycle == CorrelationLifecycle.REVOKED

    # 2. Tampered dossier (mismatched digest)
    tampered_dossier = {**signed_dossier, "target_endpoint": "https://target.local/auth/other"}
    with pytest.raises(ApprovalSecurityError, match="digest mismatch"):
        validator.execute_controlled_invalidation(sess, action_id, tampered_dossier)

    # 3. Invalid signature (tampered signature or wrong key)
    invalid_sig_dossier = {**signed_dossier, "approval_signature": "SIG-" + "0" * 64}
    with pytest.raises(ApprovalSecurityError, match="authorization signature verification failed"):
        validator.execute_controlled_invalidation(sess, action_id, invalid_sig_dossier)

    # 4. Expired approval
    exp_dossier_data = {**dossier_data, "created_at": time.time() - 400, "unique_approval_id": "appr_002"}
    signed_exp = sign_action_approval(exp_dossier_data, approval_key=test_key)
    with pytest.raises(ApprovalSecurityError, match="expired"):
        validator.execute_controlled_invalidation(sess, signed_exp["action_id"], signed_exp)

    # 5. Missing ScopeEngine fails closed
    validator_no_scope = PostRevocationResourceValidator(
        validation_engine=engine,
        state_dir=str(tmp_path),
        scope_engine=None,
        approval_key=test_key,
        evidence_store=store,
        program_id="test_prog",
    )
    valid_dossier2 = sign_action_approval({**dossier_data, "unique_approval_id": "appr_003"}, approval_key=test_key)
    with pytest.raises(ApprovalSecurityError, match="Mandatory ScopeEngine is required"):
        validator_no_scope.execute_controlled_invalidation(sess, valid_dossier2["action_id"], valid_dossier2)

    # 6. Out-of-scope target endpoint fails closed
    out_of_scope_dossier = sign_action_approval({
        **dossier_data,
        "target_endpoint": "https://out-of-scope.com/auth/logout",
        "unique_approval_id": "appr_004",
    }, approval_key=test_key)
    with pytest.raises(ApprovalSecurityError, match="out of scope"):
        validator.execute_controlled_invalidation(sess, out_of_scope_dossier["action_id"], out_of_scope_dossier)

    # 7. Unsupported scheme fails closed
    ftp_dossier = sign_action_approval({
        **dossier_data,
        "target_endpoint": "ftp://target.local/auth/logout",
        "unique_approval_id": "appr_005",
    }, approval_key=test_key)
    with pytest.raises(ApprovalSecurityError, match="invalid or unsupported scheme"):
        validator.execute_controlled_invalidation(sess, ftp_dossier["action_id"], ftp_dossier)

    # 8. Missing EvidenceStore fails closed
    validator_no_store = PostRevocationResourceValidator(
        validation_engine=engine,
        state_dir=str(tmp_path),
        scope_engine=mock_scope,
        approval_key=test_key,
        evidence_store=None,
        program_id="test_prog",
    )
    valid_dossier8 = sign_action_approval({**dossier_data, "unique_approval_id": "appr_008"}, approval_key=test_key)
    with pytest.raises(ApprovalSecurityError, match="EvidenceStore is mandatory"):
        validator_no_store.execute_controlled_invalidation(sess, valid_dossier8["action_id"], valid_dossier8)

    # 9. Attribution mismatch on test_account
    dossier_mismatch_acc = sign_action_approval({
        **dossier_data,
        "test_account": "wrong_user",
        "unique_approval_id": "appr_mismatch_acc",
    }, approval_key=test_key)
    with pytest.raises(ApprovalSecurityError, match="does not match session principal_id"):
        validator.execute_controlled_invalidation(sess, dossier_mismatch_acc["action_id"], dossier_mismatch_acc)

    # 10. Attribution mismatch on program_id
    dossier_mismatch_prog = sign_action_approval({
        **dossier_data,
        "program_id": "other_program",
        "unique_approval_id": "appr_mismatch_prog",
    }, approval_key=test_key)
    with pytest.raises(ApprovalSecurityError, match="does not match validator program_id"):
        validator.execute_controlled_invalidation(sess, dossier_mismatch_prog["action_id"], dossier_mismatch_prog)


def test_revocation_mode_b_replay_and_security_edge_cases(tmp_path):
    """Verifies replay rejection, future timestamps, and corrupted approval tracking in Mode B."""
    from framework.auth_correlation.revocation import sign_action_approval
    target_url = "https://target.local/auth/logout"
    engine = MockValidationEngine({
        target_url: ControlledResponse(200, {}, b'{"status": "logged_out"}'),
    })
    test_key = b"B" * 32
    mock_scope = MockScopeEngine()
    store_dir = tmp_path / "ev_store_b_replay"
    store_dir.mkdir()
    store = EvidenceStore(str(store_dir))
    validator = PostRevocationResourceValidator(
        validation_engine=engine,
        state_dir=str(tmp_path),
        scope_engine=mock_scope,
        approval_key=test_key,
        evidence_store=store,
        program_id="prog1",
    )
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1")

    def make_dossier(appr_id: str, created_at: float = None):
        data = {
            "target_endpoint": target_url,
            "method": "POST",
            "test_account": "u1",
            "action_type": "LOGOUT",
            "program_id": "prog1",
            "unique_approval_id": appr_id,
            "created_at": created_at if created_at is not None else time.time(),
            "ttl": 300,
        }
        signed = sign_action_approval(data, approval_key=test_key)
        return signed["action_id"], signed

    # 1. Single-use execution succeeds first time
    act_id1, dossier1 = make_dossier("appr_single_use_01")
    assert validator.execute_controlled_invalidation(sess, act_id1, dossier1) is True

    # 2. Replay attempt with same unique_approval_id must fail closed
    with pytest.raises(ApprovalSecurityError, match="has already been consumed"):
        validator.execute_controlled_invalidation(sess, act_id1, dossier1)

    # 3. Future-dated approval (timestamp skew attack) must fail closed
    future_time = time.time() + 3600
    act_id_fut, dossier_fut = make_dossier("appr_future_01", created_at=future_time)
    with pytest.raises(ApprovalSecurityError, match="future"):
        validator.execute_controlled_invalidation(sess, act_id_fut, dossier_fut)

    # 4. Corrupted consumed_approvals.json fails closed
    consumed_file = tmp_path / "consumed_approvals.json"
    consumed_file.write_text("{malformed json...", encoding="utf-8")
    act_id3, dossier3 = make_dossier("appr_03")
    with pytest.raises(ApprovalSecurityError, match="is corrupted"):
        validator.execute_controlled_invalidation(sess, act_id3, dossier3)

    # 5. Failed mutation leaves approval consumed (cannot be reused)
    engine_error = MockValidationEngine()
    def raise_network_fault(req):
        raise ConnectionResetError("Connection reset by peer")
    engine_error.send_request = raise_network_fault

    consumed_dir2 = tmp_path / "consumed_test2"
    consumed_dir2.mkdir()
    store_dir2 = consumed_dir2 / "ev"
    store_dir2.mkdir()
    store2 = EvidenceStore(str(store_dir2))
    validator_err = PostRevocationResourceValidator(
        validation_engine=engine_error,
        state_dir=str(consumed_dir2),
        scope_engine=mock_scope,
        approval_key=test_key,
        evidence_store=store2,
        program_id="prog1",
    )
    act_id4, dossier4 = make_dossier("appr_failed_mutation_04")
    with pytest.raises(ApprovalSecurityError, match="Failed to execute controlled invalidation mutation"):
        validator_err.execute_controlled_invalidation(sess, act_id4, dossier4)
    # Proves approval was consumed BEFORE network attempt: subsequent attempt fails as already consumed
    with pytest.raises(ApprovalSecurityError, match="has already been consumed"):
        validator_err.execute_controlled_invalidation(sess, act_id4, dossier4)
    # Proves approval was consumed BEFORE network attempt: subsequent attempt fails as already consumed
    with pytest.raises(ApprovalSecurityError, match="has already been consumed"):
        validator_err.execute_controlled_invalidation(sess, act_id4, dossier4)


def test_preflight_response_classification_distinctions():
    """Verifies granular classification: 401 vs 403 vs login redirect vs public shell vs verified."""
    validator = DualControlPreflightValidator()

    # 1. 401 Unauthorized with expiration cues -> EXPIRED
    resp_expired = ControlledResponse(401, {}, b'{"error": "Session token expired"}')
    assert validator.classify_probe_response(resp_expired) == CorrelationLifecycle.EXPIRED

    # 2. Generic 401 Unauthorized -> AUTHENTICATION_FAILED
    resp_401 = ControlledResponse(401, {}, b'{"error": "Invalid authentication credentials"}')
    assert validator.classify_probe_response(resp_401) == CorrelationLifecycle.AUTHENTICATION_FAILED

    # 3. 403 Forbidden -> AUTHORIZATION_DENIED
    resp_403 = ControlledResponse(403, {}, b'{"error": "Forbidden: insufficient permissions"}')
    assert validator.classify_probe_response(resp_403) == CorrelationLifecycle.AUTHORIZATION_DENIED

    # 4. 302 Redirect to /login -> AUTHENTICATION_FAILED
    resp_302 = ControlledResponse(302, {"Location": "/auth/login"}, b'')
    assert validator.classify_probe_response(resp_302) == CorrelationLifecycle.AUTHENTICATION_FAILED

    # 5. 200 OK containing login challenge form -> AUTHENTICATION_FAILED
    resp_login_form = ControlledResponse(200, {"content-type": "text/html"}, b'<html><form action="/login"><input type="password"/></form></html>')
    assert validator.classify_probe_response(resp_login_form) == CorrelationLifecycle.AUTHENTICATION_FAILED

    # 6. 200 OK containing authorized profile JSON -> VERIFIED
    resp_profile = ControlledResponse(200, {"content-type": "application/json"}, b'{"user_id": "u1", "email": "u1@corp.local"}')
    assert validator.classify_probe_response(resp_profile) == CorrelationLifecycle.VERIFIED

    # 7. Differential comparison: 200 OK identical to anonymous control -> UNKNOWN
    resp_shell = ControlledResponse(200, {"content-type": "text/html"}, b'<html><body>Loading App Shell...</body></html>')
    assert validator.classify_probe_response(resp_shell, anon_resp=resp_shell) == CorrelationLifecycle.UNKNOWN


def test_preflight_anonymous_control_differential_cases():
    """Verifies all required anonymous control differential cases:
    1. Authenticated response equivalent to anonymous control -> UNKNOWN
    2. Authenticated differs meaningfully from anonymous control -> VERIFIED
    3. Both authenticated sessions independently pass -> VERIFIED
    4. Anonymous request failure (transport exception or 500) -> FAILED
    5. Generic SPA shell and WAF challenge do not pass -> UNKNOWN
    """
    preflight_url = "https://target.local/api/profile"

    # Case 1: Authenticated response equivalent to anonymous control -> UNKNOWN
    engine1 = MockValidationEngine({
        f"{preflight_url}|Bearer tok_a": ControlledResponse(200, {"content-type": "application/json"}, b'{"app": "v1", "public": true, "msg": "welcome"}'),
        f"{preflight_url}|Bearer tok_b": ControlledResponse(200, {"content-type": "application/json"}, b'{"app": "v1", "public": true, "msg": "welcome"}'),
        f"{preflight_url}|ANONYMOUS": ControlledResponse(200, {"content-type": "application/json"}, b'{"app": "v1", "public": true, "msg": "welcome"}'),
    })
    v1 = DualControlPreflightValidator(validation_engine=engine1)
    s1_a = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1", volatile_headers={"Authorization": "Bearer tok_a"})
    s1_b = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000002", principal_id="u2", volatile_headers={"Authorization": "Bearer tok_b"})
    ok1, status1, details1 = v1.validate_session_pair(s1_a, s1_b, preflight_url)
    assert ok1 is False
    assert status1 == "SESSION_HEALTH_FAILED"
    assert s1_a.lifecycle == CorrelationLifecycle.UNKNOWN
    assert s1_b.lifecycle == CorrelationLifecycle.UNKNOWN

    # Case 2 & 3: Authenticated differs meaningfully from anonymous control & both sessions independently pass -> VERIFIED
    engine2 = MockValidationEngine({
        f"{preflight_url}|Bearer tok_a": ControlledResponse(200, {"content-type": "application/json"}, b'{"user": "alice", "account_id": "ACC-100", "private_records": [1, 2, 3]}'),
        f"{preflight_url}|Bearer tok_b": ControlledResponse(200, {"content-type": "application/json"}, b'{"user": "bob", "account_id": "ACC-200", "private_records": [4, 5, 6]}'),
        f"{preflight_url}|ANONYMOUS": ControlledResponse(401, {"content-type": "application/json"}, b'{"error": "Authentication credentials required"}'),
    })
    v2 = DualControlPreflightValidator(validation_engine=engine2)
    s2_a = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000003", principal_id="u1", volatile_headers={"Authorization": "Bearer tok_a"})
    s2_b = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000004", principal_id="u2", volatile_headers={"Authorization": "Bearer tok_b"})
    ok2, status2, details2 = v2.validate_session_pair(s2_a, s2_b, preflight_url)
    assert ok2 is True
    assert status2 == "VERIFIED"
    assert s2_a.lifecycle == CorrelationLifecycle.VERIFIED
    assert s2_b.lifecycle == CorrelationLifecycle.VERIFIED

    # Also test validate_single_session for both independently:
    v2_single = DualControlPreflightValidator(validation_engine=engine2)
    s2_a_solo = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000003", principal_id="u1", volatile_headers={"Authorization": "Bearer tok_a"})
    s2_b_solo = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000004", principal_id="u2", volatile_headers={"Authorization": "Bearer tok_b"})
    s_ok_a, s_status_a, _ = v2_single.validate_single_session(s2_a_solo, preflight_url)
    assert s_ok_a is True
    assert s_status_a == "VERIFIED"
    assert s2_a_solo.lifecycle == CorrelationLifecycle.VERIFIED
    s_ok_b, s_status_b, _ = v2_single.validate_single_session(s2_b_solo, preflight_url)
    assert s_ok_b is True
    assert s_status_b == "VERIFIED"
    assert s2_b_solo.lifecycle == CorrelationLifecycle.VERIFIED

    # Case 4a: Anonymous request failure (server error 500) -> FAILED
    engine4a = MockValidationEngine({
        f"{preflight_url}|Bearer tok_a": ControlledResponse(200, {"content-type": "application/json"}, b'{"user": "alice", "data": "ok"}'),
        f"{preflight_url}|Bearer tok_b": ControlledResponse(200, {"content-type": "application/json"}, b'{"user": "bob", "data": "ok"}'),
        f"{preflight_url}|ANONYMOUS": ControlledResponse(500, {"content-type": "application/json"}, b'{"error": "Internal Server Error"}'),
    })
    v4a = DualControlPreflightValidator(validation_engine=engine4a)
    s4a_a = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000005", principal_id="u1", volatile_headers={"Authorization": "Bearer tok_a"})
    s4a_b = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000006", principal_id="u2", volatile_headers={"Authorization": "Bearer tok_b"})
    ok4a, status4a, details4a = v4a.validate_session_pair(s4a_a, s4a_b, preflight_url)
    assert ok4a is False
    assert status4a == "SESSION_HEALTH_FAILED"
    assert s4a_a.lifecycle == CorrelationLifecycle.FAILED
    assert s4a_b.lifecycle == CorrelationLifecycle.FAILED

    # Case 4b: Anonymous request failure (transport exception) -> FAILED
    engine4b = MockValidationEngine({
        f"{preflight_url}|Bearer tok_a": ControlledResponse(200, {"content-type": "application/json"}, b'{"user": "alice", "data": "ok"}'),
        f"{preflight_url}|Bearer tok_b": ControlledResponse(200, {"content-type": "application/json"}, b'{"user": "bob", "data": "ok"}'),
    })
    def fail_anon(req):
        if req.headers.get("Authorization") == "Bearer tok_a":
            return ControlledResponse(200, {"content-type": "application/json"}, b'{"user": "alice", "data": "ok"}')
        if req.headers.get("Authorization") == "Bearer tok_b":
            return ControlledResponse(200, {"content-type": "application/json"}, b'{"user": "bob", "data": "ok"}')
        raise ConnectionResetError("Anonymous connection reset")
    engine4b.send_request = fail_anon
    v4b = DualControlPreflightValidator(validation_engine=engine4b)
    s4b_a = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000007", principal_id="u1", volatile_headers={"Authorization": "Bearer tok_a"})
    s4b_b = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000008", principal_id="u2", volatile_headers={"Authorization": "Bearer tok_b"})
    ok4b, status4b, details4b = v4b.validate_session_pair(s4b_a, s4b_b, preflight_url)
    assert ok4b is False
    assert status4b == "SESSION_HEALTH_FAILED"
    assert s4b_a.lifecycle == CorrelationLifecycle.FAILED
    assert s4b_b.lifecycle == CorrelationLifecycle.FAILED

    # Case 5: Generic SPA shell and WAF challenge do not pass -> UNKNOWN
    # 5a: Generic SPA shell
    engine5a = MockValidationEngine({
        f"{preflight_url}|Bearer tok_a": ControlledResponse(200, {"content-type": "text/html"}, b'<!DOCTYPE html><html><body><div id="root">Loading Single Page Application</div><script src="/app.js"></script></body></html>'),
        f"{preflight_url}|Bearer tok_b": ControlledResponse(200, {"content-type": "text/html"}, b'<!DOCTYPE html><html><body><div id="root">Loading Single Page Application</div><script src="/app.js"></script></body></html>'),
        f"{preflight_url}|ANONYMOUS": ControlledResponse(404, {}, b'Not Found'),
    })
    v5a = DualControlPreflightValidator(validation_engine=engine5a)
    s5a_a = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000009", principal_id="u1", volatile_headers={"Authorization": "Bearer tok_a"})
    s5a_b = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000010", principal_id="u2", volatile_headers={"Authorization": "Bearer tok_b"})
    ok5a, status5a, details5a = v5a.validate_session_pair(s5a_a, s5a_b, preflight_url)
    assert ok5a is False
    assert s5a_a.lifecycle == CorrelationLifecycle.UNKNOWN

    # 5b: WAF challenge (Cloudflare / captcha / etc)
    engine5b = MockValidationEngine({
        f"{preflight_url}|Bearer tok_a": ControlledResponse(200, {"content-type": "text/html"}, b'<html><title>Just a moment...</title><body>Checking your browser before accessing the website. Cloudflare ray id 12345.</body></html>'),
        f"{preflight_url}|Bearer tok_b": ControlledResponse(200, {"content-type": "text/html"}, b'<html><title>Just a moment...</title><body>Checking your browser before accessing the website. Cloudflare ray id 12345.</body></html>'),
        f"{preflight_url}|ANONYMOUS": ControlledResponse(403, {}, b'Forbidden'),
    })
    v5b = DualControlPreflightValidator(validation_engine=engine5b)
    s5b_a = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000011", principal_id="u1", volatile_headers={"Authorization": "Bearer tok_a"})
    s5b_b = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000012", principal_id="u2", volatile_headers={"Authorization": "Bearer tok_b"})
    ok5b, status5b, details5b = v5b.validate_session_pair(s5b_a, s5b_b, preflight_url)
    assert ok5b is False
    assert s5b_a.lifecycle == CorrelationLifecycle.UNKNOWN


def test_controlled_attestation_security_matrix_d1(tmp_path):
    """
    Comprehensive regression test suite for Correction D1: Controlled Invalidation Attestation.
    Covers all 26 required security scenarios fail-closed.
    """
    base_url = "https://target.local"
    logout_url = f"{base_url}/auth/logout"
    doc_url = f"{base_url}/api/v1/doc"
    doc_body = b'{"data": "secret_doc"}'
    engine = MockValidationEngine({
        logout_url: ControlledResponse(200, {"content-type": "application/json"}, b'{"status": "logged_out", "revoked": true}'),
        doc_url: ControlledResponse(200, {"content-type": "application/json"}, doc_body),
    })

    store_dir = tmp_path / "d1_store"
    store_dir.mkdir()
    store = EvidenceStore(str(store_dir))
    key_dir = str(tmp_path / "d1_keys")
    os.makedirs(key_dir, exist_ok=True)
    appr_key = b"\x11" * 32
    att_key = b"\x22" * 32
    state_dir = str(tmp_path / "d1_state")

    mock_scope = MockScopeEngine()
    validator = PostRevocationResourceValidator(
        validation_engine=engine,
        evidence_store=store,
        scope_engine=mock_scope,
        approval_key=appr_key,
        attestation_key=att_key,
        approval_key_dir=key_dir,
        state_dir=state_dir,
        program_id="test_d1_program",
    )

    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1", volatile_headers={"Authorization": "Bearer t1"})
    target = ResourceAccessTarget(resource_id="res_01", resource_type="DOC", endpoint=doc_url, method="GET")
    baseline = ControlledResponse(200, {"content-type": "application/json"}, doc_body)

    # 1. Valid approved action and actual verified execution
    dossier1 = sign_action_approval({
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": "test_d1_program",
        "target_endpoint": logout_url,
        "test_account": "u1",
        "ttl": 300,
        "unique_approval_id": "appr_d1_01",
    }, approval_key=appr_key)
    success1 = validator.execute_controlled_invalidation(sess, dossier1["action_id"], dossier1)
    assert success1 is True
    assert sess.invalidation_evidence_ref is not None
    v1_ok, _, v1_rec = validator.verify_invalidation_provenance(sess.invalidation_evidence_ref, sess, program_id="test_d1_program")
    assert v1_ok is True
    assert v1_rec["trust_classification"] == "INDEPENDENTLY_VERIFIED_WORKFLOW"

    # 2. Fabricated action ID without execution
    with pytest.raises(AttestationSecurityError, match="Controlled attestation cannot be created from caller assertion"):
        create_controlled_invalidation_attestation(
            evidence_store=store,
            execution_result=None,
            action_id="ACT-0000000000000000000000000000000000000000000000000000000000000002",
        )

    # 3. Missing approval
    with pytest.raises(ApprovalSecurityError, match="Action dossier must be a dictionary"):
        validator.execute_controlled_invalidation(sess, "ACT-" + "0" * 64, None)

    # 4. Invalid approval signature
    dossier4 = dict(dossier1)
    dossier4["action_id"] = "ACT-" + "4" * 64
    dossier4["approval_signature"] = "SIG-" + "f" * 64
    with pytest.raises(ApprovalSecurityError, match="digest mismatch|signature verification failed"):
        validator.execute_controlled_invalidation(sess, dossier4["action_id"], dossier4)

    # 5. Modified action dossier
    dossier5 = sign_action_approval({
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": "test_d1_program",
        "target_endpoint": logout_url,
        "test_account": "u1",
        "ttl": 300,
        "unique_approval_id": "appr_d1_05",
    }, approval_key=appr_key)
    dossier5["target_endpoint"] = "https://evil.local/logout"
    with pytest.raises(ApprovalSecurityError, match="digest mismatch"):
        validator.execute_controlled_invalidation(sess, dossier5["action_id"], dossier5)

    # 6. Wrong action ID
    dossier6 = sign_action_approval({
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": "test_d1_program",
        "target_endpoint": logout_url,
        "test_account": "u1",
        "ttl": 300,
        "unique_approval_id": "appr_d1_06",
    }, approval_key=appr_key)
    with pytest.raises(ApprovalSecurityError, match="does not match parameter action_id"):
        validator.execute_controlled_invalidation(sess, "ACT-" + "6" * 64, dossier6)

    # 7. Wrong endpoint (out of scope)
    class RejectScope:
        def is_in_scope(self, url):
            return False
    val_out_of_scope = PostRevocationResourceValidator(
        validation_engine=engine, evidence_store=store, scope_engine=RejectScope(),
        approval_key=appr_key, attestation_key=att_key, state_dir=state_dir, program_id="test_d1_program",
    )
    dossier7 = sign_action_approval({
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": "test_d1_program",
        "target_endpoint": "https://out-of-scope.local/auth/logout",
        "test_account": "u1",
        "ttl": 300,
        "unique_approval_id": "appr_d1_07",
    }, approval_key=appr_key)
    with pytest.raises(ApprovalSecurityError, match="out of scope"):
        val_out_of_scope.execute_controlled_invalidation(sess, dossier7["action_id"], dossier7)

    # 8. Wrong HTTP method
    with pytest.raises(ApprovalSecurityError, match="invalid or unsupported HTTP method"):
        sign_action_approval({
            "action_type": "LOGOUT",
            "created_at": time.time(),
            "method": "GET",
            "program_id": "test_d1_program",
            "target_endpoint": logout_url,
            "test_account": "u1",
            "ttl": 300,
            "unique_approval_id": "appr_d1_08",
        }, approval_key=appr_key)

    # 9. Wrong principal attribution
    sess_u2 = CorrelatedSessionContext(session_ref=sess.session_ref, principal_id="u2")
    v9_ok, v9_reason, _ = validator.verify_invalidation_provenance(sess.invalidation_evidence_ref, sess_u2, program_id="test_d1_program")
    assert v9_ok is False
    assert "principal_id" in v9_reason and "mismatch" in v9_reason

    # 10. Wrong program attribution
    v10_ok, v10_reason, _ = validator.verify_invalidation_provenance(sess.invalidation_evidence_ref, sess, program_id="other_prog")
    assert v10_ok is False
    assert "program_id" in v10_reason and "mismatch" in v10_reason

    # 11. Wrong session attribution
    sess_other = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000999", principal_id="u1")
    v11_ok, v11_reason, _ = validator.verify_invalidation_provenance(sess.invalidation_evidence_ref, sess_other, program_id="test_d1_program")
    assert v11_ok is False
    assert "session_ref" in v11_reason and "mismatch" in v11_reason

    # 12. Missing mutation evidence
    dossier12 = sign_action_approval({
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": "test_d1_program",
        "target_endpoint": logout_url,
        "test_account": "u1",
        "ttl": 300,
        "unique_approval_id": "appr_d1_12",
    }, approval_key=appr_key)
    sess12 = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000012", principal_id="u1")
    assert validator.execute_controlled_invalidation(sess12, dossier12["action_id"], dossier12) is True
    att_rec12 = store.get_invalidation_attestation(sess12.invalidation_evidence_ref)
    mut_rec12 = store.get_evidence(att_rec12["mutation_evidence_ref"])
    os.remove(mut_rec12["capture_path"])
    v12_ok, v12_reason, _ = validator.verify_invalidation_provenance(sess12.invalidation_evidence_ref, sess12, program_id="test_d1_program")
    assert v12_ok is False
    assert "missing from EvidenceStore" in v12_reason

    # 13. Missing verification evidence
    dossier13 = sign_action_approval({
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": "test_d1_program",
        "target_endpoint": logout_url,
        "test_account": "u1",
        "ttl": 300,
        "unique_approval_id": "appr_d1_13",
    }, approval_key=appr_key)
    sess13 = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000013", principal_id="u1")
    assert validator.execute_controlled_invalidation(sess13, dossier13["action_id"], dossier13) is True
    att_rec13 = store.get_invalidation_attestation(sess13.invalidation_evidence_ref)
    ver_rec13 = store.get_evidence(att_rec13["verification_evidence_ref"])
    os.remove(ver_rec13["capture_path"])
    v13_ok, v13_reason, _ = validator.verify_invalidation_provenance(sess13.invalidation_evidence_ref, sess13, program_id="test_d1_program")
    assert v13_ok is False
    assert "missing from EvidenceStore" in v13_reason

    # 14. Mutation response without successful invalidation verification (500 Server Error)
    engine_fail = MockValidationEngine({
        logout_url: ControlledResponse(500, {}, b'Internal Server Error'),
    })
    val_fail = PostRevocationResourceValidator(
        validation_engine=engine_fail, evidence_store=store, scope_engine=mock_scope,
        approval_key=appr_key, attestation_key=att_key, state_dir=state_dir, program_id="test_d1_program",
    )
    dossier14 = sign_action_approval({
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": "test_d1_program",
        "target_endpoint": logout_url,
        "test_account": "u1",
        "ttl": 300,
        "unique_approval_id": "appr_d1_14",
    }, approval_key=appr_key)
    sess14 = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000014", principal_id="u1")
    success14 = val_fail.execute_controlled_invalidation(sess14, dossier14["action_id"], dossier14)
    assert success14 is False
    assert sess14.invalidation_evidence_ref is None

    # 15. Ambiguous verification result (generic 200 without revocation keywords and probe returns 200)
    engine_ambig = MockValidationEngine({
        logout_url: ControlledResponse(200, {"content-type": "text/html"}, b'<html><body>Generic Landing Shell</body></html>'),
    })
    val_ambig = PostRevocationResourceValidator(
        validation_engine=engine_ambig, evidence_store=store, scope_engine=mock_scope,
        approval_key=appr_key, attestation_key=att_key, state_dir=state_dir, program_id="test_d1_program",
    )
    dossier15 = sign_action_approval({
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": "test_d1_program",
        "target_endpoint": logout_url,
        "test_account": "u1",
        "ttl": 300,
        "unique_approval_id": "appr_d1_15",
    }, approval_key=appr_key)
    sess15 = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000015", principal_id="u1")
    success15 = val_ambig.execute_controlled_invalidation(sess15, dossier15["action_id"], dossier15)
    assert success15 is False
    assert sess15.invalidation_evidence_ref is None

    # 16. Missing signing key
    val_missing_key = PostRevocationResourceValidator(
        validation_engine=engine, evidence_store=store, scope_engine=mock_scope,
        approval_key=appr_key, attestation_key=None, approval_key_dir="/nonexistent_path_key_dir_9999",
        state_dir=state_dir, program_id="test_d1_program",
    )
    v16_ok, v16_reason, _ = val_missing_key.verify_invalidation_provenance(sess.invalidation_evidence_ref, sess, program_id="test_d1_program")
    assert v16_ok is False
    assert "key unavailable or insecure" in v16_reason.lower() or "signature verification failed" in v16_reason.lower()

    # 17. Wrong signing key
    val_wrong_key = PostRevocationResourceValidator(
        validation_engine=engine, evidence_store=store, scope_engine=mock_scope,
        approval_key=appr_key, attestation_key=b"\x99" * 32, state_dir=state_dir, program_id="test_d1_program",
    )
    v17_ok, v17_reason, _ = val_wrong_key.verify_invalidation_provenance(sess.invalidation_evidence_ref, sess, program_id="test_d1_program")
    assert v17_ok is False
    assert "signature verification failed" in v17_reason

    # 18. Unknown key ID
    base_rec = store.get_invalidation_attestation(sess.invalidation_evidence_ref)
    att_rec18 = dict(base_rec)
    att_rec18["key_id"] = "KEY-UNKNOWN-999"
    store.save_invalidation_attestation(att_rec18)
    v18_ok, v18_reason, _ = validator.verify_invalidation_provenance(sess.invalidation_evidence_ref, sess, program_id="test_d1_program")
    assert v18_ok is False
    assert "key_id" in v18_reason

    # 19. Modified signed action ID
    att_rec19 = dict(base_rec)
    att_rec19["action_id"] = "ACT-" + "9" * 64
    store.save_invalidation_attestation(att_rec19)
    v19_ok, v19_reason, _ = validator.verify_invalidation_provenance(sess.invalidation_evidence_ref, sess, program_id="test_d1_program")
    assert v19_ok is False
    assert "digest mismatch" in v19_reason or "does not match" in v19_reason

    # 20. Modified signed evidence reference
    att_rec20 = dict(base_rec)
    att_rec20["original_evidence_ref"] = "EVID-000000000000"
    store.save_invalidation_attestation(att_rec20)
    v20_ok, v20_reason, _ = validator.verify_invalidation_provenance(sess.invalidation_evidence_ref, sess, program_id="test_d1_program")
    assert v20_ok is False
    assert "digest mismatch" in v20_reason or "missing from EvidenceStore" in v20_reason

    # 21. Modified verification result
    att_rec21 = dict(base_rec)
    att_rec21["invalidation_verification_result"] = "INVALID"
    store.save_invalidation_attestation(att_rec21)
    v21_ok, v21_reason, _ = validator.verify_invalidation_provenance(sess.invalidation_evidence_ref, sess, program_id="test_d1_program")
    assert v21_ok is False
    assert "digest mismatch" in v21_reason or "not valid" in v21_reason

    # 22. Modified timestamp
    att_rec22 = dict(base_rec)
    att_rec22["created_at"] = "2099-01-01T00:00:00Z"
    store.save_invalidation_attestation(att_rec22)
    v22_ok, v22_reason, _ = validator.verify_invalidation_provenance(sess.invalidation_evidence_ref, sess, program_id="test_d1_program")
    assert v22_ok is False
    assert "digest mismatch" in v22_reason or "tampered" in v22_reason

    # 23. Replay of an existing attestation / action
    with pytest.raises(ApprovalSecurityError, match="already been consumed"):
        validator.execute_controlled_invalidation(sess, dossier1["action_id"], dossier1)

    # 24. Cross-session attestation reuse
    sess_x = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000088", principal_id="u1")
    st24, find24 = validator.evaluate_revoked_session(sess_x, target, baseline, sess.invalidation_evidence_ref)
    assert st24 == "INCONCLUSIVE" and find24 is None

    # 25. Cross-program attestation reuse
    val_prog2 = PostRevocationResourceValidator(
        validation_engine=engine, evidence_store=store, scope_engine=mock_scope,
        approval_key=appr_key, attestation_key=att_key, state_dir=state_dir, program_id="other_program_id",
    )
    st25, find25 = val_prog2.evaluate_revoked_session(sess, target, baseline, sess.invalidation_evidence_ref)
    assert st25 == "INCONCLUSIVE" and find25 is None

    # 26. Evidence persistence failure
    class FailingStore:
        def is_writable(self):
            return True
        def save_http_capture(self, *a, **kw):
            raise OSError("Disk quota exceeded")
    val_fail_store = PostRevocationResourceValidator(
        validation_engine=engine, evidence_store=FailingStore(), scope_engine=mock_scope,
        approval_key=appr_key, attestation_key=att_key, state_dir=state_dir, program_id="test_d1_program",
    )
    dossier26 = sign_action_approval({
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": "test_d1_program",
        "target_endpoint": logout_url,
        "test_account": "u1",
        "ttl": 300,
        "unique_approval_id": "appr_d1_26",
    }, approval_key=appr_key)
    sess26 = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000026", principal_id="u1")
    with pytest.raises(EvidencePersistenceError, match="Failed to record execution or issue attestation|Failed to persist controlled revocation evidence"):
        val_fail_store.execute_controlled_invalidation(sess26, dossier26["action_id"], dossier26)

    # 27. Fabricated execution ID in attestation (not found in ExecutionLedger)
    first_eid = base_rec["execution_id"]
    att_rec27 = dict(base_rec)
    att_rec27["execution_id"] = "EXEC-" + "0" * 64
    store.save_invalidation_attestation(att_rec27)
    v27_ok, v27_reason, _ = validator.verify_invalidation_provenance(sess.invalidation_evidence_ref, sess, program_id="test_d1_program")
    assert v27_ok is False
    assert "digest mismatch" in v27_reason or "missing from ExecutionLedger" in v27_reason
    store.save_invalidation_attestation(base_rec)

    # 28. Single-use execution record claim replay rejected
    with pytest.raises(ExecutionProvenanceError, match="already been claimed"):
        validator.ledger.claim_for_attestation(first_eid, "ATT-REPLAY-ATTEMPT-01")

    # 29. Negative revocation statement in mutation response fails closed
    engine_neg = MockValidationEngine({
        logout_url: ControlledResponse(200, {"content-type": "application/json"}, b'{"status": "Your session was not revoked"}'),
    })
    val_neg = PostRevocationResourceValidator(
        validation_engine=engine_neg, evidence_store=store, scope_engine=mock_scope,
        approval_key=appr_key, attestation_key=att_key, state_dir=state_dir, program_id="test_d1_program",
    )
    dossier29 = sign_action_approval({
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": "test_d1_program",
        "target_endpoint": logout_url,
        "test_account": "u1",
        "ttl": 300,
        "unique_approval_id": "appr_d1_29",
    }, approval_key=appr_key)
    sess29 = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000029", principal_id="u1")
    success29 = val_neg.execute_controlled_invalidation(sess29, dossier29["action_id"], dossier29)
    assert success29 is False
    assert sess29.invalidation_evidence_ref is None

    # 30. Unwritable EvidenceStore before mutation fails closed
    class UnwritableStore:
        def is_writable(self):
            return False
    val_unwritable = PostRevocationResourceValidator(
        validation_engine=engine, evidence_store=UnwritableStore(), scope_engine=mock_scope,
        approval_key=appr_key, attestation_key=att_key, state_dir=state_dir, program_id="test_d1_program",
    )
    dossier30 = sign_action_approval({
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": "test_d1_program",
        "target_endpoint": logout_url,
        "test_account": "u1",
        "ttl": 300,
        "unique_approval_id": "appr_d1_30",
    }, approval_key=appr_key)
    sess30 = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000030", principal_id="u1")
    with pytest.raises(ApprovalSecurityError, match="EvidenceStore is not writable or evidence directory is insecure"):
        val_unwritable.execute_controlled_invalidation(sess30, dossier30["action_id"], dossier30)

    # 31. Attribution mismatch on test_account in Mode B fails closed
    dossier31 = sign_action_approval({
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": "test_d1_program",
        "target_endpoint": logout_url,
        "test_account": "wrong_account",
        "ttl": 300,
        "unique_approval_id": "appr_d1_31",
    }, approval_key=appr_key)
    sess31 = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000031", principal_id="u1")
    with pytest.raises(ApprovalSecurityError, match="does not match session principal_id"):
        validator.execute_controlled_invalidation(sess31, dossier31["action_id"], dossier31)

    # 32. Attribution mismatch on program_id in Mode B fails closed
    dossier32 = sign_action_approval({
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": "foreign_program",
        "target_endpoint": logout_url,
        "test_account": "u1",
        "ttl": 300,
        "unique_approval_id": "appr_d1_32",
    }, approval_key=appr_key)
    sess32 = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000032", principal_id="u1")
    with pytest.raises(ApprovalSecurityError, match="does not match validator program_id"):
        validator.execute_controlled_invalidation(sess32, dossier32["action_id"], dossier32)


def test_operator_attestation_security_matrix_d2(tmp_path):
    """
    Comprehensive regression test suite for Correction D2: Operator Attestation Trust Classification.
    Covers all 9 required operator-attestation security and trust boundary cases.
    """
    base_url = "https://target.local"
    doc_url = f"{base_url}/api/v1/doc"
    doc_body = b'{"data": "sensitive"}'
    engine = MockValidationEngine({
        doc_url: ControlledResponse(200, {"content-type": "application/json"}, doc_body),
    })

    store = EvidenceStore(str(tmp_path / "d2_store"))
    att_key = b"\x33" * 32
    mock_scope = MockScopeEngine()
    validator = PostRevocationResourceValidator(
        validation_engine=engine,
        evidence_store=store,
        scope_engine=mock_scope,
        attestation_key=att_key,
        program_id="prog_d2",
    )

    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1", volatile_headers={"Authorization": "Bearer t1"})
    target = ResourceAccessTarget(resource_id="res_01", resource_type="DOC", endpoint=doc_url, method="GET")
    baseline = ControlledResponse(200, {"content-type": "application/json"}, doc_body)

    orig_cap = store.save_http_capture(
        request_text="POST /admin/terminate-session\nAuthorization: Bearer admin_tok",
        response_text='HTTP 200 OK\n{"terminated": true}',
        metadata={"event_type": "SESSION_REVOCATION", "session_ref": sess.session_ref, "principal_id": sess.principal_id, "program_id": "prog_d2"},
        prefix="admin_action",
    )

    # 1. Valid operator attestation
    op_att = create_operator_invalidation_attestation(
        evidence_store=store,
        original_evidence_ref=orig_cap["evidence_id"],
        session_ctx=sess,
        program_id="prog_d2",
        event_type="SESSION_REVOCATION",
        operator_id="sec-analyst-99",
        reason="Manual session termination following credential leak report",
        attestation_key=att_key,
    )
    v1_ok, v1_reason, v1_rec = validator.verify_invalidation_provenance(op_att["attestation_id"], sess, program_id="prog_d2")
    assert v1_ok is True
    assert v1_rec["source"] == "OPERATOR_ATTESTATION"
    assert v1_rec["trust_classification"] == "OPERATOR_REPORTED"
    assert "Operator attestation verified" in v1_reason

    # 2. Missing operator ID
    with pytest.raises(AttestationSecurityError, match="Operator ID is required"):
        create_operator_invalidation_attestation(
            evidence_store=store,
            original_evidence_ref=orig_cap["evidence_id"],
            session_ctx=sess,
            program_id="prog_d2",
            event_type="SESSION_REVOCATION",
            operator_id="",
            reason="Some valid reason",
            attestation_key=att_key,
        )

    # 3. Missing reason
    with pytest.raises(AttestationSecurityError, match="Attestation reason is required"):
        create_operator_invalidation_attestation(
            evidence_store=store,
            original_evidence_ref=orig_cap["evidence_id"],
            session_ctx=sess,
            program_id="prog_d2",
            event_type="SESSION_REVOCATION",
            operator_id="sec-analyst-99",
            reason="   ",
            attestation_key=att_key,
        )

    # 4. Modified signature
    op_att_bad_sig = dict(op_att)
    op_att_bad_sig["signature"] = "ATT-SIG-" + "0" * 64
    store.save_invalidation_attestation(op_att_bad_sig)
    v4_ok, v4_reason, _ = validator.verify_invalidation_provenance(op_att["attestation_id"], sess, program_id="prog_d2")
    assert v4_ok is False
    assert "signature verification failed" in v4_reason
    store.save_invalidation_attestation(op_att)

    # 5. Wrong session
    sess_wrong_s = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000999", principal_id="u1")
    v5_ok, v5_reason, _ = validator.verify_invalidation_provenance(op_att["attestation_id"], sess_wrong_s, program_id="prog_d2")
    assert v5_ok is False
    assert "session_ref" in v5_reason and "mismatch" in v5_reason

    # 6. Wrong principal
    sess_wrong_p = CorrelatedSessionContext(session_ref=sess.session_ref, principal_id="u2")
    v6_ok, v6_reason, _ = validator.verify_invalidation_provenance(op_att["attestation_id"], sess_wrong_p, program_id="prog_d2")
    assert v6_ok is False
    assert "principal_id" in v6_reason and "mismatch" in v6_reason

    # 7. Wrong program
    v7_ok, v7_reason, _ = validator.verify_invalidation_provenance(op_att["attestation_id"], sess, program_id="other_prog")
    assert v7_ok is False
    assert "program_id" in v7_reason and "mismatch" in v7_reason

    # 8. Attempted upgrade to controlled workflow (tamper source)
    op_att_tampered_source = dict(op_att)
    op_att_tampered_source["source"] = "CONTROLLED_WORKFLOW"
    store.save_invalidation_attestation(op_att_tampered_source)
    v8_ok, v8_reason, _ = validator.verify_invalidation_provenance(op_att["attestation_id"], sess, program_id="prog_d2")
    assert v8_ok is False
    assert "digest mismatch" in v8_reason or "signature verification failed" in v8_reason
    store.save_invalidation_attestation(op_att)

    # 9. Operator-only evidence cannot generate a falsely confirmed controlled-workflow finding
    s9, f9 = validator.evaluate_revoked_session(sess, target, baseline, op_att["attestation_id"])
    assert s9 == "INCONCLUSIVE"
    assert f9 is None

