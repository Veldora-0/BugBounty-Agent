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
import json
import time
import pytest

from framework.auth_correlation.cvss import CVSS31Calculator
from framework.auth_correlation.model import (
    CorrelatedSessionContext,
    CorrelationLifecycle,
    CorrelationFinding,
    EvidencePersistenceError,
)
from framework.auth_correlation.preflight import DualControlPreflightValidator
from framework.auth_correlation.revocation import (
    PostRevocationResourceValidator,
    ApprovalSecurityError,
    classify_revocation_response,
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


def test_revocation_mode_a_secure_invalidation():
    """Verifies that 401 with explicit revocation keywords confirms REVOKED."""
    target_url = "https://target.local/api/v1/docs/1"
    engine = MockValidationEngine({
        target_url: ControlledResponse(401, {}, b'{"error": "Token has been revoked"}'),
    })
    validator = PostRevocationResourceValidator(validation_engine=engine)
    target = ResourceAccessTarget(resource_id="res_01", resource_type="DOCUMENT", endpoint=target_url, method="GET")
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1", volatile_headers={"Authorization": "Bearer revoked_token"})
    baseline = ControlledResponse(200, {}, b'{"doc": "confidential"}')

    status, finding = validator.evaluate_revoked_session(sess, target, baseline, "EVID-0123456789ab")
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

    # 1. With configured EvidenceStore: evidence is saved and chain contains valid ID
    validator = PostRevocationResourceValidator(validation_engine=engine, evidence_store=store)
    target = ResourceAccessTarget(resource_id="res_01", resource_type="DOCUMENT", endpoint=target_url, method="GET")
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1", volatile_headers={"Authorization": "Bearer revoked_token"})
    baseline = ControlledResponse(200, {"content-type": "application/json"}, doc_body)

    status, finding = validator.evaluate_revoked_session(sess, target, baseline, "EVID-0123456789ab")
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

    # 2. Without EvidenceStore: evidence_chain is empty and description notes lack of persistence
    validator_no_store = PostRevocationResourceValidator(validation_engine=engine, evidence_store=None)
    status_ns, finding_ns = validator_no_store.evaluate_revoked_session(sess, target, baseline, "EVID-0123456789ab")
    assert status_ns == "SESSION_NOT_INVALIDATED"
    assert finding_ns is not None
    assert finding_ns.evidence_chain == []
    assert "[EVIDENCE_NOT_PERSISTED]" in finding_ns.description

    # 3. Failing EvidenceStore raises EvidencePersistenceError
    class FailingStore:
        def save_http_capture(self, *args, **kwargs):
            raise IOError("Simulated disk error during capture")

    validator_fail = PostRevocationResourceValidator(validation_engine=engine, evidence_store=FailingStore())
    with pytest.raises(EvidencePersistenceError, match="Failed to persist Mode A revocation evidence"):
        validator_fail.evaluate_revoked_session(sess, target, baseline, "EVID-0123456789ab")


def test_revocation_conservative_response_classifications():
    """Verifies that non-matching, 403, generic 401, redirect, and WAF responses do not emit findings."""
    target_url = "https://target.local/api/v1/docs/1"
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1")
    baseline = ControlledResponse(200, {"content-type": "application/json"}, b'{"user": "alice", "doc": "confidential"}')
    target = ResourceAccessTarget(resource_id="res_01", resource_type="DOCUMENT", endpoint=target_url, method="GET")

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
        val = PostRevocationResourceValidator(validation_engine=engine)
        status, finding = val.evaluate_revoked_session(sess, target, baseline, "EVID-0123456789ab")
        assert status == exp_status, f"Expected status {exp_status} for {resp.status_code}, got {status}"
        assert finding is None, f"Expected no finding for {exp_status}, but finding was emitted"


def test_revocation_mode_a_strictly_read_only():
    """Verifies that Mode A strictly restricts requests to GET or HEAD, never dispatching unsafe mutations."""
    target_url = "https://target.local/api/v1/resource"
    engine = MockValidationEngine({
        target_url: ControlledResponse(401, {}, b'{"error": "Token revoked"}'),
    })
    val = PostRevocationResourceValidator(validation_engine=engine)
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1")
    baseline = ControlledResponse(200, {}, b'{"data": "active"}')

    # Even if target defines POST or DELETE, Mode A must downgrade to GET
    target_post = ResourceAccessTarget(resource_id="res_post", resource_type="ITEM", endpoint=target_url, method="POST")
    val.evaluate_revoked_session(sess, target_post, baseline, "EVID-0123456789ab")
    assert len(engine.dispatched_requests) == 1
    assert engine.dispatched_requests[0].method == "GET"

    # HEAD method is preserved
    target_head = ResourceAccessTarget(resource_id="res_head", resource_type="ITEM", endpoint=target_url, method="HEAD")
    val.evaluate_revoked_session(sess, target_head, baseline, "EVID-0123456789ab")
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
    validator = PostRevocationResourceValidator(
        validation_engine=engine,
        state_dir=str(tmp_path),
        scope_engine=mock_scope,
        approval_key=test_key,
    )
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1", volatile_headers={"Authorization": "Bearer active_token"})

    # Build valid dossier and sign with test_key
    from framework.auth_correlation.revocation import sign_action_approval
    dossier_data = {
        "target_endpoint": target_url,
        "method": "POST",
        "test_account": "user_test_b",
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


def test_revocation_mode_b_replay_and_security_edge_cases(tmp_path):
    """Verifies replay rejection, future timestamps, and corrupted approval tracking in Mode B."""
    from framework.auth_correlation.revocation import sign_action_approval
    target_url = "https://target.local/auth/logout"
    engine = MockValidationEngine({
        target_url: ControlledResponse(200, {}, b'{"status": "logged_out"}'),
    })
    test_key = b"B" * 32
    mock_scope = MockScopeEngine()
    validator = PostRevocationResourceValidator(
        validation_engine=engine,
        state_dir=str(tmp_path),
        scope_engine=mock_scope,
        approval_key=test_key,
    )
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1")

    def make_dossier(appr_id: str, created_at: float = None):
        data = {
            "target_endpoint": target_url,
            "method": "POST",
            "test_account": "user_test_b",
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
    validator_err = PostRevocationResourceValidator(
        validation_engine=engine_error,
        state_dir=str(consumed_dir2),
        scope_engine=mock_scope,
        approval_key=test_key,
    )
    act_id4, dossier4 = make_dossier("appr_failed_mutation_04")
    with pytest.raises(ApprovalSecurityError, match="Failed to execute controlled invalidation mutation"):
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

