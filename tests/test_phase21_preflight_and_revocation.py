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
)
from framework.auth_correlation.preflight import DualControlPreflightValidator
from framework.auth_correlation.revocation import (
    PostRevocationResourceValidator,
    ApprovalSecurityError,
)
from framework.authz.model import ResourceAccessTarget
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
    """Verifies that 401/403 post-revocation response confirms SECURE_INVALIDATION."""
    target_url = "https://target.local/api/v1/docs/1"
    engine = MockValidationEngine({
        target_url: ControlledResponse(401, {}, b'{"error": "Token has been revoked"}'),
    })
    validator = PostRevocationResourceValidator(validation_engine=engine)
    target = ResourceAccessTarget(resource_id="res_01", resource_type="DOCUMENT", endpoint=target_url, method="GET")
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1", volatile_headers={"Authorization": "Bearer revoked_token"})
    baseline = ControlledResponse(200, {}, b'{"doc": "confidential"}')

    status, finding = validator.evaluate_revoked_session(sess, target, baseline, "EVID-0123456789ab")
    assert status == "SECURE_INVALIDATION"
    assert finding is None


def test_revocation_mode_a_vulnerability_emission():
    """Verifies that 200 OK post-revocation with matching baseline emits SESSION_NOT_INVALIDATED."""
    target_url = "https://target.local/api/v1/docs/1"
    doc_body = b'{"document_id": "1", "sensitive_data": "secret_content_xyz"}'
    engine = MockValidationEngine({
        target_url: ControlledResponse(200, {"content-type": "application/json"}, doc_body),
    })
    validator = PostRevocationResourceValidator(validation_engine=engine)
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
    assert "EVID-0123456789ab" in finding.evidence_chain


def test_revocation_mode_b_controlled_invalidation_approval(tmp_path):
    """Verifies Mode B single-use action-specific approval verification and execution."""
    target_url = "https://target.local/auth/logout"
    engine = MockValidationEngine({
        target_url: ControlledResponse(200, {}, b'{"status": "logged_out"}'),
    })
    validator = PostRevocationResourceValidator(validation_engine=engine, state_dir=str(tmp_path))
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1", volatile_headers={"Authorization": "Bearer active_token"})

    # Build valid dossier matching mandatory bound action properties
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
    canonical_str = json.dumps(dict(sorted(dossier_data.items())), sort_keys=True)
    digest = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
    action_id = f"ACT-{digest}"
    dossier = {**dossier_data, "action_id": action_id}

    # Successful controlled invalidation execution
    res = validator.execute_controlled_invalidation(sess, action_id, dossier)
    assert res is True
    assert sess.lifecycle == CorrelationLifecycle.REVOKED

    # Case 2: Tampered dossier (mismatched digest)
    tampered_dossier = {**dossier, "target_endpoint": "https://attacker.local/evil"}
    with pytest.raises(ApprovalSecurityError, match="digest mismatch"):
        validator.execute_controlled_invalidation(sess, action_id, tampered_dossier)

    # Case 3: Expired approval
    expired_dossier = {**dossier_data, "created_at": time.time() - 400, "unique_approval_id": "appr_002"}
    exp_digest = hashlib.sha256(json.dumps(dict(sorted(expired_dossier.items())), sort_keys=True).encode("utf-8")).hexdigest()
    exp_action_id = f"ACT-{exp_digest}"
    with pytest.raises(ApprovalSecurityError, match="expired"):
        validator.execute_controlled_invalidation(sess, exp_action_id, {**expired_dossier, "action_id": exp_action_id})


def test_revocation_mode_b_replay_and_security_edge_cases(tmp_path):
    """Verifies replay rejection, future timestamps, and corrupted approval tracking in Mode B."""
    target_url = "https://target.local/auth/logout"
    engine = MockValidationEngine({
        target_url: ControlledResponse(200, {}, b'{"status": "logged_out"}'),
    })
    validator = PostRevocationResourceValidator(validation_engine=engine, state_dir=str(tmp_path))
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
        can_str = json.dumps(dict(sorted(data.items())), sort_keys=True)
        digest = hashlib.sha256(can_str.encode("utf-8")).hexdigest()
        act_id = f"ACT-{digest}"
        return act_id, {**data, "action_id": act_id}

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

