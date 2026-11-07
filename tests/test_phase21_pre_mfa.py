"""
Tests for Phase 21 PreMfaPrivilegeValidator.

Verifies:
- Pre-MFA privilege boundary evaluation
- Step-up authentication enforcement
- Active elimination of 200 OK MFA challenge forms and public shells
- Authentic CVSS 3.1 scoring on PRE_MFA_PRIVILEGE_LEAK findings
"""

import pytest

from framework.auth_correlation.model import (
    CorrelatedSessionContext,
    CorrelationFinding,
)
from framework.auth_correlation.pre_mfa import PreMfaPrivilegeValidator
from framework.authz.model import ResourceAccessTarget
from framework.validation.request import ControlledRequest, ControlledResponse


class MockValidationEngine:
    def __init__(self, response: ControlledResponse):
        self.response = response
        self.last_request = None

    def send_request(self, req: ControlledRequest) -> ControlledResponse:
        self.last_request = req
        return self.response


def test_mfa_challenge_detection():
    """Verifies that is_mfa_challenge_form accurately detects challenge pages and forms."""
    validator = PreMfaPrivilegeValidator()

    # Case 1: OTP challenge prompt
    resp_otp = ControlledResponse(200, {}, b'{"error": "mfa_required", "challenge_token": "ch_12345", "message": "Enter your OTP code"}')
    assert validator.is_mfa_challenge_form(resp_otp) is True

    # Case 2: HTML form with password or code input
    resp_html = ControlledResponse(200, {"content-type": "text/html"}, b'<html><form><input name="otp" type="text"/></form></html>')
    assert validator.is_mfa_challenge_form(resp_html) is True

    # Case 3: Protected user data (not challenge)
    resp_data = ControlledResponse(200, {"content-type": "application/json"}, b'{"user_id": "u1", "email": "alice@corp.local", "balance": 5000}')
    assert validator.is_mfa_challenge_form(resp_data) is False


def test_pre_mfa_safe_denial_401_403():
    """Verifies that 401 or 403 responses are recognized as secure access denial."""
    engine = MockValidationEngine(ControlledResponse(401, {}, b'{"error": "MFA completion required"}'))
    validator = PreMfaPrivilegeValidator(validation_engine=engine)
    sess = CorrelatedSessionContext(
        session_ref="sess_00000000000000000000000000000001",
        principal_id="u1",
        volatile_headers={"Authorization": "Bearer pre_mfa_tok"},
        metadata={"mfa_level": "PRE_MFA"},
    )
    full_sess = CorrelatedSessionContext(
        session_ref="sess_00000000000000000000000000000002",
        principal_id="u2",
        volatile_headers={"Authorization": "Bearer full_mfa_tok"},
        metadata={"mfa_level": "FULL_MFA"},
    )
    target = ResourceAccessTarget(resource_id="res_01", resource_type="PROFILE", endpoint="https://target.local/api/v1/profile")
    baseline = ControlledResponse(200, {}, b'{"user_id": "u1", "email": "alice@corp.local"}')

    finding = validator.evaluate_pre_mfa_boundary(sess, target, baseline, full_session_ctx=full_sess)
    assert finding is None


def test_pre_mfa_challenge_form_filtered():
    """Verifies that 200 OK challenge forms are filtered out and emit no finding."""
    engine = MockValidationEngine(ControlledResponse(200, {}, b'{"challenge": "Enter the 6-digit code sent to your phone"}'))
    validator = PreMfaPrivilegeValidator(validation_engine=engine)
    sess = CorrelatedSessionContext(
        session_ref="sess_00000000000000000000000000000001",
        principal_id="u1",
        volatile_headers={"Authorization": "Bearer pre_mfa_tok"},
        metadata={"mfa_level": "PRE_MFA"},
    )
    full_sess = CorrelatedSessionContext(
        session_ref="sess_00000000000000000000000000000002",
        principal_id="u2",
        volatile_headers={"Authorization": "Bearer full_mfa_tok"},
        metadata={"mfa_level": "FULL_MFA"},
    )
    target = ResourceAccessTarget(resource_id="res_01", resource_type="PROFILE", endpoint="https://target.local/api/v1/profile")
    baseline = ControlledResponse(200, {}, b'{"user_id": "u1", "email": "alice@corp.local"}')

    finding = validator.evaluate_pre_mfa_boundary(sess, target, baseline, full_session_ctx=full_sess)
    assert finding is None


def test_pre_mfa_privilege_leak_detected():
    """Verifies that exposing protected baseline data to pre-MFA session emits PRE_MFA_PRIVILEGE_LEAK."""
    protected_payload = b'{"user_id": "u1", "email": "alice@corp.local", "ssn": "000-11-2222", "roles": ["ADMIN"]}'
    engine = MockValidationEngine(ControlledResponse(200, {"content-type": "application/json"}, protected_payload))
    validator = PreMfaPrivilegeValidator(validation_engine=engine)
    sess = CorrelatedSessionContext(
        session_ref="sess_00000000000000000000000000000001",
        principal_id="u1",
        volatile_headers={"Authorization": "Bearer pre_mfa_tok"},
        metadata={"mfa_level": "PRE_MFA"},
    )
    full_sess = CorrelatedSessionContext(
        session_ref="sess_00000000000000000000000000000002",
        principal_id="u2",
        volatile_headers={"Authorization": "Bearer full_mfa_tok"},
        metadata={"mfa_level": "FULL_MFA"},
    )
    target = ResourceAccessTarget(resource_id="res_01", resource_type="PROFILE", endpoint="https://target.local/api/v1/profile")
    baseline = ControlledResponse(200, {"content-type": "application/json"}, protected_payload)

    finding = validator.evaluate_pre_mfa_boundary(sess, target, baseline, full_session_ctx=full_sess)
    assert finding is not None
    assert finding.category == "PRE_MFA_PRIVILEGE_LEAK"
    assert finding.severity == "HIGH"
    assert finding.cvss_score == 7.5
    assert finding.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert finding.confidence == 0.90


def test_step_up_boundary_evaluation():
    """Verifies that sensitive endpoints lacking step-up authentication emit finding."""
    transfer_payload = b'{"action": "TRANSFER", "status": "COMPLETED", "amount": 10000}'
    engine = MockValidationEngine(ControlledResponse(200, {"content-type": "application/json"}, transfer_payload))
    validator = PreMfaPrivilegeValidator(validation_engine=engine)
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1", volatile_headers={"Authorization": "Bearer low_auth_tok"})
    target = ResourceAccessTarget(resource_id="res_02", resource_type="FINANCIAL", endpoint="https://target.local/api/v1/transfer", method="POST")
    baseline = ControlledResponse(200, {"content-type": "application/json"}, transfer_payload)

    finding = validator.evaluate_step_up_boundary(sess, target, baseline)
    assert finding is not None
    assert finding.category == "PRE_MFA_PRIVILEGE_LEAK"
    assert finding.cvss_score == 6.5
    assert finding.severity == "MEDIUM"


def test_pre_mfa_state_enforcement_matrix():
    """Verifies strict state enforcement before probe dispatch in PreMfaPrivilegeValidator."""
    protected_payload = b'{"secret": "internal_tokens_list", "confidential": true}'
    valid_baseline = ControlledResponse(200, {"content-type": "application/json"}, protected_payload)
    target = ResourceAccessTarget(resource_id="res_01", resource_type="PROFILE", endpoint="https://target.local/api/v1/profile")

    # 1. Explicit PRE_MFA + distinct FULL_MFA: eligible and evaluated
    engine_ok = MockValidationEngine(ControlledResponse(200, {"content-type": "application/json"}, protected_payload))
    validator_ok = PreMfaPrivilegeValidator(validation_engine=engine_ok)
    sess_valid = CorrelatedSessionContext(
        session_ref="sess_00000000000000000000000000000001",
        principal_id="u1",
        volatile_headers={"Authorization": "Bearer pre_mfa_token"},
        metadata={"mfa_level": "PRE_MFA"},
    )
    full_valid = CorrelatedSessionContext(
        session_ref="sess_00000000000000000000000000000002",
        principal_id="u2",
        volatile_headers={"Authorization": "Bearer full_mfa_token"},
        metadata={"mfa_level": "FULL_MFA"},
    )
    finding_ok = validator_ok.evaluate_pre_mfa_boundary(sess_valid, target, valid_baseline, full_session_ctx=full_valid)
    assert finding_ok is not None
    assert engine_ok.last_request is not None

    # Negative Matrix: zero network dispatch for rejected states (all 15 specified cases)
    login_shell = ControlledResponse(200, {"content-type": "text/html"}, b'<html><form action="/login"><input type="password" name="pwd"/></form></html>')
    spa_shell = ControlledResponse(200, {"content-type": "text/html"}, b'<html><body>Loading App Shell...</body></html>')

    rejected_cases = [
        # 2. Missing comparison session
        (sess_valid, None, valid_baseline, "Missing comparison session (None)"),
        # 3. Invalid comparison-session object
        (sess_valid, "not_a_session_instance", valid_baseline, "Invalid comparison session type (string)"),
        # 4. Missing comparison metadata
        (sess_valid, CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000002", principal_id="u2", metadata=None), valid_baseline, "None metadata on comparison session"),
        # 5. NONE comparison state
        (sess_valid, CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000002", principal_id="u2", metadata={"mfa_level": "NONE"}), valid_baseline, "NONE comparison state"),
        # 6. UNKNOWN comparison state
        (sess_valid, CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000002", principal_id="u2", metadata={"mfa_level": "UNKNOWN"}), valid_baseline, "UNKNOWN comparison state"),
        # 7. PRE_MFA comparison state
        (sess_valid, CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000002", principal_id="u2", metadata={"mfa_level": "PRE_MFA"}), valid_baseline, "PRE_MFA comparison state"),
        # 8. Malformed comparison state
        (sess_valid, CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000002", principal_id="u2", metadata={"mfa_level": 9999}), valid_baseline, "Malformed integer comparison state"),
        # 9. Candidate FULL_MFA
        (CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1", metadata={"mfa_level": "FULL_MFA"}), full_valid, valid_baseline, "Candidate FULL_MFA state"),
        # 10. Candidate missing MFA metadata
        (CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1", metadata={}), full_valid, valid_baseline, "Candidate missing MFA metadata"),
        # 11a. Candidate NONE
        (CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1", metadata={"mfa_level": "NONE"}), full_valid, valid_baseline, "Candidate NONE state"),
        # 11b. Candidate UNKNOWN
        (CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1", metadata={"mfa_level": "UNKNOWN"}), full_valid, valid_baseline, "Candidate UNKNOWN state"),
        # 12. Missing baseline
        (sess_valid, full_valid, None, "Missing baseline (None)"),
        # 13a. Invalid baseline status 500
        (sess_valid, full_valid, ControlledResponse(500, {}, b'Internal Server Error'), "HTTP 500 baseline"),
        # 13b. Invalid baseline status 401
        (sess_valid, full_valid, ControlledResponse(401, {}, b'Unauthorized'), "HTTP 401 baseline"),
        # 14a. Login form baseline
        (sess_valid, full_valid, login_shell, "Login form baseline shell"),
        # 14b. SPA shell baseline
        (sess_valid, full_valid, spa_shell, "Generic SPA landing shell baseline"),
        # 15. Identical candidate and comparison sessions
        (sess_valid, sess_valid, valid_baseline, "Identical candidate and comparison session references"),
    ]

    for cand_s, comp_s, base_resp, desc in rejected_cases:
        mock_engine = MockValidationEngine(ControlledResponse(200, {"content-type": "application/json"}, protected_payload))
        val = PreMfaPrivilegeValidator(validation_engine=mock_engine)

        finding = val.evaluate_pre_mfa_boundary(cand_s, target, base_resp, full_session_ctx=comp_s)
        assert finding is None, f"Expected None for '{desc}', got finding"
        assert mock_engine.last_request is None, f"Expected ZERO network dispatch for '{desc}', but request was sent"


def test_pre_mfa_orchestrator_zero_dispatch_when_session_missing(tmp_path):
    """Verifies that AuthCorrelationEngine does not dispatch any pre-MFA probe when either session is missing."""
    from framework.auth_correlation.engine import AuthCorrelationEngine
    from framework.auth_correlation.model import CorrelatedPrincipalContext, CorrelationHypothesis

    class CountingEngine:
        def __init__(self):
            self.dispatched_requests = []
        def send_request(self, req):
            self.dispatched_requests.append(req)
            return ControlledResponse(200, {"content-type": "application/json"}, b'{"ok": true}')

    transport = CountingEngine()
    engine = AuthCorrelationEngine(
        program_id="test_mfa_orch",
        workspace_root=str(tmp_path),
        validation_engine=transport,
    )

    # Register only ONE principal and session
    p1 = CorrelatedPrincipalContext(principal_id="u1", role="USER")
    s1 = CorrelatedSessionContext(
        session_ref="sess_00000000000000000000000000000001",
        principal_id="u1",
        metadata={"mfa_level": "PRE_MFA"},
    )
    engine.register_principal(p1)
    engine.register_session(s1)

    hyp = CorrelationHypothesis(
        hypothesis_id="HYP-MFA-01",
        category="PRE_MFA_PRIVILEGE",
        target_endpoint="/api/v1/profile",
        principal_a_id="u1",
        principal_b_id="u2",  # Missing principal/session!
        expected_result="ACCESS_ALLOWED",
    )
    engine.hypotheses = [hyp]

    res = engine.run_correlation(
        target_asset="https://target.local",
        workflow_filter=["pre_mfa"],
    )

    assert hyp.validation_status in ("INCONCLUSIVE", "SESSION_HEALTH_FAILED")
    # Zero network probes dispatched!
    assert len(transport.dispatched_requests) == 0

