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
    target = ResourceAccessTarget(resource_id="res_01", resource_type="PROFILE", endpoint="https://target.local/api/v1/profile")
    baseline = ControlledResponse(200, {}, b'{"user_id": "u1", "email": "alice@corp.local"}')

    finding = validator.evaluate_pre_mfa_boundary(sess, target, baseline)
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
    target = ResourceAccessTarget(resource_id="res_01", resource_type="PROFILE", endpoint="https://target.local/api/v1/profile")
    baseline = ControlledResponse(200, {}, b'{"user_id": "u1", "email": "alice@corp.local"}')

    finding = validator.evaluate_pre_mfa_boundary(sess, target, baseline)
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
    target = ResourceAccessTarget(resource_id="res_01", resource_type="PROFILE", endpoint="https://target.local/api/v1/profile")
    baseline = ControlledResponse(200, {"content-type": "application/json"}, protected_payload)

    finding = validator.evaluate_pre_mfa_boundary(sess, target, baseline)
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

    # 1. Explicit PRE_MFA: eligible and evaluated
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
        principal_id="u1",
        volatile_headers={"Authorization": "Bearer full_mfa_token"},
        metadata={"mfa_level": "FULL_MFA"},
    )
    finding_ok = validator_ok.evaluate_pre_mfa_boundary(sess_valid, target, valid_baseline, full_session_ctx=full_valid)
    assert finding_ok is not None
    assert engine_ok.last_request is not None

    # Negative Matrix: zero network dispatch for rejected states
    rejected_cases = [
        # (session_meta, full_session_meta, baseline, description)
        ({"mfa_level": "FULL_MFA"}, {"mfa_level": "FULL_MFA"}, valid_baseline, "Explicit FULL_MFA candidate session"),
        ({}, {"mfa_level": "FULL_MFA"}, valid_baseline, "Missing MFA metadata on candidate"),
        ({"mfa_level": "NONE"}, {"mfa_level": "FULL_MFA"}, valid_baseline, "mfa_level NONE on candidate"),
        ({"mfa_level": "UNKNOWN"}, {"mfa_level": "FULL_MFA"}, valid_baseline, "mfa_level UNKNOWN on candidate"),
        ({"mfa_level": 12345}, {"mfa_level": "FULL_MFA"}, valid_baseline, "Malformed integer mfa_level on candidate"),
        ({"mfa_level": "PRE_MFA"}, {"mfa_level": "FULL_MFA"}, None, "Missing full-authentication baseline"),
        ({"mfa_level": "PRE_MFA"}, {"mfa_level": "FULL_MFA"}, ControlledResponse(500, {}, b'Internal Server Error'), "500 baseline"),
        ({"mfa_level": "PRE_MFA"}, {"mfa_level": "NONE"}, valid_baseline, "Comparison session mfa_level NONE"),
        ({"mfa_level": "PRE_MFA"}, {}, valid_baseline, "Comparison session missing MFA metadata"),
    ]

    for sess_meta, full_meta, baseline_resp, desc in rejected_cases:
        mock_engine = MockValidationEngine(ControlledResponse(200, {"content-type": "application/json"}, protected_payload))
        val = PreMfaPrivilegeValidator(validation_engine=mock_engine)
        c_sess = CorrelatedSessionContext(
            session_ref="sess_00000000000000000000000000000001",
            principal_id="u1",
            volatile_headers={"Authorization": "Bearer cand_tok"},
            metadata=sess_meta,
        )
        c_full = CorrelatedSessionContext(
            session_ref="sess_00000000000000000000000000000002",
            principal_id="u1",
            volatile_headers={"Authorization": "Bearer full_tok"},
            metadata=full_meta,
        ) if full_meta is not None else None

        finding = val.evaluate_pre_mfa_boundary(c_sess, target, baseline_resp, full_session_ctx=c_full)
        assert finding is None, f"Expected None for {desc}, got finding"
        assert mock_engine.last_request is None, f"Expected ZERO network dispatch for {desc}, but request was sent"

