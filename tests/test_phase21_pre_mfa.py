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
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1", volatile_headers={"Authorization": "Bearer pre_mfa_tok"})
    target = ResourceAccessTarget(resource_id="res_01", resource_type="PROFILE", endpoint="https://target.local/api/v1/profile")
    baseline = ControlledResponse(200, {}, b'{"user_id": "u1", "email": "alice@corp.local"}')

    finding = validator.evaluate_pre_mfa_boundary(sess, target, baseline)
    assert finding is None


def test_pre_mfa_challenge_form_filtered():
    """Verifies that 200 OK challenge forms are filtered out and emit no finding."""
    engine = MockValidationEngine(ControlledResponse(200, {}, b'{"challenge": "Enter the 6-digit code sent to your phone"}'))
    validator = PreMfaPrivilegeValidator(validation_engine=engine)
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1", volatile_headers={"Authorization": "Bearer pre_mfa_tok"})
    target = ResourceAccessTarget(resource_id="res_01", resource_type="PROFILE", endpoint="https://target.local/api/v1/profile")
    baseline = ControlledResponse(200, {}, b'{"user_id": "u1", "email": "alice@corp.local"}')

    finding = validator.evaluate_pre_mfa_boundary(sess, target, baseline)
    assert finding is None


def test_pre_mfa_privilege_leak_detected():
    """Verifies that exposing protected baseline data to pre-MFA session emits PRE_MFA_PRIVILEGE_LEAK."""
    protected_payload = b'{"user_id": "u1", "email": "alice@corp.local", "ssn": "000-11-2222", "roles": ["ADMIN"]}'
    engine = MockValidationEngine(ControlledResponse(200, {"content-type": "application/json"}, protected_payload))
    validator = PreMfaPrivilegeValidator(validation_engine=engine)
    sess = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1", volatile_headers={"Authorization": "Bearer pre_mfa_tok"})
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
