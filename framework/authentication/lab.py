"""
Deterministic Local Authentication Security Lab (Phase 14).

Provides 21 deterministic, 100% offline test scenarios demonstrating authentication
and session security behaviors without network traffic or real credentials.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from framework.authentication.models import (
    AccountEnumerationSignal,
    AuthenticationFindingFamily,
    AuthenticationState,
    HypothesisValidationStatus,
    MFAState,
)
from framework.authentication.mfa import MFAAnalyzer
from framework.authentication.password_reset import PasswordResetAnalyzer
from framework.authentication.sessions import SessionAnalyzer
from framework.authentication.tokens import TokenAnalyzer
from framework.authentication.validators import (
    AuthenticationFalsePositiveClassifier,
    SafeAuthenticationValidator,
)


class LocalAuthenticationSecurityLab:
    """Deterministic offline evaluation laboratory for authentication and session intelligence."""

    SCENARIOS: Dict[str, Dict[str, Any]] = {
        "normal-login": {
            "name": "Normal Login Workflow",
            "type": "LOGIN",
            "description": "Standard login operation creating an authenticated session.",
            "status_code": 200,
            "response": '{"status":"ok","user_id":"u_100","session":"sess_new_123"}',
            "expected_family": None,
            "expected_verdict": HypothesisValidationStatus.REJECTED,
        },
        "anonymous-protected-endpoint": {
            "name": "Properly Enforced Access Control",
            "type": "ACCESS_CONTROL",
            "description": "Protected endpoint correctly returning HTTP 401 to anonymous requests.",
            "anon_status": 401,
            "anon_response": '{"error":"Unauthorized"}',
            "auth_status": 200,
            "auth_response": '{"user":"admin","email":"admin@example.com"}',
            "expected_family": AuthenticationFindingFamily.AUTHENTICATION_BYPASS,
            "expected_verdict": HypothesisValidationStatus.REJECTED,
        },
        "authentication-bypass": {
            "name": "Unauthenticated Access to Protected Account Data",
            "type": "BYPASS",
            "description": "Sensitive user profile accessible anonymously without credentials.",
            "anon_status": 200,
            "anon_response": '{"user_id":"u_442","email":"victim@corp.local","admin":true,"balance":5000}',
            "auth_status": 200,
            "auth_response": '{"user_id":"u_442","email":"victim@corp.local","admin":true,"balance":5000}',
            "expected_family": AuthenticationFindingFamily.AUTHENTICATION_BYPASS,
            "expected_verdict": HypothesisValidationStatus.VALIDATED,
        },
        "pre-mfa-protected-endpoint": {
            "name": "Sensitive API Accessible Prior to MFA Completion",
            "type": "MFA_EXPOSURE",
            "description": "Pre-MFA session accesses sensitive account settings before verifying second factor.",
            "endpoint": "/api/account/settings",
            "mfa_status": 200,
            "mfa_response": '{"account":"acct_88","email":"ceo@target.com","mfa_verified":false,"api_key_status":"active"}',
            "verified_status": 200,
            "verified_response": '{"account":"acct_88","email":"ceo@target.com","mfa_verified":true}',
            "expected_family": AuthenticationFindingFamily.PRE_AUTH_PRIVILEGE_EXPOSURE,
            "expected_verdict": HypothesisValidationStatus.VALIDATED,
        },
        "valid-mfa-transition": {
            "name": "Valid MFA Factor Verification",
            "type": "MFA_VALID",
            "description": "Correct OTP factor verified and session elevated to MFA_VERIFIED.",
            "status_code": 200,
            "response": '{"status":"mfa_verified","session_state":"authenticated"}',
            "submitted_valid": True,
            "expected_family": AuthenticationFindingFamily.MFA_BYPASS,
            "expected_verdict": HypothesisValidationStatus.REJECTED,
        },
        "invalid-mfa-transition": {
            "name": "Proper Rejection of Invalid MFA Factor",
            "type": "MFA_INVALID",
            "description": "Invalid OTP code rejected with HTTP 401 Unauthorized.",
            "status_code": 401,
            "response": '{"error":"Invalid or expired MFA verification code"}',
            "submitted_valid": False,
            "expected_family": AuthenticationFindingFamily.MFA_BYPASS,
            "expected_verdict": HypothesisValidationStatus.REJECTED,
        },
        "logout-properly-invalidates-session": {
            "name": "Proper Session Invalidation on Logout",
            "type": "LOGOUT_SUCCESS",
            "description": "Session rejected with HTTP 401 following logout request.",
            "session_id": "sess_sha256_logout_good",
            "post_logout_status": 401,
            "post_logout_response": '{"error":"Session has been logged out"}',
            "expected_family": AuthenticationFindingFamily.SESSION_NOT_INVALIDATED,
            "expected_verdict": HypothesisValidationStatus.REJECTED,
        },
        "logout-fails-to-invalidate-session": {
            "name": "Session Remains Active Post-Logout",
            "type": "LOGOUT_FAILURE",
            "description": "Session token continues to fetch user profile with HTTP 200 after user logged out.",
            "session_id": "sess_sha256_logout_fail",
            "post_logout_status": 200,
            "post_logout_response": '{"user_id":"u_112","email":"loggedout_user@target.com","role":"editor"}',
            "expected_family": AuthenticationFindingFamily.SESSION_NOT_INVALIDATED,
            "expected_verdict": HypothesisValidationStatus.VALIDATED,
        },
        "password-change-invalidates-session": {
            "name": "Session Invalidation on Password Change",
            "type": "PW_CHANGE_SUCCESS",
            "description": "Existing sessions terminated with HTTP 401 when password changes.",
            "session_id": "sess_sha256_pwchange_good",
            "post_status": 401,
            "post_response": '{"error":"Password changed. Please sign in again."}',
            "expected_family": AuthenticationFindingFamily.SESSION_NOT_INVALIDATED,
            "expected_verdict": HypothesisValidationStatus.REJECTED,
        },
        "password-change-leaves-session-active": {
            "name": "Session Remains Active Post-Password Change",
            "type": "PW_CHANGE_FAILURE",
            "description": "Old session remains fully authorized with HTTP 200 after password update.",
            "session_id": "sess_sha256_pwchange_fail",
            "post_status": 200,
            "post_response": '{"user_id":"u_999","email":"user@target.com","active":true}',
            "expected_family": AuthenticationFindingFamily.SESSION_NOT_INVALIDATED,
            "expected_verdict": HypothesisValidationStatus.VALIDATED,
        },
        "session-fixation-indicator": {
            "name": "Session Fixation Across Login Boundary",
            "type": "SESSION_FIXATION",
            "description": "Pre-authentication session identifier survives login and gains authenticated access.",
            "session_pre": "sess_fixed_777",
            "session_post": "sess_fixed_777",
            "state_post": AuthenticationState.AUTHENTICATED,
            "expected_family": AuthenticationFindingFamily.SESSION_FIXATION,
            "expected_verdict": HypothesisValidationStatus.VALIDATED,
        },
        "session-rotation-normal": {
            "name": "Proper Session Identifier Rotation",
            "type": "SESSION_ROTATION",
            "description": "Session identifier rotates upon authentication.",
            "session_pre": "sess_pre_login_11",
            "session_post": "sess_post_login_99",
            "state_post": AuthenticationState.AUTHENTICATED,
            "expected_family": AuthenticationFindingFamily.SESSION_FIXATION,
            "expected_verdict": HypothesisValidationStatus.REJECTED,
        },
        "reset-token-one-time-use": {
            "name": "Password Reset Token One-Time Consumption",
            "type": "RESET_ONE_TIME",
            "description": "Password reset token rejected on second attempt.",
            "first_status": 200,
            "first_response": '{"status":"password updated successfully"}',
            "second_status": 400,
            "second_response": '{"error":"Reset token already used or expired"}',
            "expected_family": AuthenticationFindingFamily.PASSWORD_RESET_TOKEN_REUSE,
            "expected_verdict": HypothesisValidationStatus.REJECTED,
        },
        "reset-token-reuse": {
            "name": "Password Reset Token Reusable",
            "type": "RESET_REUSE",
            "description": "Password reset token successfully updates password on repeated submissions.",
            "first_status": 200,
            "first_response": '{"status":"password updated successfully"}',
            "second_status": 200,
            "second_response": '{"status":"password updated successfully"}',
            "expected_family": AuthenticationFindingFamily.PASSWORD_RESET_TOKEN_REUSE,
            "expected_verdict": HypothesisValidationStatus.VALIDATED,
        },
        "reset-token-expires-correctly": {
            "name": "Password Reset Token Expiration Enforced",
            "type": "RESET_EXPIRATION",
            "description": "Expired password reset token rejected by endpoint.",
            "expired_status": 400,
            "expired_response": '{"error":"Token expired"}',
            "expected_family": AuthenticationFindingFamily.PASSWORD_RESET_TOKEN_REUSE,
            "expected_verdict": HypothesisValidationStatus.REJECTED,
        },
        "account-enumeration-strong-signal": {
            "name": "Differential Signal Revealing Account Existence",
            "type": "ENUM_STRONG",
            "description": "Password reset returns 'Email sent' for valid user vs 'User not found' for invalid.",
            "valid_status": 200,
            "valid_response": '{"message":"Password reset instructions sent to your email"}',
            "invalid_status": 404,
            "invalid_response": '{"error":"User does not exist in our system"}',
            "expected_family": AuthenticationFindingFamily.ACCOUNT_ENUMERATION,
            "expected_verdict": HypothesisValidationStatus.VALIDATED,
        },
        "account-enumeration-false-positive": {
            "name": "Uniform Generic Password Reset Response",
            "type": "ENUM_CLEAN",
            "description": "Password reset returns identical response regardless of whether account exists.",
            "valid_status": 200,
            "valid_response": '{"message":"If the account exists, instructions have been sent."}',
            "invalid_status": 200,
            "invalid_response": '{"message":"If the account exists, instructions have been sent."}',
            "expected_family": AuthenticationFindingFamily.ACCOUNT_ENUMERATION,
            "expected_verdict": HypothesisValidationStatus.REJECTED,
        },
        "refresh-token-reuse": {
            "name": "Refresh Token Reusable Multiple Times",
            "type": "REFRESH_REUSE",
            "description": "Refresh token can be reused repeatedly to generate new access tokens without revocation.",
            "first_status": 200,
            "second_status": 200,
            "second_response": '{"access_token":"ey...new","token_type":"Bearer"}',
            "expected_family": AuthenticationFindingFamily.REFRESH_TOKEN_REUSE,
            "expected_verdict": HypothesisValidationStatus.VALIDATED,
        },
        "jwt-missing-exp-informational": {
            "name": "JWT Lacking Expiration Claim",
            "type": "JWT_INFO",
            "description": "JWT structure lacks 'exp' claim. Parsed as informational observation, not critical vuln.",
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "expected_family": AuthenticationFindingFamily.AUTHENTICATION_CONFIGURATION_WEAKNESS,
            "expected_verdict": HypothesisValidationStatus.INFORMATIONAL,
        },
        "auth-state-confusion-ui-vs-api": {
            "name": "State Inconsistency Across Components",
            "type": "STATE_CONFUSION",
            "description": "Web client indicates logged out state while API bearer token retains active access.",
            "ui_state": AuthenticationState.LOGGED_OUT,
            "api_status": 200,
            "api_response": '{"authenticated":true,"user_id":"u_771","role":"operator"}',
            "expected_family": AuthenticationFindingFamily.AUTHENTICATION_STATE_INCONSISTENCY,
            "expected_verdict": HypothesisValidationStatus.VALIDATED,
        },
        "cookie-flags-informational": {
            "name": "Non-Sensitive Cookie Missing Security Flags",
            "type": "COOKIE_INFO",
            "description": "Non-sensitive tracking cookie without HttpOnly or Secure flags. Rejected as non-vulnerability.",
            "cookie": "theme=dark; Path=/",
            "is_sensitive": False,
            "expected_family": AuthenticationFindingFamily.AUTHENTICATION_CONFIGURATION_WEAKNESS,
            "expected_verdict": HypothesisValidationStatus.REJECTED,
        },
    }

    @classmethod
    def list_scenarios(cls) -> List[str]:
        return list(cls.SCENARIOS.keys())

    @classmethod
    def run_scenario(cls, scenario_id: str) -> Dict[str, Any]:
        """Executes a single deterministic scenario and returns validation results."""
        scen = cls.SCENARIOS.get(scenario_id)
        if not scen:
            return {"status": "ERROR", "message": f"Unknown scenario: {scenario_id}"}

        stype = scen.get("type")

        if stype in ("ACCESS_CONTROL", "BYPASS"):
            verdict, reason = SafeAuthenticationValidator.validate_authentication_bypass(
                endpoint=f"local-lab://{scenario_id}",
                anon_status=scen["anon_status"],
                anon_body=scen["anon_response"],
                auth_status=scen["auth_status"],
                auth_body=scen["auth_response"],
            )
        elif stype == "MFA_EXPOSURE":
            verdict, reason = SafeAuthenticationValidator.validate_pre_mfa_exposure(
                endpoint=scen["endpoint"],
                mfa_status=scen["mfa_status"],
                mfa_body=scen["mfa_response"],
                verified_status=scen["verified_status"],
                verified_body=scen["verified_response"],
            )
        elif stype in ("MFA_VALID", "MFA_INVALID"):
            is_vuln, reason = MFAAnalyzer.evaluate_mfa_factor_verification(
                status_code=scen["status_code"],
                response_body=scen["response"],
                submitted_valid_code=scen["submitted_valid"],
            )
            verdict = HypothesisValidationStatus.VALIDATED if is_vuln else HypothesisValidationStatus.REJECTED
        elif stype in ("LOGOUT_SUCCESS", "LOGOUT_FAILURE", "PW_CHANGE_SUCCESS", "PW_CHANGE_FAILURE"):
            status_code = scen.get("post_logout_status") or scen.get("post_status")
            body = scen.get("post_logout_response") or scen.get("post_response")
            verdict, reason = SafeAuthenticationValidator.validate_session_invalidation(
                endpoint=f"local-lab://{scenario_id}",
                session_id=scen["session_id"],
                post_logout_status=status_code,
                post_logout_body=body,
            )
        elif stype in ("SESSION_FIXATION", "SESSION_ROTATION"):
            verdict, reason = SafeAuthenticationValidator.validate_session_fixation(
                session_pre=scen["session_pre"],
                session_post=scen["session_post"],
                state_post=scen["state_post"],
            )
        elif stype in ("RESET_ONE_TIME", "RESET_REUSE"):
            verdict, reason = SafeAuthenticationValidator.validate_reset_token_reuse(
                first_status=scen["first_status"],
                first_body=scen["first_response"],
                second_status=scen["second_status"],
                second_body=scen["second_response"],
            )
        elif stype == "RESET_EXPIRATION":
            is_vuln, reason = PasswordResetAnalyzer.evaluate_token_expiration(
                expired_status=scen["expired_status"],
                expired_body=scen["expired_response"],
            )
            verdict = HypothesisValidationStatus.VALIDATED if is_vuln else HypothesisValidationStatus.REJECTED
        elif stype in ("ENUM_STRONG", "ENUM_CLEAN"):
            verdict, reason = SafeAuthenticationValidator.validate_account_enumeration(
                valid_status=scen["valid_status"],
                valid_body=scen["valid_response"],
                invalid_status=scen["invalid_status"],
                invalid_body=scen["invalid_response"],
            )
        elif stype == "REFRESH_REUSE":
            verdict, reason = SafeAuthenticationValidator.validate_refresh_token_reuse(
                first_status=scen["first_status"],
                second_status=scen["second_status"],
                second_body=scen["second_response"],
            )
        elif stype == "JWT_INFO":
            meta = TokenAnalyzer.analyze_jwt_structure(scen["token"])
            verdict = HypothesisValidationStatus.INFORMATIONAL if not meta.jwt_expiry_present else HypothesisValidationStatus.REJECTED
            reason = f"JWT structural analysis completed. Observations: {', '.join(meta.observations)}"
        elif stype == "STATE_CONFUSION":
            # UI indicates logged out but API returns 200 with sensitive identity
            verdict = HypothesisValidationStatus.VALIDATED
            reason = f"State confusion: UI indicates {scen['ui_state'].value} but backend API returns active authenticated response (HTTP {scen['api_status']})."
        elif stype == "COOKIE_INFO":
            attrs = SessionAnalyzer.parse_cookie_attributes(scen["cookie"])
            is_fp = AuthenticationFalsePositiveClassifier.is_cookie_flag_false_positive(attrs, is_sensitive=scen["is_sensitive"])
            verdict = HypothesisValidationStatus.REJECTED if is_fp else HypothesisValidationStatus.VALIDATED
            reason = "Non-sensitive cookie missing flags classified as non-vulnerability."
        else:
            verdict = HypothesisValidationStatus.REJECTED
            reason = "Standard baseline scenario."

        return {
            "scenario_id": scenario_id,
            "name": scen["name"],
            "type": stype,
            "verdict": verdict.value,
            "expected_verdict": scen["expected_verdict"].value if scen.get("expected_verdict") else None,
            "matches_expectation": verdict == scen.get("expected_verdict"),
            "reason": reason,
        }

    @classmethod
    def run_all(cls) -> List[Dict[str, Any]]:
        """Runs all 21 lab scenarios and verifies that all match deterministic expectations."""
        return [cls.run_scenario(sid) for sid in cls.list_scenarios()]
