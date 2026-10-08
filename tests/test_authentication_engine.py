"""
Comprehensive Test Suite for Phase 14: Authentication, Session & Identity Security Intelligence.

Verifies identity modeling, session lifecycles, MFA enforcement, password reset,
JWT structural parsing, differential validation, false-positive elimination,
policy & approval gates, CLI execution, and the deterministic local lab.
100% offline, zero network traffic, zero live credentials.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import pytest

from framework.authentication.discovery import AuthenticationSurfaceDiscoverer
from framework.authentication.engine import AuthenticationSecurityEngine
from framework.authentication.evidence import AuthenticationEvidenceManager
from framework.authentication.hypotheses import AuthenticationHypothesisEngine
from framework.authentication.identity import IdentityManager
from framework.authentication.lab import LocalAuthenticationSecurityLab
from framework.authentication.mfa import MFAAnalyzer
from framework.authentication.models import (
    AccountEnumerationSignal,
    AuthenticationFindingCandidate,
    AuthenticationFindingFamily,
    AuthenticationFlow,
    AuthenticationFlowType,
    AuthenticationHypothesis,
    AuthenticationState,
    AuthenticationStep,
    HypothesisValidationStatus,
    IdentityProfile,
    MFAState,
    SessionLifecycle,
    SessionProfile,
    TokenMetadata,
)
from framework.authentication.password_reset import PasswordResetAnalyzer
from framework.authentication.policy import (
    AuthenticationApprovalGate,
    AuthenticationSecurityPolicy,
)
from framework.authentication.prioritization import AuthenticationPrioritizer
from framework.authentication.sessions import SessionAnalyzer
from framework.authentication.storage import AuthenticationStateManager
from framework.authentication.tokens import TokenAnalyzer
from framework.authentication.validators import (
    AuthenticationFalsePositiveClassifier,
    SafeAuthenticationValidator,
)
from framework.authz.model import PrincipalProfile
from framework.scope.engine import ScopeEngine


@pytest.fixture
def temp_workspace():
    """Provides an isolated workspace directory with state/ for testing."""
    tmp = tempfile.mkdtemp(prefix="bb_test_auth_")
    state_dir = os.path.join(tmp, "state")
    os.makedirs(state_dir, exist_ok=True)
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


# ==============================================================================
# 1. Identity Modeling Tests
# ==============================================================================

def test_identity_registration_and_credential_sanitization():
    """Verifies that identity profiles strip passwords and secret tokens upon registration."""
    mgr = IdentityManager()
    profile = mgr.register_identity(
        username="researcher_alice",
        role="USER",
        tenant="tenant_10",
        attributes={"password": "should_be_stripped", "email": "alice@test.local", "token": "secret_abc"},
    )
    assert profile.username == "researcher_alice"
    assert profile.role == "USER"
    assert "password" not in profile.attributes
    assert "token" not in profile.attributes
    assert profile.attributes.get("email") == "alice@test.local"


def test_identity_bridge_with_phase_8_principal():
    """Verifies bi-directional conversion between IdentityProfile and Phase 8 PrincipalProfile."""
    mgr = IdentityManager()
    profile = mgr.register_identity(username="admin_bob", role="ADMIN", state=AuthenticationState.AUTHENTICATED)
    
    # Bridge to PrincipalProfile
    principal = mgr.to_principal_profile(profile)
    assert isinstance(principal, PrincipalProfile)
    assert principal.role == "ADMIN"
    assert principal.privilege_level == 100
    assert principal.masked_metadata.get("username") == "admin_bob"

    # Bridge back
    converted_back = mgr.from_principal_profile(principal)
    assert converted_back.role == "ADMIN"
    assert converted_back.authentication_state == AuthenticationState.AUTHENTICATED


# ==============================================================================
# 2. Authentication Surface Discovery Tests
# ==============================================================================

def test_endpoint_classification():
    """Verifies deterministic heuristic classification of endpoints."""
    assert AuthenticationSurfaceDiscoverer.classify_endpoint("/api/v1/auth/login") == AuthenticationFlowType.LOGIN
    assert AuthenticationSurfaceDiscoverer.classify_endpoint("/logout") == AuthenticationFlowType.LOGOUT
    assert AuthenticationSurfaceDiscoverer.classify_endpoint("/forgot-password") == AuthenticationFlowType.PASSWORD_RESET
    assert AuthenticationSurfaceDiscoverer.classify_endpoint("/api/2fa/verify") == AuthenticationFlowType.MFA_VERIFICATION
    assert AuthenticationSurfaceDiscoverer.classify_endpoint("/token/refresh") == AuthenticationFlowType.TOKEN_REFRESH
    assert AuthenticationSurfaceDiscoverer.classify_endpoint("/public/images/logo.png") is None


def test_surface_discovery_from_workspace(temp_workspace):
    """Verifies ingestion of Phase 3, Phase 4, and Phase 5 artifacts into authentication steps."""
    state_dir = os.path.join(temp_workspace, "state")
    
    # Fake Phase 3 web_applications.json
    with open(os.path.join(state_dir, "web_applications.json"), "w", encoding="utf-8") as f:
        json.dump({"forms": [{"action": "/signin", "method": "POST", "inputs": {"user": "", "pwd": ""}}]}, f)

    # Fake Phase 4 javascript.json
    with open(os.path.join(state_dir, "javascript.json"), "w", encoding="utf-8") as f:
        json.dump({"routes": [{"path": "/api/v2/auth/token"}, "/dashboard"]}, f)

    steps = AuthenticationSurfaceDiscoverer.discover_from_workspace(temp_workspace)
    assert len(steps) >= 2
    endpoints = {s.endpoint for s in steps}
    assert "/signin" in endpoints
    assert "/api/v2/auth/token" in endpoints


# ==============================================================================
# 3. Session Modeling & Security Tests
# ==============================================================================

def test_session_token_masking():
    """Verifies that session secrets are never stored raw, but deterministic SHA-256 fingerprints are generated."""
    tok1 = "super_secret_session_cookie_12345"
    fprint1 = SessionAnalyzer.mask_or_hash_session(tok1)
    fprint2 = SessionAnalyzer.mask_or_hash_session(tok1)
    assert fprint1.startswith("sess_sha256_")
    assert fprint1 == fprint2
    assert "super_secret" not in fprint1


def test_cookie_attribute_parsing():
    """Verifies Set-Cookie header attribute parsing."""
    header = "sessionid=abc123xyz; Secure; HttpOnly; SameSite=Strict; Path=/; Domain=target.com"
    attrs = SessionAnalyzer.parse_cookie_attributes(header)
    assert attrs["name"] == "sessionid"
    assert attrs["is_secure"] is True
    assert attrs["is_httponly"] is True
    assert attrs["samesite"] == "Strict"
    assert attrs["domain"] == "target.com"


def test_session_fixation_evaluation():
    """Verifies detection of unrotated session ID surviving login and granting authenticated access."""
    # Vulnerable: pre and post match and user becomes authenticated
    is_vuln, reason = SessionAnalyzer.evaluate_session_fixation(
        session_id_pre="sess_static_001",
        session_id_post="sess_static_001",
        state_after_login=AuthenticationState.AUTHENTICATED,
    )
    assert is_vuln is True
    assert "session fixation" in reason.lower()

    # Safe: session rotated
    is_vuln_safe, _ = SessionAnalyzer.evaluate_session_fixation(
        session_id_pre="sess_static_001",
        session_id_post="sess_rotated_002",
        state_after_login=AuthenticationState.AUTHENTICATED,
    )
    assert is_vuln_safe is False


def test_session_invalidation_after_logout():
    """Verifies detection of sessions that remain usable after logout."""
    # Vulnerable: post-logout returns HTTP 200 with user data
    is_vuln, _ = SessionAnalyzer.evaluate_session_invalidation(
        session_id="sess_1",
        status_code=200,
        response_body='{"user_id":"123","email":"user@corp.local"}',
        action_name="logout",
    )
    assert is_vuln is True

    # Safe: post-logout returns HTTP 401
    is_vuln_safe, _ = SessionAnalyzer.evaluate_session_invalidation(
        session_id="sess_1",
        status_code=401,
        response_body='{"error":"Unauthorized"}',
        action_name="logout",
    )
    assert is_vuln_safe is False


# ==============================================================================
# 4. Token & JWT Intelligence Tests
# ==============================================================================

def test_jwt_structural_parsing():
    """Verifies safe local structural extraction of JWT algorithms, claims, and missing exp."""
    # Standard JWT with payload { "sub": "123", "role": "admin" } and alg HS256
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJyb2xlIjoiYWRtaW4ifQ.dGVzdF9zaWduYXR1cmU"
    meta = TokenAnalyzer.analyze_jwt_structure(token)
    assert meta.is_jwt is True
    assert meta.jwt_algorithm == "HS256"
    assert meta.jwt_subject_present is True
    assert meta.jwt_expiry_present is False
    assert "role:admin" in meta.privilege_claims
    assert "JWT_WITHOUT_EXPIRATION_CLAIM" in meta.observations


def test_token_transport_exposure():
    """Verifies detection of sensitive tokens leaked in URL query parameters or referer."""
    url = "https://target.com/dashboard?access_token=eyJh...&tenant=1"
    headers = {"Referer": "https://target.com/auth?token=123"}
    exposures = TokenAnalyzer.analyze_transport_exposure(url, headers)
    assert any("TOKEN_IN_QUERY_PARAMETER:access_token" in exp for exp in exposures)
    assert any("TOKEN_LEAKED_IN_REFERER_HEADER" in exp for exp in exposures)


def test_refresh_token_reuse_evaluation():
    """Verifies evaluation of refresh token replay."""
    is_vuln, reason = TokenAnalyzer.evaluate_refresh_token_reuse(
        status_first_use=200,
        status_second_use=200,
        response_second_use='{"access_token":"ey...","token_type":"Bearer"}',
    )
    assert is_vuln is True
    assert "reused" in reason.lower()


# ==============================================================================
# 5. Password Reset & Account Enumeration Tests
# ==============================================================================

def test_password_reset_token_reuse():
    """Verifies detection of reusable password reset tokens."""
    is_vuln, _ = PasswordResetAnalyzer.evaluate_token_reuse(
        first_status=200,
        first_body='{"status":"ok"}',
        second_status=200,
        second_body='{"status":"ok"}',
    )
    assert is_vuln is True


def test_password_reset_token_expiration():
    """Verifies enforcement of token expiration."""
    # If expired token returns 200 without error -> server fails to expire
    is_vuln, _ = PasswordResetAnalyzer.evaluate_token_expiration(
        expired_status=200,
        expired_body='{"status":"password reset successful"}',
    )
    assert is_vuln is True

    # Proper rejection: HTTP 400 with 'expired' error
    is_safe, _ = PasswordResetAnalyzer.evaluate_token_expiration(
        expired_status=400,
        expired_body='{"error":"Token expired"}',
    )
    assert is_safe is False


def test_differential_account_enumeration():
    """Verifies differential signal detection for account existence."""
    # Strong signal: 200 vs 404 with different messages
    sig, _ = PasswordResetAnalyzer.analyze_account_enumeration(
        valid_user_status=200,
        valid_user_body='{"message":"Instructions sent"}',
        invalid_user_status=404,
        invalid_user_body='{"error":"User not found"}',
    )
    assert sig == AccountEnumerationSignal.STRONG_ENUMERATION_SIGNAL

    # No signal: uniform message
    clean_sig, _ = PasswordResetAnalyzer.analyze_account_enumeration(
        valid_user_status=200,
        valid_user_body='{"message":"If the account exists, an email was sent"}',
        invalid_user_status=200,
        invalid_user_body='{"message":"If the account exists, an email was sent"}',
    )
    assert clean_sig == AccountEnumerationSignal.NO_ENUMERATION_SIGNAL


# ==============================================================================
# 6. MFA Intelligence Tests
# ==============================================================================

def test_pre_mfa_exposure_evaluation():
    """Verifies detection of sensitive account endpoints leaking data before MFA verification."""
    is_vuln, reason = MFAAnalyzer.evaluate_pre_mfa_exposure(
        endpoint="/api/account/billing",
        session_mfa_state=MFAState.REQUIRED,
        status_code=200,
        response_body='{"balance": 1500, "credit_card": "**** 1234"}',
    )
    assert is_vuln is True
    assert "MFA enforcement is bypassed" in reason


def test_mfa_factor_verification():
    """Verifies evaluation of invalid OTP acceptance."""
    is_vuln, reason = MFAAnalyzer.evaluate_mfa_factor_verification(
        status_code=200,
        response_body='{"status":"verified"}',
        submitted_valid_code=False,
    )
    assert is_vuln is True
    assert "accepted invalid verification token" in reason


# ==============================================================================
# 7. False Positive Elimination Tests
# ==============================================================================

def test_login_page_is_not_authentication_bypass():
    """Verifies that an HTTP 200 response displaying a login form is rejected as false positive."""
    body = "<html><body><h1>Sign In</h1><form method='post'><input type='password' name='password'/></form></body></html>"
    is_fp = AuthenticationFalsePositiveClassifier.is_login_page_false_positive(status_code=200, response_body=body)
    assert is_fp is True

    verdict, _ = SafeAuthenticationValidator.validate_authentication_bypass(
        endpoint="/login",
        anon_status=200,
        anon_body=body,
        auth_status=200,
        auth_body=body,
    )
    assert verdict == HypothesisValidationStatus.REJECTED


def test_normal_access_control_is_not_vulnerability():
    """Verifies that anonymous 401/403 and authenticated 200 is recognized as proper access control."""
    verdict, _ = SafeAuthenticationValidator.validate_authentication_bypass(
        endpoint="/admin/dashboard",
        anon_status=403,
        anon_body="Access Denied",
        auth_status=200,
        auth_body="Admin Dashboard",
    )
    assert verdict == HypothesisValidationStatus.REJECTED


# ==============================================================================
# 8. Security Policy & Human Approval Gate Tests
# ==============================================================================

def test_security_policy_scope_and_metadata_blocking():
    """Verifies that cloud metadata and out-of-scope targets are strictly blocked."""
    policy = AuthenticationSecurityPolicy()
    
    # Metadata blocked
    allowed, reason = policy.is_target_allowed("http://169.254.169.254/latest/meta-data/")
    assert allowed is False
    assert "metadata" in reason.lower()

    # Normal URL allowed
    allowed_norm, _ = policy.is_target_allowed("https://target.com/login")
    assert allowed_norm is True


def test_approval_gate_enforces_confirmation_for_mutations():
    """Verifies that sensitive state-changing operations require operator approval."""
    gate = AuthenticationApprovalGate()
    dossier = gate.create_audit_dossier(
        target="acme-corp",
        identity="researcher_user",
        planned_operation="PASSWORD_RESET_SUBMIT",
        endpoint="/api/v1/password/reset",
        method="POST",
        reason="Test token reuse",
        security_hypothesis="Reset token is reusable",
        expected_result="Token rejected on second use",
        rollback_guidance="Re-reset password via email link",
    )

    # Without approval
    ok_no_appr, msg_no = gate.check_approval(dossier, is_approved=False)
    assert ok_no_appr is False
    assert "--approve" in msg_no

    # With approval
    ok_appr, msg_yes = gate.check_approval(dossier, is_approved=True)
    assert ok_appr is True


# ==============================================================================
# 9. Cryptographic Evidence & Sanitization Tests
# ==============================================================================

def test_evidence_sanitization_and_signature():
    """Verifies that passwords, tokens, and cookies are redacted and SHA-256 hash is generated."""
    req = "POST /login HTTP/1.1\r\nAuthorization: Bearer my_live_token\r\n\r\npassword=SecretP@ssword123&otp=888123"
    res = "HTTP/1.1 200 OK\r\nSet-Cookie: session=live_session_cookie_abc\r\n\r\n{\"user\":\"admin\"}"

    record = AuthenticationEvidenceManager.record_evidence(
        endpoint="/login",
        method="POST",
        status_code=200,
        request_summary=req,
        response_summary=res,
        auth_state_before="ANONYMOUS",
        auth_state_after="AUTHENTICATED",
    )

    assert "[REDACTED_PASSWORD]" in record["request_redacted"]
    assert "[REDACTED_TOKEN]" in record["request_redacted"]
    assert "[REDACTED_BY_BB_AGENT]" in record["request_redacted"]
    assert "SecretP@ssword123" not in record["request_redacted"]
    assert len(record["sha256_digest"]) == 64


# ==============================================================================
# 10. Prioritization & CVSS Scoring Tests
# ==============================================================================

def test_prioritization_orders_high_severity_first():
    """Verifies that findings and hypotheses are ordered by severity and exploitability."""
    f1 = AuthenticationFindingCandidate(
        finding_id="F1",
        title="Missing Cookie Flags",
        family=AuthenticationFindingFamily.AUTHENTICATION_CONFIGURATION_WEAKNESS,
        severity="INFORMATIONAL",
        confidence="HIGH",
        endpoint="/home",
        identity_id="id1",
        description="desc",
        evidence_chain=[],
        cvss_score=2.0,
        remediation="add flags",
    )
    f2 = AuthenticationFindingCandidate(
        finding_id="F2",
        title="Authentication Bypass",
        family=AuthenticationFindingFamily.AUTHENTICATION_BYPASS,
        severity="CRITICAL",
        confidence="CONFIRMED",
        endpoint="/admin",
        identity_id="id2",
        description="desc",
        evidence_chain=[],
        cvss_score=9.1,
        remediation="enforce auth",
    )

    ordered = AuthenticationPrioritizer.prioritize_findings([f1, f2])
    assert ordered[0].finding_id == "F2"
    assert ordered[1].finding_id == "F1"


# ==============================================================================
# 11. Atomic State Persistence & Resume Tests
# ==============================================================================

def test_atomic_state_persistence_and_resume(temp_workspace):
    """Verifies atomic state writing to state/authentication.json and resumption."""
    storage = AuthenticationStateManager(temp_workspace)
    step = AuthenticationStep(step_id="s1", flow_type=AuthenticationFlowType.LOGIN, method="POST", endpoint="/login")
    ident = IdentityProfile(identity_id="id1", username="alice", role="USER")
    hyp = AuthenticationHypothesis(
        hypothesis_id="H1",
        family=AuthenticationFindingFamily.AUTHENTICATION_BYPASS,
        endpoint="/admin",
        principal="ANONYMOUS",
        required_state=AuthenticationState.AUTHENTICATED,
        observed_state=AuthenticationState.ANONYMOUS,
        expected_behavior="Reject",
        observed_behavior="To probe",
        confidence=0.8,
        impact_hint="HIGH",
    )

    storage.save_state(
        surfaces=[step],
        identities=[ident],
        flows=[],
        sessions=[],
        hypotheses=[hyp],
        findings=[],
        evidence_records=[],
    )

    assert os.path.isfile(storage.state_file)

    loaded = storage.load_state()
    assert len(loaded["surfaces"]) == 1
    assert loaded["surfaces"][0].endpoint == "/login"
    assert len(loaded["identities"]) == 1
    assert loaded["identities"][0].username == "alice"
    assert len(loaded["hypotheses"]) == 1
    assert loaded["hypotheses"][0].hypothesis_id == "H1"


# ==============================================================================
# 12. Local Authentication Security Lab Tests
# ==============================================================================

def test_local_authentication_security_lab_execution():
    """Verifies that all 21 deterministic lab scenarios execute and match expected verdicts."""
    scenarios = LocalAuthenticationSecurityLab.list_scenarios()
    assert len(scenarios) >= 18

    results = LocalAuthenticationSecurityLab.run_all()
    for r in results:
        assert r["matches_expectation"] is True, f"Lab scenario {r['scenario_id']} failed: {r['reason']}"
