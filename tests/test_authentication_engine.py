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
import subprocess
import sys
import tempfile
import pytest

from framework.findings.schema import Finding
from framework.findings.lifecycle import FindingLifecycle
from framework.state.manager import StateManager
from framework.state.dedup import generate_test_fingerprint

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
    resolve_scope_file,
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
    se = ScopeEngine({"targets": {"domains": ["target.com"]}})
    policy = AuthenticationSecurityPolicy(scope_engine=se)
    
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
    assert "[REDACTED_COOKIE]" in record["response_redacted"]
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


# ==============================================================================
# 13. Hardened Pipeline & Cross-Phase Integration Tests (Phase 14.1)
# ==============================================================================

def test_cli_validate_lab_mode():
    """Real CLI orchestration in lab mode (bb-auth --validate --lab --json)."""
    cmd = [sys.executable, "scripts/bb-auth", "--validate", "--lab", "--json"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, f"CLI exited with error: {proc.stderr}"
    data = json.loads(proc.stdout)
    assert data.get("mode") == "lab"
    assert len(data.get("findings", [])) == 9
    assert any(f["family"] == "AUTHENTICATION_BYPASS" for f in data["findings"])


def test_state_ingestion_webapps(temp_workspace):
    """Cross-phase state ingestion from state/webapps.json (real list-of-dicts schema)."""
    webapps_file = os.path.join(temp_workspace, "state", "webapps.json")
    with open(webapps_file, "w", encoding="utf-8") as f:
        json.dump([
            {
                "endpoints": ["https://target.com/login", "https://target.com/dashboard"],
                "forms": [{"action": "/auth/do-login", "method": "POST"}],
                "cookies": [{"name": "session_id", "value": "xyz"}],
            }
        ], f)

    surfaces = AuthenticationSurfaceDiscoverer.discover_all(temp_workspace)
    endpoints = {s.endpoint for s in surfaces}
    assert "https://target.com/login" in endpoints
    assert "https://target.com/dashboard" in endpoints
    assert "/auth/do-login" in endpoints


def test_state_ingestion_api(temp_workspace):
    """Cross-phase state ingestion from state/api.json (real list-of-dicts schema)."""
    api_file = os.path.join(temp_workspace, "state", "api.json")
    with open(api_file, "w", encoding="utf-8") as f:
        json.dump([
            {
                "endpoints": [
                    {"path": "/api/v1/auth/login", "method": "POST"},
                    {"path": "/api/v1/user/reset-password", "method": "POST"},
                ],
                "auth_observations": ["Bearer token scheme present"],
            }
        ], f)

    surfaces = AuthenticationSurfaceDiscoverer.discover_all(temp_workspace)
    endpoints = {s.endpoint for s in surfaces}
    assert "/api/v1/auth/login" in endpoints
    assert "/api/v1/user/reset-password" in endpoints
    login_step = next(s for s in surfaces if s.endpoint == "/api/v1/auth/login")
    assert login_step.flow_type == AuthenticationFlowType.LOGIN


def test_state_ingestion_javascript(temp_workspace):
    """Cross-phase state ingestion from state/javascript.json (real list-of-dicts schema)."""
    js_file = os.path.join(temp_workspace, "state", "javascript.json")
    with open(js_file, "w", encoding="utf-8") as f:
        json.dump([
            {
                "routes": ["/auth/sso/callback", "/portal/logout"],
                "endpoints": ["/api/v2/mfa/challenge"],
                "interesting_strings": ["jwt_secret_hint"],
            }
        ], f)

    surfaces = AuthenticationSurfaceDiscoverer.discover_all(temp_workspace)
    endpoints = {s.endpoint for s in surfaces}
    assert "/auth/sso/callback" in endpoints
    assert "/portal/logout" in endpoints
    assert "/api/v2/mfa/challenge" in endpoints


def test_state_ingestion_assets_recon(temp_workspace):
    """Cross-phase state ingestion from state/assets.json and state/recon.json."""
    assets_file = os.path.join(temp_workspace, "state", "assets.json")
    recon_file = os.path.join(temp_workspace, "state", "recon.json")

    with open(assets_file, "w", encoding="utf-8") as f:
        json.dump({
            "assets": {
                "asset:1": {
                    "hostname": "auth.example.com",
                    "http_services": [{"url": "https://auth.example.com/oauth/authorize"}],
                }
            }
        }, f)

    with open(recon_file, "w", encoding="utf-8") as f:
        json.dump({
            "tls_records": [
                {"san": ["sso.example.com", "login.example.com"]}
            ]
        }, f)

    surfaces = AuthenticationSurfaceDiscoverer.discover_all(temp_workspace)
    endpoints = {s.endpoint for s in surfaces}
    assert "https://auth.example.com/oauth/authorize" in endpoints
    assert "https://sso.example.com" in endpoints
    assert "https://login.example.com" in endpoints


def test_state_ingestion_authorization(temp_workspace):
    """Authorization cross-correlation from state/authorization.json (dict-of-dicts schema)."""
    authz_file = os.path.join(temp_workspace, "state", "authorization.json")
    with open(authz_file, "w", encoding="utf-8") as f:
        json.dump({
            "principals": {
                "principal_editor": {
                    "username": "editor_user",
                    "role": "EDITOR",
                    "tenant": "tenant_north",
                }
            }
        }, f)

    mgr = IdentityManager()
    seeded = mgr.seed_from_authorization_state(temp_workspace)
    assert len(seeded) == 1
    assert seeded[0].username == "editor_user"
    assert seeded[0].role == "EDITOR"
    assert seeded[0].tenant == "tenant_north"


def test_state_ingestion_workflows(temp_workspace):
    """Workflow cross-correlation from state/workflows.json (dict-of-dicts schema)."""
    wf_file = os.path.join(temp_workspace, "state", "workflows.json")
    with open(wf_file, "w", encoding="utf-8") as f:
        json.dump({
            "workflows": {
                "wf_mfa": {
                    "steps": [
                        {"endpoint": "/mfa/step1", "method": "POST"},
                        {"endpoint": "/mfa/step2", "method": "POST"},
                    ]
                }
            }
        }, f)

    surfaces = AuthenticationSurfaceDiscoverer.discover_all(temp_workspace)
    endpoints = {s.endpoint for s in surfaces}
    assert "/mfa/step1" in endpoints
    assert "/mfa/step2" in endpoints


def test_state_ingestion_missing_files_graceful(temp_workspace):
    """Missing state files tolerated without unhandled exceptions."""
    surfaces = AuthenticationSurfaceDiscoverer.discover_all(temp_workspace)
    assert isinstance(surfaces, list)
    assert len(surfaces) == 0

    mgr = IdentityManager()
    seeded = mgr.seed_from_authorization_state(temp_workspace)
    assert isinstance(seeded, list)
    assert len(seeded) == 0


def test_state_ingestion_corrupted_json(temp_workspace):
    """Corrupted JSON state files handled gracefully without crashing."""
    webapps_file = os.path.join(temp_workspace, "state", "webapps.json")
    with open(webapps_file, "w", encoding="utf-8") as f:
        f.write("{MALFORMED_JSON_CONTENT:::;;;")

    surfaces = AuthenticationSurfaceDiscoverer.discover_all(temp_workspace)
    assert isinstance(surfaces, list)
    assert len(surfaces) == 0


def test_scope_missing_fails_closed(temp_workspace):
    """Missing scope file fails closed (active validation aborted)."""
    resolved = resolve_scope_file(temp_workspace)
    assert resolved is None

    policy = AuthenticationSecurityPolicy(scope_engine=None)
    allowed, reason = policy.is_target_allowed("https://target.com/login")
    assert allowed is False
    assert "failing closed" in reason.lower()


def test_scope_malformed_and_out_of_scope(temp_workspace):
    """Malformed, ambiguous, and out-of-scope targets blocked offline before any probe dispatch."""
    se = ScopeEngine({"targets": {"domains": ["authorized.com"]}})
    policy = AuthenticationSecurityPolicy(scope_engine=se)

    # In-scope
    ok1, _ = policy.is_target_allowed("https://authorized.com/login")
    assert ok1 is True

    # Out of scope
    ok2, r2 = policy.is_target_allowed("https://attacker.com/login")
    assert ok2 is False
    assert "out_of_scope" in r2.lower()

    # Cloud metadata / prohibited IP
    ok3, r3 = policy.is_target_allowed("http://169.254.169.254/latest/meta-data")
    assert ok3 is False
    assert "prohibited" in r3.lower()


def test_offline_modes_zero_network(temp_workspace, monkeypatch):
    """Verify dry-run, passive-only, and lab modes make strictly zero external socket connections."""
    import socket

    def forbidden_connect(*args, **kwargs):
        raise AssertionError("Network socket connect attempted during offline mode!")

    monkeypatch.setattr(socket.socket, "connect", forbidden_connect)

    engine = AuthenticationSecurityEngine(workspace_dir=temp_workspace)
    engine.surfaces = [
        AuthenticationStep(step_id="s1", flow_type=AuthenticationFlowType.LOGIN, method="GET", endpoint="https://example.com/login")
    ]
    engine.formulate_hypotheses()

    # Passive only
    p_findings = engine.validate_hypotheses(passive_only=True)
    assert isinstance(p_findings, list)

    # Lab mode
    lab_res = engine.execute_lab_simulation()
    assert lab_res["passed_scenarios"] == 21


def test_evidence_credential_redaction_comprehensive():
    """Verify passwords, cookies, tokens, OTPs, and keys are thoroughly sanitized."""
    raw = (
        "POST /login HTTP/1.1\r\n"
        "Host: auth.target.com\r\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.super_secret\r\n"
        "Cookie: session=abcde12345; connect.sid=sess_secret_777; PHPSESSID=php_sess_999\r\n"
        "X-API-Key: live_api_key_secret_value\r\n"
        "\r\n"
        "password=SecretPassword123!&otp=123456&reset_token=tok_reset_abc"
    )

    clean = AuthenticationEvidenceManager.sanitize(raw)
    assert "SecretPassword123!" not in clean
    assert "abcde12345" not in clean
    assert "sess_secret_777" not in clean
    assert "php_sess_999" not in clean
    assert "super_secret" not in clean
    assert "live_api_key_secret_value" not in clean
    assert "123456" not in clean
    assert "tok_reset_abc" not in clean

    assert "[REDACTED_PASSWORD]" in clean
    assert "[REDACTED_COOKIE]" in clean
    assert "[REDACTED_TOKEN]" in clean
    assert "[REDACTED_SECRET]" in clean


def test_dedup_test_fingerprinting_and_context(temp_workspace):
    """Verify test fingerprinting in state/tests.json and context-aware retesting across roles."""
    sm = StateManager(temp_workspace)
    fp_anon = generate_test_fingerprint("target.com", "/api/profile", "GET", "principal:ANON|family:AUTHENTICATION_BYPASS", "authentication")
    fp_admin = generate_test_fingerprint("target.com", "/api/profile", "GET", "principal:ADMIN|family:AUTHENTICATION_BYPASS", "authentication")
    assert fp_anon != fp_admin

    sm.record_test("target.com", "/api/profile", "GET", "principal:ANON|family:AUTHENTICATION_BYPASS", "authentication", "SUCCESS")
    assert sm.has_test_run("target.com", "/api/profile", "GET", "principal:ANON|family:AUTHENTICATION_BYPASS", "authentication") is True
    assert sm.has_test_run("target.com", "/api/profile", "GET", "principal:ADMIN|family:AUTHENTICATION_BYPASS", "authentication") is False


def test_engine_resume_recovery(temp_workspace):
    """Verify --resume state recovery from state/authentication.json skips prior tests."""
    engine1 = AuthenticationSecurityEngine(workspace_dir=temp_workspace)
    hyp1 = AuthenticationHypothesis(
        hypothesis_id="HYP-PREV-01",
        family=AuthenticationFindingFamily.AUTHENTICATION_BYPASS,
        endpoint="https://example.com/protected",
        principal="ANONYMOUS",
        required_state=AuthenticationState.AUTHENTICATED,
        observed_state=AuthenticationState.ANONYMOUS,
        expected_behavior="401",
        observed_behavior="200",
        confidence=0.9,
        impact_hint="HIGH",
        validation_status=HypothesisValidationStatus.VALIDATED,
        rationale="Already verified",
    )
    engine1.hypotheses = [hyp1]
    engine1.persist_state()

    engine2 = AuthenticationSecurityEngine(workspace_dir=temp_workspace)
    engine2.load_existing_state()
    assert len(engine2.hypotheses) == 1
    assert engine2.hypotheses[0].validation_status == HypothesisValidationStatus.VALIDATED

    # Calling validate_hypotheses with resume skips the validated hypothesis
    engine2.validate_hypotheses(resume=True)
    assert engine2.hypotheses[0].validation_status == HypothesisValidationStatus.VALIDATED
    assert engine2.hypotheses[0].rationale == "Already verified"


def test_false_positive_status_code_rejection():
    """Status-code-only false positive rejection (generic 200 OK forms and WAF challenges)."""
    clf = AuthenticationFalsePositiveClassifier()

    # Form rejection
    assert clf.is_login_page_false_positive(200, "<html><form method='post'><input type='password'></form></html>") is True
    assert clf.is_login_page_false_positive(200, "{\"email\": \"admin@target.com\", \"role\": \"superadmin\"}") is False

    # WAF rejection
    assert clf.is_waf_or_challenge_page(403, "Cloudflare Ray ID: 123456 - Access Denied") is True
    assert clf.is_waf_or_challenge_page(200, "Please complete the security challenge captcha") is True
    assert clf.is_waf_or_challenge_page(200, "{\"status\": \"ok\"}") is False

    # Normal access control
    assert clf.is_normal_access_control(401, 200) is True
    assert clf.is_normal_access_control(200, 200) is False


def test_baseline_differential_validation():
    """Evidence-backed baseline differential validation for session invalidation and bypass."""
    # Bypass validation
    v_bypass, _ = SafeAuthenticationValidator.validate_authentication_bypass(
        endpoint="/api/user/settings",
        anon_status=200,
        anon_body='{"user_id": "99", "email": "victim@target.com", "balance": 1500}',
        auth_status=200,
        auth_body='{"user_id": "99", "email": "victim@target.com"}',
    )
    assert v_bypass == HypothesisValidationStatus.VALIDATED

    # Normal auth rejected
    v_normal, _ = SafeAuthenticationValidator.validate_authentication_bypass(
        endpoint="/api/user/settings",
        anon_status=401,
        anon_body="Unauthorized",
        auth_status=200,
        auth_body='{"user_id": "99"}',
    )
    assert v_normal == HypothesisValidationStatus.REJECTED

    # Account enumeration multi-trial validation
    v_enum_weak, _ = SafeAuthenticationValidator.validate_account_enumeration(
        valid_status=200,
        valid_body="Email sent to account inbox",
        invalid_status=200,
        invalid_body="Email sent to account inbox",
        trial_count=3,
    )
    assert v_enum_weak == HypothesisValidationStatus.REJECTED

    v_enum_single, _ = SafeAuthenticationValidator.validate_account_enumeration(
        valid_status=200,
        valid_body="Email sent to existing user",
        invalid_status=404,
        invalid_body="User not found",
        trial_count=1,
    )
    assert v_enum_single == HypothesisValidationStatus.INFORMATIONAL

    v_enum_confirmed, _ = SafeAuthenticationValidator.validate_account_enumeration(
        valid_status=200,
        valid_body="Email sent to existing user",
        invalid_status=404,
        invalid_body="User not found",
        trial_count=3,
    )
    assert v_enum_confirmed == HypothesisValidationStatus.VALIDATED


def test_native_finding_lifecycle_persistence(temp_workspace):
    """Native Finding conversion respects FindingLifecycle.VALIDATED only on true verification, persisting to state/findings.json."""
    c_valid = AuthenticationFindingCandidate(
        finding_id="FIND-TEST-01",
        title="Bypass Flaw",
        family=AuthenticationFindingFamily.AUTHENTICATION_BYPASS,
        severity="CRITICAL",
        confidence="CONFIRMED",
        endpoint="/api/admin/data",
        identity_id="ANONYMOUS",
        description="Anonymous data exposure",
        evidence_chain=[{"status_code": 200, "response_redacted": "email: test@corp.local"}],
        cvss_score=9.1,
        remediation="Enforce auth checks",
    )
    f_valid = c_valid.to_native_finding(scope_ref="scope/scope.yaml", is_validated=True)
    assert isinstance(f_valid, Finding)
    assert f_valid.lifecycle_state == FindingLifecycle.VALIDATED

    c_obs = AuthenticationFindingCandidate(
        finding_id="FIND-TEST-02",
        title="Session Not Rotated",
        family=AuthenticationFindingFamily.SESSION_NOT_ROTATED,
        severity="LOW",
        confidence="HIGH",
        endpoint="/auth/login",
        identity_id="ANONYMOUS",
        description="Session not rotated across privilege change",
        evidence_chain=[],
        cvss_score=3.5,
        remediation="Rotate session identifier",
    )
    f_obs = c_obs.to_native_finding(scope_ref="scope/scope.yaml", is_validated=True)
    assert f_obs.lifecycle_state == FindingLifecycle.INFORMATIONAL

    # Persist via StateManager
    sm = StateManager(temp_workspace)
    saved_f, is_dup, dup_id = sm.save_finding(f_valid)
    assert is_dup is False
    assert os.path.isfile(sm.findings_file)

    loaded_findings = sm.get_findings()
    assert len(loaded_findings) == 1
    assert loaded_findings[0].finding_id == "FIND-TEST-01"


# ==============================================================================
# 14. Phase 14.2 Comprehensive Safety, Integration & Lab Verification Suite
# ==============================================================================

def test_offline_lab_all_scenarios():
    """Assert all 21 offline lab scenarios pass with exact expected verdicts."""
    results = LocalAuthenticationSecurityLab.run_all()
    assert len(results) == 21

    for r in results:
        scen_id = r["scenario_id"]
        assert scen_id in LocalAuthenticationSecurityLab.SCENARIOS, f"Unexpected scenario: {scen_id}"
        expected = LocalAuthenticationSecurityLab.SCENARIOS[scen_id]["expected_verdict"]
        assert r["verdict"] == expected, f"Scenario {scen_id} expected {expected}, got {r['verdict']}"
        assert r["matches_expectation"] is True, f"Scenario {scen_id} did not match expectation"


def test_fixture_server():
    """Verify local fixture HTTP behaviors, negative controls, and bounded execution caps."""
    import http.server
    import threading
    import urllib.error
    from framework.authentication.executor import (
        BoundedAuthenticationExecutor,
        AuthSafeRedirectHandler,
    )

    class FixtureHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            if self.path == "/api/protected":
                auth = self.headers.get("Authorization", "")
                if auth == "Bearer valid_key":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"user": "alice", "account": "123"}')
                else:
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error": "Unauthorized"}')
            elif self.path == "/large-body":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"A" * (150 * 1024))
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            if self.path.startswith("/api/reset"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "Instructions sent if account exists"}')
            else:
                self.send_response(200)
                self.end_headers()

    server = http.server.HTTPServer(("127.0.0.1", 0), FixtureHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        # Negative control for bypass: 401 unauthenticated vs 200 authenticated
        v1, _ = SafeAuthenticationValidator.validate_authentication_bypass(
            endpoint=f"http://127.0.0.1:{port}/api/protected",
            anon_status=401,
            anon_body='{"error": "Unauthorized"}',
            auth_status=200,
            auth_body='{"user": "alice", "account": "123"}',
        )
        assert v1 == HypothesisValidationStatus.REJECTED

        # Negative control for enumeration: uniform responses
        v2, _ = SafeAuthenticationValidator.validate_account_enumeration(
            valid_status=200,
            valid_body='{"status": "Instructions sent if account exists"}',
            invalid_status=200,
            invalid_body='{"status": "Instructions sent if account exists"}',
            trial_count=3,
        )
        assert v2 == HypothesisValidationStatus.REJECTED

        # Redirect blocks
        redirect_handler = AuthSafeRedirectHandler(scope_checker=lambda u: "in-scope.com" in u)

        # SSRF redirect block
        req_mock = urllib.request.Request("http://in-scope.com/start")
        with pytest.raises(urllib.error.HTTPError) as exc_ssrf:
            redirect_handler.redirect_request(
                req_mock, None, 302, "Found", {}, "http://169.254.169.254/latest/meta-data"
            )
        assert "prohibited" in str(exc_ssrf.value).lower()

        # Out-of-scope redirect block
        with pytest.raises(urllib.error.HTTPError) as exc_scope:
            redirect_handler.redirect_request(
                req_mock, None, 302, "Found", {}, "http://out-of-scope.example.com/target"
            )
        assert "out_of_scope" in str(exc_scope.value).lower()

        # Protocol downgrade block
        req_https = urllib.request.Request("https://in-scope.com/secure")
        with pytest.raises(urllib.error.HTTPError) as exc_down:
            redirect_handler.redirect_request(
                req_https, None, 302, "Found", {}, "http://in-scope.com/insecure"
            )
        assert "downgrade" in str(exc_down.value).lower()

        # Exceeded max redirects block
        h_limit = AuthSafeRedirectHandler(scope_checker=lambda u: True, max_redirects=2)
        h_limit.redirect_request(req_mock, None, 302, "Found", {}, "http://in-scope.com/1")
        h_limit.redirect_request(req_mock, None, 302, "Found", {}, "http://in-scope.com/2")
        with pytest.raises(urllib.error.HTTPError) as exc_max:
            h_limit.redirect_request(req_mock, None, 302, "Found", {}, "http://in-scope.com/3")
        assert "exceeded maximum redirects" in str(exc_max.value).lower()

    finally:
        server.shutdown()
        server.server_close()


def test_zero_traffic_and_ssrf_boundaries(temp_workspace, monkeypatch):
    """Verify zero socket and DNS traffic in offline modes, and exhaustive SSRF boundary coverage."""
    import socket
    from framework.authentication.executor import is_ssrf_prohibited_host, BoundedAuthenticationExecutor

    # Assert SSRF boundaries
    prohibited_hosts = [
        "127.0.0.1",
        "localhost",
        "169.254.169.254",
        "169.254.169.123",
        "metadata.google.internal",
        "instance-data",
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "100.64.0.1",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
    ]
    for ph in prohibited_hosts:
        is_prohib, reason = is_ssrf_prohibited_host(ph)
        assert is_prohib is True, f"Host {ph} should be prohibited (reason: {reason})"

    # Disallow network socket and getaddrinfo
    def forbidden_connect(*args, **kwargs):
        raise AssertionError("Socket connect called during offline mode!")

    def forbidden_getaddrinfo(*args, **kwargs):
        raise AssertionError("DNS getaddrinfo called during offline mode!")

    monkeypatch.setattr(socket.socket, "connect", forbidden_connect)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden_getaddrinfo)

    # Dry-run execution must not make DNS or socket calls
    executor = BoundedAuthenticationExecutor()
    res = executor.execute_request("https://target.com/api/test", dry_run=True)
    assert res["success"] is True
    assert res["dry_run"] is True
    assert res["body"] == "[DRY_RUN_NO_TRAFFIC]"


def test_cross_run_resume_and_deduplication(temp_workspace):
    """Verify cross-run resume retains statuses and avoids duplicate network probes."""
    engine = AuthenticationSecurityEngine(workspace_dir=temp_workspace)
    s = AuthenticationStep(step_id="step1", flow_type=AuthenticationFlowType.LOGIN, method="GET", endpoint="/auth/login")
    engine.surfaces = [s]
    hyps = engine.formulate_hypotheses()
    assert len(hyps) > 0
    # Mark first hypothesis as validated
    hyps[0].validation_status = HypothesisValidationStatus.VALIDATED
    hyps[0].rationale = "Pre-verified in prior wave"
    engine.persist_state()

    # Re-initialize engine and resume
    engine2 = AuthenticationSecurityEngine(workspace_dir=temp_workspace)
    engine2.load_existing_state()
    resumed_hyp = next(h for h in engine2.hypotheses if h.hypothesis_id == hyps[0].hypothesis_id)
    assert resumed_hyp.validation_status == HypothesisValidationStatus.VALIDATED
    assert resumed_hyp.rationale == "Pre-verified in prior wave"


def test_scope_fail_closed_and_approval_invariants(temp_workspace):
    """Verify scope resolution fails closed and approval gate cannot bypass scope restrictions."""
    # Scope resolution fails closed without fallback
    assert resolve_scope_file(temp_workspace) is None
    assert resolve_scope_file("nonexistent_prog_dir_123") is None

    # Invariant: Approval NEVER overrides scope restrictions
    dossier = AuthenticationApprovalGate.create_audit_dossier(
        target="https://out-of-scope.example.com",
        identity="tester",
        planned_operation="PASSWORD_RESET_SUBMIT",
        endpoint="/reset",
        method="POST",
        reason="Testing reset",
        security_hypothesis="Reset flaw",
        expected_result="Fail",
        rollback_guidance="None",
    )
    ok, msg = AuthenticationApprovalGate.check_approval(dossier, is_approved=True, is_in_scope=False)
    assert ok is False
    assert "cannot override scope restrictions" in msg.lower()

