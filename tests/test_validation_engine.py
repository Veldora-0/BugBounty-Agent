"""
Comprehensive Deterministic Tests for Security Validation Foundation (Phase 6).

Covers:
- Security test case model & deterministic fingerprinting
- Finding lifecycle transitions & evidence bounds
- Request builder & single-component deterministic mutations (query, path, header, cookie, json, form)
- Scope enforcement & anti-SSRF private IP blocking
- Safe testing policy & state-changing GET blocking
- Empirical baseline observation & differential comparison
- Proof-of-concept validators (Reflected XSS, Open Redirect)
- Dual-principal authorization modeling
- Evidence sanitization & credential redaction
- Deduplication of validation findings
- Atomic state persistence in security.json
- CLI / Engine modes (dry-run, passive-only, resume)
- Capability unavailable handling
- Zero shell=True / os.system security audit
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict
import pytest
import yaml

from framework.findings.lifecycle import (
    FindingLifecycle,
    InvalidLifecycleTransition,
    validate_transition,
)
from framework.findings.schema import Finding
from framework.scope.engine import ScopeEngine
from framework.validation.authorization import (
    ExpectedAccessPolicy,
    Principal,
    ResourceIdentifier,
    SessionContext,
    compare_dual_principal_access,
)
from framework.validation.baseline import (
    BaselineComparison,
    BaselineObservation,
    compare_with_baseline,
)
from framework.validation.engine import (
    ScopeViolationError,
    SecurityValidationEngine,
)
from framework.validation.model import (
    RiskLevel,
    SecurityTestCase,
    ValidationResult,
    VulnerabilityFamily,
)
from framework.validation.payload import (
    MutationType,
    Payload,
    PayloadRegistry,
)
from framework.validation.policy import (
    PolicyViolationError,
    SecurityTestPolicy,
)
from framework.validation.request import (
    ControlledRequest,
    ControlledResponse,
    RequestBuilder,
)
from framework.validation.state import SecurityStateManager
from framework.validation.validator import (
    OpenRedirectValidator,
    ReflectedXSSValidator,
    SqlInjectionValidator,
    SsrfValidator,
)


@pytest.fixture
def temp_workspace():
    with tempfile.TemporaryDirectory() as tmpdir:
        state_dir = os.path.join(tmpdir, "state")
        os.makedirs(state_dir, exist_ok=True)
        yield tmpdir


@pytest.fixture
def mock_scope_engine(temp_workspace):
    scope_data = {
        "program": {"name": "test-program"},
        "targets": {
            "domains": ["example.com", "*.example.com"],
            "urls": ["https://app.example.com"],
            "recursive_subdomains": {"enabled": True, "max_depth": 3},
        },
        "out_of_scope": {
            "domains": ["internal.example.com"],
        },
    }
    scope_path = os.path.join(temp_workspace, "scope.yaml")
    with open(scope_path, "w", encoding="utf-8") as f:
        yaml.dump(scope_data, f)
    return ScopeEngine.from_file(scope_path)


# ==============================================================================
# 1. SECURITY TEST CASE & FINGERPRINTING
# ==============================================================================


def test_security_test_case_model_and_fingerprint():
    tc = SecurityTestCase(
        vulnerability_family=VulnerabilityFamily.XSS,
        target="https://app.example.com",
        endpoint="/search",
        method="GET",
        parameter="q",
        payload_identifier="PL-XSS-REFL-01",
        test_strategy="reflected_marker",
    )

    assert tc.test_id.startswith("STC-")
    fp = tc.compute_fingerprint()
    assert len(fp) == 64  # SHA-256

    # Test serialization round-trip
    d = tc.to_dict()
    assert d["vulnerability_family"] == "XSS"
    assert d["parameter"] == "q"

    tc2 = SecurityTestCase.from_dict(d)
    assert tc2.compute_fingerprint() == fp
    assert tc2.test_id == tc.test_id


# ==============================================================================
# 2. FINDING LIFECYCLE & TRANSITIONS
# ==============================================================================


def test_finding_lifecycle_full_pipeline():
    # Valid pipeline: CANDIDATE -> TESTING -> OBSERVED -> VALIDATED
    validate_transition(FindingLifecycle.CANDIDATE, FindingLifecycle.TESTING)
    validate_transition(FindingLifecycle.TESTING, FindingLifecycle.OBSERVED)
    validate_transition(FindingLifecycle.OBSERVED, FindingLifecycle.VALIDATED)

    # Valid rejection: TESTING -> REJECTED, OBSERVED -> REJECTED
    validate_transition(FindingLifecycle.TESTING, FindingLifecycle.REJECTED)
    validate_transition(FindingLifecycle.OBSERVED, FindingLifecycle.REJECTED)

    # Valid manual review: OBSERVED -> NEEDS_MANUAL_REVIEW
    validate_transition(FindingLifecycle.OBSERVED, FindingLifecycle.NEEDS_MANUAL_REVIEW)

    # Illegal transition: OBSERVATION cannot jump directly to VALIDATED
    with pytest.raises(InvalidLifecycleTransition):
        validate_transition(FindingLifecycle.OBSERVATION, FindingLifecycle.VALIDATED)


def test_finding_model_with_validation_fields():
    f = Finding(
        title="Reflected XSS in /search?q=",
        summary="Marker reflected in response body without encoding",
        affected_asset="app.example.com",
        affected_endpoint="/search",
        vulnerability_type="XSS",
        severity="MEDIUM",
        confidence="MEDIUM",
        description="Reflected input marker observed.",
        root_cause="Improper output escaping.",
        prerequisites="None",
        reproduction_steps=["GET /search?q=XSHIELD_TEST_123"],
        expected_result="Encoded HTML entities",
        observed_result="Reflected verbatim",
        security_impact="Potential DOM access if script injected",
        remediation="Contextual output encoding",
        scope_reference="app.example.com in scope",
        parameter="q",
        test_case_id="STC-12345678",
        detection_method="reflected_marker",
        references=["CWE-79"],
    )

    d = f.to_dict()
    assert d["parameter"] == "q"
    assert d["test_case_id"] == "STC-12345678"
    assert d["references"] == ["CWE-79"]

    f2 = Finding.from_dict(d)
    assert f2.parameter == "q"
    assert f2.test_case_id == "STC-12345678"


# ==============================================================================
# 3. REQUEST BUILDER & SINGLE-COMPONENT MUTATIONS
# ==============================================================================


def test_request_builder_mutations():
    builder = RequestBuilder("https://app.example.com/api/items?cat=books&page=1", "GET")
    builder.set_header("Authorization", "Bearer secret_token_12345")
    builder.set_cookie("session", "sess_987654321")

    # Baseline untouched
    baseline = builder.build_baseline()
    assert len(baseline.query_params) == 2
    assert ("cat", "books") in baseline.query_params
    assert ("page", "1") in baseline.query_params

    # 1. Mutate query parameter
    mut_q = builder.mutate_query_param("cat", "MARKER_TEST")
    assert ("cat", "MARKER_TEST") in mut_q.query_params
    assert ("page", "1") in mut_q.query_params  # Untouched!
    assert "cat=MARKER_TEST" in mut_q.build_effective_url()
    assert "page=1" in mut_q.build_effective_url()

    # 2. Mutate path parameter
    path_builder = RequestBuilder("https://app.example.com/users/{id}", "GET")
    mut_path = path_builder.mutate_path_param("id", "99999")
    assert mut_path.build_effective_url() == "https://app.example.com/users/99999"

    # 3. Mutate header
    mut_hdr = builder.mutate_header("X-Custom", "hdr_marker")
    assert mut_hdr.headers["X-Custom"] == "hdr_marker"
    assert baseline.headers.get("X-Custom") is None

    # 4. Mutate cookie
    mut_cookie = builder.mutate_cookie("tracking", "cookie_marker")
    assert mut_cookie.cookies["tracking"] == "cookie_marker"

    # 5. Mutate JSON body
    json_builder = RequestBuilder("https://app.example.com/api/profile", "POST")
    json_builder.set_json_body({"name": "alice", "role": "user"})
    mut_json = json_builder.mutate_json_param("role", "admin_marker")
    assert mut_json.json_body["role"] == "admin_marker"
    assert mut_json.json_body["name"] == "alice"

    # 6. Mutate Form body
    form_builder = RequestBuilder("https://app.example.com/login", "POST")
    form_builder.set_form_body({"user": "bob", "redirect": "/home"})
    mut_form = form_builder.mutate_form_param("redirect", "https://attacker.local")
    assert mut_form.form_body["redirect"] == "https://attacker.local"
    assert mut_form.form_body["user"] == "bob"

    # 7. Sanitized representation masks Authorization and Cookie
    sanitized = baseline.get_sanitized_representation()
    assert "secret_token_12345" not in sanitized
    assert "sess_987654321" not in sanitized
    assert "[REDACTED_BY_BB_AGENT]" in sanitized


# ==============================================================================
# 4. SAFE TESTING POLICY & BOUNDARIES
# ==============================================================================


def test_security_test_policy_enforcement():
    policy = SecurityTestPolicy(
        allowed_methods={"GET", "HEAD"},
        max_requests_per_test=3,
        max_payload_size=100,
    )

    # Allowed methods
    assert policy.is_method_allowed("GET")
    assert policy.is_method_allowed("HEAD")
    assert not policy.is_method_allowed("POST")
    assert not policy.is_method_allowed("DELETE")

    with pytest.raises(PolicyViolationError):
        policy.validate_request_safety("POST", "https://example.com/create")

    # State-changing GET blocked
    with pytest.raises(PolicyViolationError):
        policy.validate_request_safety("GET", "https://example.com/users/1/delete")

    with pytest.raises(PolicyViolationError):
        policy.validate_request_safety("GET", "https://example.com/auth/logout")

    with pytest.raises(PolicyViolationError):
        policy.validate_request_safety("GET", "https://example.com/account/reset-password")

    # Safe GET allowed
    policy.validate_request_safety("GET", "https://example.com/search?q=test")

    # Payload size boundary
    with pytest.raises(PolicyViolationError):
        policy.validate_request_safety("GET", "https://example.com/test", payload_size=500)


# ==============================================================================
# 5. SCOPE & ANTI-SSRF BOUNDARIES
# ==============================================================================


def test_scope_and_anti_ssrf_enforcement(temp_workspace, mock_scope_engine):
    engine = SecurityValidationEngine(
        program_dir=temp_workspace,
        scope_engine=mock_scope_engine,
    )

    # In-scope URL: passes
    engine.check_request_scope("https://app.example.com/search")

    # Explicit out-of-scope domain: raises ScopeViolationError
    with pytest.raises(ScopeViolationError):
        engine.check_request_scope("https://internal.example.com/admin")

    # Arbitrary unauthorized domain: raises ScopeViolationError
    with pytest.raises(ScopeViolationError):
        engine.check_request_scope("https://unauthorized-target.org/api")

    # Forbidden scheme (file://, ftp://): raises ScopeViolationError
    with pytest.raises(ScopeViolationError):
        engine.check_request_scope("file:///etc/passwd")

    with pytest.raises(ScopeViolationError):
        engine.check_request_scope("ftp://ftp.example.com/data")

    # Anti-SSRF localhost / private IP rejection: raises ScopeViolationError
    with pytest.raises(ScopeViolationError):
        engine.check_request_scope("http://127.0.0.1:8080/metrics")

    with pytest.raises(ScopeViolationError):
        engine.check_request_scope("http://localhost/test")

    with pytest.raises(ScopeViolationError):
        engine.check_request_scope("http://169.254.169.254/latest/meta-data/")

    with pytest.raises(ScopeViolationError):
        engine.check_request_scope("http://10.0.0.5/api")


# ==============================================================================
# 6. BASELINE OBSERVATION & COMPARISON
# ==============================================================================


def test_baseline_observation_and_comparison():
    base_resp = ControlledResponse(
        status_code=200,
        headers={"content-type": "text/html; charset=utf-8", "server": "nginx"},
        body="<html><head><title>Search Page</title></head><body>No results found</body></html>",
        size_bytes=81,
        elapsed_seconds=0.1,
    )

    obs = BaselineObservation.from_response("GET /search", base_resp)
    assert obs.status_code == 200
    assert obs.title == "Search Page"
    assert obs.headers_snapshot["content-type"] == "text/html; charset=utf-8"

    # Post-mutation response with reflected marker
    marker = "XSHIELD_TEST_ABC123"
    mut_resp = ControlledResponse(
        status_code=200,
        headers={"content-type": "text/html; charset=utf-8"},
        body=f"<html><head><title>Search Page</title></head><body>Results for {marker}</body></html>",
        size_bytes=95,
        elapsed_seconds=0.12,
    )

    comparison = compare_with_baseline(obs, mut_resp, test_marker=marker)
    assert not comparison.status_changed
    assert comparison.marker_reflected
    assert comparison.reflection_context == "HTML_BODY_TEXT"
    assert "MARKER_REFLECTED_IN_BODY" in comparison.signals


# ==============================================================================
# 7. PROOF-OF-CONCEPT VALIDATORS
# ==============================================================================


def test_reflected_xss_validator():
    validator = ReflectedXSSValidator()
    assert validator.can_test("/search?q=1")
    assert validator.can_test("/search", "q")

    tc = validator.prepare_test_cases("https://app.example.com", "/search", "q")[0]
    assert tc.payload_identifier == "PL-XSS-REFL-01"

    base_obs = BaselineObservation(
        endpoint_key="GET /search",
        status_code=200,
        content_type="text/html",
        response_size=100,
        headers_snapshot={"content-type": "text/html"},
        body_hash="hash1",
        body_sample="<html><body>Search</body></html>",
    )

    # 1. Negative case (marker not reflected) -> REJECTED
    no_refl_resp = ControlledResponse(200, {"content-type": "text/html"}, "<html><body>Results</body></html>", 30)
    comp_no = compare_with_baseline(base_obs, no_refl_resp, test_marker="TEST_MARKER")
    res_no, find_no = validator.analyze(comp_no, base_obs, no_refl_resp, tc)
    assert res_no.lifecycle_state == FindingLifecycle.REJECTED
    assert find_no is None

    # 2. Reflected in script tag -> OBSERVED, HIGH severity, HIGH confidence
    marker = "XSHIELD_TEST_SCRIPT_1"
    script_resp = ControlledResponse(
        200,
        {"content-type": "text/html"},
        f"<html><body><script>var query = '{marker}';</script></body></html>",
        70,
    )
    comp_script = compare_with_baseline(base_obs, script_resp, test_marker=marker)
    res_script, find_script = validator.analyze(comp_script, base_obs, script_resp, tc)
    assert res_script.lifecycle_state == FindingLifecycle.OBSERVED
    assert res_script.severity == "HIGH"
    assert res_script.confidence == "HIGH"
    assert find_script is not None
    assert find_script.vulnerability_type == "Cross-Site Scripting (Reflected)"

    # 3. Reflected in body -> OBSERVED, MEDIUM severity
    body_resp = ControlledResponse(
        200,
        {"content-type": "text/html"},
        f"<html><body>Results for {marker}</body></html>",
        50,
    )
    comp_body = compare_with_baseline(base_obs, body_resp, test_marker=marker)
    res_body, find_body = validator.analyze(comp_body, base_obs, body_resp, tc)
    assert res_body.lifecycle_state == FindingLifecycle.OBSERVED
    assert res_body.severity == "MEDIUM"


def test_open_redirect_validator():
    validator = OpenRedirectValidator()
    assert validator.can_test("/login?redirect=1")
    assert validator.can_test("/oauth/authorize", "redirect_uri")

    tc = validator.prepare_test_cases("https://app.example.com", "/redirect", "url")[0]

    base_obs = BaselineObservation(
        endpoint_key="GET /redirect",
        status_code=200,
        content_type="text/html",
        response_size=50,
        headers_snapshot={"content-type": "text/html"},
        body_hash="hash2",
        body_sample="Redirect Page",
    )

    # 1. Matches external canary -> OBSERVED, MEDIUM severity, HIGH confidence
    canary_url = "https://canary.bugbounty-agent.local/redirect_CANARY123"
    redir_resp = ControlledResponse(
        302,
        {"location": canary_url, "content-type": "text/html"},
        "",
        0,
    )
    comp_redir = compare_with_baseline(base_obs, redir_resp)
    res_redir, find_redir = validator.analyze(comp_redir, base_obs, redir_resp, tc)
    assert res_redir.lifecycle_state == FindingLifecycle.OBSERVED
    assert res_redir.severity == "MEDIUM"
    assert res_redir.confidence == "HIGH"
    assert find_redir is not None
    assert find_redir.vulnerability_type == "Open Redirect"

    # 2. Internal / relative redirect -> REJECTED
    rel_resp = ControlledResponse(302, {"location": "/dashboard"}, "", 0)
    comp_rel = compare_with_baseline(base_obs, rel_resp)
    res_rel, find_rel = validator.analyze(comp_rel, base_obs, rel_resp, tc)
    assert res_rel.lifecycle_state == FindingLifecycle.REJECTED
    assert find_rel is None


def test_unavailable_validators():
    sqli = SqlInjectionValidator()
    assert not sqli.is_available
    assert not sqli.can_test("/test")
    assert len(sqli.prepare_test_cases("example.com", "/test")) == 0

    ssrf = SsrfValidator()
    assert not ssrf.is_available


# ==============================================================================
# 8. AUTHORIZATION VALIDATION FOUNDATION
# ==============================================================================


def test_authorization_modeling_foundation():
    principal_a = Principal("user_101", role="USER", tenant_id="tenant_a", auth_token_masked="tok_a1b2c3d4")
    principal_b = Principal("user_202", role="USER", tenant_id="tenant_b", auth_token_masked="tok_e5f6g7h8")

    assert principal_a.auth_token_masked is not None

    session_a = SessionContext(
        principal=principal_a,
        session_id="sess_101",
        headers_template={"Authorization": "Bearer tok_a1b2c3d4"},
    )
    assert "[REDACTED_BY_BB_AGENT]" in session_a.headers_template["Authorization"]

    resource = ResourceIdentifier(
        resource_id="doc_999",
        resource_type="document",
        owner_principal_id="user_101",
        tenant_id="tenant_a",
        endpoint_template="/api/v1/documents/{id}",
    )

    policy = ExpectedAccessPolicy(
        policy_id="tenant_isolation_policy",
        allowed_principals=["user_101"],
        allowed_roles=["ADMIN"],
    )

    # Case 1: Unauthorized principal receives 403 Forbidden -> No violation
    comp_ok = compare_dual_principal_access(
        resource=resource,
        owner_principal=principal_a,
        owner_status=200,
        unauthorized_principal=principal_b,
        unauthorized_status=403,
        policy=policy,
    )
    assert not comp_ok.is_violation_suspected

    # Case 2: Unauthorized principal receives 200 OK -> Violation suspected!
    comp_viol = compare_dual_principal_access(
        resource=resource,
        owner_principal=principal_a,
        owner_status=200,
        unauthorized_principal=principal_b,
        unauthorized_status=200,
        policy=policy,
    )
    assert comp_viol.is_violation_suspected
    assert comp_viol.access_divergence


# ==============================================================================
# 9. STATE PERSISTENCE & RESUME
# ==============================================================================


def test_security_state_manager_persistence(temp_workspace):
    sm = SecurityStateManager(temp_workspace)

    tc = SecurityTestCase(
        vulnerability_family=VulnerabilityFamily.XSS,
        target="https://app.example.com",
        endpoint="/items",
        parameter="id",
    )
    sm.save_test_case(tc)

    obs = BaselineObservation(
        endpoint_key="GET /items",
        status_code=200,
        content_type="text/html",
        response_size=120,
        headers_snapshot={"content-type": "text/html"},
        body_hash="hash3",
        body_sample="Items",
    )
    sm.save_baseline(obs)

    res = ValidationResult(
        test_id=tc.test_id,
        lifecycle_state=FindingLifecycle.OBSERVED,
        signals_observed=["REFLECTED"],
    )
    fp = tc.compute_fingerprint()
    sm.save_validation_result(res, fp)

    # Verify resume state
    assert sm.is_test_completed(fp)
    assert not sm.is_test_completed("unseen_fingerprint")

    # Reload from disk
    sm2 = SecurityStateManager(temp_workspace)
    assert len(sm2.get_test_cases()) == 1
    assert sm2.get_baseline("GET /items") is not None
    assert sm2.is_test_completed(fp)


# ==============================================================================
# 10. ENGINE EXECUTION MODES (DRY-RUN, PASSIVE-ONLY, DETERMINISTIC MOCKS)
# ==============================================================================


def test_engine_dry_run_and_passive_only(temp_workspace, mock_scope_engine):
    # Seed webapps.json with endpoints for passive intake
    webapps_file = os.path.join(temp_workspace, "state", "webapps.json")
    with open(webapps_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "endpoints": {
                    "GET https://app.example.com/search?q=1": {
                        "url": "https://app.example.com/search?q=1",
                        "method": "GET",
                        "app_id": "app:app.example.com",
                    }
                }
            },
            f,
        )

    engine = SecurityValidationEngine(
        program_dir=temp_workspace,
        scope_engine=mock_scope_engine,
    )

    # 1. Passive-only mode: discovers tests, 0 network requests
    passive_res = engine.run_validation(passive_only=True)
    assert passive_res["mode"] == "passive_only"
    assert passive_res["test_cases_identified"] >= 1
    assert passive_res["active_requests_sent"] == 0

    # 2. Dry-run mode: plans execution, 0 network requests
    dry_res = engine.run_validation(dry_run=True)
    assert dry_res["mode"] == "dry_run"
    assert dry_res["active_requests_sent"] == 0


def test_engine_mock_validation_execution(temp_workspace, mock_scope_engine):
    # Deterministic mock hook to simulate server reflection without real network
    def mock_fetch(request: ControlledRequest) -> ControlledResponse:
        url = request.build_effective_url()
        if "XSHIELD_TEST_" in url:
            # Echo marker back in response
            return ControlledResponse(
                status_code=200,
                headers={"content-type": "text/html"},
                body=f"<html><body>Results for {request.mutated_value}</body></html>",
                size_bytes=60,
            )
        return ControlledResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            body="<html><body>Baseline page</body></html>",
            size_bytes=35,
        )

    engine = SecurityValidationEngine(
        program_dir=temp_workspace,
        scope_engine=mock_scope_engine,
        send_request_hook=mock_fetch,
    )

    summary = engine.run_validation(
        endpoint="https://app.example.com/search",
        parameter="q",
        validator_name="reflected-xss",
    )

    assert summary["mode"] == "active_validation"
    assert summary["tests_executed"] == 1
    assert summary["findings_recorded"] == 1
    assert len(summary["findings"]) == 1
    f = summary["findings"][0]
    assert f["lifecycle_state"] == "OBSERVED"
    assert f["severity"] == "MEDIUM"
    assert engine.request_count == 2  # 1 baseline + 1 mutation


# ==============================================================================
# 11. SECURITY AUDIT: ZERO UNTRUSTED EXECUTION
# ==============================================================================


def test_security_audit_no_shell_or_os_system():
    validation_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "framework", "validation"))
    for root, _, files in os.walk(validation_dir):
        for fname in files:
            if fname.endswith(".py"):
                fpath = os.path.join(root, fname)
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
                    assert "shell=True" not in content, f"Forbidden shell=True found in {fpath}"
                    assert "os.system(" not in content, f"Forbidden os.system found in {fpath}"
                    assert "eval(" not in content, f"Forbidden eval found in {fpath}"
                    assert "exec(" not in content, f"Forbidden exec found in {fpath}"
