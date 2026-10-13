"""
Deterministic Regression Tests for Fail-Closed Scope Authorization and Simulation Separation.

Verifies:
- Test 1: Active validation in SecurityValidationEngine without ScopeEngine raises ScopeViolationError.
- Test 2: Missing or malformed scope configuration prevents active execution in bb-validate.
- Test 3: Out-of-scope targets rejected before network dispatch.
- Test 4: Explicit offline fixtures (send_request_hook and allowed_fixture_ports) work properly.
- Test 5: Cloud validation without ScopeEngine is blocked.
- Test 6: Missing cloud request handler fails closed and does not fabricate observations.
- Test 7: Missing business-logic request handler fails closed and does not fabricate observations.
- Test 8: Simulated results cannot be transitioned to VALIDATED or report-ready disclosure.
- Test 9: Real observations via local fixtures can progress to VALIDATED.
- Test 10: Redirects cannot bypass scope or transport policy.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from typing import Any, Dict
import urllib.request
import pytest

from framework.business_logic.engine import BusinessLogicEngine
from framework.business_logic.model import (
    BusinessLogicCategory,
    Workflow,
    WorkflowHypothesis,
    WorkflowStep,
)
from framework.cloud_security.engine import CloudSecurityEngine
from framework.cloud_security.models import (
    CloudExposureHypothesis,
    CloudHypothesisType,
    CloudProvider,
    CloudServiceType,
    HypothesisValidationStatus,
)
from framework.cloud_security.validators import SafeCloudValidator
from framework.findings.lifecycle import (
    FindingLifecycle,
    InvalidLifecycleTransition,
)
from framework.findings.schema import Finding
from framework.scope.engine import ScopeEngine
from framework.validation.engine import (
    SafeRedirectHandler,
    ScopeViolationError,
    SecurityValidationEngine,
)
from framework.validation.policy import SecurityTestPolicy
from framework.validation.request import ControlledRequest, ControlledResponse


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmp:
        state_dir = os.path.join(tmp, "state")
        os.makedirs(state_dir, exist_ok=True)
        yield tmp


@pytest.fixture
def authorized_scope():
    return ScopeEngine({
        "program": {"name": "test-program"},
        "targets": {
            "domains": ["authorized.example.com", "*.authorized.example.com"],
            "urls": ["https://authorized.example.com/api"],
        },
        "out_of_scope": {
            "domains": ["forbidden.authorized.example.com"],
            "urls": ["https://authorized.example.com/api/forbidden"],
        },
    })


# ------------------------------------------------------------------------------
# Test 1: Active validation in SecurityValidationEngine without ScopeEngine
# ------------------------------------------------------------------------------
def test_active_validation_without_scope_engine_raises_error(temp_dir):
    """Verifies that SecurityValidationEngine without ScopeEngine fails closed immediately."""
    engine = SecurityValidationEngine(
        program_dir=temp_dir,
        scope_engine=None,
    )

    req = ControlledRequest(
        url="https://authorized.example.com/api/test",
        method="GET",
    )

    # send_request fails closed before any network attempt
    with pytest.raises(ScopeViolationError) as exc_info:
        engine.send_request(req)
    assert "Active validation requires a valid, initialized ScopeEngine" in str(exc_info.value)

    # resolve_scope_ips also fails closed
    with pytest.raises(ScopeViolationError) as exc_info2:
        engine.resolve_scope_ips("https://authorized.example.com/api/test")
    assert "Active validation requires a valid, initialized ScopeEngine" in str(exc_info2.value)


# ------------------------------------------------------------------------------
# Test 2: Missing or malformed scope configuration in bb-validate
# ------------------------------------------------------------------------------
def test_bb_validate_missing_or_malformed_scope_prevents_active_execution(temp_dir):
    """Verifies that bb-validate aborts with exit code 1 if active validation has no valid scope."""
    script_path = os.path.join(os.path.dirname(__file__), "..", "scripts", "bb-validate")

    # 1. Missing scope.yaml
    proc = subprocess.run(
        [sys.executable, script_path, "--program", "nonexistent-program", "--endpoint", "https://example.com"],
        capture_output=True,
        text=True,
        cwd=temp_dir,
    )
    assert proc.returncode == 1
    assert "Active validation requires a valid scope configuration" in proc.stderr

    # 2. Malformed scope.yaml
    malformed_scope = os.path.join(temp_dir, "malformed_scope.yaml")
    with open(malformed_scope, "w", encoding="utf-8") as f:
        f.write("invalid: [broken yaml: {")

    proc2 = subprocess.run(
        [sys.executable, script_path, "--program", "test", "--scope", malformed_scope, "--endpoint", "https://example.com"],
        capture_output=True,
        text=True,
        cwd=temp_dir,
    )
    assert proc2.returncode == 1
    assert "Active validation requires a valid scope configuration" in proc2.stderr


# ------------------------------------------------------------------------------
# Test 3: Out-of-scope targets rejected before network dispatch
# ------------------------------------------------------------------------------
def test_out_of_scope_targets_rejected_before_dispatch(temp_dir, authorized_scope):
    """Verifies out-of-scope targets are rejected before connection or hook dispatch."""
    dispatched = []

    def mock_hook(req: ControlledRequest) -> ControlledResponse:
        dispatched.append(req.build_effective_url())
        return ControlledResponse(status_code=200, body_text="OK")

    engine = SecurityValidationEngine(
        program_dir=temp_dir,
        scope_engine=authorized_scope,
        send_request_hook=mock_hook,
    )

    # Target entirely outside scope
    with pytest.raises(ScopeViolationError) as exc_info:
        engine.send_request(ControlledRequest("https://unauthorized-domain.com/v1"))
    assert "OUT_OF_SCOPE" in str(exc_info.value)
    assert len(dispatched) == 0

    # Target explicitly in out_of_scope
    with pytest.raises(ScopeViolationError) as exc_info2:
        engine.send_request(ControlledRequest("https://forbidden.authorized.example.com/api"))
    assert "OUT_OF_SCOPE" in str(exc_info2.value)
    assert len(dispatched) == 0


# ------------------------------------------------------------------------------
# Test 4: Explicit offline fixtures still work properly
# ------------------------------------------------------------------------------
def test_explicit_offline_fixtures_work_properly(temp_dir, authorized_scope):
    """Verifies that allowed fixture ports and mock hooks work without network connection."""
    # 1. Unscoped engine cannot authorize a fixture (must fail closed)
    engine_unscoped = SecurityValidationEngine(
        program_dir=temp_dir,
        scope_engine=None,
    )
    engine_unscoped.allow_fixture_port(8989)
    with pytest.raises(ScopeViolationError) as exc_unscoped:
        engine_unscoped.resolve_scope_ips("http://127.0.0.1:8989/local-test")
    assert "No scope engine configured" in str(exc_unscoped.value)

    # 2. Local fixture port with authorized fixture scope initialized
    fixture_scope = ScopeEngine({
        "program": {"name": "fixture-program"},
        "targets": {
            "urls": ["http://127.0.0.1"],
        },
    })
    engine_fixture = SecurityValidationEngine(
        program_dir=temp_dir,
        scope_engine=fixture_scope,
    )
    engine_fixture.allow_fixture_port(8989)
    ips = engine_fixture.resolve_scope_ips("http://127.0.0.1:8989/local-test")
    assert ips == ["127.0.0.1"]

    # Mock request hook with authorized scope
    hook_called = False

    def mock_hook(req: ControlledRequest) -> ControlledResponse:
        nonlocal hook_called
        hook_called = True
        return ControlledResponse(status_code=200, body_text="Fixture OK")

    engine_hook = SecurityValidationEngine(
        program_dir=temp_dir,
        scope_engine=authorized_scope,
        send_request_hook=mock_hook,
    )
    resp = engine_hook.send_request(ControlledRequest("https://authorized.example.com/api"))
    assert hook_called is True
    assert resp.status_code == 200
    assert resp.body_text == "Fixture OK"


# ------------------------------------------------------------------------------
# Test 5: Cloud validation without ScopeEngine is blocked
# ------------------------------------------------------------------------------
def test_cloud_validation_without_scope_engine_is_blocked(temp_dir):
    """Verifies that CloudSecurityEngine blocks validation if ScopeEngine is None."""
    engine = CloudSecurityEngine(
        program_dir=temp_dir,
        scope_engine=None,
    )

    hyp = CloudExposureHypothesis(
        id="hyp-cloud-test",
        asset="target.s3.amazonaws.com",
        provider=CloudProvider.AWS,
        service=CloudServiceType.OBJECT_STORAGE,
        hypothesis_type=CloudHypothesisType.PUBLIC_OBJECT_READ,
        confidence=0.7,
        severity_hint="MEDIUM",
        rationale="Unscoped target probe test",
        endpoint="https://target.s3.amazonaws.com/test",
    )

    results = engine.validate_hypotheses([hyp])
    assert len(results) == 1
    h, status, candidate, reason = results[0]
    assert status == HypothesisValidationStatus.REJECTED
    assert candidate is None
    assert "No ScopeEngine bound" in reason


# ------------------------------------------------------------------------------
# Test 6: Missing cloud request handler fails closed
# ------------------------------------------------------------------------------
def test_missing_cloud_request_handler_fails_closed():
    """Verifies SafeCloudValidator fails closed and raises RuntimeError when request_hook is None."""
    validator = SafeCloudValidator(request_hook=None)

    hyp = CloudExposureHypothesis(
        id="hyp-cloud-missing-hook",
        asset="target.s3.amazonaws.com",
        provider=CloudProvider.AWS,
        service=CloudServiceType.OBJECT_STORAGE,
        hypothesis_type=CloudHypothesisType.PUBLIC_OBJECT_LISTING,
        confidence=0.7,
        severity_hint="HIGH",
        rationale="Test missing hook",
        endpoint="https://target.s3.amazonaws.com",
    )

    with pytest.raises(RuntimeError) as exc_info:
        validator.validate_hypothesis(hyp)
    assert "No live request handler or test mock configured" in str(exc_info.value)
    assert "Simulated HTTP responses are forbidden" in str(exc_info.value)


# ------------------------------------------------------------------------------
# Test 7: Missing business-logic request handler fails closed
# ------------------------------------------------------------------------------
def test_missing_business_logic_request_handler_fails_closed(temp_dir, authorized_scope):
    """Verifies BusinessLogicEngine fails closed when send_request_hook is None."""
    engine = BusinessLogicEngine(
        program_dir=temp_dir,
        scope_engine=authorized_scope,
        send_request_hook=None,
        auto_approve=True,
    )

    wf = Workflow(
        workflow_id="wf-test-missing-req",
        program="test-program",
        application="authorized.example.com",
        name="Test Workflow",
        description="Testing missing request handler",
        steps=[
            WorkflowStep("step-1", "Step 1", "https://authorized.example.com/api/step1", "POST"),
            WorkflowStep("step-2", "Step 2", "https://authorized.example.com/api/step2", "POST", is_terminal=True),
        ],
    )
    engine.state_mgr.save_workflow(wf)

    hyp = WorkflowHypothesis(
        hypothesis_id="hyp-bl-test",
        workflow_id=wf.workflow_id,
        category=BusinessLogicCategory.STEP_SKIPPING,
        title="Test Step Skipping",
        description="Testing missing dispatcher",
        target_step_id="step-2",
        target_actor="USER",
        test_strategy="Skip prerequisite",
        priority=80,
    )

    with pytest.raises(RuntimeError) as exc_info:
        engine.execute_hypothesis(hyp)
    assert "No request dispatcher configured" in str(exc_info.value)
    assert "Simulated HTTP responses are forbidden" in str(exc_info.value)


# ------------------------------------------------------------------------------
# Test 8: Simulated results cannot be transitioned to VALIDATED or report-ready
# ------------------------------------------------------------------------------
def test_simulated_results_cannot_transition_to_validated_or_report_ready():
    """Verifies simulated findings are blocked from VALIDATED lifecycle and report readiness."""
    finding_sim = Finding(
        title="Simulated Storage Exposure",
        summary="Lab simulation of object storage exposure",
        affected_asset="lab.s3.amazonaws.com",
        affected_endpoint="https://lab.s3.amazonaws.com",
        vulnerability_type="cloud-misconfiguration",
        severity="HIGH",
        description="Simulated test result in local lab fixture",
        root_cause="Mock lab scenario",
        prerequisites="Lab access",
        reproduction_steps=["Step 1: Execute lab simulation", "Step 2: Observe simulated response"],
        expected_result="AccessDenied",
        observed_result="HTTP 200 with XML bucket listing",
        security_impact="Potential information disclosure",
        remediation="Restrict anonymous access",
        scope_reference="local-lab-scope",
        confidence="HIGH",
        lifecycle_state=FindingLifecycle.SIMULATED,
        provenance={"is_simulation": True},
    )

    # 1. State machine transition from SIMULATED to VALIDATED is blocked
    with pytest.raises(InvalidLifecycleTransition) as exc_info:
        finding_sim.transition_to(FindingLifecycle.VALIDATED, notes="Attempting promotion of lab result")
    assert "Cannot transition finding from 'SIMULATED' to 'VALIDATED'" in str(exc_info.value)

    # 2. Transition from OBSERVED with is_simulation=True is also blocked
    finding_obs_sim = Finding(
        title="Simulated Storage Exposure",
        summary="Lab simulation of object storage exposure",
        affected_asset="lab.s3.amazonaws.com",
        affected_endpoint="https://lab.s3.amazonaws.com",
        vulnerability_type="cloud-misconfiguration",
        severity="HIGH",
        description="Simulated test result in local lab fixture",
        root_cause="Mock lab scenario",
        prerequisites="Lab access",
        reproduction_steps=["Step 1: Execute lab simulation", "Step 2: Observe simulated response"],
        expected_result="AccessDenied",
        observed_result="HTTP 200 with XML bucket listing",
        security_impact="Potential information disclosure",
        remediation="Restrict anonymous access",
        scope_reference="local-lab-scope",
        confidence="HIGH",
        lifecycle_state=FindingLifecycle.OBSERVED,
        provenance={"is_simulation": True},
        evidence=[{"content": "data", "metadata": {"sha256": "a" * 64}}],
    )
    with pytest.raises(InvalidLifecycleTransition) as exc_info2:
        finding_obs_sim.transition_to(FindingLifecycle.VALIDATED, notes="Attempting promotion of observed lab result")
    assert "simulated or mock observations are forbidden from entering VALIDATED state" in str(exc_info2.value)

    # 3. is_report_ready fails closed
    ready, reason = finding_sim.is_report_ready()
    assert ready is False
    assert "only VALIDATED findings can be reported" in reason or "Simulated or mock observations cannot be used" in reason

    # 3. Even if forcibly constructed in VALIDATED state with is_simulation=True, report readiness fails
    finding_forced = Finding(
        title="Simulated Storage Exposure",
        summary="Lab simulation of object storage exposure",
        affected_asset="lab.s3.amazonaws.com",
        affected_endpoint="https://lab.s3.amazonaws.com",
        vulnerability_type="cloud-misconfiguration",
        severity="HIGH",
        description="Simulated test result in local lab fixture",
        root_cause="Mock lab scenario",
        prerequisites="Lab access",
        reproduction_steps=["Step 1: Execute lab simulation", "Step 2: Observe simulated response"],
        expected_result="AccessDenied",
        observed_result="HTTP 200 with XML bucket listing",
        security_impact="Potential information disclosure",
        remediation="Restrict anonymous access",
        scope_reference="local-lab-scope",
        confidence="HIGH",
        lifecycle_state=FindingLifecycle.VALIDATED,
        provenance={"is_simulation": True, "validation_notes": "Lab test notes"},
        evidence=[{
            "content": "Simulated evidence payload",
            "metadata": {"sha256": hashlib.sha256(b"Simulated evidence payload").hexdigest()},
        }],
        validation_notes="Lab test notes",
    )
    ready2, reason2 = finding_forced.is_report_ready()
    assert ready2 is False
    assert "Simulated or mock observations cannot be used for disclosure reporting" in reason2


# ------------------------------------------------------------------------------
# Test 9: Real observations via local fixtures can progress to VALIDATED
# ------------------------------------------------------------------------------
def test_real_observations_progress_to_validated_and_report_ready():
    """Verifies legitimate observed findings with cryptographic evidence progress to VALIDATED."""
    evidence_content = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Reflected <xss-marker></body></html>"
    evidence_hash = hashlib.sha256(evidence_content.encode("utf-8")).hexdigest()

    finding = Finding(
        title="Reflected Cross-Site Scripting in Search Query",
        summary="Reflected XSS observed in query parameter 'q'",
        affected_asset="authorized.example.com",
        affected_endpoint="https://authorized.example.com/search",
        vulnerability_type="reflected-xss",
        severity="MEDIUM",
        description="Unsanitized user input reflected in response body without output encoding.",
        root_cause="Direct echo into DOM without HTML entity encoding",
        prerequisites="User interaction navigating to crafted link",
        reproduction_steps=[
            "Step 1: Navigate to search endpoint with harmless arithmetic canary marker",
            "Step 2: Observe verbatim unescaped marker reflection in HTML body",
        ],
        expected_result="Marker must be entity-encoded or stripped in response body",
        observed_result="Marker is reflected verbatim and unencoded in response HTML",
        security_impact="Execution of arbitrary JavaScript in the context of victim user session",
        remediation="Contextually encode all user-supplied output in HTML responses using standard sanitization library.",
        scope_reference="scope.yaml: authorized.example.com",
        confidence="HIGH",
        lifecycle_state=FindingLifecycle.OBSERVED,
        evidence=[{
            "content": evidence_content,
            "metadata": {"sha256": evidence_hash},
        }],
    )

    finding.transition_to(
        FindingLifecycle.VALIDATED,
        notes="Differential baseline comparison confirmed verbatim reflection violating output-encoding invariant.",
    )

    assert finding.lifecycle_state == FindingLifecycle.VALIDATED

    ready, reason = finding.is_report_ready()
    assert ready is True
    assert reason == "Finding is report-ready."


# ------------------------------------------------------------------------------
# Test 10: Redirects cannot bypass scope or transport policy
# ------------------------------------------------------------------------------
def test_redirect_handler_enforces_scope_and_prevents_downgrade(authorized_scope):
    """Verifies SafeRedirectHandler rejects protocol downgrade and out-of-scope targets."""
    engine = SecurityValidationEngine(
        program_dir=".",
        scope_engine=authorized_scope,
    )

    handler = SafeRedirectHandler(
        check_scope_fn=engine.resolve_scope_ips,
        original_url="https://authorized.example.com/api",
    )

    # 1. Protocol downgrade HTTPS -> HTTP is blocked
    req_https = urllib.request.Request("https://authorized.example.com/api")
    with pytest.raises(ScopeViolationError) as exc_downgrade:
        handler.redirect_request(req_https, None, 302, "Found", {}, "http://authorized.example.com/api")
    assert "Protocol downgrade from HTTPS to HTTP forbidden" in str(exc_downgrade.value)

    # 2. Redirect to out-of-scope target is blocked
    with pytest.raises(ScopeViolationError) as exc_out_scope:
        handler.redirect_request(req_https, None, 302, "Found", {}, "https://attacker.com/evil")
    assert "OUT_OF_SCOPE" in str(exc_out_scope.value)

    # 3. Missing request context fails closed
    handler_no_ctx = SafeRedirectHandler(
        check_scope_fn=engine.resolve_scope_ips,
        original_url=None,
    )
    with pytest.raises(ScopeViolationError) as exc_no_ctx:
        handler_no_ctx.redirect_request(None, None, 302, "Found", {}, "https://authorized.example.com/api/v2")
    assert "Missing request context in redirect handler" in str(exc_no_ctx.value)

    # 4. Normal permitted redirect within scope
    req_v1 = urllib.request.Request("https://authorized.example.com/api/v1")
    req_v2 = handler.redirect_request(req_v1, None, 301, "Moved", {}, "https://authorized.example.com/api/v2")
    assert req_v2 is not None
    assert req_v2.full_url == "https://authorized.example.com/api/v2"


# ------------------------------------------------------------------------------
# Test 11: Fixture mode cannot authorize arbitrary non-fixture targets
# ------------------------------------------------------------------------------
def test_fixture_mode_cannot_authorize_arbitrary_targets(temp_dir):
    """Verifies that allow_fixture_port only permits localhost/127.0.0.1 on the designated port."""
    engine = SecurityValidationEngine(
        program_dir=temp_dir,
        scope_engine=None,
    )
    engine.allow_fixture_port(8080)

    # 1. External hostname with fixture port is NOT treated as fixture; fails closed
    with pytest.raises(ScopeViolationError) as exc_ext:
        engine.resolve_scope_ips("http://external.example.com:8080/test")
    assert "Active validation requires a valid, initialized ScopeEngine" in str(exc_ext.value)

    # 2. Private IP with fixture port is NOT treated as fixture; fails closed
    with pytest.raises(ScopeViolationError) as exc_priv:
        engine.resolve_scope_ips("http://10.0.0.1:8080/test")
    assert "Active validation requires a valid, initialized ScopeEngine" in str(exc_priv.value)

    # 3. Localhost on unapproved port fails closed
    with pytest.raises(ScopeViolationError) as exc_unapproved:
        engine.resolve_scope_ips("http://127.0.0.1:9090/test")
    assert "Active validation requires a valid, initialized ScopeEngine" in str(exc_unapproved.value)

    # 4. Localhost on approved fixture port fails closed without ScopeEngine
    with pytest.raises(ScopeViolationError) as exc_fixture_unscoped:
        engine.resolve_scope_ips("http://127.0.0.1:8080/test")
    assert "Active validation requires a valid, initialized ScopeEngine" in str(exc_fixture_unscoped.value)

    # 5. Localhost on approved fixture port succeeds when ScopeEngine is initialized
    scoped_engine = SecurityValidationEngine(
        program_dir=temp_dir,
        scope_engine=ScopeEngine({"targets": {"urls": ["http://127.0.0.1"]}}),
    )
    scoped_engine.allow_fixture_port(8080)
    assert scoped_engine.resolve_scope_ips("http://127.0.0.1:8080/test") == ["127.0.0.1"]


# ------------------------------------------------------------------------------
# Test 12: Cloud and business-logic engines enforce scope bounds
# ------------------------------------------------------------------------------
def test_cloud_and_business_logic_enforce_scope_bounds(temp_dir, authorized_scope):
    """Verifies CloudSecurityEngine and BusinessLogicEngine reject out-of-scope targets."""
    # 1. CloudSecurityEngine with out-of-scope asset
    cloud_engine = CloudSecurityEngine(
        program_dir=temp_dir,
        scope_engine=authorized_scope,
        request_hook=lambda req: ControlledResponse(200, body_text="OK"),
    )
    hyp_oos = CloudExposureHypothesis(
        id="hyp-oos-1",
        asset="unauthorized-target.s3.amazonaws.com",
        provider=CloudProvider.AWS,
        service=CloudServiceType.OBJECT_STORAGE,
        hypothesis_type=CloudHypothesisType.PUBLIC_OBJECT_READ,
        confidence=0.8,
        severity_hint="HIGH",
        rationale="Out of scope cloud probe",
        endpoint="https://unauthorized-target.s3.amazonaws.com/data",
    )
    res = cloud_engine.validate_hypotheses([hyp_oos])
    assert len(res) == 1
    assert res[0][1] == HypothesisValidationStatus.REJECTED
    assert "OUT_OF_SCOPE" in res[0][3]

    # 2. BusinessLogicEngine with out-of-scope target
    bl_engine = BusinessLogicEngine(
        program_dir=temp_dir,
        scope_engine=authorized_scope,
        send_request_hook=lambda req: ControlledResponse(200, body_text="OK"),
        auto_approve=True,
    )
    wf_oos = Workflow(
        workflow_id="wf-oos",
        program="test",
        application="unauthorized.org",
        name="Out of scope workflow",
        description="Testing out of scope target",
        steps=[
            WorkflowStep("step-1", "Step 1", "https://unauthorized.org/checkout", "POST", is_terminal=True),
        ],
    )
    bl_engine.state_mgr.save_workflow(wf_oos)
    hyp_bl_oos = WorkflowHypothesis(
        hypothesis_id="hyp-bl-oos-1",
        workflow_id=wf_oos.workflow_id,
        category=BusinessLogicCategory.NEGATIVE_QUANTITY,
        title="Negative quantity on unauthorized target",
        description="Out of scope test",
        target_step_id="step-1",
        target_actor="USER",
        test_strategy="Tamper quantity",
        priority=90,
    )
    tc = bl_engine.execute_hypothesis(hyp_bl_oos)
    assert tc is None
    assert hyp_bl_oos.lifecycle == FindingLifecycle.REJECTED


# ------------------------------------------------------------------------------
# Test 13: Simulation provenance survives serialization and persistence
# ------------------------------------------------------------------------------
def test_simulation_provenance_survives_persistence_and_deduplication(temp_dir):
    """Verifies that simulation provenance is preserved through to_dict, from_dict, and state storage."""
    from framework.state.manager import StateManager

    state_mgr = StateManager(temp_dir)

    finding_data = {
        "finding_id": "FIND-SIM-001",
        "title": "Simulated Misconfiguration Finding",
        "summary": "Simulated finding in lab environment",
        "affected_asset": "lab.internal",
        "affected_endpoint": "https://lab.internal/api",
        "vulnerability_type": "cloud-misconfiguration",
        "severity": "HIGH",
        "confidence": "HIGH",
        "lifecycle_state": "SIMULATED",
        "description": "Simulation finding",
        "root_cause": "Lab simulation",
        "prerequisites": "Lab environment",
        "reproduction_steps": ["Step 1: Run lab scenario", "Step 2: Observe simulated response"],
        "expected_result": "Secure",
        "observed_result": "Simulated vulnerability",
        "security_impact": "Simulated impact",
        "remediation": "Fix misconfiguration",
        "scope_reference": "scope.yaml: lab.internal",
        "provenance": {"is_simulation": True, "engine_source": "cloud-security"},
        "evidence": [{"content": "Simulated payload", "metadata": {"sha256": "0" * 64}}],
    }

    # Deserialization preserves SIMULATED and provenance
    deserialized = Finding.from_dict(finding_data)
    assert deserialized.lifecycle_state == FindingLifecycle.SIMULATED
    assert deserialized.provenance.get("is_simulation") is True
    assert deserialized.is_report_ready()[0] is False

    # Persistence preserves SIMULATED state and provenance in findings.json
    recorded_obj, is_dup, dup_id = state_mgr.record_finding(deserialized, engine_source="cloud-security")
    assert recorded_obj.lifecycle_state == FindingLifecycle.SIMULATED
    assert not is_dup

    # Reload from disk
    loaded_findings = state_mgr.get_findings()
    matching = next((f for f in loaded_findings if f.finding_id == "FIND-SIM-001"), None)
    assert matching is not None
    assert matching.lifecycle_state == FindingLifecycle.SIMULATED
    assert matching.provenance.get("is_simulation") is True
    assert matching.is_report_ready()[0] is False


# ------------------------------------------------------------------------------
# Test 14: Direct lifecycle transition forgery is blocked
# ------------------------------------------------------------------------------
def test_direct_lifecycle_transition_forgery_is_blocked():
    """Verifies that validate_transition and Finding.transition_to prevent forging VALIDATED state."""
    from framework.findings.lifecycle import validate_transition

    # SIMULATED cannot transition to VALIDATED, CANDIDATE, TESTING, or OBSERVED
    forbidden_targets = [
        FindingLifecycle.VALIDATED,
        FindingLifecycle.CANDIDATE,
        FindingLifecycle.TESTING,
        FindingLifecycle.OBSERVED,
    ]
    for target in forbidden_targets:
        with pytest.raises(InvalidLifecycleTransition):
            validate_transition(FindingLifecycle.SIMULATED, target)

    # Allowed transitions from SIMULATED
    assert validate_transition(FindingLifecycle.SIMULATED, FindingLifecycle.REJECTED) is True
    assert validate_transition(FindingLifecycle.SIMULATED, FindingLifecycle.INFORMATIONAL) is True


# ------------------------------------------------------------------------------
# Test 15: Redirect to private IP or metadata destination fails closed
# ------------------------------------------------------------------------------
def test_redirect_to_private_ip_or_metadata_fails_closed(authorized_scope):
    """Verifies SafeRedirectHandler rejects redirects to SSRF-prohibited and metadata destinations."""
    engine = SecurityValidationEngine(
        program_dir=".",
        scope_engine=authorized_scope,
    )
    handler = SafeRedirectHandler(
        check_scope_fn=engine.resolve_scope_ips,
        original_url="https://authorized.example.com/api",
    )
    req = urllib.request.Request("https://authorized.example.com/api")

    # 1. Redirect to 169.254.169.254 (Cloud metadata)
    with pytest.raises(ScopeViolationError) as exc_meta:
        handler.redirect_request(req, None, 302, "Found", {}, "https://169.254.169.254/latest/meta-data/")
    assert "forbidden" in str(exc_meta.value).lower() or "prohibited" in str(exc_meta.value).lower()

    # 2. Redirect to private IPv4 space (same scheme, private IP)
    with pytest.raises(ScopeViolationError) as exc_priv:
        handler.redirect_request(req, None, 302, "Found", {}, "https://10.0.0.1/admin")
    assert "prohibited" in str(exc_priv.value).lower() or "out_of_scope" in str(exc_priv.value).lower()

