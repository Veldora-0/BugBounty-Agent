"""
Deterministic Test Suite for Business Logic & External Pentesting Engines (Phase 12).

Tests:
- Workflow extraction & state machines
- Actor transitions & authorization integration
- Invariant engine evaluations across categories
- Replay engine: single, sequence, and bounded concurrent race simulations
- Approval gating & pre-test audit dossiers
- State persistence in ~/BugBounty-Workspace/.../state/workflows.json
- External pentesting engine contracts & adapters (Xalgorix, Strix)
- Engine detection, health check, job preparation, and result parsing
- Independent validator & external finding correlator
- Security hygiene: zero shell=True, os.system, eval, or exec
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import pytest

from framework.business_logic.approval import WorkflowApprovalGate
from framework.business_logic.engine import BusinessLogicEngine
from framework.business_logic.invariants import BusinessLogicInvariantEngine
from framework.business_logic.lab import LocalBusinessLogicLab
from framework.business_logic.model import (
    BusinessLogicCategory,
    InvariantStatus,
    Workflow,
    WorkflowActor,
    WorkflowActorType,
    WorkflowConfidence,
    WorkflowEvidence,
    WorkflowFinding,
    WorkflowHypothesis,
    WorkflowInvariant,
    WorkflowParameter,
    WorkflowResource,
    WorkflowState,
    WorkflowStep,
    WorkflowTestCase,
    WorkflowTransition,
)
from framework.business_logic.replay import WorkflowReplayEngine, WorkflowStateMachine
from framework.business_logic.state import WorkflowStateManager
from framework.external_engines.base import (
    ExternalEngineStatus,
    ExternalFinding,
    ExternalPentestEngine,
)
from framework.external_engines.correlator import (
    ExternalEngineSelector,
    ExternalFindingCorrelator,
    IndependentValidator,
)
from framework.external_engines.strix import StrixAdapter
from framework.external_engines.xalgorix import XalgorixAdapter
from framework.findings.lifecycle import FindingLifecycle
from framework.scope.engine import ScopeEngine
from framework.validation.request import ControlledRequest, ControlledResponse


@pytest.fixture
def temp_program_dir():
    tmp = tempfile.mkdtemp(prefix="test_bb_phase12_")
    state_dir = os.path.join(tmp, "state")
    os.makedirs(state_dir, exist_ok=True)
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def mock_lab():
    return LocalBusinessLogicLab()


# ============================================================================
# 1. Workflow Models & State Machine
# ============================================================================

def test_workflow_models_and_state_machine():
    step1 = WorkflowStep(
        step_id="step-1",
        name="Submit Order",
        endpoint="http://lab.local/api/order/submit",
        method="POST",
        parameters=[WorkflowParameter(name="price", location="body", is_security_sensitive=True)],
    )
    step2 = WorkflowStep(
        step_id="step-2",
        name="Finalize Order",
        endpoint="http://lab.local/api/workflow/finalize",
        method="POST",
        is_terminal=True,
    )
    trans = [WorkflowTransition("t-1", "INITIAL", "SUBMITTED", "step-1")]
    inv = [WorkflowInvariant("inv-1", "No Price Tampering", "Price must not be client-authoritative", BusinessLogicCategory.PRICE_MANIPULATION)]

    wf = Workflow(
        workflow_id="wf-test-01",
        program="test",
        application="lab.local",
        name="Order Workflow",
        steps=[step1, step2],
        transitions=trans,
        invariants=inv,
    )

    fp = wf.compute_fingerprint()
    assert fp is not None
    assert len(fp) == 64

    sm = WorkflowStateMachine(wf)
    assert sm.current_state == "INITIAL"
    allowed = sm.get_allowed_next_steps()
    assert len(allowed) == 1
    assert allowed[0].step_id == "step-1"

    sm.transition_to("SUBMITTED", action_summary="Order placed")
    assert sm.current_state == "SUBMITTED"
    assert len(sm.history) == 1


def test_evidence_sanitization_and_hash():
    ev = WorkflowEvidence(
        evidence_id="ev-wf-001",
        workflow_id="wf-01",
        test_case_id="tc-01",
        category=BusinessLogicCategory.STEP_SKIPPING,
        endpoint="http://lab.local/api/checkout/capture",
        actor_id="USER_A",
        baseline_status=400,
        tampered_status=200,
        baseline_headers={"Set-Cookie": "session=secret_token_123"},
        tampered_headers={"Authorization": "Bearer supersecret"},
        match_signals=["STEP_SKIPPING_PERMITTED"],
        body_snippet="Captured with token secret_xyz",
    )
    assert "secret_token_123" not in json.dumps(ev.baseline_headers)
    assert "supersecret" not in json.dumps(ev.tampered_headers)
    assert ev.integrity_hash is not None
    assert len(ev.integrity_hash) == 64


# ============================================================================
# 2. Invariant Engine Evaluation
# ============================================================================

def test_invariant_evaluations():
    base = ControlledResponse(status_code=400, body_text='{"error": "AUTH_REQUIRED"}')
    test = ControlledResponse(status_code=200, body_text='{"status": "SUCCESS"}')

    # Step skipping violation
    st, details, sigs = BusinessLogicInvariantEngine.evaluate_invariant(
        BusinessLogicCategory.STEP_SKIPPING, "Step Skipping Rule", base, test
    )
    assert st == InvariantStatus.INVARIANT_VIOLATED
    assert "STEP_SKIPPING_PERMITTED" in sigs

    # Negative quantity violation
    st_neg, _, sigs_neg = BusinessLogicInvariantEngine.evaluate_invariant(
        BusinessLogicCategory.NEGATIVE_QUANTITY, "Numeric Bounds", base, test
    )
    assert st_neg == InvariantStatus.INVARIANT_VIOLATED
    assert "ARITHMETIC_MANIPULATION_ACCEPTED" in sigs_neg

    # Replay protection upheld
    replay_blocked = ControlledResponse(status_code=400, body_text='{"error": "TOKEN_ALREADY_USED"}')
    st_rep, _, sigs_rep = BusinessLogicInvariantEngine.evaluate_invariant(
        BusinessLogicCategory.REPLAY_ACTION, "One-Time Token Rule", test, replay_blocked
    )
    assert st_rep == InvariantStatus.INVARIANT_OBSERVED
    assert "REPLAY_PREVENTED" in sigs_rep


# ============================================================================
# 3. Local Security Lab Scenarios
# ============================================================================

def test_lab_step_skipping_and_negative_quantity(mock_lab):
    # Scenario 1: Step skipping
    req_skip = ControlledRequest(url="http://lab.local/api/checkout/capture", method="POST", body='{"auth_token": ""}')
    res_skip = mock_lab.handle_request(req_skip)
    assert res_skip.status_code == 200
    assert "captured" in res_skip.body_text

    # Scenario 9: Negative quantity
    req_qty = ControlledRequest(url="http://lab.local/api/cart/update", method="POST", body='{"quantity": -5}')
    res_qty = mock_lab.handle_request(req_qty)
    assert res_qty.status_code == 200
    assert '"quantity": -5' in res_qty.body_text

    # Scenario 10: Price tampering
    req_price = ControlledRequest(url="http://lab.local/api/order/submit", method="POST", body='{"price": 1}')
    res_price = mock_lab.handle_request(req_price)
    assert res_price.status_code == 200
    assert '"price_charged": 1' in res_price.body_text


def test_lab_token_replay_and_safe_workflow(mock_lab):
    # Scenario 3: Token replay
    req1 = ControlledRequest(url="http://lab.local/api/tokens/redeem", method="POST", body='{"token": "tok-single"}')
    res1 = mock_lab.handle_request(req1)
    assert res1.status_code == 200

    # Second replay must be rejected
    res2 = mock_lab.handle_request(req1)
    assert res2.status_code == 400
    assert "TOKEN_ALREADY_USED" in res2.body_text

    # Flawed token endpoint allows replay
    req_flaw = ControlledRequest(url="http://lab.local/api/tokens/redeem-flawed", method="POST", body='{"token": "tok-reusable"}')
    assert mock_lab.handle_request(req_flaw).status_code == 200
    assert mock_lab.handle_request(req_flaw).status_code == 200


def test_lab_race_condition_simulation(mock_lab):
    req_race = ControlledRequest(url="http://lab.local/api/coupon/apply", method="POST")
    replay = WorkflowReplayEngine(mock_lab.handle_request, max_concurrency=4)
    responses = replay.replay_concurrent(req_race, concurrency=4)
    assert len(responses) == 4
    for r in responses:
        assert r.status_code == 200
    assert mock_lab.coupon_redemptions == 4


# ============================================================================
# 4. Engine Pipeline, Approval Gate & State
# ============================================================================

def test_engine_pipeline_and_state_persistence(temp_program_dir, mock_lab):
    engine = BusinessLogicEngine(
        program_dir=temp_program_dir,
        send_request_hook=mock_lab.handle_request,
        auto_approve=False,
    )

    wfs = engine.discover_workflows()
    assert len(wfs) >= 1
    wf = wfs[0]

    hyps = engine.generate_hypotheses_for_workflow(wf)
    assert len(hyps) >= 1
    h = hyps[0]

    # Blocked without operator approval
    assert engine.execute_hypothesis(h) is None

    # Approved and executed
    engine.approval_gate.approve_hypothesis(h.hypothesis_id)
    tc = engine.execute_hypothesis(h)
    assert tc is not None
    assert tc.result in ("VIOLATED", "UPHELD")

    # State reloaded
    reloaded_wf = engine.state_mgr.get_workflow(wf.workflow_id)
    assert reloaded_wf is not None
    findings = engine.state_mgr.list_findings()
    assert len(findings) >= 1


# ============================================================================
# 5. External Pentest Engine Integration
# ============================================================================

def test_external_engine_adapters_and_detection():
    x_adapter = XalgorixAdapter()
    x_det = x_adapter.detect()
    assert x_det["name"] == "xalgorix"
    assert x_det["pinned_version"] == "v0.4.0-stable"
    assert "installed" in x_det

    s_adapter = StrixAdapter()
    s_det = s_adapter.detect()
    assert s_det["name"] == "strix"
    assert s_det["pinned_version"] == "v0.3.2-stable"
    assert "installed" in s_det

    selector = ExternalEngineSelector()
    all_engines = selector.list_engines()
    assert len(all_engines) == 2


def test_external_job_preparation_and_scope_filtering(temp_program_dir):
    scope = ScopeEngine({
        "program": {"name": "test"},
        "targets": {
            "domains": ["lab.local"],
            "urls": ["http://lab.local/api"],
        },
    })
    x_adapter = XalgorixAdapter()
    targets = ["http://lab.local/api", "https://out-of-scope.example/admin"]
    job = x_adapter.prepare_job(temp_program_dir, targets, scope, budget_requests=50)

    # Out-of-scope target must be excluded
    assert len(job["scoped_targets"]) == 1
    assert "out-of-scope.example" not in job["scoped_targets"][0]
    assert job["max_requests"] == 50


def test_external_finding_parsing_and_correlation(temp_program_dir):
    report_file = os.path.join(temp_program_dir, "xalgorix_findings.json")
    mock_data = [
        {
            "run_id": "run-x1",
            "vulnerability_class": "step_skipping",
            "title": "Bypassed checkout step",
            "endpoint": "http://lab.local/api/checkout/capture",
            "severity": "HIGH",
            "confidence": "VALIDATED",
        }
    ]
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(mock_data, f)

    x_adapter = XalgorixAdapter()
    ext_findings = x_adapter.parse_results(report_file)
    assert len(ext_findings) == 1
    assert ext_findings[0].engine == "xalgorix"

    native_finding = WorkflowFinding(
        finding_id="wf-find-101",
        workflow_id="wf-1",
        test_case_id="tc-1",
        title="Business Logic Vulnerability: Step Skipping",
        category=BusinessLogicCategory.STEP_SKIPPING,
        severity="HIGH",
        endpoint="http://lab.local/api/checkout/capture",
        actor="USER_A",
        violated_invariant="Step skipped",
        description="Capture permitted",
        remediation="Enforce sequence",
        evidence_id="ev-101",
    )

    correlated = ExternalFindingCorrelator.correlate([native_finding], ext_findings)
    assert len(correlated) == 1
    assert "external_xalgorix" in correlated[0]["sources"]
    assert len(correlated[0]["external_confirmations"]) == 1


def test_independent_validator_reproduction():
    mock_ext_finding = ExternalFinding(
        finding_id="ext-f-1",
        engine="xalgorix",
        engine_version="v0.4.0-stable",
        run_id="run-1",
        target="http://lab.local",
        vulnerability_class="step_skipping",
        title="Unverified Step Bypass",
        severity="HIGH",
        confidence="VALIDATED",
        endpoint="http://lab.local/reproduce",
    )

    def success_hook(req):
        return ControlledResponse(status_code=200, body_text='{"reproduced": true}')

    def fail_hook(req):
        return ControlledResponse(status_code=403, body_text='{"error": "FORBIDDEN"}')

    validator_pass = IndependentValidator(success_hook)
    life_pass, note_pass = validator_pass.independently_validate(mock_ext_finding)
    assert life_pass == FindingLifecycle.VALIDATED
    assert "Independently reproduced" in note_pass

    validator_fail = IndependentValidator(fail_hook)
    life_fail, note_fail = validator_fail.independently_validate(mock_ext_finding)
    assert life_fail == FindingLifecycle.REJECTED
    assert "Reproduction failed" in note_fail


# ============================================================================
# 6. Security Hygiene Invariants
# ============================================================================

def test_security_hygiene_no_shell_exec():
    """Verify strictly zero shell=True, os.system, eval, or exec in Phase 12 frameworks."""
    dirs_to_check = [
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "framework", "business_logic")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "framework", "external_engines")),
    ]
    for d in dirs_to_check:
        for root, _, files in os.walk(d):
            for fname in files:
                if fname.endswith(".py"):
                    fpath = os.path.join(root, fname)
                    with open(fpath, "r", encoding="utf-8") as f:
                        content = f.read()
                        assert "shell=True" not in content
                        assert "os.system(" not in content
                        assert "eval(" not in content
                        assert "exec(" not in content
