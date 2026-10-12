"""
Business Logic & Workflow Intelligence Engine (Phase 12).

Discovers workflows, prioritizes test cases, performs safe bounded replay and
parameter tampering, evaluates formal invariants, and persists deduplicated findings.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import uuid

from framework.business_logic.approval import WorkflowApprovalGate
from framework.business_logic.invariants import BusinessLogicInvariantEngine
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
    WorkflowStep,
    WorkflowTestCase,
    WorkflowTransition,
)
from framework.business_logic.replay import WorkflowReplayEngine, WorkflowStateMachine
from framework.business_logic.state import WorkflowStateManager
from framework.findings.lifecycle import FindingLifecycle
from framework.scope.engine import ScopeEngine
from framework.validation.engine import ScopeViolationError
from framework.validation.policy import SecurityTestPolicy
from framework.validation.request import ControlledRequest, ControlledResponse


class BusinessLogicEngine:
    """Primary orchestrator for Business Logic & Workflow Intelligence."""

    def __init__(
        self,
        program_dir: str,
        scope_engine: Optional[ScopeEngine] = None,
        policy: Optional[SecurityTestPolicy] = None,
        send_request_hook: Optional[Callable[[ControlledRequest], ControlledResponse]] = None,
        auto_approve: bool = False,
        is_simulation: bool = False,
    ):
        self.program_dir = os.path.abspath(program_dir)
        self.program_name = os.path.basename(self.program_dir)
        self.state_mgr = WorkflowStateManager(self.program_dir)
        self.policy = policy or SecurityTestPolicy()
        self.send_request = send_request_hook
        self.replay_engine = WorkflowReplayEngine(self.send_request)
        self.approval_gate = WorkflowApprovalGate(auto_approve=auto_approve)
        self.scope_engine = scope_engine
        self.is_simulation = is_simulation

    def discover_workflows(self) -> List[Workflow]:
        """
        Infers application workflows from webapps.json, api.json, and existing intelligence.
        Returns empty list if insufficient state exists; never fabricates mock endpoints.
        """
        workflows: List[Workflow] = []
        state_dir = os.path.join(self.program_dir, "state")

        # 1. Inspect api.json and webapps.json
        endpoints: List[str] = []
        api_file = os.path.join(state_dir, "api.json")
        if os.path.isfile(api_file):
            try:
                with open(api_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for ep in data.get("endpoints", []):
                        url = ep.get("url") or ep.get("path")
                        if url:
                            endpoints.append(url)
            except Exception:
                pass

        webapps_file = os.path.join(state_dir, "webapps.json")
        if os.path.isfile(webapps_file):
            try:
                with open(webapps_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for app in data.get("webapps", []):
                        for ep in app.get("endpoints", []):
                            url = ep.get("url") or ep.get("path")
                            if url:
                                endpoints.append(url)
            except Exception:
                pass

        if not endpoints:
            return []

        # Group candidate endpoints by host
        endpoints_by_host: Dict[str, List[str]] = {}
        for ep in endpoints:
            parsed = urlparse(ep if "://" in ep else f"http://{ep}")
            host = parsed.netloc or "target.local"
            endpoints_by_host.setdefault(host, []).append(ep)

        for host, host_eps in endpoints_by_host.items():
            cart_ep = next((e for e in host_eps if any(k in e.lower() for k in ["cart", "basket", "item"])), None)
            auth_ep = next((e for e in host_eps if any(k in e.lower() for k in ["checkout", "authorize", "payment", "order"])), None)
            capture_ep = next((e for e in host_eps if any(k in e.lower() for k in ["capture", "finalize", "confirm", "complete"])), None)

            if cart_ep or auth_ep or capture_ep:
                w_id = f"wf-{uuid.uuid4().hex[:8]}"
                steps = []
                trans = []
                prev_state = "INITIAL"
                if cart_ep:
                    steps.append(WorkflowStep(
                        step_id=f"step-{len(steps)+1}",
                        name="Cart Selection",
                        endpoint=cart_ep,
                        method="POST",
                        parameters=[WorkflowParameter(name="quantity", location="body", inferred_type="integer", is_security_sensitive=True)],
                    ))
                    trans.append(WorkflowTransition(f"t-{len(trans)+1}", prev_state, "CART_SELECTED", steps[-1].step_id))
                    prev_state = "CART_SELECTED"
                if auth_ep:
                    steps.append(WorkflowStep(
                        step_id=f"step-{len(steps)+1}",
                        name="Payment Authorization",
                        endpoint=auth_ep,
                        method="POST",
                    ))
                    trans.append(WorkflowTransition(f"t-{len(trans)+1}", prev_state, "AUTHORIZED", steps[-1].step_id))
                    prev_state = "AUTHORIZED"
                if capture_ep:
                    steps.append(WorkflowStep(
                        step_id=f"step-{len(steps)+1}",
                        name="Capture & Finalize",
                        endpoint=capture_ep,
                        method="POST",
                        is_terminal=True,
                    ))
                    trans.append(WorkflowTransition(f"t-{len(trans)+1}", prev_state, "COMPLETED", steps[-1].step_id))

                if len(steps) >= 2:
                    invariants = [
                        WorkflowInvariant("inv-1", "No Step Skipping", "Capture cannot be invoked without authorization", BusinessLogicCategory.STEP_SKIPPING),
                        WorkflowInvariant("inv-2", "Positive Quantity", "Item quantity must be strictly positive", BusinessLogicCategory.NEGATIVE_QUANTITY),
                    ]
                    wf = Workflow(
                        workflow_id=w_id,
                        program=self.program_name,
                        application=host,
                        name=f"Discovered Multi-Step Workflow ({host})",
                        description=f"Multi-step e-commerce/authorization flow discovered for {host}",
                        steps=steps,
                        transitions=trans,
                        invariants=invariants,
                    )
                    workflows.append(wf)
                    self.state_mgr.save_workflow(wf)

        return workflows

    def generate_hypotheses_for_workflow(self, workflow: Workflow) -> List[WorkflowHypothesis]:
        """Generates targeted business logic hypotheses for a modeled workflow."""
        hypotheses: List[WorkflowHypothesis] = []

        # 1. Step Skipping Hypothesis for terminal steps
        terminal_steps = [s for s in workflow.steps if s.is_terminal]
        for ts in terminal_steps:
            h = WorkflowHypothesis(
                hypothesis_id=f"hyp-skip-{uuid.uuid4().hex[:8]}",
                workflow_id=workflow.workflow_id,
                category=BusinessLogicCategory.STEP_SKIPPING,
                title=f"Step Skipping to {ts.name}",
                description=f"Attempting to invoke terminal step '{ts.name}' without executing mandatory preceding steps.",
                target_step_id=ts.step_id,
                test_strategy="Direct invocation of terminal endpoint omitting prerequisite session tokens.",
                priority=85,
            )
            hypotheses.append(h)
            self.state_mgr.save_hypothesis(h)

        # 2. Arithmetic / Negative quantity on parameter steps
        for step in workflow.steps:
            for p in step.parameters:
                if p.name.lower() in ("quantity", "qty", "count", "amount"):
                    h = WorkflowHypothesis(
                        hypothesis_id=f"hyp-arith-{uuid.uuid4().hex[:8]}",
                        workflow_id=workflow.workflow_id,
                        category=BusinessLogicCategory.NEGATIVE_QUANTITY,
                        title=f"Negative Quantity Manipulation on '{p.name}'",
                        description=f"Testing negative or boundary values on '{p.name}' at {step.endpoint}.",
                        target_step_id=step.step_id,
                        test_strategy="Mutating quantity to negative integer (-5) to observe cart/price inversion.",
                        priority=80,
                    )
                    hypotheses.append(h)
                    self.state_mgr.save_hypothesis(h)

        return hypotheses

    def execute_hypothesis(
        self,
        hypothesis: WorkflowHypothesis,
        dry_run: bool = False,
    ) -> Optional[WorkflowTestCase]:
        """Executes a bounded business logic hypothesis test with approval gating and scope verification."""
        wf = self.state_mgr.get_workflow(hypothesis.workflow_id)
        if not wf:
            return None

        # Approval Gate
        if not self.approval_gate.is_hypothesis_approved(hypothesis):
            return None

        if dry_run:
            return None

        target_step = next((s for s in wf.steps if s.step_id == hypothesis.target_step_id), None)
        if not target_step:
            return None

        # Scope enforcement
        if self.scope_engine is None:
            raise ScopeViolationError(
                "Active workflow testing requires a valid, initialized ScopeEngine. No scope engine configured."
            )

        if not self.scope_engine.is_in_scope(target_step.endpoint):
            hypothesis.lifecycle = FindingLifecycle.REJECTED
            self.state_mgr.save_hypothesis(hypothesis)
            return None

        # Request dispatcher enforcement
        if self.send_request is None:
            raise RuntimeError(
                "No request dispatcher configured for BusinessLogicEngine. Simulated HTTP responses are forbidden."
            )

        # Baseline execution
        base_req = ControlledRequest(url=target_step.endpoint, method=target_step.method, headers={"Content-Type": "application/json"})
        base_resp = self.send_request(base_req)

        # Mutated execution based on category
        mutated_req = ControlledRequest(url=target_step.endpoint, method=target_step.method, headers={"Content-Type": "application/json"})
        tampered_params = {}

        if hypothesis.category == BusinessLogicCategory.STEP_SKIPPING:
            # Send direct request omitting required prerequisite token
            mutated_req.body = json.dumps({"auth_token": ""})
        elif hypothesis.category == BusinessLogicCategory.NEGATIVE_QUANTITY:
            tampered_params = {"quantity": -5}
            mutated_req.body = json.dumps(tampered_params)

        test_resp = self.send_request(mutated_req)

        # Invariant evaluation
        inv_status, details, signals = BusinessLogicInvariantEngine.evaluate_invariant(
            category=hypothesis.category,
            rule_name=hypothesis.title,
            baseline_resp=base_resp,
            test_resp=test_resp,
            context={"tampered_param": tampered_params},
        )

        evidence = WorkflowEvidence(
            evidence_id=f"ev-wf-{uuid.uuid4().hex[:8]}",
            workflow_id=wf.workflow_id,
            test_case_id=f"tc-{uuid.uuid4().hex[:8]}",
            category=hypothesis.category,
            endpoint=target_step.endpoint,
            actor_id=hypothesis.target_actor,
            baseline_status=base_resp.status_code,
            tampered_status=test_resp.status_code,
            baseline_headers=base_resp.headers,
            tampered_headers=test_resp.headers,
            match_signals=signals,
            body_snippet=test_resp.body_text,
            violated_invariant=details if inv_status == InvariantStatus.INVARIANT_VIOLATED else "",
        )
        self.state_mgr.record_evidence(evidence)

        effective_lifecycle = FindingLifecycle.SIMULATED if self.is_simulation else (FindingLifecycle.VALIDATED if inv_status == InvariantStatus.INVARIANT_VIOLATED else FindingLifecycle.OBSERVED)
        effective_confidence = WorkflowConfidence.LOW if self.is_simulation else (WorkflowConfidence.VALIDATED if inv_status == InvariantStatus.INVARIANT_VIOLATED else WorkflowConfidence.OBSERVED)

        test_case = WorkflowTestCase(
            test_case_id=evidence.test_case_id,
            hypothesis_id=hypothesis.hypothesis_id,
            workflow_id=wf.workflow_id,
            category=hypothesis.category,
            step_id=target_step.step_id,
            endpoint=target_step.endpoint,
            method=target_step.method,
            actor_id=hypothesis.target_actor,
            mutated_parameters=tampered_params,
            result="VIOLATED" if inv_status == InvariantStatus.INVARIANT_VIOLATED else "UPHELD",
            evidence=evidence,
            confidence=effective_confidence,
            priority=hypothesis.priority,
            lifecycle=effective_lifecycle,
        )
        self.state_mgr.record_test_case(test_case)

        if inv_status == InvariantStatus.INVARIANT_VIOLATED:
            hypothesis.lifecycle = effective_lifecycle
            finding = WorkflowFinding(
                finding_id=f"wf-find-{uuid.uuid4().hex[:8]}",
                workflow_id=wf.workflow_id,
                test_case_id=test_case.test_case_id,
                title=f"Business Logic Vulnerability: {hypothesis.title}",
                category=hypothesis.category,
                severity="HIGH",
                endpoint=target_step.endpoint,
                actor=hypothesis.target_actor,
                violated_invariant=details,
                description=hypothesis.description,
                remediation="Enforce server-side workflow state machine validation and strict numeric bounds checks.",
                evidence_id=evidence.evidence_id,
            )
            self.state_mgr.record_finding(finding)
        else:
            hypothesis.lifecycle = FindingLifecycle.OBSERVED

        self.state_mgr.save_hypothesis(hypothesis)
        return test_case
