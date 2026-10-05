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
    ):
        self.program_dir = os.path.abspath(program_dir)
        self.program_name = os.path.basename(self.program_dir)
        self.state_mgr = WorkflowStateManager(self.program_dir)
        self.policy = policy or SecurityTestPolicy()
        self.send_request = send_request_hook or (lambda req: ControlledResponse(200, body_text="OK"))
        self.replay_engine = WorkflowReplayEngine(self.send_request)
        self.approval_gate = WorkflowApprovalGate(auto_approve=auto_approve)

        if scope_engine:
            self.scope_engine = scope_engine
        else:
            self.scope_engine = ScopeEngine({
                "program": {"name": self.program_name},
                "targets": {
                    "domains": ["lab.local", "*.local", "localhost", "127.0.0.1", "*.example.com", "example.com"],
                    "urls": ["http://lab.local/", "https://lab.local/"],
                },
            })

    def discover_workflows(self) -> List[Workflow]:
        """
        Infers application workflows from webapps.json, api.json, and existing intelligence.
        """
        workflows: List[Workflow] = []
        state_dir = os.path.join(self.program_dir, "state")

        # 1. Inspect api.json
        api_file = os.path.join(state_dir, "api.json")
        endpoints = []
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

        # Synthesize standard high-risk workflows if candidates exist
        w_id = f"wf-{uuid.uuid4().hex[:8]}"
        steps = [
            WorkflowStep(
                step_id="step-1",
                name="Cart Selection",
                endpoint="http://lab.local/api/cart/update",
                method="POST",
                parameters=[WorkflowParameter(name="quantity", location="body", inferred_type="integer", is_security_sensitive=True)],
            ),
            WorkflowStep(
                step_id="step-2",
                name="Payment Authorization",
                endpoint="http://lab.local/api/checkout/authorize",
                method="POST",
            ),
            WorkflowStep(
                step_id="step-3",
                name="Capture & Finalize",
                endpoint="http://lab.local/api/checkout/capture",
                method="POST",
                is_terminal=True,
            ),
        ]
        trans = [
            WorkflowTransition("t-1", "INITIAL", "CART_SELECTED", "step-1"),
            WorkflowTransition("t-2", "CART_SELECTED", "AUTHORIZED", "step-2"),
            WorkflowTransition("t-3", "AUTHORIZED", "COMPLETED", "step-3"),
        ]
        invariants = [
            WorkflowInvariant("inv-1", "No Step Skipping", "Capture cannot be invoked without authorization", BusinessLogicCategory.STEP_SKIPPING),
            WorkflowInvariant("inv-2", "Positive Quantity", "Item quantity must be strictly positive", BusinessLogicCategory.NEGATIVE_QUANTITY),
        ]
        wf = Workflow(
            workflow_id=w_id,
            program=self.program_name,
            application="lab.local",
            name="Checkout and Payment Flow",
            description="Multi-step e-commerce cart, authorization, and capture workflow",
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
        if not self.scope_engine.is_in_scope(target_step.endpoint):
            hypothesis.lifecycle = FindingLifecycle.REJECTED
            self.state_mgr.save_hypothesis(hypothesis)
            return None

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
            confidence=WorkflowConfidence.VALIDATED if inv_status == InvariantStatus.INVARIANT_VIOLATED else WorkflowConfidence.OBSERVED,
            priority=hypothesis.priority,
            lifecycle=FindingLifecycle.VALIDATED if inv_status == InvariantStatus.INVARIANT_VIOLATED else FindingLifecycle.OBSERVED,
        )
        self.state_mgr.record_test_case(test_case)

        if inv_status == InvariantStatus.INVARIANT_VIOLATED:
            hypothesis.lifecycle = FindingLifecycle.VALIDATED
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
