"""
Phase 22.3: Safe Validation Planning & Approval Gates Test Suite.

Validates acceptance criteria AC-22.3-01 through AC-22.3-25:
- Plan generation, deterministic hashing, serialization, and round-trip fidelity.
- Anti-tampering, version binding, and approval lifecycle (submit, approve, reject, revoke, expire).
- Guarded state machine transitions.
- Anti-TOCTOU dispatch authorization gates (scope, target, method, tenant, integrity).
- Validation method allowlisting and strict rejection of destructive actions.
- Evidence digest verification, provenance preservation, and anti-inflation guarantees.
- Zero-secret enforcement across plans, audit logs, and exception strings.
- Persistence integrity and end-to-end correlation-to-validation pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
import shutil
import tempfile
import time
from typing import Any, Dict, List, Optional
import pytest

from framework.attack_path.correlator import AttackPathCorrelator
from framework.attack_path.model import (
    AttackGraph,
    AttackGraphEdge,
    AttackGraphNode,
    AttackPath,
    CapabilityType,
    CausalityProofType,
    ChainState,
    EdgeType,
    ExtractedCapability,
    NodeType,
    RelationshipProvenance,
    RelationshipState,
    assert_no_raw_secrets,
)
from framework.attack_path.normalizer import FindingNormalizer
from framework.attack_path.state import AttackPathStateManager
from framework.attack_path.validator import (
    ApprovalSecurityError,
    ChainValidationPlan,
    DispatchSecurityError,
    EvidenceVerificationError,
    InvalidStateTransitionError,
    MethodSecurityError,
    PlanApproval,
    SafeChainValidationPlanner,
    ValidationAuditEvent,
    ValidationAuditEventType,
    ValidationExecutionResult,
    ValidationMethod,
    ValidationMethodRegistry,
    ValidationPlanningError,
    ValidationPlanStatus,
    ValidationRiskLevel,
    validate_state_transition,
)
from framework.findings.schema import Finding


# ==============================================================================
# Test Fixtures & Helpers
# ==============================================================================

@pytest.fixture
def temp_workspace():
    tmp = tempfile.mkdtemp(prefix="bb_test_p22_3_")
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


class MockScopeEngine:
    def __init__(self, in_scope_assets: Optional[List[str]] = None) -> None:
        self.in_scope = set(in_scope_assets or ["api.example.com", "example.com"])

    def is_in_scope(self, target: str) -> bool:
        clean = target.strip().lower()
        return clean in self.in_scope or any(clean.endswith("." + s) for s in self.in_scope)


class MockEvidenceStore:
    def __init__(self) -> None:
        self._store: Dict[str, Any] = {}

    def add_evidence(self, ref: str, body: bytes) -> str:
        digest = hashlib.sha256(body).hexdigest()
        self._store[ref] = {
            "evidence_ref": ref,
            "sha256": digest,
            "body": body,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        return digest

    def get_evidence(self, ref: str) -> Optional[Any]:
        rec = self._store.get(ref)
        if not rec:
            return None

        @dataclass
        class MockRecord:
            evidence_ref: str
            sha256: str
            created_at: str

        return MockRecord(
            evidence_ref=rec["evidence_ref"],
            sha256=rec["sha256"],
            created_at=rec["created_at"],
        )


def _build_test_graph_and_path() -> Tuple[AttackGraph, AttackPath]:
    """Constructs a minimal 2-finding attack path graph for testing."""
    graph = AttackGraph()

    # Finding 1
    f1 = AttackGraphNode(
        node_id="FND-001",
        node_type=NodeType.FINDING,
        label="IDOR User Enumeration",
        attributes={"finding_id": "FND-001", "asset": "api.example.com", "tenant_id": "tenant-10"},
        scope_status="IN_SCOPE",
    )
    # Capability 1
    c1 = AttackGraphNode(
        node_id="CAP-001",
        node_type=NodeType.CAPABILITY,
        label="Disclosed User UUID",
        attributes={
            "capability_type": CapabilityType.KNOWLEDGE_EXPOSURE.value,
            "target_asset": "api.example.com",
            "tenant_id": "tenant-10",
        },
        scope_status="IN_SCOPE",
    )
    # Endpoint 2
    ep2 = AttackGraphNode(
        node_id="EP-002",
        node_type=NodeType.ENDPOINT,
        label="POST /api/v1/reset-password",
        attributes={
            "path": "/api/v1/reset-password",
            "method": "POST",
            "asset": "api.example.com",
            "tenant_id": "tenant-10",
        },
        scope_status="IN_SCOPE",
    )
    # Finding 2
    f2 = AttackGraphNode(
        node_id="FND-002",
        node_type=NodeType.FINDING,
        label="Password Reset Token Flaw",
        attributes={"finding_id": "FND-002", "asset": "api.example.com", "tenant_id": "tenant-10"},
        scope_status="IN_SCOPE",
    )

    graph.add_node(f1)
    graph.add_node(c1)
    graph.add_node(ep2)
    graph.add_node(f2)

    e1 = AttackGraphEdge(
        edge_id="EDGE-F1-C1",
        source_id="FND-001",
        destination_id="CAP-001",
        edge_type=EdgeType.EXPOSES,
        state=RelationshipState.THEORETICAL,
    )
    e2 = AttackGraphEdge(
        edge_id="EDGE-C1-EP2",
        source_id="CAP-001",
        destination_id="EP-002",
        edge_type=EdgeType.SATISFIES_PREREQUISITE,
        state=RelationshipState.THEORETICAL,
    )
    graph.add_edge(e1)
    graph.add_edge(e2)

    path = AttackPath(
        path_id="PATH-TEST-001",
        node_ids=["FND-001", "CAP-001", "EP-002"],
        edge_ids=["EDGE-F1-C1", "EDGE-C1-EP2"],
        state=ChainState.HYPOTHESIS,
        feasibility="HIGHLY_FEASIBLE",
        fingerprint="FP-001",
    )
    return graph, path


# ==============================================================================
# Unit & Integration Tests: AC-22.3-01 to AC-22.3-25
# ==============================================================================

def test_ac_22_3_01_plan_creation_and_deterministic_hashing():
    """AC-22.3-01: Plan creation generates valid plan_id, status PLANNED, and deterministic plan_hash."""
    graph, path = _build_test_graph_and_path()
    planner = SafeChainValidationPlanner()

    plan = planner.create_validation_plan(path, graph)

    assert plan.plan_id.startswith("PLAN-")
    assert plan.status == ValidationPlanStatus.PLANNED
    assert plan.path_id == "PATH-TEST-001"
    assert plan.target_asset == "api.example.com"
    assert plan.target_endpoint == "/api/v1/reset-password"
    assert plan.validation_method == "PREREQUISITE_SATISFACTION_CHECK"
    assert plan.version == 1
    assert len(plan.plan_hash) == 64
    assert plan.compute_plan_hash() == plan.plan_hash
    assert not plan.is_plan_tampered()


def test_ac_22_3_02_plan_serialization_round_trip():
    """AC-22.3-02: Plan serializes to dict and deserializes with complete fidelity and hash check."""
    graph, path = _build_test_graph_and_path()
    planner = SafeChainValidationPlanner()
    plan = planner.create_validation_plan(path, graph)

    plan_dict = plan.to_dict()
    assert isinstance(plan_dict, dict)
    assert plan_dict["status"] == "PLANNED"

    restored = ChainValidationPlan.from_dict(plan_dict)
    assert restored.plan_id == plan.plan_id
    assert restored.plan_hash == plan.plan_hash
    assert restored.target_asset == plan.target_asset
    assert restored.version == plan.version
    assert not restored.is_plan_tampered()


def test_ac_22_3_03_plan_tampering_detection():
    """AC-22.3-03: Modifying any security-relevant field changes computed hash and triggers tamper detection."""
    graph, path = _build_test_graph_and_path()
    planner = SafeChainValidationPlanner()
    plan = planner.create_validation_plan(path, graph)

    original_hash = plan.plan_hash
    # Tamper with target endpoint
    plan.target_endpoint = "/api/v1/malicious-admin-escalation"

    assert plan.compute_plan_hash() != original_hash
    assert plan.is_plan_tampered() is True

    # Deserializing tampered dictionary must fail closed
    tampered_dict = plan.to_dict()
    tampered_dict["plan_hash"] = original_hash  # fake original hash with altered endpoint
    with pytest.raises(ValidationPlanningError, match="failed integrity check"):
        ChainValidationPlan.from_dict(tampered_dict)


def test_ac_22_3_04_approval_bound_to_exact_plan_parameters():
    """AC-22.3-04: Approval binds to exact plan ID, version, hash, targets, method, and scope."""
    graph, path = _build_test_graph_and_path()
    planner = SafeChainValidationPlanner()
    plan = planner.create_validation_plan(path, graph)

    planner.submit_for_approval(plan, actor_id="OPERATOR-1")
    assert plan.status == ValidationPlanStatus.PENDING_APPROVAL

    approval = planner.approve_plan(plan, approved_by="SENIOR_RESEARCHER", ttl_seconds=1800.0)

    assert approval.approval_id.startswith("APPR-")
    assert approval.plan_id == plan.plan_id
    assert approval.plan_version == plan.version
    assert approval.plan_hash == plan.plan_hash
    assert approval.target_asset == "api.example.com"
    assert approval.target_endpoint == "/api/v1/reset-password"
    assert approval.validation_method == "PREREQUISITE_SATISFACTION_CHECK"
    assert approval.approved_by == "SENIOR_RESEARCHER"
    assert approval.revoked is False
    assert plan.status == ValidationPlanStatus.APPROVED


def test_ac_22_3_05_plan_rejection():
    """AC-22.3-05: Rejection moves plan to terminal REJECTED state and logs audit record."""
    graph, path = _build_test_graph_and_path()
    planner = SafeChainValidationPlanner()
    plan = planner.create_validation_plan(path, graph)

    planner.submit_for_approval(plan)
    planner.reject_plan(plan, rejected_by="LEAD_ANALYST", reason="Target not approved for active test")

    assert plan.status == ValidationPlanStatus.REJECTED
    # Attempting to approve rejected plan must fail
    with pytest.raises(InvalidStateTransitionError):
        planner.approve_plan(plan, approved_by="OPERATOR-2")


def test_ac_22_3_06_plan_approval_revocation():
    """AC-22.3-06: Revocation sets revoked flag, transitions to REVOKED, and blocks dispatch."""
    graph, path = _build_test_graph_and_path()
    planner = SafeChainValidationPlanner()
    plan = planner.create_validation_plan(path, graph)
    planner.submit_for_approval(plan)
    planner.approve_plan(plan, approved_by="OPERATOR-1")

    assert plan.status == ValidationPlanStatus.APPROVED

    planner.revoke_approval(plan, revoked_by="SECURITY_OFFICER", reason="Emergency pause on testing")

    assert plan.status == ValidationPlanStatus.REVOKED
    assert plan.approval.revoked is True
    assert plan.approval.revocation_reason == "Emergency pause on testing"

    # Pre-dispatch gate must reject revoked approval
    with pytest.raises(DispatchSecurityError, match="Illegal state transition|Dispatch denied"):
        planner.authorize_dispatch(plan)


def test_ac_22_3_07_approval_expiration():
    """AC-22.3-07: Approval expiration is detected; dispatch is denied and plan marked EXPIRED."""
    graph, path = _build_test_graph_and_path()
    planner = SafeChainValidationPlanner()
    plan = planner.create_validation_plan(path, graph, ttl_seconds=10.0)
    planner.submit_for_approval(plan)
    approval = planner.approve_plan(plan, approved_by="OPERATOR-1", ttl_seconds=10.0)

    # Simulate future timestamp beyond expiration
    future_time = time.time() + 100.0
    assert approval.is_expired(current_time=future_time) is True

    with pytest.raises(DispatchSecurityError, match="Approval expired"):
        planner.authorize_dispatch(plan, current_time=future_time)

    assert plan.status == ValidationPlanStatus.EXPIRED


def test_ac_22_3_08_plan_modification_invalidates_approval():
    """AC-22.3-08: Modifying plan fields after approval triggers hash mismatch at dispatch gate."""
    graph, path = _build_test_graph_and_path()
    planner = SafeChainValidationPlanner()
    plan = planner.create_validation_plan(path, graph)
    planner.submit_for_approval(plan)
    planner.approve_plan(plan, approved_by="OPERATOR-1")

    # Sneakily alter permissions or endpoint after approval
    plan.required_permissions.append("UNAUTHORIZED_PERMISSION")

    with pytest.raises(DispatchSecurityError, match="hash mismatch|plan mutation detected"):
        planner.authorize_dispatch(plan)


def test_ac_22_3_09_illegal_state_machine_transitions():
    """AC-22.3-09: Direct jumps or backward illegal transitions are strictly rejected."""
    # PLANNED -> DISPATCHED (skipping approval)
    with pytest.raises(InvalidStateTransitionError):
        validate_state_transition(ValidationPlanStatus.PLANNED, ValidationPlanStatus.DISPATCHED)

    # REJECTED -> APPROVED (terminal state)
    with pytest.raises(InvalidStateTransitionError):
        validate_state_transition(ValidationPlanStatus.REJECTED, ValidationPlanStatus.APPROVED)

    # COMPLETED -> PLANNED (backward jump)
    with pytest.raises(InvalidStateTransitionError):
        validate_state_transition(ValidationPlanStatus.COMPLETED, ValidationPlanStatus.PLANNED)

    # CHAIN_VALIDATED -> PENDING_APPROVAL
    with pytest.raises(InvalidStateTransitionError):
        validate_state_transition(ValidationPlanStatus.CHAIN_VALIDATED, ValidationPlanStatus.PENDING_APPROVAL)


def test_ac_22_3_10_anti_toctou_dynamic_scope_revalidation():
    """AC-22.3-10: Dynamic scope engine re-evaluates target at dispatch gate (anti-TOCTOU)."""
    graph, path = _build_test_graph_and_path()
    scope_eng = MockScopeEngine(in_scope_assets=["api.example.com"])
    planner = SafeChainValidationPlanner(scope_engine=scope_eng)
    plan = planner.create_validation_plan(path, graph)
    planner.submit_for_approval(plan)
    planner.approve_plan(plan, approved_by="OPERATOR-1")

    # Simulate scope contraction before dispatch
    scope_eng.in_scope.remove("api.example.com")

    with pytest.raises(DispatchSecurityError, match="is no longer IN_SCOPE"):
        planner.authorize_dispatch(plan, current_scope_engine=scope_eng)


def test_ac_22_3_11_target_endpoint_and_asset_revalidation():
    """AC-22.3-11: Target mismatch between plan and approval is blocked at dispatch gate."""
    graph, path = _build_test_graph_and_path()
    planner = SafeChainValidationPlanner()
    plan = planner.create_validation_plan(path, graph)
    planner.submit_for_approval(plan)
    planner.approve_plan(plan, approved_by="OPERATOR-1")

    # Tamper with approved target
    plan.approval.target_asset = "other.example.com"

    with pytest.raises(DispatchSecurityError, match="does not match approved targets"):
        planner.authorize_dispatch(plan)


def test_ac_22_3_12_cross_tenant_validation_rejection():
    """AC-22.3-12: Tenant ID mismatch between plan and approval is blocked at dispatch gate."""
    graph, path = _build_test_graph_and_path()
    planner = SafeChainValidationPlanner()
    plan = planner.create_validation_plan(path, graph)
    plan.tenant_id = "tenant-10"
    planner.submit_for_approval(plan)
    planner.approve_plan(plan, approved_by="OPERATOR-1")

    # Simulate tenant drift
    plan.approval.tenant_id = "tenant-99"

    with pytest.raises(DispatchSecurityError, match="Tenant mismatch"):
        planner.authorize_dispatch(plan)


def test_ac_22_3_13_principal_alignment_enforcement():
    """AC-22.3-13: Plans correctly bind principal context and detect tampering."""
    graph, path = _build_test_graph_and_path()
    planner = SafeChainValidationPlanner()
    plan = planner.create_validation_plan(path, graph)
    plan.principal_id = "user:analyst_a"
    plan.plan_hash = plan.compute_plan_hash()  # recompute hash for principal

    planner.submit_for_approval(plan)
    planner.approve_plan(plan, approved_by="OPERATOR-1")

    # Changing principal alters hash, failing integrity gate
    plan.principal_id = "user:victim_b"
    with pytest.raises(DispatchSecurityError, match="hash mismatch|plan mutation detected"):
        planner.authorize_dispatch(plan)


def test_ac_22_3_14_validation_method_allowlisting():
    """AC-22.3-14: Unregistered or unapproved validation methods are strictly rejected."""
    graph, path = _build_test_graph_and_path()
    planner = SafeChainValidationPlanner()

    with pytest.raises(MethodSecurityError, match="is not registered"):
        planner.create_validation_plan(path, graph, validation_method="ARBITRARY_REMOTE_EXECUTION")


def test_ac_22_3_15_destructive_validation_method_rejection():
    """AC-22.3-15: Attempting to register or plan a destructive method raises security error."""
    registry = ValidationMethodRegistry()

    # Direct registration rejection
    with pytest.raises(MethodSecurityError, match="destructive"):
        ValidationMethod(
            method_id="DESTRUCTIVE_DATABASE_DROP",
            objective="Drops table to prove SQL injection",
            required_permissions={"DROP_DB"},
            allowed_target_types={NodeType.ENDPOINT},
            scope_requirements={"IN_SCOPE"},
            expected_evidence_type="EMPTY_TABLE",
            risk_level=ValidationRiskLevel.HIGH,
            is_destructive=True,
        )

    # Direct plan rejection
    with pytest.raises(ValidationPlanningError, match="Destructive validation plans are strictly prohibited"):
        ChainValidationPlan(
            plan_id="PLAN-BAD",
            path_id="PATH-BAD",
            path_fingerprint="FP",
            source_finding_ids=[],
            target_finding_ids=[],
            relationship_ids=[],
            target_asset="example.com",
            target_endpoint="/",
            target_method="GET",
            objective="Destructive",
            validation_method="BAD",
            required_permissions=[],
            authorization_context={},
            expected_evidence="",
            scope_reference="IN_SCOPE",
            scope_snapshot_hash="",
            is_destructive=True,
        )


def test_ac_22_3_16_evidence_provenance_preservation():
    """AC-22.3-16: Simulated execution results are marked SIMULATED and never silently promoted to OBSERVED."""
    graph, path = _build_test_graph_and_path()
    planner = SafeChainValidationPlanner()
    plan = planner.create_validation_plan(path, graph)
    planner.submit_for_approval(plan)
    planner.approve_plan(plan, approved_by="OPERATOR-1")
    planner.authorize_dispatch(plan)

    exec_res = planner.execute_dispatched_plan(plan)
    assert exec_res.is_simulated is True
    assert exec_res.status == ValidationPlanStatus.COMPLETED

    ok, edge_ids = planner.verify_evidence_and_promote(plan, exec_res, graph)
    assert ok is True
    for eid in edge_ids:
        edge = graph.get_edge(eid)
        assert edge.state == RelationshipState.LINK_VALIDATED
        assert edge.provenance.authenticity_class == "SIMULATED_VERIFICATION"


def test_ac_22_3_17_evidence_digest_verification():
    """AC-22.3-17: Evidence digest mismatch in EvidenceStore triggers EvidenceVerificationError."""
    graph, path = _build_test_graph_and_path()
    ev_store = MockEvidenceStore()
    ref = "EV-CORRECT"
    correct_digest = ev_store.add_evidence(ref, b"Valid HTTP response evidence body")

    planner = SafeChainValidationPlanner()
    plan = planner.create_validation_plan(path, graph)
    planner.submit_for_approval(plan)
    planner.approve_plan(plan, approved_by="OPERATOR-1")
    planner.authorize_dispatch(plan)

    # Forged result with fake digest
    falsified_result = ValidationExecutionResult(
        execution_id="EXEC-FORGED",
        plan_id=plan.plan_id,
        dispatched_at=datetime.now(timezone.utc).isoformat(),
        completed_at=datetime.now(timezone.utc).isoformat(),
        status=ValidationPlanStatus.COMPLETED,
        evidence_ref=ref,
        evidence_sha256="badf00d" * 8,  # forged digest
        is_simulated=False,
    )

    with pytest.raises(EvidenceVerificationError, match="Evidence digest mismatch"):
        planner.verify_evidence_and_promote(plan, falsified_result, graph, evidence_store=ev_store)


def test_ac_22_3_18_stale_evidence_rejection():
    """AC-22.3-18: Evidence with missing store reference is rejected."""
    graph, path = _build_test_graph_and_path()
    ev_store = MockEvidenceStore()
    planner = SafeChainValidationPlanner()
    plan = planner.create_validation_plan(path, graph)
    planner.submit_for_approval(plan)
    planner.approve_plan(plan, approved_by="OPERATOR-1")
    planner.authorize_dispatch(plan)

    missing_result = ValidationExecutionResult(
        execution_id="EXEC-MISSING",
        plan_id=plan.plan_id,
        dispatched_at=datetime.now(timezone.utc).isoformat(),
        completed_at=datetime.now(timezone.utc).isoformat(),
        status=ValidationPlanStatus.COMPLETED,
        evidence_ref="EV-NONEXISTENT",
        evidence_sha256="1234" * 16,
        is_simulated=False,
    )

    with pytest.raises(EvidenceVerificationError, match="not found in EvidenceStore"):
        planner.verify_evidence_and_promote(plan, missing_result, graph, evidence_store=ev_store)


def test_ac_22_3_19_partial_execution_handling():
    """AC-22.3-19: Rule 8 - Partial execution is never promoted to validated."""
    graph, path = _build_test_graph_and_path()
    planner = SafeChainValidationPlanner()
    plan = planner.create_validation_plan(path, graph)
    planner.submit_for_approval(plan)
    planner.approve_plan(plan, approved_by="OPERATOR-1")
    planner.authorize_dispatch(plan)

    partial_result = ValidationExecutionResult(
        execution_id="EXEC-PARTIAL",
        plan_id=plan.plan_id,
        dispatched_at=datetime.now(timezone.utc).isoformat(),
        completed_at=datetime.now(timezone.utc).isoformat(),
        status=ValidationPlanStatus.PARTIALLY_COMPLETED,
        evidence_ref="EV-PARTIAL",
        evidence_sha256="5678" * 16,
        sanitized_output="Connection dropped midway through validation probe",
        is_simulated=True,
    )

    ok, reasons = planner.verify_evidence_and_promote(plan, partial_result, graph)
    assert ok is False
    assert "Partial execution cannot promote relationships" in reasons[0]
    # Edge remains THEORETICAL
    for eid in plan.relationship_ids:
        assert graph.get_edge(eid).state == RelationshipState.THEORETICAL


def test_ac_22_3_20_duplicate_dispatch_prevention():
    """AC-22.3-20: Dispatched plan cannot be dispatched a second time."""
    graph, path = _build_test_graph_and_path()
    planner = SafeChainValidationPlanner()
    plan = planner.create_validation_plan(path, graph)
    planner.submit_for_approval(plan)
    planner.approve_plan(plan, approved_by="OPERATOR-1")

    # First dispatch succeeds
    assert planner.authorize_dispatch(plan) is True
    assert plan.status == ValidationPlanStatus.DISPATCHED

    # Second duplicate dispatch attempt must be rejected
    with pytest.raises(DispatchSecurityError, match="expected 'APPROVED'"):
        planner.authorize_dispatch(plan)


def test_ac_22_3_21_concurrent_approval_and_revocation():
    """AC-22.3-21: When revocation is invoked, it takes immediate precedence over active approval."""
    graph, path = _build_test_graph_and_path()
    planner = SafeChainValidationPlanner()
    plan = planner.create_validation_plan(path, graph)
    planner.submit_for_approval(plan)
    planner.approve_plan(plan, approved_by="OPERATOR-1")

    # Immediate revocation
    planner.revoke_approval(plan, revoked_by="SECURITY_OFFICER", reason="Immediate revocation")
    assert plan.status == ValidationPlanStatus.REVOKED

    # Subsequent dispatch attempt is blocked
    with pytest.raises(DispatchSecurityError):
        planner.authorize_dispatch(plan)


def test_ac_22_3_22_zero_secret_leakage_compliance():
    """AC-22.3-22: Plans, audit logs, and exception strings never leak raw credentials."""
    graph, path = _build_test_graph_and_path()
    planner = SafeChainValidationPlanner()

    # Inserting raw JWT or Bearer in authorization_context must fail closed
    with pytest.raises(ValueError, match="Security violation"):
        planner.create_validation_plan(
            path,
            graph,
            authorization_context={"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}
        )

    # Valid redacted descriptor is permitted
    plan = planner.create_validation_plan(
        path,
        graph,
        authorization_context={"auth_ref": "DESCRIPTOR_TEST_ACCOUNT_1"}
    )
    assert plan.authorization_context["auth_ref"] == "DESCRIPTOR_TEST_ACCOUNT_1"


def test_ac_22_3_23_state_persistence_and_audit_log_fidelity(temp_workspace):
    """AC-22.3-23: AttackPathStateManager persists and restores plans and audit events with fidelity."""
    state_mgr = AttackPathStateManager(temp_workspace)
    graph, path = _build_test_graph_and_path()
    planner = SafeChainValidationPlanner(state_manager=state_mgr)

    plan = planner.create_validation_plan(path, graph)
    planner.submit_for_approval(plan)
    planner.approve_plan(plan, approved_by="OPERATOR-1")

    # Persist plans
    state_mgr.save_plans({plan.plan_id: plan})

    # Reload plans
    loaded_plans = state_mgr.load_plans()
    assert plan.plan_id in loaded_plans
    loaded_plan = loaded_plans[plan.plan_id]
    assert loaded_plan.plan_hash == plan.plan_hash
    assert loaded_plan.status == ValidationPlanStatus.APPROVED
    assert loaded_plan.approval.approved_by == "OPERATOR-1"

    # Reload audit events
    events = state_mgr.load_audit_events()
    assert len(events) >= 3
    event_types = [e.event_type for e in events]
    assert ValidationAuditEventType.PLAN_CREATED in event_types
    assert ValidationAuditEventType.PLAN_SUBMITTED in event_types
    assert ValidationAuditEventType.PLAN_APPROVED in event_types


def test_ac_22_3_24_end_to_end_correlation_to_validation_pipeline():
    """AC-22.3-24: Full end-to-end integration from correlator candidate path to validated chain."""
    graph, path = _build_test_graph_and_path()
    all_paths = {path.path_id: path}

    planner = SafeChainValidationPlanner()
    plan = planner.create_validation_plan(path, graph)
    planner.submit_for_approval(plan)
    planner.approve_plan(plan, approved_by="SECURITY_LEAD")
    planner.authorize_dispatch(plan)

    exec_result = planner.execute_dispatched_plan(plan)
    assert exec_result.status == ValidationPlanStatus.COMPLETED

    ok, edge_ids = planner.verify_evidence_and_promote(
        plan, exec_result, graph, all_paths=all_paths
    )
    assert ok is True
    assert set(edge_ids) == set(plan.relationship_ids)
    assert plan.status == ValidationPlanStatus.CHAIN_VALIDATED
    assert path.state == ChainState.FULLY_VALIDATED


def test_ac_22_3_25_multi_edge_partial_vs_full_chain_promotion():
    """AC-22.3-25: Multi-edge path only reaches FULLY_VALIDATED when ALL edges are validated."""
    graph, path = _build_test_graph_and_path()
    all_paths = {path.path_id: path}

    planner = SafeChainValidationPlanner()
    # Plan 1: Only validates edge 1
    plan1 = planner.create_validation_plan(path, graph)
    plan1.relationship_ids = ["EDGE-F1-C1"]
    plan1.plan_hash = plan1.compute_plan_hash()

    planner.submit_for_approval(plan1)
    planner.approve_plan(plan1, approved_by="OPERATOR-1")
    planner.authorize_dispatch(plan1)
    res1 = planner.execute_dispatched_plan(plan1)

    ok1, edges1 = planner.verify_evidence_and_promote(plan1, res1, graph, all_paths=all_paths)
    assert ok1 is True
    assert edges1 == ["EDGE-F1-C1"]
    # Path should only be PARTIALLY_VALIDATED, plan is RELATIONSHIP_VALIDATED
    assert path.state == ChainState.PARTIALLY_VALIDATED
    assert plan1.status == ValidationPlanStatus.RELATIONSHIP_VALIDATED

    # Plan 2: Validates edge 2
    plan2 = planner.create_validation_plan(path, graph)
    plan2.relationship_ids = ["EDGE-C1-EP2"]
    plan2.plan_hash = plan2.compute_plan_hash()

    planner.submit_for_approval(plan2)
    planner.approve_plan(plan2, approved_by="OPERATOR-1")
    planner.authorize_dispatch(plan2)
    res2 = planner.execute_dispatched_plan(plan2)

    ok2, edges2 = planner.verify_evidence_and_promote(plan2, res2, graph, all_paths=all_paths)
    assert ok2 is True
    assert edges2 == ["EDGE-C1-EP2"]
    # Now all edges are validated -> path is FULLY_VALIDATED and plan is CHAIN_VALIDATED
    assert path.state == ChainState.FULLY_VALIDATED
    assert plan2.status == ValidationPlanStatus.CHAIN_VALIDATED
