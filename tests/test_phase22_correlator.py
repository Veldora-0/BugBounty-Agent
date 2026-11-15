"""
Unit and Adversarial Acceptance Tests for Phase 22.2.3:
AttackPathCorrelator and Feasibility Evaluation Engine.

Validates Acceptance Criteria AC-22.3-01 through AC-22.3-10:
- AC-22.3-01: End-to-end correlation pipeline (Finding -> Graph -> Candidate Paths)
- AC-22.3-02 (ADV-22-01): Parameter and format mismatch pruning
- AC-22.3-03 (ADV-22-02): Privilege & unachieved role prerequisite rejection
- AC-22.3-04 (ADV-22-03): Multi-tenant boundary violation pruning
- AC-22.3-05 (ADV-22-04): Cross-principal session confusion rejection
- AC-22.3-06 (ADV-22-05): Stale and expired capability pruning
- AC-22.3-07 (ADV-22-06): Decoupled state invariant (HYPOTHESIS state guarantee)
- AC-22.3-08: Severity non-inflation guarantee
- AC-22.3-09: AttackPathStateManager integration and round-trip persistence
- AC-22.3-10: Zero-secret guarantee and cross-platform determinism
"""

from datetime import datetime, timezone
import os
import shutil
import tempfile
import time
from typing import List
import pytest

from framework.attack_path.correlator import (
    AttackPathCorrelator,
    CorrelationResult,
    FeasibilityResult,
)
from framework.attack_path.model import (
    AttackGraph,
    AttackGraphEdge,
    AttackGraphNode,
    AttackPath,
    CapabilityType,
    ChainState,
    EdgeType,
    NodeType,
    RelationshipState,
    assert_no_raw_secrets,
)
from framework.attack_path.state import AttackPathStateManager
from framework.findings.schema import Finding


def _make_dummy_finding(
    finding_id: str,
    vuln_type: str,
    asset: str,
    endpoint: str,
    param: str = "",
    severity: str = "MEDIUM",
    tenant_id: str = "tenant-100",
    principal_id: str = "user-100",
) -> Finding:
    """Helper to construct synthetic Finding records adhering to Finding schema."""
    f = Finding(
        finding_id=finding_id,
        title=f"Synthetic {vuln_type} on {endpoint}",
        summary=f"Demonstration finding for {vuln_type}",
        affected_asset=asset,
        affected_endpoint=endpoint,
        vulnerability_type=vuln_type,
        severity=severity.upper(),
        description=f"Demonstration finding for {vuln_type}",
        root_cause="Improper authorization or input handling",
        prerequisites="Standard access",
        reproduction_steps=["1. Send request", "2. Observe impact"],
        expected_result="Access denied",
        observed_result="Access granted",
        security_impact=f"Impact of {vuln_type}",
        remediation="Apply proper authorization controls",
        scope_reference="authorized_scope",
        confidence="HIGH",
        lifecycle_state="VALIDATED",
        evidence=[],
        parameter=param,
    )
    # Finding doesn't have tenant_id in constructor kwargs, but we can set it in provenance
    f.provenance = {
        "tenant_id": tenant_id,
        "principal_id": principal_id,
    }
    return f


class TestAttackPathCorrelator:
    """Acceptance test suite for Sub-milestone 22.2.3."""

    def test_ac_22_3_01_end_to_end_correlation_pipeline(self):
        """AC-22.3-01: End-to-end correlation from raw Finding objects."""
        # Step 1: IDOR leaking an account identifier
        f1 = _make_dummy_finding(
            finding_id="FND-01",
            vuln_type="idor",
            asset="api.example.com",
            endpoint="https://api.example.com/api/v1/profile",
            param="user_id",
            severity="MEDIUM",
        )
        # Step 2: BFLA endpoint requiring account identifier
        f2 = _make_dummy_finding(
            finding_id="FND-02",
            vuln_type="bola",
            asset="api.example.com",
            endpoint="https://api.example.com/api/v1/billing/invoices",
            param="user_id",
            severity="HIGH",
        )

        correlator = AttackPathCorrelator()
        result: CorrelationResult = correlator.correlate_findings([f1, f2])

        assert result.graph.node_count() >= 4  # Assets, Endpoints, Findings, Capabilities
        assert result.stats["findings_ingested"] == 2
        assert result.stats["capabilities_count"] >= 2
        assert len(result.candidate_paths) >= 1

        for path in result.candidate_paths:
            assert path.state == ChainState.HYPOTHESIS
            assert len(path.node_ids) >= 2

    def test_ac_22_3_02_adv_22_01_parameter_format_mismatch(self):
        """AC-22.3-02 (ADV-22-01): Parameter format mismatch causes path pruning."""
        graph = AttackGraph()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Capability yielding an EMAIL format
        cap_node = AttackGraphNode(
            node_id="CAP-EMAIL-01",
            node_type=NodeType.CAPABILITY,
            label="KNOWLEDGE_EXPOSURE",
            attributes={
                "capability_type": "KNOWLEDGE_EXPOSURE",
                "descriptor": {"format": "EMAIL", "parameter": "email"},
            },
            scope_status="IN_SCOPE",
            created_at=now_iso,
            updated_at=now_iso,
        )
        # Target finding expecting a NUMERIC_ID format
        fnd_node = AttackGraphNode(
            node_id="FND-TARGET-01",
            node_type=NodeType.FINDING,
            label="SQLi on numeric ID",
            attributes={
                "parameter": "user_id",
                "expected_format": "NUMERIC_ID",
            },
            scope_status="IN_SCOPE",
            created_at=now_iso,
            updated_at=now_iso,
        )
        edge = AttackGraphEdge(
            edge_id="EDGE-01",
            source_id=cap_node.node_id,
            destination_id=fnd_node.node_id,
            edge_type=EdgeType.SATISFIES_PREREQUISITE,
            state=RelationshipState.THEORETICAL,
            created_at=now_iso,
        )
        graph.add_node(cap_node)
        graph.add_node(fnd_node)
        graph.add_edge(edge)

        correlator = AttackPathCorrelator()
        path = AttackPath(
            path_id="PATH-01",
            node_ids=[cap_node.node_id, fnd_node.node_id],
            edge_ids=[edge.edge_id],
            state=ChainState.HYPOTHESIS,
            created_at=now_iso,
        )

        feasibility: FeasibilityResult = correlator.evaluate_path_feasibility(path, graph)
        assert not feasibility.is_feasible
        assert "PARAMETER_FORMAT_MISMATCH" in (feasibility.rejection_reason or "")

    def test_ac_22_3_03_adv_22_02_unachieved_role_prerequisite(self):
        """AC-22.3-03 (ADV-22-02): Terminal step requiring unachieved ADMIN role is rejected."""
        graph = AttackGraph()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Low-privilege finding
        f1 = AttackGraphNode(
            node_id="FND-LOW-01",
            node_type=NodeType.FINDING,
            label="Low priv finding",
            attributes={"role": "USER"},
            scope_status="IN_SCOPE",
            created_at=now_iso,
            updated_at=now_iso,
        )
        # High-privilege terminal endpoint requiring SYSTEM/ADMIN
        f2 = AttackGraphNode(
            node_id="FND-ADMIN-01",
            node_type=NodeType.FINDING,
            label="Admin debug endpoint",
            attributes={"required_role": "ADMIN"},
            scope_status="IN_SCOPE",
            created_at=now_iso,
            updated_at=now_iso,
        )
        edge = AttackGraphEdge(
            edge_id="EDGE-02",
            source_id=f1.node_id,
            destination_id=f2.node_id,
            edge_type=EdgeType.TARGETS,
            state=RelationshipState.THEORETICAL,
            created_at=now_iso,
        )
        graph.add_node(f1)
        graph.add_node(f2)
        graph.add_edge(edge)

        correlator = AttackPathCorrelator()
        path = AttackPath(
            path_id="PATH-02",
            node_ids=[f1.node_id, f2.node_id],
            edge_ids=[edge.edge_id],
            state=ChainState.HYPOTHESIS,
            created_at=now_iso,
        )

        feasibility: FeasibilityResult = correlator.evaluate_path_feasibility(path, graph)
        assert not feasibility.is_feasible
        assert "UNACHIEVED_ROLE_PREREQUISITE" in (feasibility.rejection_reason or "")

    def test_ac_22_3_04_adv_22_03_cross_tenant_isolation_violation(self):
        """AC-22.3-04 (ADV-22-03): Cross-tenant transition without supported flaw is rejected."""
        graph = AttackGraph()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Step 1: Info disclosure belonging to Tenant A (generic info disclosure, not bola/idor)
        n1 = AttackGraphNode(
            node_id="FND-TENANT-A",
            node_type=NodeType.FINDING,
            label="Info Disclosure",
            attributes={"tenant_id": "tenant-A", "vulnerability_type": "info_disclosure"},
            scope_status="IN_SCOPE",
            created_at=now_iso,
            updated_at=now_iso,
        )
        # Step 2: Target belonging to Tenant B
        n2 = AttackGraphNode(
            node_id="FND-TENANT-B",
            node_type=NodeType.FINDING,
            label="Admin Profile",
            attributes={"tenant_id": "tenant-B", "vulnerability_type": "sql_injection"},
            scope_status="IN_SCOPE",
            created_at=now_iso,
            updated_at=now_iso,
        )
        edge = AttackGraphEdge(
            edge_id="EDGE-TENANT",
            source_id=n1.node_id,
            destination_id=n2.node_id,
            edge_type=EdgeType.CROSSES_BOUNDARY,
            state=RelationshipState.THEORETICAL,
            created_at=now_iso,
        )
        graph.add_node(n1)
        graph.add_node(n2)
        graph.add_edge(edge)

        correlator = AttackPathCorrelator()
        path = AttackPath(
            path_id="PATH-TENANT-LEAK",
            node_ids=[n1.node_id, n2.node_id],
            edge_ids=[edge.edge_id],
            state=ChainState.HYPOTHESIS,
            created_at=now_iso,
        )

        feasibility = correlator.evaluate_path_feasibility(path, graph)
        assert not feasibility.is_feasible
        assert "UNAUTHORIZED_CROSS_TENANT_TRANSITION" in (feasibility.rejection_reason or "")

    def test_ac_22_3_05_adv_22_04_cross_principal_session_mismatch(self):
        """AC-22.3-05 (ADV-22-04): Cross-principal session confusion without hijack is rejected."""
        graph = AttackGraph()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Step 1: Principal Alice's finding
        n1 = AttackGraphNode(
            node_id="FND-ALICE",
            node_type=NodeType.FINDING,
            label="Alice finding",
            attributes={"principal_id": "user-alice"},
            scope_status="IN_SCOPE",
            created_at=now_iso,
            updated_at=now_iso,
        )
        # Step 2: Principal Bob's private endpoint
        n2 = AttackGraphNode(
            node_id="FND-BOB",
            node_type=NodeType.FINDING,
            label="Bob endpoint",
            attributes={"principal_id": "user-bob"},
            scope_status="IN_SCOPE",
            created_at=now_iso,
            updated_at=now_iso,
        )
        edge = AttackGraphEdge(
            edge_id="EDGE-PRINCIPAL",
            source_id=n1.node_id,
            destination_id=n2.node_id,
            edge_type=EdgeType.TARGETS,
            state=RelationshipState.THEORETICAL,
            created_at=now_iso,
        )
        graph.add_node(n1)
        graph.add_node(n2)
        graph.add_edge(edge)

        correlator = AttackPathCorrelator()
        path = AttackPath(
            path_id="PATH-PRINCIPAL-MISMATCH",
            node_ids=[n1.node_id, n2.node_id],
            edge_ids=[edge.edge_id],
            state=ChainState.HYPOTHESIS,
            created_at=now_iso,
        )

        feasibility = correlator.evaluate_path_feasibility(path, graph)
        assert not feasibility.is_feasible
        assert "PRINCIPAL_CONTEXT_MISMATCH" in (feasibility.rejection_reason or "")

    def test_ac_22_3_06_adv_22_05_stale_expired_capability_pruning(self):
        """AC-22.3-06 (ADV-22-05): Expired capability causes path to be pruned."""
        graph = AttackGraph()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Capability explicitly marked expired
        cap_node = AttackGraphNode(
            node_id="CAP-EXPIRED",
            node_type=NodeType.CAPABILITY,
            label="Expired Session",
            attributes={
                "capability_type": "SESSION_HIJACK",
                "is_expired": True,
            },
            scope_status="IN_SCOPE",
            created_at=now_iso,
            updated_at=now_iso,
        )
        fnd_node = AttackGraphNode(
            node_id="FND-DOWNSTREAM",
            node_type=NodeType.FINDING,
            label="Authenticated Endpoint",
            attributes={},
            scope_status="IN_SCOPE",
            created_at=now_iso,
            updated_at=now_iso,
        )
        edge = AttackGraphEdge(
            edge_id="EDGE-STALE",
            source_id=cap_node.node_id,
            destination_id=fnd_node.node_id,
            edge_type=EdgeType.AUTHENTICATES_AS,
            state=RelationshipState.THEORETICAL,
            created_at=now_iso,
        )
        graph.add_node(cap_node)
        graph.add_node(fnd_node)
        graph.add_edge(edge)

        correlator = AttackPathCorrelator()
        path = AttackPath(
            path_id="PATH-STALE",
            node_ids=[cap_node.node_id, fnd_node.node_id],
            edge_ids=[edge.edge_id],
            state=ChainState.HYPOTHESIS,
            created_at=now_iso,
        )

        feasibility = correlator.evaluate_path_feasibility(path, graph)
        assert not feasibility.is_feasible
        assert "STALE_CAPABILITY_EXPIRED" in (feasibility.rejection_reason or "")

    def test_ac_22_3_07_adv_22_06_decoupled_state_hypothesis_invariant(self):
        """AC-22.3-07 (ADV-22-06): All emitted candidate paths are HYPOTHESIS."""
        f1 = _make_dummy_finding("F1", "idor", "app.example.com", "https://app.example.com/u")
        f2 = _make_dummy_finding("F2", "bola", "app.example.com", "https://app.example.com/o")

        correlator = AttackPathCorrelator()
        result = correlator.correlate_findings([f1, f2])

        for path in result.candidate_paths:
            assert path.state == ChainState.HYPOTHESIS
            assert path.state != ChainState.FULLY_VALIDATED
            assert path.state != ChainState.PARTIALLY_VALIDATED

    def test_ac_22_3_08_finding_severity_non_inflation(self):
        """AC-22.3-08: Underlying finding severities remain strictly unmodified."""
        f1 = _make_dummy_finding("F1", "idor", "app.example.com", "https://app.example.com/u", severity="LOW")
        f2 = _make_dummy_finding("F2", "bola", "app.example.com", "https://app.example.com/o", severity="MEDIUM")

        assert f1.severity == "LOW"
        assert f2.severity == "MEDIUM"

        correlator = AttackPathCorrelator()
        result = correlator.correlate_findings([f1, f2])

        # Verify findings maintain immutable severities
        assert f1.severity == "LOW"
        assert f2.severity == "MEDIUM"

    def test_ac_22_3_09_state_manager_persistence_integration(self):
        """AC-22.3-09: AttackPathStateManager round-trip persistence integration."""
        temp_dir = tempfile.mkdtemp(prefix="test_correlator_state_")
        try:
            state_mgr = AttackPathStateManager(program_dir=temp_dir)
            correlator = AttackPathCorrelator(state_manager=state_mgr)

            f1 = _make_dummy_finding("F1", "idor", "app.example.com", "https://app.example.com/u")
            f2 = _make_dummy_finding("F2", "bola", "app.example.com", "https://app.example.com/o")

            result = correlator.correlate_findings([f1, f2], auto_persist=True)
            assert os.path.exists(os.path.join(temp_dir, "state", "attack_graph.json"))

            # Reload graph from state
            loaded_graph = state_mgr.load_graph()
            assert loaded_graph.node_count() == result.graph.node_count()
            assert loaded_graph.edge_count() == result.graph.edge_count()
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_ac_22_3_10_zero_secret_guarantee(self):
        """AC-22.3-10: Zero raw secrets in correlation results and graph state."""
        f1 = _make_dummy_finding("F1", "idor", "app.example.com", "https://app.example.com/u")
        f2 = _make_dummy_finding("F2", "bola", "app.example.com", "https://app.example.com/o")

        correlator = AttackPathCorrelator()
        result = correlator.correlate_findings([f1, f2])

        # Pass through recursive zero-secret assertion
        assert_no_raw_secrets(result.graph)
        assert_no_raw_secrets(result.candidate_paths)
        assert_no_raw_secrets(result.to_dict())
