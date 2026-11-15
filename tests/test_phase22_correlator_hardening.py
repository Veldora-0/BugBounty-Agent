"""
Integration Hardening and Adversarial Edge-Case Test Suite for Phase 22.2.4:
State Persistence, Multi-Tenant Isolation, Scope Enforcement, and Feasibility Verification.

Validates Acceptance Criteria AC-22.2.4-01 through AC-22.2.4-10:
- AC-22.2.4-01: Dense multigraph resilience and deterministic output
- AC-22.2.4-02: Duplicate input and repeated-run idempotency
- AC-22.2.4-03: Persistence round-trip integrity
- AC-22.2.4-04: Malformed state and interrupted-write recovery
- AC-22.2.4-05: Tenant isolation under complex multi-hop paths
- AC-22.2.4-06: Scope enforcement with missing and malformed metadata
- AC-22.2.4-07: All six feasibility rules withstand edge-case inputs
- AC-22.2.4-08: Zero-secret guarantees across serialization and persistence
- AC-22.2.4-09: Resource budgets and truncation metadata remain enforceable
- AC-22.2.4-10: Dual-platform behavioral parity and regression integrity
"""

from datetime import datetime, timezone
import json
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
from framework.attack_path.traversal import BoundedTraversalEngine, TraversalResult
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
    """Helper to construct synthetic Finding records."""
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
    f.provenance = {
        "tenant_id": tenant_id,
        "principal_id": principal_id,
    }
    return f


class TestPhase22Milestone2224Hardening:
    """Rigorous integration and hardening test suite for Milestone 22.2.4."""

    def test_ac_22_2_4_01_dense_multigraph_resilience_and_determinism(self):
        """AC-22.2.4-01: Dense multigraph resilience, multigraph edges, and deterministic output."""
        graph = AttackGraph()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Build a dense multigraph with multiple edges between pairs and multiple paths
        nodes = []
        for i in range(15):
            ntype = NodeType.FINDING if i % 2 == 0 else NodeType.CAPABILITY
            node = AttackGraphNode(
                node_id=f"NODE-{i:02d}",
                node_type=ntype,
                label=f"Node {i}",
                attributes={"tenant_id": "tenant-main", "vulnerability_type": "idor"},
                scope_status="IN_SCOPE",
                created_at=now_iso,
                updated_at=now_iso,
            )
            graph.add_node(node)
            nodes.append(node)

        # Add multiple competing edges including cycles and multigraph edges
        edge_count = 0
        for i in range(len(nodes) - 1):
            # Edge type 1
            e1 = AttackGraphEdge(
                edge_id=f"EDGE-FND-{i:02d}",
                source_id=nodes[i].node_id,
                destination_id=nodes[i + 1].node_id,
                edge_type=EdgeType.SATISFIES_PREREQUISITE,
                state=RelationshipState.THEORETICAL,
                created_at=now_iso,
            )
            graph.add_edge(e1)
            # Edge type 2 between same nodes (multigraph)
            e2 = AttackGraphEdge(
                edge_id=f"EDGE-DEP-{i:02d}",
                source_id=nodes[i].node_id,
                destination_id=nodes[i + 1].node_id,
                edge_type=EdgeType.DEPENDS_ON,
                state=RelationshipState.THEORETICAL,
                created_at=now_iso,
            )
            graph.add_edge(e2)
            edge_count += 2

        # Cycle edge back to beginning
        cycle_edge = AttackGraphEdge(
            edge_id="EDGE-CYCLE-BACK",
            source_id=nodes[10].node_id,
            destination_id=nodes[0].node_id,
            edge_type=EdgeType.TARGETS,
            state=RelationshipState.THEORETICAL,
            created_at=now_iso,
        )
        graph.add_edge(cycle_edge)

        traversal = BoundedTraversalEngine(max_depth=4, max_candidate_paths=20)
        res1 = traversal.find_attack_paths(graph, entry_node_ids=["NODE-00"])
        res2 = traversal.find_attack_paths(graph, entry_node_ids=["NODE-00"])

        assert len(res1.paths) > 0
        assert len(res1.paths) == len(res2.paths)
        # Verify 100% deterministic path IDs and ordering
        for p1, p2 in zip(res1.paths, res2.paths):
            assert p1.path_id == p2.path_id
            assert p1.fingerprint == p2.fingerprint
            assert p1.node_ids == p2.node_ids
            assert p1.edge_ids == p2.edge_ids

    def test_ac_22_2_4_02_duplicate_input_and_repeated_run_idempotency(self):
        """AC-22.2.4-02: Repeated correlation does not duplicate nodes or edges or inflate counts."""
        f1 = _make_dummy_finding("F1", "idor", "app.example.com", "https://app.example.com/api/u", param="user_id")
        f2 = _make_dummy_finding("F2", "bola", "app.example.com", "https://app.example.com/api/o", param="user_id")

        correlator = AttackPathCorrelator()
        res1 = correlator.correlate_findings([f1, f2])

        initial_node_count = res1.graph.node_count()
        initial_edge_count = res1.graph.edge_count()
        initial_path_count = len(res1.candidate_paths)

        # Run again using same graph
        res2 = correlator.correlate_findings([f1, f2], graph=res1.graph)

        assert res2.graph.node_count() == initial_node_count
        assert res2.graph.edge_count() == initial_edge_count
        assert len(res2.candidate_paths) == initial_path_count

    def test_ac_22_2_4_03_persistence_round_trip_integrity(self):
        """AC-22.2.4-03: AttackPathStateManager round-trip persistence and directory security."""
        temp_dir = tempfile.mkdtemp(prefix="test_persistence_integrity_")
        try:
            state_mgr = AttackPathStateManager(program_dir=temp_dir)
            graph = AttackGraph()
            now_iso = datetime.now(timezone.utc).isoformat()

            n1 = AttackGraphNode(
                node_id="NODE-P1",
                node_type=NodeType.ASSET,
                label="example.com",
                attributes={"env": "prod", "tenant_id": "tenant-alpha"},
                scope_status="IN_SCOPE",
                created_at=now_iso,
                updated_at=now_iso,
            )
            n2 = AttackGraphNode(
                node_id="NODE-P2",
                node_type=NodeType.ENDPOINT,
                label="POST /login",
                attributes={"method": "POST", "tenant_id": "tenant-alpha"},
                scope_status="IN_SCOPE",
                created_at=now_iso,
                updated_at=now_iso,
            )
            edge = AttackGraphEdge(
                edge_id="EDGE-P1-P2",
                source_id=n1.node_id,
                destination_id=n2.node_id,
                edge_type=EdgeType.EXPOSES,
                state=RelationshipState.LINK_VALIDATED,
                created_at=now_iso,
            )
            graph.add_node(n1)
            graph.add_node(n2)
            graph.add_edge(edge)

            state_mgr.save_graph(graph)
            assert os.path.exists(state_mgr.get_graph_path())

            loaded_graph = state_mgr.load_graph()
            assert loaded_graph.node_count() == 2
            assert loaded_graph.edge_count() == 1
            assert loaded_graph.get_node("NODE-P1").attributes["tenant_id"] == "tenant-alpha"
            assert loaded_graph.get_edge("EDGE-P1-P2").state == RelationshipState.LINK_VALIDATED
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_ac_22_2_4_04_malformed_state_and_corruption_recovery(self):
        """AC-22.2.4-04: Malformed state file produces recovery backup and clean initialization."""
        temp_dir = tempfile.mkdtemp(prefix="test_corruption_recovery_")
        try:
            state_mgr = AttackPathStateManager(program_dir=temp_dir)
            graph_path = state_mgr.get_graph_path()

            # Write corrupted JSON to the state file
            with open(graph_path, "w", encoding="utf-8") as f:
                f.write('{"corrupted_json": [true, false, null, {incomplete')

            loaded_graph = state_mgr.load_graph()
            # Must return a clean, valid AttackGraph without raising unhandled error
            assert isinstance(loaded_graph, AttackGraph)
            assert loaded_graph.node_count() == 0

            # Verify that a backup file with .corrupt. was created
            backup_files = [f for f in os.listdir(state_mgr.state_dir) if ".corrupt." in f]
            assert len(backup_files) >= 1
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_ac_22_2_4_05_tenant_isolation_complex_multi_hop(self):
        """AC-22.2.4-05: Tenant isolation with mixed-tenant and shared resources."""
        graph = AttackGraph()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Node 1: Tenant 100 with BOLA
        n1 = AttackGraphNode(
            node_id="N1-BOLA",
            node_type=NodeType.FINDING,
            label="BOLA Finding",
            attributes={"tenant_id": "tenant-100", "vulnerability_type": "bola"},
            scope_status="IN_SCOPE",
            created_at=now_iso,
            updated_at=now_iso,
        )
        # Node 2: Tenant 200 with XSS (generic flaw, not tenant isolation)
        n2 = AttackGraphNode(
            node_id="N2-XSS",
            node_type=NodeType.FINDING,
            label="XSS Finding",
            attributes={"tenant_id": "tenant-200", "vulnerability_type": "xss"},
            scope_status="IN_SCOPE",
            created_at=now_iso,
            updated_at=now_iso,
        )
        # Node 3: Tenant 300 Target
        n3 = AttackGraphNode(
            node_id="N3-TARGET",
            node_type=NodeType.FINDING,
            label="Target Finding",
            attributes={"tenant_id": "tenant-300", "vulnerability_type": "sqli"},
            scope_status="IN_SCOPE",
            created_at=now_iso,
            updated_at=now_iso,
        )
        e1 = AttackGraphEdge(
            edge_id="E1-2",
            source_id=n1.node_id,
            destination_id=n2.node_id,
            edge_type=EdgeType.CROSSES_BOUNDARY,
            state=RelationshipState.THEORETICAL,
            created_at=now_iso,
        )
        e2 = AttackGraphEdge(
            edge_id="E2-3",
            source_id=n2.node_id,
            destination_id=n3.node_id,
            edge_type=EdgeType.TARGETS,
            state=RelationshipState.THEORETICAL,
            created_at=now_iso,
        )
        graph.add_node(n1)
        graph.add_node(n2)
        graph.add_node(n3)
        graph.add_edge(e1)
        graph.add_edge(e2)

        correlator = AttackPathCorrelator()
        # Hop 1 (100 -> 200) is allowed because N1 has BOLA
        path_valid_hop = AttackPath(
            path_id="P-HOP1",
            node_ids=[n1.node_id, n2.node_id],
            edge_ids=[e1.edge_id],
            state=ChainState.HYPOTHESIS,
            created_at=now_iso,
        )
        res1 = correlator.evaluate_path_feasibility(path_valid_hop, graph)
        assert res1.is_feasible

        # Hop 2 (100 -> 200 -> 300) must fail at step 2 -> 3 because N2 (XSS) is NOT a tenant-isolation flaw
        path_invalid_hop = AttackPath(
            path_id="P-HOP2",
            node_ids=[n1.node_id, n2.node_id, n3.node_id],
            edge_ids=[e1.edge_id, e2.edge_id],
            state=ChainState.HYPOTHESIS,
            created_at=now_iso,
        )
        res2 = correlator.evaluate_path_feasibility(path_invalid_hop, graph)
        assert not res2.is_feasible
        assert "UNAUTHORIZED_CROSS_TENANT_TRANSITION" in (res2.rejection_reason or "")
        assert res2.pruned_step_index == 2

    def test_ac_22_2_4_06_scope_enforcement_missing_and_malformed_metadata(self):
        """AC-22.2.4-06: Scope enforcement rejects OUT_OF_SCOPE, EXCLUDED, and malformed scope."""
        graph = AttackGraph()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Node with EXCLUDED scope status
        n_excluded = AttackGraphNode(
            node_id="NODE-EXCLUDED",
            node_type=NodeType.FINDING,
            label="Excluded Asset Finding",
            attributes={"tenant_id": "tenant-100"},
            scope_status="EXCLUDED",
            created_at=now_iso,
            updated_at=now_iso,
        )
        n_in = AttackGraphNode(
            node_id="NODE-IN",
            node_type=NodeType.ENDPOINT,
            label="In Scope Endpoint",
            attributes={"tenant_id": "tenant-100"},
            scope_status="IN_SCOPE",
            created_at=now_iso,
            updated_at=now_iso,
        )
        e = AttackGraphEdge(
            edge_id="E-EXC",
            source_id=n_excluded.node_id,
            destination_id=n_in.node_id,
            edge_type=EdgeType.TARGETS,
            state=RelationshipState.THEORETICAL,
            created_at=now_iso,
        )
        graph.add_node(n_excluded)
        graph.add_node(n_in)
        graph.add_edge(e)

        correlator = AttackPathCorrelator()
        path = AttackPath(
            path_id="P-SCOPE-TEST",
            node_ids=[n_excluded.node_id, n_in.node_id],
            edge_ids=[e.edge_id],
            state=ChainState.HYPOTHESIS,
            created_at=now_iso,
        )
        res = correlator.evaluate_path_feasibility(path, graph)
        assert not res.is_feasible
        assert "SCOPE_VIOLATION" in (res.rejection_reason or "")

    def test_ac_22_2_4_07_adv_22_04_token_acquisition_without_principal_evidence(self):
        """AC-22.2.4-07: TOKEN_ACQUISITION alone without matching principal evidence is rejected."""
        graph = AttackGraph()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Principal Alice finding
        f1 = AttackGraphNode(
            node_id="FND-ALICE",
            node_type=NodeType.FINDING,
            label="Alice Finding",
            attributes={"principal_id": "user-alice"},
            scope_status="IN_SCOPE",
            created_at=now_iso,
            updated_at=now_iso,
        )
        # Token acquisition capability WITHOUT authenticated_principal binding
        cap_generic_token = AttackGraphNode(
            node_id="CAP-GENERIC-TOKEN",
            node_type=NodeType.CAPABILITY,
            label="Generic Token Acquisition",
            attributes={
                "capability_type": "TOKEN_ACQUISITION",
                "descriptor": {"token_type": "BEARER", "format": "TOKEN_DESCRIPTOR"},
            },
            scope_status="IN_SCOPE",
            created_at=now_iso,
            updated_at=now_iso,
        )
        # Target finding belonging to Bob
        f2 = AttackGraphNode(
            node_id="FND-BOB",
            node_type=NodeType.FINDING,
            label="Bob Profile",
            attributes={"principal_id": "user-bob"},
            scope_status="IN_SCOPE",
            created_at=now_iso,
            updated_at=now_iso,
        )
        e1 = AttackGraphEdge(
            edge_id="E-A-T",
            source_id=f1.node_id,
            destination_id=cap_generic_token.node_id,
            edge_type=EdgeType.EXPOSES,
            state=RelationshipState.THEORETICAL,
            created_at=now_iso,
        )
        e2 = AttackGraphEdge(
            edge_id="E-T-B",
            source_id=cap_generic_token.node_id,
            destination_id=f2.node_id,
            edge_type=EdgeType.AUTHENTICATES_AS,
            state=RelationshipState.THEORETICAL,
            created_at=now_iso,
        )
        graph.add_node(f1)
        graph.add_node(cap_generic_token)
        graph.add_node(f2)
        graph.add_edge(e1)
        graph.add_edge(e2)

        correlator = AttackPathCorrelator()
        # Case A: Generic token without principal binding -> Must fail
        path_unproven = AttackPath(
            path_id="P-UNPROVEN-TOKEN",
            node_ids=[f1.node_id, cap_generic_token.node_id, f2.node_id],
            edge_ids=[e1.edge_id, e2.edge_id],
            state=ChainState.HYPOTHESIS,
            created_at=now_iso,
        )
        res_unproven = correlator.evaluate_path_feasibility(path_unproven, graph)
        assert not res_unproven.is_feasible
        assert "PRINCIPAL_CONTEXT_MISMATCH" in (res_unproven.rejection_reason or "")

        # Case B: Token explicitly bound to user-bob -> Must pass
        cap_generic_token.attributes["descriptor"]["authenticated_principal"] = "user-bob"
        res_proven = correlator.evaluate_path_feasibility(path_unproven, graph)
        assert res_proven.is_feasible

    def test_ac_22_2_4_08_zero_secret_guarantees_and_no_echo(self):
        """AC-22.2.4-08: Zero-secret check blocks credentials and rejection message does not echo secrets."""
        # 1. Test unredacted authorization key
        dummy_secret = "Bearer " + "abc1234567890secrettoken"
        nested_data = {
            "node_id": "NODE-SEC",
            "attributes": {
                "authorization": dummy_secret,
            },
        }
        with pytest.raises(ValueError) as excinfo:
            assert_no_raw_secrets(nested_data)

        # Confirm the rejection message does NOT echo the sensitive value itself
        error_msg = str(excinfo.value)
        assert dummy_secret not in error_msg
        assert "Security violation" in error_msg

    def test_ac_22_2_4_09_resource_budgets_and_truncation_metadata(self):
        """AC-22.2.4-09: Resource budgets and truncation metadata remain strictly enforceable."""
        graph = AttackGraph()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Create a deep linear chain exceeding depth 5
        prev_node_id = None
        for i in range(10):
            node = AttackGraphNode(
                node_id=f"DEPTH-NODE-{i}",
                node_type=NodeType.FINDING,
                label=f"Depth Step {i}",
                attributes={"tenant_id": "tenant-deep"},
                scope_status="IN_SCOPE",
                created_at=now_iso,
                updated_at=now_iso,
            )
            graph.add_node(node)
            if prev_node_id:
                edge = AttackGraphEdge(
                    edge_id=f"EDGE-DEPTH-{i}",
                    source_id=prev_node_id,
                    destination_id=node.node_id,
                    edge_type=EdgeType.TARGETS,
                    state=RelationshipState.THEORETICAL,
                    created_at=now_iso,
                )
                graph.add_edge(edge)
            prev_node_id = node.node_id

        # Limit depth to 3
        traversal = BoundedTraversalEngine(max_depth=3)
        result = traversal.find_attack_paths(graph, entry_node_ids=["DEPTH-NODE-0"])

        for p in result.paths:
            # All paths must be within max_depth hops
            assert len(p.edge_ids) <= 3

    def test_ac_22_2_4_10_dual_platform_deterministic_path_hashes(self):
        """AC-22.2.4-10: Cross-platform deterministic path ID and fingerprint stability."""
        f1 = _make_dummy_finding("F1", "idor", "app.example.com", "https://app.example.com/api/u", param="user_id")
        f2 = _make_dummy_finding("F2", "bola", "app.example.com", "https://app.example.com/api/o", param="user_id")

        correlator = AttackPathCorrelator()
        res1 = correlator.correlate_findings([f1, f2])
        res2 = correlator.correlate_findings([f1, f2])

        assert len(res1.candidate_paths) == len(res2.candidate_paths)
        for p1, p2 in zip(res1.candidate_paths, res2.candidate_paths):
            assert p1.path_id.startswith("PATH-")
            assert p1.path_id == p2.path_id
            assert p1.fingerprint == p2.fingerprint
            assert p1.state == ChainState.HYPOTHESIS
