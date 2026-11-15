"""
Phase 22.2 Acceptance & Adversarial Test Suite for Candidate Discovery & Bounded Traversal.

Validates all 10 acceptance criteria (AC-22.2-01 through AC-22.2-10):
1. Deterministic discovery and explicit shortest-path-first priority.
2. Cycle termination and finite recursion.
3. Multi-tenant boundary isolation and authorized flaw exceptions.
4. Scope boundary enforcement and out-of-scope pruning.
5. Resource-limit exhaustion and truncation metadata.
6. Anti-inflation guarantee (strictly HYPOTHESIS, never LINK_VALIDATED).
7. Stale capability pruning.
8. Zero-secret enforcement on emitted paths.
9. Dangling-edge and malformed-element resilience.
10. Cross-platform deterministic output parity.
"""

from __future__ import annotations

from datetime import datetime, timezone
import time
import pytest

from framework.attack_path.discovery import (
    CandidateRelationshipEngine,
    SUPPORTED_TENANT_ISOLATION_FLAWS,
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
from framework.attack_path.normalizer import FindingNormalizer
from framework.attack_path.traversal import (
    BoundedTraversalEngine,
    TraversalResult,
)
from framework.findings.lifecycle import FindingLifecycle
from framework.findings.schema import Finding


def _make_finding(
    finding_id: str,
    vulnerability_type: str,
    asset: str = "app.example.com",
    endpoint: str = "https://app.example.com/api",
    parameter: str = "",
    prerequisites: str = "None",
    severity: str = "HIGH",
    tenant_id: str = "tenant-1",
    scope_status: str = "IN_SCOPE",
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title=f"Test Finding {finding_id}",
        summary=f"Summary for {finding_id}",
        affected_asset=asset,
        affected_endpoint=endpoint,
        vulnerability_type=vulnerability_type,
        severity=severity,
        description="Detailed description",
        root_cause="Missing control",
        prerequisites=prerequisites,
        reproduction_steps=["Step 1"],
        expected_result="403",
        observed_result="200",
        security_impact="Impact description",
        remediation="Remediation description",
        scope_reference="*.example.com",
        lifecycle_state=FindingLifecycle.VALIDATED,
        parameter=parameter,
    )


# ==============================================================================
# AC-22.2-01: Deterministic Discovery & Shortest-Path-First Priority
# ==============================================================================

def test_ac01_deterministic_discovery_and_shortest_path_first():
    graph = AttackGraph()
    normalizer = FindingNormalizer(evidence_store=None)

    # 1. IDOR finding leaking user_id
    f1 = _make_finding(
        finding_id="BB-01-IDOR",
        vulnerability_type="idor",
        parameter="user_id",
        prerequisites="Standard user login",
        severity="MEDIUM",
    )
    # 2. BFLA modifying user profile via user_id, elevating role
    f2 = _make_finding(
        finding_id="BB-02-BFLA",
        vulnerability_type="business_logic",
        parameter="user_id",
        prerequisites="Requires victim user_id",
        severity="HIGH",
    )
    # 3. Privileged Admin action requiring admin role
    f3 = _make_finding(
        finding_id="BB-03-ADMIN",
        vulnerability_type="privilege_escalation",
        parameter="",
        prerequisites="Requires elevated admin role",
        severity="CRITICAL",
    )

    graph = normalizer.ingest_findings_into_graph([f1, f2, f3], graph)

    # Run discovery engine
    discovery = CandidateRelationshipEngine()
    edges = discovery.discover_candidate_relationships(graph)

    assert len(edges) >= 1
    for edge in edges:
        graph.add_edge(edge)

    # Run traversal engine
    traversal = BoundedTraversalEngine()
    result = traversal.find_attack_paths(graph)

    assert len(result.paths) >= 1
    # Verify Shortest-Path-First: path hop counts must be non-decreasing
    hop_counts = [len(p.edge_ids) for p in result.paths]
    assert hop_counts == sorted(hop_counts), f"Paths not ordered shortest-path-first: {hop_counts}"

    # Verify determinism across repeated executions
    first_path_ids = [p.path_id for p in result.paths]
    for _ in range(5):
        repeat_res = traversal.find_attack_paths(graph)
        repeat_ids = [p.path_id for p in repeat_res.paths]
        assert repeat_ids == first_path_ids


# ==============================================================================
# AC-22.2-02: Cycle Termination & Finite Recursion
# ==============================================================================

def test_ac02_cycle_termination():
    graph = AttackGraph()

    # Create cyclic graph: N1 -> N2 -> N3 -> N1
    n1 = AttackGraphNode("FND-A", NodeType.FINDING, "Finding A", {"vulnerability_type": "v1"})
    n2 = AttackGraphNode("FND-B", NodeType.FINDING, "Finding B", {"vulnerability_type": "v2"})
    n3 = AttackGraphNode("FND-C", NodeType.FINDING, "Finding C", {"vulnerability_type": "v3"})
    graph.add_node(n1)
    graph.add_node(n2)
    graph.add_node(n3)

    e1 = AttackGraphEdge("E-AB", "FND-A", "FND-B", EdgeType.SATISFIES_PREREQUISITE)
    e2 = AttackGraphEdge("E-BC", "FND-B", "FND-C", EdgeType.SATISFIES_PREREQUISITE)
    e3 = AttackGraphEdge("E-CA", "FND-C", "FND-A", EdgeType.SATISFIES_PREREQUISITE)  # Cycle back to A
    graph.add_edge(e1)
    graph.add_edge(e2)
    graph.add_edge(e3)

    traversal = BoundedTraversalEngine(max_depth=5)
    result = traversal.find_attack_paths(graph)

    # Must terminate without infinite recursion
    assert result.examined_edges_count > 0
    # No path may contain duplicate nodes (no cycles in paths)
    for path in result.paths:
        assert len(path.node_ids) == len(set(path.node_ids)), f"Cycle detected in path: {path.node_ids}"


# ==============================================================================
# AC-22.2-03: Multi-Tenant Boundary Isolation
# ==============================================================================

def test_ac03_multi_tenant_isolation_and_authorized_flaws():
    # Case A: Generic flaw (XSS) cannot bridge between Tenant 100 and Tenant 200
    graph_a = AttackGraph()
    n_t1 = AttackGraphNode(
        "CAP-T1", NodeType.CAPABILITY, "Cap T1",
        {"capability_type": CapabilityType.KNOWLEDGE_EXPOSURE.value, "tenant_id": "tenant-100", "descriptor": {"target_parameter": "user_id"}}
    )
    n_t2 = AttackGraphNode(
        "FND-T2", NodeType.FINDING, "Target T2",
        {"vulnerability_type": "xss", "parameter": "user_id", "tenant_id": "tenant-200"}
    )
    graph_a.add_node(n_t1)
    graph_a.add_node(n_t2)

    discovery = CandidateRelationshipEngine()
    edges_a = discovery.discover_candidate_relationships(graph_a)
    assert len(edges_a) == 0, "Discovered cross-tenant edge without authorized tenant flaw!"

    # Case B: Supported tenant-isolation flaw (BOLA/IDOR) CAN bridge tenants
    graph_b = AttackGraph()
    f_bola = AttackGraphNode(
        "FND-BOLA", NodeType.FINDING, "BOLA Finding",
        {"finding_id": "BOLA-1", "vulnerability_type": "bola", "tenant_id": "tenant-100"}
    )
    c_bola = AttackGraphNode(
        "CAP-BOLA", NodeType.CAPABILITY, "BOLA Cap",
        {"capability_type": CapabilityType.KNOWLEDGE_EXPOSURE.value, "source_finding_id": "BOLA-1", "tenant_id": "tenant-100", "descriptor": {"target_parameter": "user_id"}}
    )
    f_target = AttackGraphNode(
        "FND-TARGET", NodeType.FINDING, "Target Finding",
        {"finding_id": "TGT-1", "vulnerability_type": "bfla", "parameter": "user_id", "tenant_id": "tenant-200"}
    )
    graph_b.add_node(f_bola)
    graph_b.add_node(c_bola)
    graph_b.add_node(f_target)
    graph_b.add_edge(AttackGraphEdge("E-FND-CAP", "FND-BOLA", "CAP-BOLA", EdgeType.EXPOSES))

    edges_b = discovery.discover_candidate_relationships(graph_b)
    assert len(edges_b) == 1
    assert edges_b[0].destination_id == "FND-TARGET"


# ==============================================================================
# AC-22.2-04: Scope Boundary Enforcement
# ==============================================================================

def test_ac04_scope_boundary_enforcement():
    graph = AttackGraph()
    n1 = AttackGraphNode("F1", NodeType.FINDING, "F1", {"vulnerability_type": "v1"}, scope_status="IN_SCOPE")
    n2_out = AttackGraphNode("F2", NodeType.FINDING, "F2 Out", {"vulnerability_type": "v2"}, scope_status="OUT_OF_SCOPE")
    n3 = AttackGraphNode("F3", NodeType.FINDING, "F3", {"vulnerability_type": "v3"}, scope_status="IN_SCOPE")
    graph.add_node(n1)
    graph.add_node(n2_out)
    graph.add_node(n3)

    graph.add_edge(AttackGraphEdge("E1", "F1", "F2", EdgeType.SATISFIES_PREREQUISITE))
    graph.add_edge(AttackGraphEdge("E2", "F2", "F3", EdgeType.SATISFIES_PREREQUISITE))

    traversal = BoundedTraversalEngine()
    result = traversal.find_attack_paths(graph)

    # Path cannot traverse through out-of-scope F2
    for path in result.paths:
        assert "F2" not in path.node_ids


# ==============================================================================
# AC-22.2-05: Resource-Limit Exhaustion & Truncation Metadata
# ==============================================================================

def test_ac05_resource_limit_exhaustion():
    graph = AttackGraph()

    # Dense branching graph
    root = AttackGraphNode("ROOT", NodeType.FINDING, "Root Finding", {"vulnerability_type": "v_root"})
    graph.add_node(root)

    prev_layer = [root]
    edge_idx = 0
    # Create 3 layers with branching factor 4
    for layer in range(3):
        curr_layer = []
        for parent in prev_layer:
            for b in range(4):
                child_id = f"N_{layer}_{parent.node_id}_{b}"
                child = AttackGraphNode(child_id, NodeType.FINDING, child_id, {"vulnerability_type": "branch"})
                graph.add_node(child)
                graph.add_edge(AttackGraphEdge(f"E_{edge_idx}", parent.node_id, child_id, EdgeType.SATISFIES_PREREQUISITE))
                edge_idx += 1
                curr_layer.append(child)
        prev_layer = curr_layer

    # Set strict limits: max_candidate_paths=5, max_visited_nodes=15
    engine = BoundedTraversalEngine(max_candidate_paths=5, max_visited_nodes=15)
    result = engine.find_attack_paths(graph)

    # Must truncate gracefully
    assert result.traversal_truncated is True
    assert result.truncated_reason in ("PATH_BUDGET_EXCEEDED", "NODE_BUDGET_EXCEEDED", "EDGE_BUDGET_EXCEEDED")
    assert len(result.paths) <= 5


# ==============================================================================
# AC-22.2-06: Connectivity Non-Validation Guarantee
# ==============================================================================

def test_ac06_connectivity_non_validation_guarantee():
    graph = AttackGraph()
    n1 = AttackGraphNode("F1", NodeType.FINDING, "F1", {"vulnerability_type": "idor", "severity": "HIGH"})
    c1 = AttackGraphNode("C1", NodeType.CAPABILITY, "C1", {"capability_type": CapabilityType.KNOWLEDGE_EXPOSURE.value})
    n2 = AttackGraphNode("F2", NodeType.FINDING, "F2", {"vulnerability_type": "bfla", "severity": "MEDIUM"})
    graph.add_node(n1)
    graph.add_node(c1)
    graph.add_node(n2)

    graph.add_edge(AttackGraphEdge("E1", "F1", "C1", EdgeType.EXPOSES, state=RelationshipState.CONTEXTUALLY_ALIGNED))
    graph.add_edge(AttackGraphEdge("E2", "C1", "F2", EdgeType.SATISFIES_PREREQUISITE, state=RelationshipState.CONTEXTUALLY_ALIGNED))

    engine = BoundedTraversalEngine()
    result = engine.find_attack_paths(graph)

    assert len(result.paths) == 1
    path = result.paths[0]
    # State MUST be HYPOTHESIS
    assert path.state == ChainState.HYPOTHESIS
    assert path.state != ChainState.FULLY_VALIDATED
    assert path.state != ChainState.PARTIALLY_VALIDATED


# ==============================================================================
# AC-22.2-07: Stale Capability Pruning
# ==============================================================================

def test_ac07_stale_capability_pruning():
    graph = AttackGraph()
    n1 = AttackGraphNode("F1", NodeType.FINDING, "F1", {"vulnerability_type": "session_fixation"})
    # Stale capability with is_expired = True
    c_stale = AttackGraphNode(
        "C_STALE", NodeType.CAPABILITY, "Expired Session",
        {"capability_type": CapabilityType.SESSION_HIJACK.value, "is_expired": True}
    )
    n2 = AttackGraphNode("F2", NodeType.FINDING, "F2", {"vulnerability_type": "account_takeover"})
    graph.add_node(n1)
    graph.add_node(c_stale)
    graph.add_node(n2)

    graph.add_edge(AttackGraphEdge("E1", "F1", "C_STALE", EdgeType.EXPOSES))
    graph.add_edge(AttackGraphEdge("E2", "C_STALE", "F2", EdgeType.AUTHENTICATES_AS))

    # Traversal should skip stale capability
    engine = BoundedTraversalEngine()
    result = engine.find_attack_paths(graph)
    assert len(result.paths) == 0


# ==============================================================================
# AC-22.2-08: Zero-Secret Assertion
# ==============================================================================

def test_ac08_zero_secret_assertion_on_emitted_paths():
    graph = AttackGraph()
    n1 = AttackGraphNode("F1", NodeType.FINDING, "F1", {"vulnerability_type": "idor", "parameter": "id"})
    c1 = AttackGraphNode(
        "C1", NodeType.CAPABILITY, "C1",
        {"capability_type": CapabilityType.KNOWLEDGE_EXPOSURE.value, "descriptor": {"format": "IDENTIFIER_DESCRIPTOR"}}
    )
    n2 = AttackGraphNode("F2", NodeType.FINDING, "F2", {"vulnerability_type": "bfla", "parameter": "id"})
    graph.add_node(n1)
    graph.add_node(c1)
    graph.add_node(n2)

    graph.add_edge(AttackGraphEdge("E1", "F1", "C1", EdgeType.EXPOSES))
    graph.add_edge(AttackGraphEdge("E2", "C1", "F2", EdgeType.SATISFIES_PREREQUISITE))

    engine = BoundedTraversalEngine()
    result = engine.find_attack_paths(graph)
    assert len(result.paths) == 1

    # Verify assert_no_raw_secrets passes on all emitted paths
    for path in result.paths:
        assert_no_raw_secrets(path.to_dict())


# ==============================================================================
# AC-22.2-09: Dangling-Edge & Malformed-Element Resilience
# ==============================================================================

def test_ac09_dangling_edge_and_malformed_element_resilience():
    graph = AttackGraph()
    n1 = AttackGraphNode("F1", NodeType.FINDING, "F1", {"vulnerability_type": "idor"})
    n2 = AttackGraphNode("F2", NodeType.FINDING, "F2", {})  # Empty/malformed attributes
    graph.add_node(n1)
    graph.add_node(n2)

    # Edge pointing to non-existent node
    dangling_edge = AttackGraphEdge("E_DANGLING", "F1", "NON_EXISTENT_DEST", EdgeType.SATISFIES_PREREQUISITE)
    # Bypass add_edge node check to simulate corrupted state
    graph._edges[dangling_edge.edge_id] = dangling_edge
    graph._out_edges.setdefault("F1", []).append(dangling_edge)

    # Valid edge
    valid_edge = AttackGraphEdge("E_VALID", "F1", "F2", EdgeType.SATISFIES_PREREQUISITE)
    graph.add_edge(valid_edge)

    engine = BoundedTraversalEngine()
    # Must not raise an exception; safely skips dangling destination
    result = engine.find_attack_paths(graph)
    assert result.examined_edges_count >= 1


# ==============================================================================
# AC-22.2-10: Cross-Platform Deterministic Output Parity
# ==============================================================================

def test_ac10_cross_platform_deterministic_parity():
    graph = AttackGraph()
    # Add multiple findings in unordered sequence
    f_b = _make_finding("BB-B", "idor", parameter="acc_id")
    f_a = _make_finding("BB-A", "idor", parameter="acc_id")
    f_c = _make_finding("BB-C", "bfla", parameter="acc_id")

    normalizer = FindingNormalizer()
    graph = normalizer.ingest_findings_into_graph([f_b, f_a, f_c], graph)

    discovery = CandidateRelationshipEngine()
    for e in discovery.discover_candidate_relationships(graph):
        graph.add_edge(e)

    engine = BoundedTraversalEngine()
    res1 = engine.find_attack_paths(graph)
    res2 = engine.find_attack_paths(graph)

    # Exact deterministic equivalence
    assert [p.path_id for p in res1.paths] == [p.path_id for p in res2.paths]
    assert [p.fingerprint for p in res1.paths] == [p.fingerprint for p in res2.paths]
    assert len(res1.paths) > 0
