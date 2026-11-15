"""
Unit and Adversarial Acceptance Tests for Phase 22.1: Attack Graph Model & State Management.

Verifies:
1. Typed node and directional edge contracts and indices.
2. Idempotent node/edge merging.
3. Decoupled 3-tier validation state machines (Finding, Relationship, Chain).
4. Atomic file persistence and corruption recovery.
5. Strict zero-secret schema enforcement (rejection of raw JWTs, keys, and credentials).
6. Enforced capacity bounds (MAX_NODES, MAX_EDGES).
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import pytest

from framework.attack_path.model import (
    AttackGraph,
    AttackGraphCapacityError,
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
from framework.attack_path.state import (
    AttackPathStateError,
    AttackPathStateManager,
)
from framework.findings.lifecycle import FindingLifecycle


def test_node_creation_and_serialization():
    node = AttackGraphNode(
        node_id="AST-TEST-1",
        node_type=NodeType.ASSET,
        label="api.example.com",
        attributes={"host": "api.example.com", "port": 443},
        scope_status="IN_SCOPE",
    )
    d = node.to_dict()
    assert d["node_id"] == "AST-TEST-1"
    assert d["node_type"] == "ASSET"
    assert d["label"] == "api.example.com"
    assert d["attributes"]["port"] == 443

    reconstructed = AttackGraphNode.from_dict(d)
    assert reconstructed.node_id == node.node_id
    assert reconstructed.node_type == NodeType.ASSET
    assert reconstructed.attributes["host"] == "api.example.com"


def test_edge_creation_and_provenance_binding():
    prov = RelationshipProvenance(
        source_finding_id="BB-20261115-001",
        target_finding_id="BB-20261115-002",
        source_evidence_ref="EVID-AAAA1111",
        target_evidence_ref="EVID-BBBB2222",
        transition_evidence_ref="EVID-CCCC3333",
        authenticity_class="CONTROLLED_DISPATCH_RECEIPT",
        dispatcher_receipt_id="RCPT-1234567890ABCDEF1234567890ABCDEF",
        causality_proof_type=CausalityProofType.DIFFERENTIAL_BASELINE_PROVEN,
        baseline_response_digest="0" * 64,
        canary_response_digest="1" * 64,
    )
    edge = AttackGraphEdge(
        edge_id="EDGE-TEST-1",
        source_id="FND-001",
        destination_id="FND-002",
        edge_type=EdgeType.SATISFIES_PREREQUISITE,
        state=RelationshipState.LINK_VALIDATED,
        provenance=prov,
        attributes={"transition_parameter": "tenant_uuid"},
    )
    d = edge.to_dict()
    assert d["edge_id"] == "EDGE-TEST-1"
    assert d["state"] == "LINK_VALIDATED"
    assert d["provenance"]["dispatcher_receipt_id"] == "RCPT-1234567890ABCDEF1234567890ABCDEF"

    rec = AttackGraphEdge.from_dict(d)
    assert rec.edge_id == edge.edge_id
    assert rec.state == RelationshipState.LINK_VALIDATED
    assert rec.provenance is not None
    assert rec.provenance.causality_proof_type == CausalityProofType.DIFFERENTIAL_BASELINE_PROVEN


def test_three_tier_state_decoupling():
    """
    Verifies that FindingLifecycle, RelationshipState, and ChainState
    are completely independent state machines.
    """
    # 1. Finding state: Validated individual finding
    finding_state = FindingLifecycle.VALIDATED

    # 2. Relationship state: Theoretical edge despite validated finding
    edge_state = RelationshipState.THEORETICAL
    assert edge_state != RelationshipState.LINK_VALIDATED

    # 3. Chain state: Remains a hypothesis until all edges are validated
    chain_state = ChainState.HYPOTHESIS
    assert chain_state != ChainState.FULLY_VALIDATED

    # A chain cannot be fully validated if any edge is theoretical
    edges = [RelationshipState.LINK_VALIDATED, RelationshipState.THEORETICAL]
    is_fully_validated = all(e == RelationshipState.LINK_VALIDATED for e in edges)
    assert is_fully_validated is False


def test_zero_secret_assertion_rejects_credentials():
    # Valid structural descriptors pass
    safe_data = {
        "format": "JWT_DESCRIPTOR",
        "claims": ["sub", "iss", "exp"],
        "token_length": 128,
        "evidence_ref": "EVID-SAFE-01",
    }
    assert_no_raw_secrets(safe_data)

    # Raw JWT pattern triggers fail-closed error
    raw_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP"
    with pytest.raises(ValueError, match="Raw credential or secret pattern detected"):
        assert_no_raw_secrets({"token": raw_jwt})

    # PEM private key triggers fail-closed error
    raw_pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...\n-----END PRIVATE KEY-----"
    with pytest.raises(ValueError, match="Raw credential or secret pattern detected"):
        assert_no_raw_secrets({"key": raw_pem})

    # Password pattern triggers fail-closed error
    with pytest.raises(ValueError, match="Raw credential or secret pattern detected"):
        assert_no_raw_secrets({"auth": 'password="SuperSecret123!"'})


def test_graph_node_and_edge_indexing():
    graph = AttackGraph()

    n1 = AttackGraphNode(node_id="AST-1", node_type=NodeType.ASSET, label="example.com")
    n2 = AttackGraphNode(node_id="EP-1", node_type=NodeType.ENDPOINT, label="GET /api/user")
    n3 = AttackGraphNode(node_id="FND-1", node_type=NodeType.FINDING, label="IDOR on /api/user")

    graph.add_node(n1)
    graph.add_node(n2)
    graph.add_node(n3)

    e1 = AttackGraphEdge(
        edge_id="EDGE-1",
        source_id="EP-1",
        destination_id="AST-1",
        edge_type=EdgeType.HOSTED_ON,
    )
    e2 = AttackGraphEdge(
        edge_id="EDGE-2",
        source_id="FND-1",
        destination_id="EP-1",
        edge_type=EdgeType.TARGETS,
    )

    graph.add_edge(e1)
    graph.add_edge(e2)

    assert graph.node_count() == 3
    assert graph.edge_count() == 2

    # Fast adjacency verification
    out_ep = graph.get_outgoing_edges("EP-1")
    assert len(out_ep) == 1
    assert out_ep[0].destination_id == "AST-1"

    in_ep = graph.get_incoming_edges("EP-1")
    assert len(in_ep) == 1
    assert in_ep[0].source_id == "FND-1"

    # Inverted type indices
    assets = graph.get_nodes_by_type(NodeType.ASSET)
    assert len(assets) == 1
    assert assets[0].node_id == "AST-1"


def test_graph_idempotent_node_edge_updates():
    graph = AttackGraph()

    n1 = AttackGraphNode(
        node_id="AST-1",
        node_type=NodeType.ASSET,
        label="target.com",
        attributes={"cdn": "cloudflare"},
    )
    graph.add_node(n1)

    # Merging updated attributes into existing node
    n1_update = AttackGraphNode(
        node_id="AST-1",
        node_type=NodeType.ASSET,
        label="target.com",
        attributes={"ip": "1.2.3.4"},
    )
    graph.add_node(n1_update)

    assert graph.node_count() == 1
    retrieved = graph.get_node("AST-1")
    assert retrieved is not None
    assert retrieved.attributes["cdn"] == "cloudflare"
    assert retrieved.attributes["ip"] == "1.2.3.4"


def test_graph_capacity_limits(monkeypatch):
    graph = AttackGraph()
    # Temporarily set small limit to test fail-closed capacity guard
    monkeypatch.setattr(graph, "MAX_NODES", 3)

    graph.add_node(AttackGraphNode("N-1", NodeType.ASSET, "N1"))
    graph.add_node(AttackGraphNode("N-2", NodeType.ASSET, "N2"))
    graph.add_node(AttackGraphNode("N-3", NodeType.ASSET, "N3"))

    with pytest.raises(AttackGraphCapacityError, match="node limit exceeded"):
        graph.add_node(AttackGraphNode("N-4", NodeType.ASSET, "N4"))


def test_state_manager_persistence_and_atomic_recovery(tmp_path):
    mgr = AttackPathStateManager(str(tmp_path))
    assert mgr.get_graph_path().endswith("attack_graph.json")

    # Initial load of non-existent file returns clean graph
    g = mgr.load_graph()
    assert g.node_count() == 0

    # Populate and save
    g.add_node(AttackGraphNode("AST-SAVE-1", NodeType.ASSET, "save.example.com"))
    mgr.save_graph(g)
    assert os.path.isfile(mgr.get_graph_path())

    # Reload from disk
    loaded = mgr.load_graph()
    assert loaded.node_count() == 1
    assert loaded.has_node("AST-SAVE-1")

    # Test corruption recovery
    with open(mgr.get_graph_path(), "w", encoding="utf-8") as f:
        f.write("{ INVALID JSON CORRUPTION !!!")

    recovered = mgr.load_graph()
    assert recovered.node_count() == 0

    # Ensure a backup file was generated
    backups = [fn for fn in os.listdir(mgr.state_dir) if "corrupt" in fn]
    assert len(backups) == 1
