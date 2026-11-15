"""
Unit and Adversarial Acceptance Tests for Phase 22.1: Finding Normalization & Capability Extraction.

Verifies:
1. Normalization of Finding into Asset, Endpoint, Finding, and Capability nodes.
2. Evidence-driven capability extraction: separating observed from inferred signals.
3. Clock-handling and freshness recalculation with skew safety window.
4. Zero-secret sanitization of finding parameters and descriptors.
5. Ingestion of findings into AttackGraph.
"""

from __future__ import annotations

import datetime
import json
import os
import tempfile
import time
import pytest

from framework.attack_path.model import (
    AttackGraph,
    CapabilityType,
    EdgeType,
    NodeType,
    RelationshipState,
)
from framework.attack_path.normalizer import FindingNormalizer
from framework.common.evidence import EvidenceStore
from framework.findings.lifecycle import FindingLifecycle
from framework.findings.schema import Finding


def _make_sample_finding(
    finding_id: str = "BB-20261115-A1B2C3",
    vulnerability_type: str = "idor",
    affected_asset: str = "app.example.com",
    affected_endpoint: str = "https://app.example.com/api/v1/users/profile",
    parameter: str = "user_id",
    evidence: list = None,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title="Insecure Direct Object Reference on User Profile",
        summary="User profile endpoint leaks victim profile data via parameter user_id",
        affected_asset=affected_asset,
        affected_endpoint=affected_endpoint,
        vulnerability_type=vulnerability_type,
        severity="HIGH",
        description="IDOR allows accessing arbitrary user records",
        root_cause="Missing authorization check on user_id parameter",
        prerequisites="Authenticated user session required",
        reproduction_steps=["1. Login as user A", "2. Request profile of user B"],
        expected_result="HTTP 403 Forbidden",
        observed_result="HTTP 200 OK with victim data",
        security_impact="Unauthorized access to victim personal data",
        remediation="Enforce object-level access control",
        scope_reference="*.example.com",
        confidence="HIGH",
        lifecycle_state=FindingLifecycle.VALIDATED,
        evidence=evidence or [],
        parameter=parameter,
    )


def test_finding_normalization_structural_nodes_and_edges():
    normalizer = FindingNormalizer(evidence_store=None)
    finding = _make_sample_finding()

    nodes, edges, capabilities = normalizer.normalize_finding(finding)

    # 1. Check generated nodes
    node_types = {n.node_type for n in nodes}
    assert NodeType.ASSET in node_types
    assert NodeType.ENDPOINT in node_types
    assert NodeType.FINDING in node_types
    assert NodeType.CAPABILITY in node_types

    # Asset Node
    asset_nodes = [n for n in nodes if n.node_type == NodeType.ASSET]
    assert len(asset_nodes) == 1
    assert asset_nodes[0].label == "app.example.com"
    assert asset_nodes[0].scope_status == "IN_SCOPE"

    # Endpoint Node
    ep_nodes = [n for n in nodes if n.node_type == NodeType.ENDPOINT]
    assert len(ep_nodes) == 1
    assert "https://app.example.com/api/v1/users/profile" in ep_nodes[0].label

    # Finding Node
    fnd_nodes = [n for n in nodes if n.node_type == NodeType.FINDING]
    assert len(fnd_nodes) == 1
    assert fnd_nodes[0].attributes["vulnerability_type"] == "idor"
    assert fnd_nodes[0].attributes["severity"] == "HIGH"

    # Capability Node
    cap_nodes = [n for n in nodes if n.node_type == NodeType.CAPABILITY]
    assert len(cap_nodes) == 1
    assert cap_nodes[0].attributes["capability_type"] == CapabilityType.KNOWLEDGE_EXPOSURE.value

    # Check edges connecting entities
    edge_types = [e.edge_type for e in edges]
    assert EdgeType.HOSTED_ON in edge_types
    assert EdgeType.TARGETS in edge_types
    assert EdgeType.EXPOSES in edge_types


def test_evidence_driven_observed_vs_inferred_capabilities(tmp_path):
    store = EvidenceStore(str(tmp_path / "evidence"))
    normalizer = FindingNormalizer(evidence_store=store)

    # Case A: Finding with NO evidence on disk -> Inferred capability
    f_inferred = _make_sample_finding(
        finding_id="BB-20261115-INFER1",
        evidence=[{"evidence_id": "EVID-NONEXISTENT"}],
    )
    _, _, caps_a = normalizer.normalize_finding(f_inferred)
    assert len(caps_a) == 1
    assert caps_a[0].is_observed is False
    assert caps_a[0].provenance_status == "INFERRED"

    # Case B: Finding with valid HTTP capture in EvidenceStore -> Observed capability
    capture_meta = store.save_http_capture(
        request_text="GET /api/v1/users/profile?user_id=101 HTTP/1.1\nHost: app.example.com\n\n",
        response_text="HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"user_id\": 101, \"email\": \"victim@example.com\"}",
        metadata={"evidence_class": "CALLER_SUPPLIED"},
    )
    ev_id = capture_meta["evidence_id"]

    f_observed = _make_sample_finding(
        finding_id="BB-20261115-OBSERV1",
        evidence=[{"evidence_id": ev_id}],
    )
    _, _, caps_b = normalizer.normalize_finding(f_observed)
    assert len(caps_b) == 1
    assert caps_b[0].is_observed is True
    assert caps_b[0].provenance_status == "SIMULATED"
    assert caps_b[0].evidence_ref == ev_id
    assert len(caps_b[0].evidence_sha256) == 64


def test_clock_handling_and_freshness_recalculation():
    normalizer = FindingNormalizer(evidence_store=None)
    # Session fixation yields a session capability with 3600s TTL
    finding = _make_sample_finding(
        finding_id="BB-20261115-SESS1",
        vulnerability_type="session_fixation",
    )

    t_created = 1000000.0
    nodes, edges, caps = normalizer.normalize_finding(
        finding, current_time=t_created, clock_skew_seconds=30.0
    )
    assert len(caps) == 1
    cap = caps[0]
    assert cap.ttl_seconds == 3600.0

    # 1. Check freshness immediately: fresh
    assert cap.check_freshness(current_time=t_created, skew_seconds=30.0) is True
    assert cap.is_expired is False

    # 2. Check freshness at 3500s: fresh
    assert cap.check_freshness(current_time=t_created + 3500.0, skew_seconds=30.0) is True
    assert cap.is_expired is False

    # 3. Check freshness at 3580s: within 30s skew window of 3600s expiration -> expired
    # (3580 >= 3600 - 30 = 3570)
    assert cap.check_freshness(current_time=t_created + 3580.0, skew_seconds=30.0) is False
    assert cap.is_expired is True

    # 4. Check freshness at 4000s: well past expiration -> expired
    assert cap.check_freshness(current_time=t_created + 4000.0, skew_seconds=30.0) is False
    assert cap.is_expired is True


def test_zero_secret_sanitization_in_descriptors():
    normalizer = FindingNormalizer(evidence_store=None)
    # Finding containing a potential sensitive token in the parameter
    finding = _make_sample_finding(
        finding_id="BB-20261115-TOKEN1",
        vulnerability_type="token_leak",
        parameter="access_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.secret123",
    )

    nodes, edges, caps = normalizer.normalize_finding(finding)

    # Verify that all generated nodes pass assert_no_raw_secrets
    for node in nodes:
        assert "eyJhbGciOiJIUzI1NiJ9" not in json.dumps(node.to_dict())
        assert "secret123" not in json.dumps(node.to_dict())


def test_batch_ingest_findings_into_attack_graph():
    graph = AttackGraph()
    normalizer = FindingNormalizer(evidence_store=None)

    f1 = _make_sample_finding(
        finding_id="BB-20261115-001",
        vulnerability_type="idor",
        affected_asset="api.example.com",
        affected_endpoint="https://api.example.com/api/v1/users/profile",
    )
    f2 = _make_sample_finding(
        finding_id="BB-20261115-002",
        vulnerability_type="open_redirect",
        affected_asset="auth.example.com",
        affected_endpoint="https://auth.example.com/oauth/redirect",
    )

    graph = normalizer.ingest_findings_into_graph([f1, f2], graph)

    # Graph contains 2 assets, 2 endpoints, 2 findings, 2 capabilities = 8 nodes
    assert graph.node_count() == 8
    assert len(graph.get_nodes_by_type(NodeType.ASSET)) == 2
    assert len(graph.get_nodes_by_type(NodeType.ENDPOINT)) == 2
    assert len(graph.get_nodes_by_type(NodeType.FINDING)) == 2
    assert len(graph.get_nodes_by_type(NodeType.CAPABILITY)) == 2

    # Edges: 2 HOSTED_ON + 2 TARGETS + 2 EXPOSES = 6 edges
    assert graph.edge_count() == 6
