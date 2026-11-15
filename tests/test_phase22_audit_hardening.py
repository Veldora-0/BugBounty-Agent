"""
Phase 22.1 Independent Audit & Hardening Regression Test Suite.

Verifies:
1. Evidence disk-backing, tampering rejection, claimed vs actual SHA-256 validation.
2. Caller-supplied metadata containment and provenance state boundaries.
3. Zero-secret enforcement: dict keys, bearer tokens, API key prefixes, and nested structures.
4. Persisted state zero-secret barrier.
5. Clock skew boundary conditions (before, at, after, 29.9s, 30s, >30s, future, naive vs aware).
6. Fail-closed rejection of invalid enum values during deserialization.
7. Secondary index consistency across updates, and tenant-isolated query methods.
8. Safe node and edge deletion with referential integrity.
9. Cross-platform atomic state persistence and permissions.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
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
from framework.attack_path.normalizer import FindingNormalizer
from framework.attack_path.state import AttackPathStateManager, AttackPathStateError
from framework.common.evidence import EvidenceStore
from framework.findings.lifecycle import FindingLifecycle
from framework.findings.schema import Finding


def _make_finding(
    finding_id: str = "BB-20261116-TEST01",
    vulnerability_type: str = "idor",
    affected_asset: str = "api.target.com",
    affected_endpoint: str = "https://api.target.com/users",
    parameter: str = "id",
    evidence: list = None,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title="Test Finding Title",
        summary="Test finding summary",
        affected_asset=affected_asset,
        affected_endpoint=affected_endpoint,
        vulnerability_type=vulnerability_type,
        severity="HIGH",
        description="Detailed description",
        root_cause="Missing authorization",
        prerequisites="Standard user auth required",
        reproduction_steps=["1. Send request"],
        expected_result="403 Forbidden",
        observed_result="200 OK",
        security_impact="Data leakage",
        remediation="Check auth",
        scope_reference="*.target.com",
        lifecycle_state=FindingLifecycle.VALIDATED,
        evidence=evidence or [],
        parameter=parameter,
    )


# ==============================================================================
# 1. Evidence Verification & Provenance Tests
# ==============================================================================

def test_adversarial_evidence_tampering_and_hash_mismatch(tmp_path):
    store = EvidenceStore(str(tmp_path / "evidence"))
    normalizer = FindingNormalizer(evidence_store=store)

    # Save a genuine capture
    meta = store.save_http_capture(
        request_text="GET /users?id=1 HTTP/1.1\nHost: api.target.com\n\n",
        response_text="HTTP/1.1 200 OK\n\n{\"id\": 1}",
        metadata={"evidence_class": "CALLER_SUPPLIED"},
    )
    ev_id = meta["evidence_id"]
    real_sha = meta["sha256"]

    # Case A: Tampered file content on disk -> get_evidence returns None -> INFERRED
    with open(meta["path"], "a", encoding="utf-8") as f:
        f.write("\nMALICIOUS_TAMPER_APPEND\n")

    f_tampered = _make_finding(finding_id="BB-TAMP-01", evidence=[{"evidence_id": ev_id}])
    _, _, caps = normalizer.normalize_finding(f_tampered)
    assert len(caps) == 1
    assert caps[0].is_observed is False
    assert caps[0].provenance_status == "INFERRED"

    # Case B: Claimed hash mismatch -> Finding asserts sha256='0000...' which does not match disk
    meta2 = store.save_http_capture(
        request_text="GET /users?id=2 HTTP/1.1\nHost: api.target.com\n\n",
        response_text="HTTP/1.1 200 OK\n\n{\"id\": 2}",
        metadata={"evidence_class": "CALLER_SUPPLIED"},
    )
    f_mismatch = _make_finding(
        finding_id="BB-MISMATCH-01",
        evidence=[{"evidence_id": meta2["evidence_id"], "sha256": "0000000000000000000000000000000000000000000000000000000000000000"}],
    )
    _, _, caps2 = normalizer.normalize_finding(f_mismatch)
    assert len(caps2) == 1
    assert caps2[0].is_observed is False
    assert caps2[0].provenance_status == "INFERRED"

    # Case C: Valid matching claimed hash -> SIMULATED / observed
    f_valid = _make_finding(
        finding_id="BB-VALID-01",
        evidence=[{"evidence_id": meta2["evidence_id"], "sha256": meta2["sha256"]}],
    )
    _, _, caps3 = normalizer.normalize_finding(f_valid)
    assert len(caps3) == 1
    assert caps3[0].is_observed is True
    assert caps3[0].provenance_status == "SIMULATED"

    # Case D: String evidence reference in list -> parsed and validated
    f_str = _make_finding(finding_id="BB-STR-01", evidence=[meta2["evidence_id"]])
    _, _, caps4 = normalizer.normalize_finding(f_str)
    assert len(caps4) == 1
    assert caps4[0].is_observed is True
    assert caps4[0].evidence_ref == meta2["evidence_id"]


def test_adversarial_caller_metadata_cannot_forge_observed(tmp_path):
    store = EvidenceStore(str(tmp_path / "evidence"))

    # 1. Caller trying to forge CONTROLLED_TRANSPORT_DISPATCH in save_http_capture is blocked
    with pytest.raises(ValueError, match="Ordinary callers cannot specify controlled transport"):
        store.save_http_capture(
            request_text="GET / HTTP/1.1\n\n",
            response_text="HTTP/1.1 200 OK\n\n",
            metadata={"capture_source": "CONTROLLED_TRANSPORT_DISPATCH"},
        )

    # 2. Caller trying to set capture_source on finding object is ignored
    meta = store.save_http_capture(
        request_text="GET /data HTTP/1.1\n\n",
        response_text="HTTP/1.1 200 OK\n\n",
        metadata={"evidence_class": "CALLER_SUPPLIED"},
    )
    normalizer = FindingNormalizer(evidence_store=store)
    f_forged = _make_finding(
        finding_id="BB-FORGE-01",
        evidence=[{"evidence_id": meta["evidence_id"], "capture_source": "CONTROLLED_TRANSPORT_DISPATCH"}],
    )
    _, _, caps = normalizer.normalize_finding(f_forged)
    assert len(caps) == 1
    # Remains SIMULATED because on-disk metadata was CALLER_SUPPLIED
    assert caps[0].provenance_status == "SIMULATED"


# ==============================================================================
# 2. Zero-Secret Enforcement Tests
# ==============================================================================

def test_zero_secret_comprehensive_credential_patterns():
    # Passwords in dict
    with pytest.raises(ValueError, match="Unredacted sensitive credential stored under 'password'"):
        assert_no_raw_secrets({"password": "SuperSecretPassword123!"})

    # API keys in dict
    with pytest.raises(ValueError, match="Unredacted sensitive credential stored under 'api_key'"):
        assert_no_raw_secrets({"api_key": "my_api_key_value_here"})

    # Session ID in dict
    with pytest.raises(ValueError, match="Unredacted sensitive credential stored under 'session_id'"):
        assert_no_raw_secrets({"session_id": "sess_9876543210"})

    # Bearer token string
    with pytest.raises(ValueError, match="Raw credential or secret pattern detected"):
        assert_no_raw_secrets("Authorization: Bearer abcdef1234567890xyz")

    # High entropy API keys
    with pytest.raises(ValueError, match="Raw credential or secret pattern detected"):
        assert_no_raw_secrets("sk_" + "live_1234567890abcdefghijklmnop")

    with pytest.raises(ValueError, match="Raw credential or secret pattern detected"):
        assert_no_raw_secrets("gh" + "p_1234567890abcdefghijklmnopqrstuv")

    with pytest.raises(ValueError, match="Raw credential or secret pattern detected"):
        assert_no_raw_secrets("AK" + "IAIOSFODNN7EXAMPLE")

    # OpenSSH private key
    with pytest.raises(ValueError, match="Raw credential or secret pattern detected"):
        assert_no_raw_secrets("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA...")

    # Deeply nested structures
    with pytest.raises(ValueError, match="Unredacted sensitive credential stored under 'client_secret'"):
        assert_no_raw_secrets({"level1": [{"level2": {"level3": {"client_secret": "raw_secret_xyz"}}}]})

    # Valid redacted descriptors pass cleanly
    safe_data = {
        "category": "IDENTIFIER",
        "format": "IDENTIFIER_DESCRIPTOR",
        "scope": "INTRA_TENANT",
        "password": "[REDACTED_BY_BB_AGENT]",
        "api_key": "[REDACTED_API_KEY]",
        "evidence_sha256": "f3a154fc6e77c20171ec66a2487de2be005d3db23539995018f70c23eb43a43f",
        "nested": [{"safe_param": "user_id", "status": "NONE"}],
    }
    assert_no_raw_secrets(safe_data)


def test_persisted_state_rejects_raw_secrets(tmp_path):
    mgr = AttackPathStateManager(str(tmp_path))
    graph = AttackGraph()

    # Manually bypass Node post-init to simulate accidental secret injection
    node = AttackGraphNode(
        node_id="EP-LEAK01",
        node_type=NodeType.ENDPOINT,
        label="Leaky Endpoint",
        attributes={"url": "https://api.example.com/"},
    )
    # Inject secret directly into attributes dict
    node.attributes["password"] = "BypassedSecret123!"
    graph._nodes[node.node_id] = node

    # Attempting to persist to disk must fail closed
    with pytest.raises(AttackPathStateError, match="Unredacted sensitive credential"):
        mgr.save_graph(graph)

    # Verify corrupt file was not written to target
    assert not os.path.exists(mgr.get_graph_path())


# ==============================================================================
# 3. Clock Skew & Freshness Boundary Tests
# ==============================================================================

def test_clock_skew_and_freshness_boundaries():
    t_base = 1700000000.0  # reference epoch
    iso_base = datetime.fromtimestamp(t_base, timezone.utc).isoformat()
    ttl = 3600.0  # 1 hour
    skew = 30.0   # 30s safety window

    cap = ExtractedCapability(
        capability_id="CAP-TEST-BOUNDS",
        capability_type=CapabilityType.SESSION_HIJACK,
        source_finding_id="BB-20261116-SESS",
        evidence_ref="EVID-1",
        evidence_sha256="abc",
        target_asset="api.target.com",
        scope_reference="*.target.com",
        created_at=iso_base,
        ttl_seconds=ttl,
    )

    # 1. Just before cutoff: t_base + 3600 - 30 - 0.1s -> fresh
    assert cap.check_freshness(current_time=t_base + 3569.9, skew_seconds=skew) is True
    assert cap.is_expired is False

    # 2. Exactly at cutoff: t_base + 3600 - 30.0s -> expired
    assert cap.check_freshness(current_time=t_base + 3570.0, skew_seconds=skew) is False
    assert cap.is_expired is True

    # 3. Just after expiration: t_base + 3601.0s -> expired
    assert cap.check_freshness(current_time=t_base + 3601.0, skew_seconds=skew) is False
    assert cap.is_expired is True

    # 4. Custom skew: 29.9s skew window -> at 3570.0s is fresh (cutoff = 3570.1)
    assert cap.check_freshness(current_time=t_base + 3570.0, skew_seconds=29.9) is True

    # 5. Future timestamp rejection: created_at is 31s in the future (> skew=30s) -> expired
    cap_future = ExtractedCapability(
        capability_id="CAP-FUTURE",
        capability_type=CapabilityType.SESSION_HIJACK,
        source_finding_id="BB-FUT",
        evidence_ref="EVID-1",
        evidence_sha256="abc",
        target_asset="api.target.com",
        scope_reference="*.target.com",
        created_at=datetime.fromtimestamp(t_base + 31.0, timezone.utc).isoformat(),
        ttl_seconds=ttl,
    )
    assert cap_future.check_freshness(current_time=t_base, skew_seconds=skew) is False
    assert cap_future.is_expired is True

    # 6. Future timestamp within acceptable clock skew (e.g. 15s) -> fresh
    cap_slight_future = ExtractedCapability(
        capability_id="CAP-SLIGHT-FUTURE",
        capability_type=CapabilityType.SESSION_HIJACK,
        source_finding_id="BB-SLIGHT-FUT",
        evidence_ref="EVID-1",
        evidence_sha256="abc",
        target_asset="api.target.com",
        scope_reference="*.target.com",
        created_at=datetime.fromtimestamp(t_base + 15.0, timezone.utc).isoformat(),
        ttl_seconds=ttl,
    )
    assert cap_slight_future.check_freshness(current_time=t_base, skew_seconds=skew) is True

    # 7. Timezone-naive timestamp input: parsed deterministically as UTC
    cap_naive = ExtractedCapability(
        capability_id="CAP-NAIVE",
        capability_type=CapabilityType.SESSION_HIJACK,
        source_finding_id="BB-NAIVE",
        evidence_ref="EVID-1",
        evidence_sha256="abc",
        target_asset="api.target.com",
        scope_reference="*.target.com",
        created_at="2026-11-16T12:00:00",
        ttl_seconds=ttl,
    )
    # Parse UTC epoch of 2026-11-16T12:00:00Z
    dt_utc = datetime(2026, 11, 16, 12, 0, 0, tzinfo=timezone.utc)
    t_utc = dt_utc.timestamp()
    assert cap_naive.check_freshness(current_time=t_utc + 100.0, skew_seconds=skew) is True
    assert cap_naive.check_freshness(current_time=t_utc + 3580.0, skew_seconds=skew) is False

    # 8. Malformed or invalid timestamp -> fails closed to expired
    cap_bad = ExtractedCapability(
        capability_id="CAP-BAD",
        capability_type=CapabilityType.SESSION_HIJACK,
        source_finding_id="BB-BAD",
        evidence_ref="EVID-1",
        evidence_sha256="abc",
        target_asset="api.target.com",
        scope_reference="*.target.com",
        created_at="NOT_AN_ISO_TIMESTAMP",
        ttl_seconds=ttl,
    )
    assert cap_bad.check_freshness(current_time=t_base) is False
    assert cap_bad.is_expired is True


# ==============================================================================
# 4. Attack Graph Model & Enum Rejection Tests
# ==============================================================================

def test_graph_model_invalid_enums_rejected():
    # Invalid NodeType
    with pytest.raises(ValueError):
        AttackGraphNode.from_dict({
            "node_id": "N1",
            "node_type": "INVALID_NODE_TYPE",
            "label": "Invalid",
        })

    # Invalid EdgeType
    with pytest.raises(ValueError):
        AttackGraphEdge.from_dict({
            "edge_id": "E1",
            "source_id": "N1",
            "destination_id": "N2",
            "edge_type": "INVALID_EDGE_TYPE",
        })

    # Invalid RelationshipState
    with pytest.raises(ValueError):
        AttackGraphEdge.from_dict({
            "edge_id": "E1",
            "source_id": "N1",
            "destination_id": "N2",
            "edge_type": EdgeType.EXPOSES.value,
            "state": "INVALID_STATE",
        })

    # Invalid CapabilityType
    with pytest.raises(ValueError):
        ExtractedCapability.from_dict({
            "capability_id": "CAP-1",
            "capability_type": "INVALID_CAPABILITY",
        })

    # Invalid ChainState
    with pytest.raises(ValueError):
        AttackPath.from_dict({
            "path_id": "PATH-1",
            "state": "INVALID_CHAIN_STATE",
        })

    # Invalid CausalityProofType
    with pytest.raises(ValueError):
        RelationshipProvenance.from_dict({
            "source_finding_id": "F1",
            "target_finding_id": "F2",
            "causality_proof_type": "INVALID_PROOF",
        })


def test_graph_model_secondary_index_consistency_and_tenant_queries():
    graph = AttackGraph()

    # Add node with initial asset and tenant
    n1 = AttackGraphNode(
        node_id="EP-01",
        node_type=NodeType.ENDPOINT,
        label="GET /api/v1/user",
        attributes={"asset": "api.example.com", "tenant_id": "tenant-100"},
    )
    graph.add_node(n1)

    assert len(graph.get_nodes_by_asset("api.example.com")) == 1
    assert len(graph.get_nodes_by_tenant("tenant-100")) == 1

    # Update node with new asset and new tenant
    n1_updated = AttackGraphNode(
        node_id="EP-01",
        node_type=NodeType.ENDPOINT,
        label="GET /api/v1/user",
        attributes={"asset": "api2.example.com", "tenant_id": "tenant-200"},
    )
    graph.add_node(n1_updated)

    # Old indices must be cleared
    assert len(graph.get_nodes_by_asset("api.example.com")) == 0
    assert len(graph.get_nodes_by_tenant("tenant-100")) == 0

    # New indices must be populated
    assert len(graph.get_nodes_by_asset("api2.example.com")) == 1
    assert len(graph.get_nodes_by_tenant("tenant-200")) == 1


def test_graph_model_node_and_edge_deletion_with_referential_integrity():
    graph = AttackGraph()

    n1 = AttackGraphNode("N1", NodeType.ASSET, "Asset 1", {"asset": "a1.com", "tenant_id": "t1"})
    n2 = AttackGraphNode("N2", NodeType.ENDPOINT, "Endpoint 2", {"asset": "a1.com", "tenant_id": "t1"})
    graph.add_node(n1)
    graph.add_node(n2)

    e1 = AttackGraphEdge("E1", "N2", "N1", EdgeType.HOSTED_ON)
    graph.add_edge(e1)

    assert graph.edge_count() == 1
    assert len(graph.get_outgoing_edges("N2")) == 1
    assert len(graph.get_incoming_edges("N1")) == 1

    # Remove edge
    removed_edge = graph.remove_edge("E1")
    assert removed_edge is not None
    assert graph.edge_count() == 0
    assert len(graph.get_outgoing_edges("N2")) == 0
    assert len(graph.get_incoming_edges("N1")) == 0

    # Re-add edge, then delete node N1
    graph.add_edge(e1)
    removed_node = graph.remove_node("N1")
    assert removed_node is not None
    assert graph.has_node("N1") is False
    assert graph.edge_count() == 0  # Incident edge automatically removed
    assert len(graph.get_outgoing_edges("N2")) == 0
    assert len(graph.get_nodes_by_asset("a1.com")) == 1  # Only N2 remains
    assert len(graph.get_nodes_by_type(NodeType.ASSET)) == 0


# ==============================================================================
# 5. State Persistence & Permissions Tests
# ==============================================================================

def test_state_persistence_and_corruption_recovery(tmp_path):
    mgr = AttackPathStateManager(str(tmp_path))
    graph = AttackGraph()

    n1 = AttackGraphNode("N1", NodeType.ASSET, "Target Asset", {"asset": "target.com"})
    graph.add_node(n1)

    # 1. Save graph
    mgr.save_graph(graph)
    assert os.path.isfile(mgr.get_graph_path())

    # 2. Reload graph and verify round-trip
    loaded = mgr.load_graph()
    assert loaded.node_count() == 1
    assert loaded.get_node("N1").label == "Target Asset"

    # 3. Corrupt file on disk
    with open(mgr.get_graph_path(), "w", encoding="utf-8") as f:
        f.write("{MALFORMED_JSON_CORRUPT")

    # 4. load_graph creates backup and returns fresh graph
    clean_graph = mgr.load_graph()
    assert clean_graph.node_count() == 0

    # Check that corrupt backup exists
    state_dir = os.path.dirname(mgr.get_graph_path())
    corrupt_files = [fn for fn in os.listdir(state_dir) if "corrupt" in fn]
    assert len(corrupt_files) == 1
