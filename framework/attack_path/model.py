"""
Phase 22.1: Attack Graph Model & Semantic Relationships.

Defines the typed graph primitives, node and edge representations,
decoupled relationship and chain state machines, evidence-driven capability contracts,
and zero-secret graph representation for Cross-Engine Attack-Path Correlation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple


# ==============================================================================
# Enums
# ==============================================================================

class NodeType(str, Enum):
    """Canonical attack surface node categories."""
    ASSET = "ASSET"              # Physical / virtual host (domain, IP, port)
    ENDPOINT = "ENDPOINT"        # HTTP endpoint / route (method + path)
    PRINCIPAL = "PRINCIPAL"      # Security identity / role / tenant
    FINDING = "FINDING"          # Normalized security vulnerability
    CAPABILITY = "CAPABILITY"    # Derived attacker capability or knowledge


class EdgeType(str, Enum):
    """Directional semantic relationships in attack graph."""
    EXPOSES = "EXPOSES"                                 # Finding / Endpoint -> Capability
    SATISFIES_PREREQUISITE = "SATISFIES_PREREQUISITE"   # Capability -> Finding
    AUTHENTICATES_AS = "AUTHENTICATES_AS"               # Capability / Token -> Principal
    CROSSES_BOUNDARY = "CROSSES_BOUNDARY"               # Finding / Action -> Target / Tenant
    HOSTED_ON = "HOSTED_ON"                             # Endpoint -> Asset
    TARGETS = "TARGETS"                                 # Finding -> Endpoint
    DEPENDS_ON = "DEPENDS_ON"                           # Prerequisite dependency


class RelationshipState(str, Enum):
    """
    Tier B State Machine: Independent lifecycle for a directed link between findings.
    A validated individual finding does NOT imply a validated relationship.
    """
    THEORETICAL = "THEORETICAL"                   # Syntactic / schema compatibility only
    CONTEXTUALLY_ALIGNED = "CONTEXTUALLY_ALIGNED" # Matching scope, tenancy, and protocol
    LINK_VALIDATED = "LINK_VALIDATED"             # Verified on-disk transition evidence (E_A->B)
    LINK_REFUTED = "LINK_REFUTED"                 # Testing proved output cannot satisfy input


class ChainState(str, Enum):
    """
    Tier C State Machine: Independent lifecycle for an end-to-end composite attack path.
    A chain is FULLY_VALIDATED if and only if EVERY edge is LINK_VALIDATED.
    """
    HYPOTHESIS = "HYPOTHESIS"                     # Graph path exists theoretically
    PARTIALLY_VALIDATED = "PARTIALLY_VALIDATED"   # >=1 edge validated, others theoretical
    FULLY_VALIDATED = "FULLY_VALIDATED"           # All edges validated with empirical evidence
    BLOCKED = "BLOCKED"                           # Path interrupted by control or scope exclusion
    REFUTED = "REFUTED"                           # End-to-end chain demonstrated impossible


class CapabilityType(str, Enum):
    """Attacker capabilities yielded by vulnerability findings."""
    KNOWLEDGE_EXPOSURE = "KNOWLEDGE_EXPOSURE"     # Disclosed internal IDs, paths, tenant IDs
    SESSION_HIJACK = "SESSION_HIJACK"             # Fixated, hijacked, or forged session
    TOKEN_ACQUISITION = "TOKEN_ACQUISITION"       # API key, OAuth token, reset token
    SSRF_PIVOT = "SSRF_PIVOT"                     # Internal network / cloud metadata access
    OPEN_REDIRECT = "OPEN_REDIRECT"               # Arbitrary external redirect vector
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION" # Role transition (e.g. User -> Admin)
    ARBITRARY_FILE_READ = "ARBITRARY_FILE_READ"   # Local file exposure / traversal
    WORKFLOW_BYPASS = "WORKFLOW_BYPASS"           # Business logic / stage sequence skip


class CausalityProofType(str, Enum):
    """Methodology proving that Finding A caused the state change in Finding B."""
    DIFFERENTIAL_BASELINE_PROVEN = "DIFFERENTIAL_BASELINE_PROVEN"
    CANARY_INJECTED_MATCH = "CANARY_INJECTED_MATCH"
    PASSIVE_INVARIANT = "PASSIVE_INVARIANT"
    UNVERIFIED_THEORETICAL = "UNVERIFIED_THEORETICAL"


# ==============================================================================
# Zero-Secret Sanitization & Assertions
# ==============================================================================

_SECRET_PATTERNS = [
    re.compile(r"\beyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)?\b"),  # JWT
    re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----", re.IGNORECASE),       # PEM Private Key
    re.compile(r"(?i)(?:password|passwd|pwd|client_secret|secret_key)\s*[:=]\s*['\"][^\s'\"]{6,}['\"]"),
]


def assert_no_raw_secrets(data: Any, path: str = "node") -> None:
    """
    Strict assertion ensuring graph nodes, edges, and descriptors never contain raw credentials,
    unredacted JWT signatures, or private keys. Raises ValueError fail-closed if detected.
    """
    if isinstance(data, str):
        for pat in _SECRET_PATTERNS:
            if pat.search(data):
                raise ValueError(
                    f"Security violation at '{path}': Raw credential or secret pattern detected in graph data. "
                    "Graph nodes must only store sanitized structural descriptors or evidence pointers."
                )
    elif isinstance(data, dict):
        for k, v in data.items():
            assert_no_raw_secrets(k, f"{path}.key({k})")
            assert_no_raw_secrets(v, f"{path}.{k}")
    elif isinstance(data, (list, tuple, set)):
        for idx, item in enumerate(data):
            assert_no_raw_secrets(item, f"{path}[{idx}]")


# ==============================================================================
# Provenance & Capability Contracts
# ==============================================================================

@dataclass(frozen=True)
class RelationshipProvenance:
    """
    Cryptographic and empirical evidence binding for a validated edge (LINK_VALIDATED).
    Separates byte integrity from authenticity and demonstrated causality.
    """
    source_finding_id: str
    target_finding_id: str
    source_evidence_ref: str              # Evidence ID for Finding A in EvidenceStore
    target_evidence_ref: str              # Evidence ID for Finding B in EvidenceStore
    transition_evidence_ref: Optional[str] = None  # Direct request evidence applying A's output to B
    authenticity_class: str = "CALLER_SUPPLIED"    # "CONTROLLED_DISPATCH_RECEIPT", "APPLICATION_OBSERVATION"
    dispatcher_receipt_id: Optional[str] = None    # RCPT-<32hex> if actively dispatched via Phase 21
    causality_proof_type: CausalityProofType = CausalityProofType.UNVERIFIED_THEORETICAL
    baseline_response_digest: Optional[str] = None # SHA-256 without Step A output
    canary_response_digest: Optional[str] = None   # SHA-256 with Step A output (proving state delta)
    verified_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_finding_id": self.source_finding_id,
            "target_finding_id": self.target_finding_id,
            "source_evidence_ref": self.source_evidence_ref,
            "target_evidence_ref": self.target_evidence_ref,
            "transition_evidence_ref": self.transition_evidence_ref,
            "authenticity_class": self.authenticity_class,
            "dispatcher_receipt_id": self.dispatcher_receipt_id,
            "causality_proof_type": self.causality_proof_type.value,
            "baseline_response_digest": self.baseline_response_digest,
            "canary_response_digest": self.canary_response_digest,
            "verified_at": self.verified_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RelationshipProvenance:
        proof_str = data.get("causality_proof_type", CausalityProofType.UNVERIFIED_THEORETICAL.value)
        try:
            proof = CausalityProofType(proof_str)
        except ValueError:
            proof = CausalityProofType.UNVERIFIED_THEORETICAL
        return cls(
            source_finding_id=data.get("source_finding_id", ""),
            target_finding_id=data.get("target_finding_id", ""),
            source_evidence_ref=data.get("source_evidence_ref", ""),
            target_evidence_ref=data.get("target_evidence_ref", ""),
            transition_evidence_ref=data.get("transition_evidence_ref"),
            authenticity_class=data.get("authenticity_class", "CALLER_SUPPLIED"),
            dispatcher_receipt_id=data.get("dispatcher_receipt_id"),
            causality_proof_type=proof,
            baseline_response_digest=data.get("baseline_response_digest"),
            canary_response_digest=data.get("canary_response_digest"),
            verified_at=data.get("verified_at"),
        )


@dataclass
class ExtractedCapability:
    """
    Evidence-driven attacker capability or knowledge yielded by a finding.
    Never stores raw secrets; preserves freshness and provenance.
    """
    capability_id: str                      # Deterministic CAP-<sha256>
    capability_type: CapabilityType
    source_finding_id: str                  # Finding ID (BB-YYYYMMDD-XXXXXX)
    evidence_ref: str                       # Mandatory evidence ID in EvidenceStore
    evidence_sha256: str                    # Byte SHA-256 digest of evidence file
    target_asset: str                       # Normalized target asset/host
    scope_reference: str                    # Scope rule reference (scope.yaml)
    is_observed: bool = False               # True ONLY if concrete value observed in evidence
    provenance_status: str = "INFERRED"     # "OBSERVED", "INFERRED", "SIMULATED"
    principal_context: Optional[str] = None # e.g. "role:user_a", "tenant:101"
    session_ref: Optional[str] = None       # Associated session reference
    yielded_descriptor: Dict[str, Any] = field(default_factory=dict)
    preconditions_required: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ttl_seconds: Optional[float] = None     # Optional expiration lifetime
    is_expired: bool = False

    def __post_init__(self) -> None:
        assert_no_raw_secrets(self.yielded_descriptor, "ExtractedCapability.yielded_descriptor")
        assert_no_raw_secrets(self.preconditions_required, "ExtractedCapability.preconditions_required")

    def check_freshness(self, current_time: Optional[float] = None, skew_seconds: float = 30.0) -> bool:
        """
        Dynamically recalculates freshness using monotonic/epoch comparison with a skew window.
        Returns True if fresh (valid); False if expired.
        """
        if self.ttl_seconds is None:
            self.is_expired = False
            return True

        now_ts = current_time if current_time is not None else time.time()
        try:
            # Parse created_at ISO timestamp
            dt = datetime.fromisoformat(self.created_at.replace("Z", "+00:00"))
            created_ts = dt.timestamp()
        except Exception:
            self.is_expired = True
            return False

        # If current time exceeds expiration minus skew safety window
        if now_ts >= (created_ts + self.ttl_seconds - skew_seconds):
            self.is_expired = True
            return False

        self.is_expired = False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "capability_type": self.capability_type.value,
            "source_finding_id": self.source_finding_id,
            "evidence_ref": self.evidence_ref,
            "evidence_sha256": self.evidence_sha256,
            "target_asset": self.target_asset,
            "scope_reference": self.scope_reference,
            "is_observed": self.is_observed,
            "provenance_status": self.provenance_status,
            "principal_context": self.principal_context,
            "session_ref": self.session_ref,
            "yielded_descriptor": dict(self.yielded_descriptor),
            "preconditions_required": dict(self.preconditions_required),
            "created_at": self.created_at,
            "ttl_seconds": self.ttl_seconds,
            "is_expired": self.is_expired,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExtractedCapability:
        cap_type_str = data.get("capability_type", CapabilityType.KNOWLEDGE_EXPOSURE.value)
        try:
            cap_type = CapabilityType(cap_type_str)
        except ValueError:
            cap_type = CapabilityType.KNOWLEDGE_EXPOSURE

        return cls(
            capability_id=data["capability_id"],
            capability_type=cap_type,
            source_finding_id=data.get("source_finding_id", ""),
            evidence_ref=data.get("evidence_ref", ""),
            evidence_sha256=data.get("evidence_sha256", ""),
            target_asset=data.get("target_asset", ""),
            scope_reference=data.get("scope_reference", ""),
            is_observed=bool(data.get("is_observed", False)),
            provenance_status=data.get("provenance_status", "INFERRED"),
            principal_context=data.get("principal_context"),
            session_ref=data.get("session_ref"),
            yielded_descriptor=data.get("yielded_descriptor", {}) or {},
            preconditions_required=data.get("preconditions_required", {}) or {},
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            ttl_seconds=data.get("ttl_seconds"),
            is_expired=bool(data.get("is_expired", False)),
        )


# ==============================================================================
# Graph Node & Edge Models
# ==============================================================================

@dataclass
class AttackGraphNode:
    """Represents an attack surface entity in the correlation graph."""
    node_id: str                      # Canonical identifier (e.g. AST-..., EP-..., FND-...)
    node_type: NodeType
    label: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    scope_status: str = "IN_SCOPE"    # "IN_SCOPE", "OUT_OF_SCOPE", "CONTEXTUAL_TIER1"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        assert_no_raw_secrets(self.attributes, f"AttackGraphNode({self.node_id}).attributes")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "label": self.label,
            "attributes": dict(self.attributes),
            "scope_status": self.scope_status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AttackGraphNode:
        nt_str = data.get("node_type", NodeType.ASSET.value)
        try:
            nt = NodeType(nt_str)
        except ValueError:
            nt = NodeType.ASSET
        return cls(
            node_id=data["node_id"],
            node_type=nt,
            label=data.get("label", data["node_id"]),
            attributes=data.get("attributes", {}) or {},
            scope_status=data.get("scope_status", "IN_SCOPE"),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            updated_at=data.get("updated_at", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class AttackGraphEdge:
    """Represents a directional relationship between two attack surface entities."""
    edge_id: str                      # Deterministic EDGE-<sha256(source:dest:type)>
    source_id: str
    destination_id: str
    edge_type: EdgeType
    state: RelationshipState = RelationshipState.THEORETICAL
    provenance: Optional[RelationshipProvenance] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        assert_no_raw_secrets(self.attributes, f"AttackGraphEdge({self.edge_id}).attributes")

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "destination_id": self.destination_id,
            "edge_type": self.edge_type.value,
            "state": self.state.value,
            "attributes": dict(self.attributes),
            "created_at": self.created_at,
        }
        if self.provenance:
            data["provenance"] = self.provenance.to_dict()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AttackGraphEdge:
        et_str = data.get("edge_type", EdgeType.DEPENDS_ON.value)
        try:
            et = EdgeType(et_str)
        except ValueError:
            et = EdgeType.DEPENDS_ON

        st_str = data.get("state", RelationshipState.THEORETICAL.value)
        try:
            st = RelationshipState(st_str)
        except ValueError:
            st = RelationshipState.THEORETICAL

        prov = None
        if data.get("provenance") and isinstance(data["provenance"], dict):
            prov = RelationshipProvenance.from_dict(data["provenance"])

        return cls(
            edge_id=data["edge_id"],
            source_id=data["source_id"],
            destination_id=data["destination_id"],
            edge_type=et,
            state=st,
            provenance=prov,
            attributes=data.get("attributes", {}) or {},
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )


# ==============================================================================
# Attack Graph Container
# ==============================================================================

class AttackGraphCapacityError(ValueError):
    """Raised when attack graph exceeds bounded capacity limits."""
    pass


class AttackGraph:
    """
    Indexed, directed multigraph for attack-path correlation.
    Enforces maximum node and edge budgets, deterministic indexing, and fast adjacency.
    """
    MAX_NODES = 5000
    MAX_EDGES = 25000

    def __init__(self) -> None:
        self._nodes: Dict[str, AttackGraphNode] = {}
        self._edges: Dict[str, AttackGraphEdge] = {}

        # Fast lookup indices
        self._out_edges: Dict[str, List[AttackGraphEdge]] = {}
        self._in_edges: Dict[str, List[AttackGraphEdge]] = {}
        self._by_type: Dict[NodeType, Set[str]] = {t: set() for t in NodeType}
        self._by_asset: Dict[str, Set[str]] = {}
        self._by_tenant: Dict[str, Set[str]] = {}

    def add_node(self, node: AttackGraphNode) -> AttackGraphNode:
        """Inserts or merges an entity node in the graph."""
        if node.node_id in self._nodes:
            existing = self._nodes[node.node_id]
            existing.attributes.update(node.attributes)
            assert_no_raw_secrets(existing.attributes, f"add_node({node.node_id})")
            existing.updated_at = datetime.now(timezone.utc).isoformat()
            if node.scope_status != "IN_SCOPE":
                existing.scope_status = node.scope_status
            return existing

        if len(self._nodes) >= self.MAX_NODES:
            raise AttackGraphCapacityError(
                f"Attack graph node limit exceeded ({self.MAX_NODES}). Capacity budget enforced."
            )

        self._nodes[node.node_id] = node
        self._by_type[node.node_type].add(node.node_id)
        self._out_edges.setdefault(node.node_id, [])
        self._in_edges.setdefault(node.node_id, [])

        asset = node.attributes.get("asset")
        if asset:
            self._by_asset.setdefault(str(asset).lower(), set()).add(node.node_id)

        tenant = node.attributes.get("tenant_id")
        if tenant:
            self._by_tenant.setdefault(str(tenant), set()).add(node.node_id)

        return node

    def get_node(self, node_id: str) -> Optional[AttackGraphNode]:
        return self._nodes.get(node_id)

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def add_edge(self, edge: AttackGraphEdge) -> AttackGraphEdge:
        """Inserts or updates a directed semantic edge."""
        if edge.source_id not in self._nodes:
            raise ValueError(f"Source node '{edge.source_id}' does not exist in graph")
        if edge.destination_id not in self._nodes:
            raise ValueError(f"Destination node '{edge.destination_id}' does not exist in graph")

        if edge.edge_id in self._edges:
            existing = self._edges[edge.edge_id]
            existing.attributes.update(edge.attributes)
            assert_no_raw_secrets(existing.attributes, f"add_edge({edge.edge_id})")
            if edge.state != RelationshipState.THEORETICAL:
                existing.state = edge.state
            if edge.provenance:
                existing.provenance = edge.provenance
            return existing

        if len(self._edges) >= self.MAX_EDGES:
            raise AttackGraphCapacityError(
                f"Attack graph edge limit exceeded ({self.MAX_EDGES}). Capacity budget enforced."
            )

        self._edges[edge.edge_id] = edge
        self._out_edges.setdefault(edge.source_id, []).append(edge)
        self._in_edges.setdefault(edge.destination_id, []).append(edge)
        return edge

    def get_outgoing_edges(self, node_id: str, edge_type: Optional[EdgeType] = None) -> List[AttackGraphEdge]:
        edges = self._out_edges.get(node_id, [])
        if edge_type is not None:
            return [e for e in edges if e.edge_type == edge_type]
        return list(edges)

    def get_incoming_edges(self, node_id: str, edge_type: Optional[EdgeType] = None) -> List[AttackGraphEdge]:
        edges = self._in_edges.get(node_id, [])
        if edge_type is not None:
            return [e for e in edges if e.edge_type == edge_type]
        return list(edges)

    def get_nodes_by_type(self, node_type: NodeType) -> List[AttackGraphNode]:
        return [self._nodes[nid] for nid in self._by_type.get(node_type, set())]

    def get_all_nodes(self) -> List[AttackGraphNode]:
        return list(self._nodes.values())

    def get_all_edges(self) -> List[AttackGraphEdge]:
        return list(self._edges.values())

    def node_count(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return len(self._edges)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes attack graph into canonical JSON dictionary."""
        return {
            "version": 1,
            "node_count": len(self._nodes),
            "edge_count": len(self._edges),
            "nodes": {nid: n.to_dict() for nid, n in self._nodes.items()},
            "edges": {eid: e.to_dict() for eid, e in self._edges.items()},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AttackGraph:
        """Constructs AttackGraph from JSON dictionary with validation."""
        graph = cls()
        nodes_data = data.get("nodes", {})
        if isinstance(nodes_data, dict):
            for n_dict in nodes_data.values():
                if isinstance(n_dict, dict):
                    graph.add_node(AttackGraphNode.from_dict(n_dict))
        elif isinstance(nodes_data, list):
            for n_dict in nodes_data:
                if isinstance(n_dict, dict):
                    graph.add_node(AttackGraphNode.from_dict(n_dict))

        edges_data = data.get("edges", {})
        if isinstance(edges_data, dict):
            for e_dict in edges_data.values():
                if isinstance(e_dict, dict):
                    graph.add_edge(AttackGraphEdge.from_dict(e_dict))
        elif isinstance(edges_data, list):
            for e_dict in edges_data:
                if isinstance(e_dict, dict):
                    graph.add_edge(AttackGraphEdge.from_dict(e_dict))

        return graph


# ==============================================================================
# Attack Path Composite Model
# ==============================================================================

@dataclass
class AttackPath:
    """Represents an ordered, multi-hop composite attack path."""
    path_id: str                      # Deterministic PATH-<sha256(ordered_nodes)>
    node_ids: List[str]               # Ordered sequence of node IDs
    edge_ids: List[str]               # Ordered sequence of edge IDs connecting nodes
    state: ChainState = ChainState.HYPOTHESIS
    feasibility: str = "THEORETICAL"  # "DEMONSTRATED", "HIGHLY_FEASIBLE", "THEORETICAL", "INFEASIBLE"
    compound_impact: str = "MEDIUM_COMPOUND"
    fingerprint: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "node_ids": list(self.node_ids),
            "edge_ids": list(self.edge_ids),
            "state": self.state.value,
            "feasibility": self.feasibility,
            "compound_impact": self.compound_impact,
            "fingerprint": self.fingerprint,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AttackPath:
        st_str = data.get("state", ChainState.HYPOTHESIS.value)
        try:
            st = ChainState(st_str)
        except ValueError:
            st = ChainState.HYPOTHESIS
        return cls(
            path_id=data["path_id"],
            node_ids=list(data.get("node_ids", [])),
            edge_ids=list(data.get("edge_ids", [])),
            state=st,
            feasibility=data.get("feasibility", "THEORETICAL"),
            compound_impact=data.get("compound_impact", "MEDIUM_COMPOUND"),
            fingerprint=data.get("fingerprint", ""),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )
