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
    re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----", re.IGNORECASE),                # OpenSSH Private Key
    re.compile(r"(?i)\bbearer\s+[a-zA-Z0-9_\-\.]{10,}\b"),                           # Bearer token
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                                             # AWS Access Key ID
    re.compile(r"(?i)\b(?:sk_live_|sk_test_|ghp_|gho_|glpat-)[a-zA-Z0-9_\-]{8,}\b"),  # API key prefixes
    re.compile(r"(?i)(?:password|passwd|pwd|client_secret|secret_key)\s*[:=]\s*['\"][^\s'\"]{6,}['\"]"),
]

_SENSITIVE_KEY_NAMES: Set[str] = {
    "password", "passwd", "pwd", "client_secret", "secret_key",
    "api_key", "apikey", "access_token", "auth_token", "bearer_token",
    "private_key", "session_id", "session_token", "cookie",
    "authorization",
}

_SAFE_REDACTED_SUBSTRINGS: Tuple[str, ...] = (
    "[REDACTED",
    "[FILTERED",
    "DESCRIPTOR",
    "OPAQUE_",
    "NONE",
    "UNKNOWN",
)


def assert_no_raw_secrets(data: Any, path: str = "node") -> None:
    """
    Strict assertion ensuring graph nodes, edges, and descriptors never contain raw credentials,
    unredacted JWT signatures, API tokens, cookies, or private keys. Raises ValueError fail-closed if detected.

    Supported detection rules:
    - JWT tokens matching RFC 7519 format (base64url header.payload.signature)
    - PEM and OpenSSH private key headers
    - Bearer authorization headers and values
    - Common high-entropy API keys (Stripe, GitHub, GitLab, AWS Access Key IDs)
    - Key-value credentials under sensitive dictionary keys (password, api_key, session_id, cookie, etc.)
    - Direct credential assignments in prose or parameters

    Limitations:
    - High-entropy random strings without structural context or sensitive keys are not universally blocked
      to avoid false-positive rejections of hashes (SHA-256) or deterministic IDs.
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
            # If the dictionary key itself indicates a sensitive credential,
            # verify that the value is either empty, redacted, or an opaque descriptor.
            k_lower = str(k).strip().lower()
            if k_lower in _SENSITIVE_KEY_NAMES and isinstance(v, str) and v.strip():
                v_upper = v.upper()
                if not any(safe in v_upper for safe in _SAFE_REDACTED_SUBSTRINGS):
                    raise ValueError(
                        f"Security violation at '{path}.{k}': Unredacted sensitive credential stored under '{k}'. "
                        "Raw credentials must be scrubbed before graph insertion."
                    )
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
        proof = CausalityProofType(proof_str)
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
        Returns True if fresh (valid); False if expired or invalid.
        """
        if self.ttl_seconds is None:
            self.is_expired = False
            return True

        now_ts = current_time if current_time is not None else time.time()
        try:
            # Parse created_at ISO timestamp, ensuring deterministic UTC timestamp
            dt = datetime.fromisoformat(self.created_at.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            created_ts = dt.timestamp()
        except Exception:
            self.is_expired = True
            return False

        # Fail-closed if timestamp is in the future beyond allowable clock skew
        if created_ts > (now_ts + skew_seconds):
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
        cap_type_str = data.get("capability_type")
        if not cap_type_str:
            raise ValueError("ExtractedCapability missing required 'capability_type'")
        cap_type = CapabilityType(cap_type_str)

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
        nt_str = data.get("node_type")
        if not nt_str:
            raise ValueError("AttackGraphNode missing required 'node_type'")
        nt = NodeType(nt_str)
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
        et_str = data.get("edge_type")
        if not et_str:
            raise ValueError("AttackGraphEdge missing required 'edge_type'")
        et = EdgeType(et_str)

        st_str = data.get("state", RelationshipState.THEORETICAL.value)
        st = RelationshipState(st_str)

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
            # Update asset secondary index if asset changed
            old_asset = existing.attributes.get("asset")
            new_asset = node.attributes.get("asset")
            if old_asset and str(old_asset).lower() in self._by_asset:
                self._by_asset[str(old_asset).lower()].discard(node.node_id)
            if new_asset:
                self._by_asset.setdefault(str(new_asset).lower(), set()).add(node.node_id)

            # Update tenant secondary index if tenant_id changed
            old_tenant = existing.attributes.get("tenant_id")
            new_tenant = node.attributes.get("tenant_id")
            if old_tenant and str(old_tenant) in self._by_tenant:
                self._by_tenant[str(old_tenant)].discard(node.node_id)
            if new_tenant:
                self._by_tenant.setdefault(str(new_tenant), set()).add(node.node_id)

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

    def get_edge(self, edge_id: str) -> Optional[AttackGraphEdge]:
        """Returns the edge corresponding to edge_id, or None if absent."""
        return self._edges.get(edge_id)

    def has_edge(self, edge_id: str) -> bool:
        """Returns True if edge_id exists in the graph."""
        return edge_id in self._edges

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
        return [self._nodes[nid] for nid in self._by_type.get(node_type, set()) if nid in self._nodes]

    def get_nodes_by_asset(self, asset: str) -> List[AttackGraphNode]:
        """Returns all nodes associated with the specified asset domain/host."""
        clean = asset.strip().lower()
        return [self._nodes[nid] for nid in self._by_asset.get(clean, set()) if nid in self._nodes]

    def get_nodes_by_tenant(self, tenant_id: str) -> List[AttackGraphNode]:
        """Returns all nodes bound to the specified tenant context for isolated analysis."""
        clean = str(tenant_id).strip()
        return [self._nodes[nid] for nid in self._by_tenant.get(clean, set()) if nid in self._nodes]

    def remove_edge(self, edge_id: str) -> Optional[AttackGraphEdge]:
        """Removes a directed edge from the graph and updates incident adjacency lists."""
        edge = self._edges.pop(edge_id, None)
        if not edge:
            return None
        if edge.source_id in self._out_edges:
            self._out_edges[edge.source_id] = [
                e for e in self._out_edges[edge.source_id] if e.edge_id != edge_id
            ]
        if edge.destination_id in self._in_edges:
            self._in_edges[edge.destination_id] = [
                e for e in self._in_edges[edge.destination_id] if e.edge_id != edge_id
            ]
        return edge

    def remove_node(self, node_id: str) -> Optional[AttackGraphNode]:
        """Removes an entity node and all its incident edges, maintaining index consistency."""
        node = self._nodes.pop(node_id, None)
        if not node:
            return None

        # Clean type index
        if node.node_type in self._by_type:
            self._by_type[node.node_type].discard(node_id)

        # Clean asset index
        asset = node.attributes.get("asset")
        if asset and str(asset).lower() in self._by_asset:
            self._by_asset[str(asset).lower()].discard(node_id)

        # Clean tenant index
        tenant = node.attributes.get("tenant_id")
        if tenant and str(tenant) in self._by_tenant:
            self._by_tenant[str(tenant)].discard(node_id)

        # Remove all incident outgoing and incoming edges
        incident = list(self._out_edges.pop(node_id, [])) + list(self._in_edges.pop(node_id, []))
        for edge in incident:
            self.remove_edge(edge.edge_id)

        return node

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
        st = ChainState(st_str)
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
