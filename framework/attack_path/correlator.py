"""
Phase 22.2.3: Cross-Engine Attack-Path Correlator and Feasibility Engine.

Orchestrates end-to-end attack-path correlation:
1. Normalizes findings into graph entities and extracts capabilities.
2. Discovers semantic candidate relationships between capabilities and target endpoints.
3. Performs resource-bounded, shortest-path-first traversal.
4. Enforces strict feasibility rules: parameter compatibility, privilege progression,
   tenant isolation, session context consistency, and capability freshness.
5. Preserves decoupled validation states (HYPOTHESIS), anti-inflation guarantees,
   and zero-secret assertions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional, Set, Tuple

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
from framework.attack_path.state import AttackPathStateManager
from framework.attack_path.traversal import BoundedTraversalEngine, TraversalResult
from framework.common.evidence import EvidenceStore
from framework.findings.schema import Finding


@dataclass
class FeasibilityResult:
    """Detailed evaluation result for a candidate attack path."""
    is_feasible: bool
    rejection_reason: Optional[str] = None
    pruned_step_index: Optional[int] = None
    evaluated_rules: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_feasible": self.is_feasible,
            "rejection_reason": self.rejection_reason,
            "pruned_step_index": self.pruned_step_index,
            "evaluated_rules": self.evaluated_rules,
        }


@dataclass
class CorrelationResult:
    """Contains end-to-end correlation outputs, valid candidate paths, and execution stats."""
    graph: AttackGraph
    candidate_paths: List[AttackPath] = field(default_factory=list)
    pruned_paths: List[Tuple[AttackPath, str]] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "graph_nodes": self.graph.node_count(),
            "graph_edges": self.graph.edge_count(),
            "candidate_paths_count": len(self.candidate_paths),
            "candidate_paths": [p.to_dict() for p in self.candidate_paths],
            "pruned_paths_count": len(self.pruned_paths),
            "pruned_paths": [
                {"path_id": p.path_id, "reason": reason}
                for p, reason in self.pruned_paths
            ],
            "stats": self.stats,
        }


class AttackPathCorrelator:
    """
    End-to-End Cross-Engine Attack-Path Correlator and Feasibility Engine.
    Coordinates finding normalization, candidate discovery, bounded traversal,
    feasibility evaluation, and state persistence.
    """

    def __init__(
        self,
        scope_engine: Optional[Any] = None,
        evidence_store: Optional[EvidenceStore] = None,
        state_manager: Optional[AttackPathStateManager] = None,
        max_depth: int = 5,
        max_candidate_paths: int = 100,
        max_paths_per_entry: int = 10,
        time_budget_seconds: float = 5.0,
    ) -> None:
        self.scope_engine = scope_engine
        self.evidence_store = evidence_store
        self.state_manager = state_manager
        self.max_depth = max_depth
        self.max_candidate_paths = max_candidate_paths
        self.max_paths_per_entry = max_paths_per_entry
        self.time_budget_seconds = time_budget_seconds

        self.normalizer = FindingNormalizer(evidence_store=evidence_store)
        self.discovery_engine = CandidateRelationshipEngine(scope_engine=scope_engine)
        self.traversal_engine = BoundedTraversalEngine(
            max_depth=max_depth,
            max_candidate_paths=max_candidate_paths,
            max_paths_per_entry=max_paths_per_entry,
            time_budget_seconds=time_budget_seconds,
        )

    def evaluate_path_feasibility(
        self,
        path: AttackPath,
        graph: AttackGraph,
        current_time: Optional[float] = None,
        clock_skew_seconds: float = 30.0,
    ) -> FeasibilityResult:
        """
        Evaluates a candidate path against semantic feasibility rules:
        - ADV-22-01: Parameter and data type format compatibility.
        - ADV-22-02: Role and privilege progression consistency.
        - ADV-22-03: Multi-tenant boundary isolation.
        - ADV-22-04: Principal and session context alignment.
        - ADV-22-05: Capability freshness and non-expiration.
        - ADV-22-06: Non-inflation and hypothesis state enforcement.
        """
        evaluated_rules: List[str] = []
        now_ts = current_time if current_time is not None else time.time()

        # Build node and edge sequences from IDs
        nodes: List[AttackGraphNode] = []
        for idx, nid in enumerate(path.node_ids):
            node = graph.get_node(nid)
            if not node:
                return FeasibilityResult(
                    is_feasible=False,
                    rejection_reason=f"DANGLING_NODE: Node '{nid}' not found in graph",
                    pruned_step_index=idx,
                    evaluated_rules=evaluated_rules,
                )
            nodes.append(node)

        # 0. Scope Enforcement
        evaluated_rules.append("SCOPE_ENFORCEMENT")
        for idx, node in enumerate(nodes):
            if node.scope_status != "IN_SCOPE":
                return FeasibilityResult(
                    is_feasible=False,
                    rejection_reason=f"SCOPE_VIOLATION: Node '{node.node_id}' has scope status '{node.scope_status}'",
                    pruned_step_index=idx,
                    evaluated_rules=evaluated_rules,
                )

        # 1. Rule 5: Capability Freshness & Stale Pruning (ADV-22-05)
        evaluated_rules.append("FRESHNESS_CHECK")
        for idx, node in enumerate(nodes):
            if node.node_type == NodeType.CAPABILITY:
                if node.attributes.get("is_expired", False):
                    return FeasibilityResult(
                        is_feasible=False,
                        rejection_reason=f"STALE_CAPABILITY_EXPIRED: Capability '{node.node_id}' is marked expired",
                        pruned_step_index=idx,
                        evaluated_rules=evaluated_rules,
                    )
                # Check created_at and ttl_seconds if present
                created_at_str = node.attributes.get("created_at") or node.created_at
                ttl = node.attributes.get("ttl_seconds")
                if created_at_str and ttl is not None and ttl > 0:
                    try:
                        dt = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
                        c_ts = dt.timestamp()
                        if now_ts > c_ts + ttl + clock_skew_seconds:
                            return FeasibilityResult(
                                is_feasible=False,
                                rejection_reason=f"STALE_CAPABILITY_EXPIRED: Capability '{node.node_id}' expired at {c_ts + ttl}",
                                pruned_step_index=idx,
                                evaluated_rules=evaluated_rules,
                            )
                    except (ValueError, TypeError):
                        pass

        # 2. Rule 1: Parameter & DataType Format Compatibility (ADV-22-01)
        evaluated_rules.append("PARAMETER_FORMAT_COMPATIBILITY")
        for i in range(len(nodes) - 1):
            src = nodes[i]
            dst = nodes[i + 1]

            if src.node_type == NodeType.CAPABILITY and dst.node_type in (NodeType.FINDING, NodeType.ENDPOINT):
                src_desc = src.attributes.get("descriptor", {})
                if isinstance(src_desc, dict):
                    src_format = src_desc.get("format", "").upper()
                    dst_param = dst.attributes.get("parameter", "")
                    dst_req_format = dst.attributes.get("expected_format", "").upper()

                    # Check explicit format contradiction (e.g. source yields EMAIL but target expects NUMERIC_ID)
                    if src_format and dst_req_format and src_format != dst_req_format:
                        if not (src_format == "IDENTIFIER" and dst_req_format in ("INT", "ID", "NUMERIC")):
                            return FeasibilityResult(
                                is_feasible=False,
                                rejection_reason=(
                                    f"PARAMETER_FORMAT_MISMATCH: Step {i} -> {i+1} yields format '{src_format}' "
                                    f"but target expects '{dst_req_format}'"
                                ),
                                pruned_step_index=i + 1,
                                evaluated_rules=evaluated_rules,
                            )

        # 3. Rule 2: Role & Privilege Progression Consistency (ADV-22-02)
        evaluated_rules.append("PRIVILEGE_PROGRESSION")
        current_roles: Set[str] = {"ANONYMOUS"}
        # Initial starting role if defined on entry node
        if nodes:
            entry_role = nodes[0].attributes.get("role") or nodes[0].attributes.get("principal_role")
            if entry_role:
                current_roles.add(entry_role.upper())

        for idx, node in enumerate(nodes):
            # If intermediate node is a capability granting privilege or role
            if node.node_type == NodeType.CAPABILITY:
                cap_type = node.attributes.get("capability_type")
                desc = node.attributes.get("descriptor") or {}
                if isinstance(desc, dict):
                    granted_role = desc.get("granted_role") or desc.get("role")
                    if granted_role:
                        current_roles.add(granted_role.upper())
                if cap_type in ("PRIVILEGE_ESCALATION", "SESSION_HIJACK"):
                    target_role = node.attributes.get("target_role") or "ADMIN"
                    current_roles.add(target_role.upper())

            # Check if this node requires an elevated role
            required_role = node.attributes.get("required_role") or node.attributes.get("prerequisite_role")
            if required_role:
                req_upper = required_role.upper()
                # If required role is elevated (e.g. ADMIN) and current path has not achieved it
                if req_upper not in current_roles and "ADMIN" not in current_roles and "SYSTEM" not in current_roles:
                    return FeasibilityResult(
                        is_feasible=False,
                        rejection_reason=(
                            f"UNACHIEVED_ROLE_PREREQUISITE: Node '{node.node_id}' requires role '{req_upper}' "
                            f"but path only achieved {sorted(current_roles)}"
                        ),
                        pruned_step_index=idx,
                        evaluated_rules=evaluated_rules,
                    )

        # 4. Rule 3: Multi-Tenant Boundary Isolation (ADV-22-03)
        evaluated_rules.append("TENANT_ISOLATION")
        for i in range(len(nodes) - 1):
            src = nodes[i]
            dst = nodes[i + 1]

            src_tenant = src.attributes.get("tenant_id")
            dst_tenant = dst.attributes.get("tenant_id")

            if src_tenant and dst_tenant and str(src_tenant) != str(dst_tenant):
                # Check whether source finding or preceding node is a supported tenant-isolation flaw
                source_vuln = (
                    src.attributes.get("vulnerability_type", "").lower()
                    or src.attributes.get("category", "").lower()
                )
                if not source_vuln and src.attributes.get("source_finding_id"):
                    src_fnd = graph.get_node(src.attributes.get("source_finding_id"))
                    if src_fnd:
                        source_vuln = src_fnd.attributes.get("vulnerability_type", "").lower()

                if source_vuln not in SUPPORTED_TENANT_ISOLATION_FLAWS:
                    return FeasibilityResult(
                        is_feasible=False,
                        rejection_reason=(
                            f"UNAUTHORIZED_CROSS_TENANT_TRANSITION: Step {i} ({src_tenant}) -> "
                            f"Step {i+1} ({dst_tenant}) without supported tenant flaw (found '{source_vuln}')"
                        ),
                        pruned_step_index=i + 1,
                        evaluated_rules=evaluated_rules,
                    )

        # 5. Rule 4: Principal & Session Context Consistency (ADV-22-04)
        evaluated_rules.append("PRINCIPAL_SESSION_ALIGNMENT")
        current_principal = nodes[0].attributes.get("principal_id")

        for idx, node in enumerate(nodes):
            node_principal = node.attributes.get("principal_id")
            if current_principal and node_principal and str(current_principal) != str(node_principal):
                # To transition from current_principal to node_principal, the path must have
                # encountered an intermediate capability that specifically binds to node_principal.
                transition_legitimized = False
                for prev_node in nodes[:idx]:
                    if prev_node.node_type == NodeType.CAPABILITY:
                        cap_type = prev_node.attributes.get("capability_type")
                        target_p = (
                            prev_node.attributes.get("target_principal")
                            or prev_node.attributes.get("target_principal_id")
                        )
                        desc = prev_node.attributes.get("descriptor")
                        if isinstance(desc, dict):
                            target_p = (
                                target_p
                                or desc.get("authenticated_principal")
                                or desc.get("target_principal")
                                or desc.get("principal_id")
                            )

                        if cap_type == "SESSION_HIJACK":
                            # Session hijack legitimizes transition if target matches or if it targets that session
                            if target_p is None or str(target_p).lower() == str(node_principal).lower():
                                transition_legitimized = True
                                break
                        elif cap_type == "TOKEN_ACQUISITION":
                            # Token acquisition alone does NOT legitimize cross-principal transition
                            # unless it explicitly proves identity binding to the target principal!
                            if target_p is not None and str(target_p).lower() == str(node_principal).lower():
                                transition_legitimized = True
                                break

                if not transition_legitimized:
                    return FeasibilityResult(
                        is_feasible=False,
                        rejection_reason=(
                            f"PRINCIPAL_CONTEXT_MISMATCH: Node '{node.node_id}' belongs to principal "
                            f"'{node_principal}' but active principal context is '{current_principal}'. "
                            "Cross-principal transition requires verified identity or session evidence."
                        ),
                        pruned_step_index=idx,
                        evaluated_rules=evaluated_rules,
                    )
                # Legitimized transition: update active principal
                current_principal = node_principal

        # 6. Rule 6: Decoupled State & Non-Inflation Invariant (ADV-22-06)
        evaluated_rules.append("HYPOTHESIS_STATE_INVARIANT")
        if path.state in (ChainState.FULLY_VALIDATED, ChainState.PARTIALLY_VALIDATED):
            # Check if all constituent edges possess empirical validation evidence
            all_edges_validated = True
            for eid in path.edge_ids:
                edge = graph.get_edge(eid)
                if not edge or edge.state != RelationshipState.LINK_VALIDATED:
                    all_edges_validated = False
                    break
            if not all_edges_validated:
                # Force reset to HYPOTHESIS to prevent unearned promotion
                path.state = ChainState.HYPOTHESIS

        return FeasibilityResult(
            is_feasible=True,
            rejection_reason=None,
            pruned_step_index=None,
            evaluated_rules=evaluated_rules,
        )

    def correlate_findings(
        self,
        findings: List[Finding],
        graph: Optional[AttackGraph] = None,
        auto_persist: bool = False,
        current_time: Optional[float] = None,
        clock_skew_seconds: float = 30.0,
    ) -> CorrelationResult:
        """
        Executes end-to-end correlation:
        1. Normalizes input findings into the AttackGraph.
        2. Discovers candidate semantic directed relationships.
        3. Traverses the graph to discover candidate attack paths.
        4. Evaluates feasibility and prunes invalid/inconsistent paths.
        5. Optionally persists graph and paths to state/attack_graph.json.
        """
        start_time = time.time()
        g = graph if graph is not None else AttackGraph()

        # Step 1: Ingest and normalize findings
        if findings:
            self.normalizer.ingest_findings_into_graph(
                findings=findings,
                graph=g,
                current_time=current_time,
                clock_skew_seconds=clock_skew_seconds,
            )

        # Step 2: Discover candidate semantic relationships
        discovered_edges = self.discovery_engine.discover_candidate_relationships(
            graph=g,
            current_time=current_time,
            clock_skew_seconds=clock_skew_seconds,
        )

        for edge in discovered_edges:
            # Enforce discovery invariant: candidate relationships are never LINK_VALIDATED
            if edge.state == RelationshipState.LINK_VALIDATED:
                edge.state = RelationshipState.THEORETICAL
            g.add_edge(edge)

        # Step 3: Bounded Traversal for Candidate Paths
        traversal_result: TraversalResult = self.traversal_engine.find_attack_paths(graph=g)

        # Step 4: Feasibility and Consistency Filtering
        feasible_paths: List[AttackPath] = []
        pruned_paths: List[Tuple[AttackPath, str]] = []

        for p in traversal_result.paths:
            # Invariant: paths from discovery default strictly to HYPOTHESIS
            if p.state in (ChainState.FULLY_VALIDATED, ChainState.PARTIALLY_VALIDATED):
                p.state = ChainState.HYPOTHESIS

            feasibility = self.evaluate_path_feasibility(
                path=p,
                graph=g,
                current_time=current_time,
                clock_skew_seconds=clock_skew_seconds,
            )

            if feasibility.is_feasible:
                feasible_paths.append(p)
            else:
                p.state = ChainState.REFUTED
                reason = feasibility.rejection_reason or "FEASIBILITY_REJECTED"
                pruned_paths.append((p, reason))

        # Enforce zero-secret guarantee across all structures
        assert_no_raw_secrets(g)
        assert_no_raw_secrets(feasible_paths)

        # Step 5: Optional State Persistence
        if auto_persist and self.state_manager is not None:
            self.state_manager.save_graph(graph=g)

        elapsed = time.time() - start_time
        stats = {
            "findings_ingested": len(findings),
            "capabilities_count": len(g.get_nodes_by_type(NodeType.CAPABILITY)),
            "edges_discovered": len(discovered_edges),
            "paths_traversed": len(traversal_result.paths),
            "paths_feasible": len(feasible_paths),
            "paths_pruned": len(pruned_paths),
            "traversal_truncated": traversal_result.traversal_truncated,
            "visited_nodes_count": traversal_result.visited_nodes_count,
            "examined_edges_count": traversal_result.examined_edges_count,
            "elapsed_seconds": round(elapsed, 4),
        }

        return CorrelationResult(
            graph=g,
            candidate_paths=feasible_paths,
            pruned_paths=pruned_paths,
            stats=stats,
        )
