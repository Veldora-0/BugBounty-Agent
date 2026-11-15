"""
Phase 22.2: Bounded Traversal Engine for Composite Attack-Path Discovery.

Executes deterministic, resource-bounded, shortest-path-first traversal
over an AttackGraph to discover candidate composite attack paths.
Enforces strict computational budgets, tenant isolation, scope invariants,
cycle elimination, and non-inflation guarantees.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from framework.attack_path.discovery import SUPPORTED_TENANT_ISOLATION_FLAWS
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


@dataclass
class TraversalResult:
    """Contains candidate attack paths and traversal execution metadata."""
    paths: List[AttackPath] = field(default_factory=list)
    traversal_truncated: bool = False
    visited_nodes_count: int = 0
    examined_edges_count: int = 0
    truncated_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "paths": [p.to_dict() for p in self.paths],
            "traversal_truncated": self.traversal_truncated,
            "visited_nodes_count": self.visited_nodes_count,
            "examined_edges_count": self.examined_edges_count,
            "truncated_reason": self.truncated_reason,
        }


class BoundedTraversalEngine:
    """
    Deterministic Bounded Traversal Engine implementing shortest-path-first BFS
    with branch-level cycle elimination and strict computational limits.
    """

    # Hard safety ceilings to prevent resource exhaustion under adversarial conditions
    HARD_MAX_DEPTH = 7
    HARD_MAX_VISITED_NODES = 5000
    HARD_MAX_EXAMINED_EDGES = 25000
    HARD_MAX_CANDIDATE_PATHS = 500
    HARD_MAX_PATHS_PER_ENTRY = 25
    HARD_MAX_WALL_CLOCK_SECONDS = 10.0

    def __init__(
        self,
        max_depth: int = 5,
        max_visited_nodes: int = 2000,
        max_examined_edges: int = 10000,
        max_candidate_paths: int = 100,
        max_paths_per_entry: int = 10,
        time_budget_seconds: float = 5.0,
    ) -> None:
        self.max_depth = min(max_depth, self.HARD_MAX_DEPTH)
        self.max_visited_nodes = min(max_visited_nodes, self.HARD_MAX_VISITED_NODES)
        self.max_examined_edges = min(max_examined_edges, self.HARD_MAX_EXAMINED_EDGES)
        self.max_candidate_paths = min(max_candidate_paths, self.HARD_MAX_CANDIDATE_PATHS)
        self.max_paths_per_entry = min(max_paths_per_entry, self.HARD_MAX_PATHS_PER_ENTRY)
        self.time_budget_seconds = min(time_budget_seconds, self.HARD_MAX_WALL_CLOCK_SECONDS)

    @staticmethod
    def generate_path_id(node_ids: List[str], edge_ids: List[str]) -> str:
        """Deterministic path identifier PATH-<sha256(nodes::edges)>[:16]."""
        raw = ":".join(node_ids) + "::" + ":".join(edge_ids)
        h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16].upper()
        return f"PATH-{h}"

    @staticmethod
    def generate_path_fingerprint(graph: AttackGraph, node_ids: List[str]) -> str:
        """
        Generates semantic structural fingerprint representing the sequence
        of vulnerability categories and capabilities traversed.
        """
        elements: List[str] = []
        for nid in node_ids:
            node = graph.get_node(nid)
            if not node:
                continue
            if node.node_type == NodeType.FINDING:
                vtype = node.attributes.get("vulnerability_type", "finding").lower()
                elements.append(f"FINDING({vtype})")
            elif node.node_type == NodeType.CAPABILITY:
                ctype = node.attributes.get("capability_type", "capability").lower()
                elements.append(f"CAP({ctype})")
            elif node.node_type == NodeType.ENDPOINT:
                elements.append("ENDPOINT")
            elif node.node_type == NodeType.ASSET:
                elements.append("ASSET")
            elif node.node_type == NodeType.PRINCIPAL:
                elements.append("PRINCIPAL")
        return "CHAIN:" + "->".join(elements)

    def find_attack_paths(
        self,
        graph: AttackGraph,
        entry_node_ids: Optional[List[str]] = None,
        target_node_ids: Optional[List[str]] = None,
    ) -> TraversalResult:
        """
        Executes bounded, shortest-path-first traversal to discover composite attack paths.
        Guarantees deterministic ordering, tenant isolation, and strict resource budgets.
        """
        start_time = time.time()
        result = TraversalResult()
        collected_path_ids: Set[str] = set()
        paths_by_entry: Dict[str, int] = {}

        # 1. Determine and sort entry nodes lexicographically for deterministic execution
        if entry_node_ids:
            raw_entries = [graph.get_node(nid) for nid in entry_node_ids if graph.has_node(nid)]
        else:
            # By default, entry nodes are findings that expose capabilities
            raw_entries = graph.get_nodes_by_type(NodeType.FINDING)

        valid_entries = [n for n in raw_entries if n is not None and n.scope_status == "IN_SCOPE"]
        sorted_entries = sorted(valid_entries, key=lambda n: n.node_id)

        target_set: Optional[Set[str]] = set(target_node_ids) if target_node_ids else None

        # 2. Shortest-path-first BFS Queue:
        # Tuple: (current_node_id, ordered_node_ids, ordered_edge_ids, visited_nodes_in_branch, entry_node_id)
        queue: deque[Tuple[str, List[str], List[str], Set[str], str]] = deque()

        for entry in sorted_entries:
            queue.append((entry.node_id, [entry.node_id], [], {entry.node_id}, entry.node_id))
            paths_by_entry[entry.node_id] = 0

        # 3. BFS Traversal Loop
        while queue:
            # Check resource bounds
            if (time.time() - start_time) > self.time_budget_seconds:
                result.traversal_truncated = True
                result.truncated_reason = "TIME_BUDGET_EXCEEDED"
                break

            if result.visited_nodes_count >= self.max_visited_nodes:
                result.traversal_truncated = True
                result.truncated_reason = "NODE_BUDGET_EXCEEDED"
                break

            if result.examined_edges_count >= self.max_examined_edges:
                result.traversal_truncated = True
                result.truncated_reason = "EDGE_BUDGET_EXCEEDED"
                break

            if len(result.paths) >= self.max_candidate_paths:
                result.traversal_truncated = True
                result.truncated_reason = "PATH_BUDGET_EXCEEDED"
                break

            curr_id, path_nodes, path_edges, branch_visited, entry_id = queue.popleft()
            result.visited_nodes_count += 1

            curr_node = graph.get_node(curr_id)
            if not curr_node:
                # Dangling node reference resilience
                continue

            # Evaluate outgoing edges, sorted lexicographically by edge_id for determinism
            outgoing_edges = graph.get_outgoing_edges(curr_id)
            sorted_edges = sorted(outgoing_edges, key=lambda e: e.edge_id)

            for edge in sorted_edges:
                result.examined_edges_count += 1

                dst_id = edge.destination_id
                dst_node = graph.get_node(dst_id)

                # Check 1: Dangling edge resilience (destination node missing from graph)
                if not dst_node:
                    continue

                # Check 2: Cycle detection (cannot re-visit any node in the current path branch)
                if dst_id in branch_visited:
                    continue

                # Check 3: Scope enforcement (only IN_SCOPE nodes may be traversed)
                if dst_node.scope_status != "IN_SCOPE":
                    continue

                # Check 4: Stale capability pruning
                if dst_node.node_type == NodeType.CAPABILITY:
                    if dst_node.attributes.get("is_expired", False):
                        continue

                # Check 5: Tenant boundary enforcement
                # Disallow cross-tenant transition unless source is a recognized tenant-isolation flaw
                src_tenant = curr_node.attributes.get("tenant_id")
                dst_tenant = dst_node.attributes.get("tenant_id")
                if src_tenant and dst_tenant and str(src_tenant) != str(dst_tenant):
                    vtype = curr_node.attributes.get("vulnerability_type", "").lower()
                    if not vtype and curr_node.attributes.get("source_finding_id"):
                        src_fnd = graph.get_node(curr_node.attributes.get("source_finding_id"))
                        if src_fnd:
                            vtype = src_fnd.attributes.get("vulnerability_type", "").lower()
                    if vtype not in SUPPORTED_TENANT_ISOLATION_FLAWS:
                        continue

                # Form new path branch
                new_path_nodes = path_nodes + [dst_id]
                new_path_edges = path_edges + [edge.edge_id]
                new_visited = branch_visited | {dst_id}
                hop_count = len(new_path_edges)

                # Check if this state forms a completed candidate attack path:
                # A path is valid if it reaches a target node (if specified) OR
                # if hop_count >= 2 and terminates at a Finding or target Asset
                is_terminal = False
                if target_set is not None:
                    if dst_id in target_set:
                        is_terminal = True
                elif hop_count >= 2:
                    # Alternating composite chain: Finding A -> Capability A -> Finding B (or target Asset)
                    if dst_node.node_type in (NodeType.FINDING, NodeType.ASSET):
                        # Ensure path contains at least two distinct findings or finding -> asset
                        finding_nodes = [
                            nid for nid in new_path_nodes
                            if graph.get_node(nid) and graph.get_node(nid).node_type == NodeType.FINDING
                        ]
                        if len(finding_nodes) >= 2 or dst_node.node_type == NodeType.ASSET:
                            is_terminal = True

                if is_terminal and paths_by_entry.get(entry_id, 0) < self.max_paths_per_entry:
                    path_id = self.generate_path_id(new_path_nodes, new_path_edges)
                    if path_id not in collected_path_ids:
                        collected_path_ids.add(path_id)
                        paths_by_entry[entry_id] = paths_by_entry.get(entry_id, 0) + 1

                        # Calculate compound impact and feasibility
                        compound_impact = self._calculate_compound_impact(graph, new_path_nodes)
                        feasibility = self._calculate_feasibility(graph, new_path_edges)
                        fingerprint = self.generate_path_fingerprint(graph, new_path_nodes)

                        attack_path = AttackPath(
                            path_id=path_id,
                            node_ids=new_path_nodes,
                            edge_ids=new_path_edges,
                            state=ChainState.HYPOTHESIS,  # Strictly HYPOTHESIS; never automatically validated
                            feasibility=feasibility,
                            compound_impact=compound_impact,
                            fingerprint=fingerprint,
                        )

                        # Enforce zero-secret assertion on emitted path
                        assert_no_raw_secrets(attack_path.to_dict(), f"AttackPath({path_id})")
                        result.paths.append(attack_path)

                # Continue BFS expansion if within maximum traversal depth
                if hop_count < self.max_depth:
                    queue.append((dst_id, new_path_nodes, new_path_edges, new_visited, entry_id))

        return result

    @staticmethod
    def _calculate_compound_impact(graph: AttackGraph, node_ids: List[str]) -> str:
        """
        Calculates compound impact of a path without modifying individual finding severities.
        Evaluates terminal impact and privilege escalation transitions.
        """
        has_critical = False
        has_high = False
        has_priv_esc = False
        has_ssrf_internal = False

        for nid in node_ids:
            node = graph.get_node(nid)
            if not node:
                continue
            if node.node_type == NodeType.FINDING:
                sev = (node.attributes.get("severity") or "").upper()
                if sev == "CRITICAL":
                    has_critical = True
                elif sev == "HIGH":
                    has_high = True
            elif node.node_type == NodeType.CAPABILITY:
                ctype = node.attributes.get("capability_type")
                if ctype == CapabilityType.PRIVILEGE_ESCALATION.value:
                    has_priv_esc = True
                elif ctype == CapabilityType.SSRF_PIVOT.value:
                    has_ssrf_internal = True

        if has_critical or (has_high and has_priv_esc) or has_ssrf_internal:
            return "CRITICAL_COMPOUND"
        elif has_high or has_priv_esc:
            return "HIGH_COMPOUND"
        return "MEDIUM_COMPOUND"

    @staticmethod
    def _calculate_feasibility(graph: AttackGraph, edge_ids: List[str]) -> str:
        """Determines path feasibility based on constituent edge alignment."""
        all_aligned = True
        for eid in edge_ids:
            edge = graph._edges.get(eid)
            if not edge:
                continue
            if edge.state not in (RelationshipState.CONTEXTUALLY_ALIGNED, RelationshipState.LINK_VALIDATED):
                all_aligned = False
                break
        return "HIGHLY_FEASIBLE" if all_aligned else "THEORETICAL"
