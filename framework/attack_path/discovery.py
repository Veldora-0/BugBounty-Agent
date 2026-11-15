"""
Phase 22.2: Cross-Engine Candidate Relationship Discovery Engine.

Identifies candidate semantic relationships between derived capabilities
and target vulnerability findings within an AttackGraph.
Enforces tenant isolation, parameter compatibility, scope rules,
and strict anti-inflation guarantees (never outputs LINK_VALIDATED).
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Set, Tuple

from framework.attack_path.model import (
    AttackGraph,
    AttackGraphEdge,
    AttackGraphNode,
    CapabilityType,
    EdgeType,
    NodeType,
    RelationshipState,
    assert_no_raw_secrets,
)
from framework.common.evidence import sanitize_sensitive_data


# Vulnerability types specifically recognized as legitimate multi-tenant isolation flaws
SUPPORTED_TENANT_ISOLATION_FLAWS: Set[str] = {
    "bola",
    "idor",
    "tenant_isolation",
    "tenant_bypass",
    "multi_tenant_leak",
    "cross_tenant_access",
    "tenant_desync",
}

# Common parameter aliases for identifier matching
_IDENTIFIER_ALIASES: Dict[str, Set[str]] = {
    "id": {"user_id", "userid", "account_id", "account", "profile_id", "target_id", "uid"},
    "user_id": {"id", "userid", "account_id", "account", "profile_id", "uid"},
    "account_id": {"id", "user_id", "account", "org_id", "organization_id"},
    "org_id": {"organization_id", "account_id", "tenant_id", "group_id"},
    "tenant_id": {"org_id", "organization_id", "account_id"},
    "file_id": {"doc_id", "document_id", "id", "attachment_id"},
}


class CandidateRelationshipEngine:
    """
    Analyzes an AttackGraph to discover candidate semantic relationships
    between capabilities exposed by findings and downstream endpoints/findings.
    """

    def __init__(self, scope_engine: Optional[Any] = None) -> None:
        self.scope_engine = scope_engine

    @staticmethod
    def generate_candidate_edge_id(source_id: str, destination_id: str, edge_type: EdgeType) -> str:
        """Generates a deterministic edge ID: EDGE-<sha256(src:dst:type)>[:16]."""
        raw = f"{source_id}:{destination_id}:{edge_type.value}"
        h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16].upper()
        return f"EDGE-{h}"

    def discover_candidate_relationships(
        self,
        graph: AttackGraph,
        current_time: Optional[float] = None,
        clock_skew_seconds: float = 30.0,
    ) -> List[AttackGraphEdge]:
        """
        Discovers and returns candidate directed edges between nodes in the graph.
        Never produces LINK_VALIDATED edges; only THEORETICAL or CONTEXTUALLY_ALIGNED.
        """
        candidate_edges: List[AttackGraphEdge] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        capabilities = graph.get_nodes_by_type(NodeType.CAPABILITY)
        findings = graph.get_nodes_by_type(NodeType.FINDING)
        assets = graph.get_nodes_by_type(NodeType.ASSET)

        # Map findings by finding_id for fast property lookups
        finding_by_id: Dict[str, AttackGraphNode] = {
            f.attributes.get("finding_id", ""): f for f in findings if f.attributes.get("finding_id")
        }

        # Evaluate each capability against potential downstream target findings
        for cap in capabilities:
            cap_type_str = cap.attributes.get("capability_type")
            if not cap_type_str:
                continue

            try:
                cap_type = CapabilityType(cap_type_str)
            except ValueError:
                continue

            # Exclude expired or stale capabilities from generating candidate links
            if cap.attributes.get("is_expired", False):
                continue

            source_finding_id = cap.attributes.get("source_finding_id", "")
            source_finding = finding_by_id.get(source_finding_id)
            source_tenant = cap.attributes.get("tenant_id") or (
                source_finding.attributes.get("tenant_id") if source_finding else None
            )
            source_asset = cap.attributes.get("asset") or (
                source_finding.attributes.get("asset") if source_finding else None
            )

            # 1. Matching Capabilities to Target Findings
            for target_fnd in findings:
                # Do not link capability back to its own generating finding
                if target_fnd.attributes.get("finding_id") == source_finding_id:
                    continue
                if target_fnd.node_id == cap.node_id:
                    continue

                target_tenant = target_fnd.attributes.get("tenant_id")
                target_asset = target_fnd.attributes.get("asset")

                # Tenant Isolation Boundary Check:
                # Disallow cross-tenant links unless source finding is a supported tenant-isolation flaw
                if source_tenant and target_tenant and str(source_tenant) != str(target_tenant):
                    source_vtype = (
                        source_finding.attributes.get("vulnerability_type", "").lower()
                        if source_finding
                        else ""
                    )
                    if source_vtype not in SUPPORTED_TENANT_ISOLATION_FLAWS:
                        # Cross-tenant correlation strictly prohibited without valid tenant-isolation flaw
                        continue

                # Scope Check: If target is out of scope, do not generate valid candidate link
                if target_fnd.scope_status == "OUT_OF_SCOPE":
                    continue

                # Evaluate matching rules based on capability type
                edge = self._match_capability_to_finding(
                    cap=cap,
                    cap_type=cap_type,
                    source_finding=source_finding,
                    target_finding=target_fnd,
                    now_iso=now_iso,
                )
                if edge:
                    candidate_edges.append(edge)

            # 2. Matching Network/SSRF Pivots to Internal Assets
            if cap_type == CapabilityType.SSRF_PIVOT:
                for target_ast in assets:
                    ast_label = (target_ast.label or "").lower()
                    if (
                        "internal" in ast_label
                        or "169.254.169.254" in ast_label
                        or "127.0.0.1" in ast_label
                        or "localhost" in ast_label
                    ):
                        edge_id = self.generate_candidate_edge_id(
                            cap.node_id, target_ast.node_id, EdgeType.CROSSES_BOUNDARY
                        )
                        edge = AttackGraphEdge(
                            edge_id=edge_id,
                            source_id=cap.node_id,
                            destination_id=target_ast.node_id,
                            edge_type=EdgeType.CROSSES_BOUNDARY,
                            state=RelationshipState.CONTEXTUALLY_ALIGNED,
                            attributes={
                                "pivot_target": ast_label,
                                "inferred": True,
                                "rule": "SSRF_TO_INTERNAL_ASSET",
                            },
                            created_at=now_iso,
                        )
                        candidate_edges.append(edge)

        return candidate_edges

    def _match_capability_to_finding(
        self,
        cap: AttackGraphNode,
        cap_type: CapabilityType,
        source_finding: Optional[AttackGraphNode],
        target_finding: AttackGraphNode,
        now_iso: str,
    ) -> Optional[AttackGraphEdge]:
        """Evaluates semantic capability alignment against target finding preconditions."""
        desc = cap.attributes.get("descriptor", {}) or {}
        target_param = (target_finding.attributes.get("parameter") or "").strip().lower()
        target_prereqs = (target_finding.attributes.get("prerequisites") or "").strip().lower()
        target_vtype = (target_finding.attributes.get("vulnerability_type") or "").strip().lower()

        edge_type: Optional[EdgeType] = None
        rule_name = ""

        # Rule 1: KNOWLEDGE_EXPOSURE -> Parameter satisfaction
        if cap_type == CapabilityType.KNOWLEDGE_EXPOSURE:
            cap_param = (desc.get("target_parameter") or "").strip().lower()
            if cap_param and target_param:
                if self._parameters_match(cap_param, target_param):
                    edge_type = EdgeType.SATISFIES_PREREQUISITE
                    rule_name = f"PARAMETER_MATCH:{cap_param}->{target_param}"
            elif cap_param and cap_param in target_prereqs:
                edge_type = EdgeType.SATISFIES_PREREQUISITE
                rule_name = f"PREREQUISITE_PARAM_MATCH:{cap_param}"

        # Rule 2: SESSION_HIJACK -> Authenticated role prerequisite
        elif cap_type == CapabilityType.SESSION_HIJACK:
            if any(term in target_prereqs for term in ("auth", "session", "login", "cookie", "token", "user", "admin")):
                edge_type = EdgeType.AUTHENTICATES_AS
                rule_name = "SESSION_AUTHENTICATES_TARGET"

        # Rule 3: TOKEN_ACQUISITION -> Token/API auth prerequisite
        elif cap_type == CapabilityType.TOKEN_ACQUISITION:
            if any(term in target_prereqs for term in ("token", "api_key", "bearer", "secret", "auth", "oauth")):
                edge_type = EdgeType.AUTHENTICATES_AS
                rule_name = "TOKEN_AUTHENTICATES_TARGET"

        # Rule 4: OPEN_REDIRECT -> OAuth workflow prerequisite
        elif cap_type == CapabilityType.OPEN_REDIRECT:
            if "oauth" in target_vtype or "redirect" in target_param or "oauth" in target_prereqs:
                edge_type = EdgeType.SATISFIES_PREREQUISITE
                rule_name = "OPEN_REDIRECT_SATISFIES_OAUTH_FLOW"

        # Rule 5: ARBITRARY_FILE_READ -> Config or credential exposure
        elif cap_type == CapabilityType.ARBITRARY_FILE_READ:
            if any(term in target_prereqs for term in ("config", "file", "secret", "key")):
                edge_type = EdgeType.SATISFIES_PREREQUISITE
                rule_name = "FILE_READ_SATISFIES_CONFIG_DEPENDENCY"

        # Rule 6: PRIVILEGE_ESCALATION -> Higher-privilege prerequisite
        elif cap_type == CapabilityType.PRIVILEGE_ESCALATION:
            if "admin" in target_prereqs or "privilege" in target_prereqs or "elevated" in target_prereqs:
                edge_type = EdgeType.AUTHENTICATES_AS
                rule_name = "ESCALATED_PRIVILEGE_SATISFIES_ROLE"

        # Rule 7: WORKFLOW_BYPASS -> Stage progression
        elif cap_type == CapabilityType.WORKFLOW_BYPASS:
            if "stage" in target_prereqs or "workflow" in target_prereqs or "step" in target_prereqs:
                edge_type = EdgeType.SATISFIES_PREREQUISITE
                rule_name = "WORKFLOW_BYPASS_ADVANCES_STAGE"

        if not edge_type:
            return None

        edge_id = self.generate_candidate_edge_id(cap.node_id, target_finding.node_id, edge_type)

        # Relationships discovered by inference default to CONTEXTUALLY_ALIGNED
        # NEVER emit LINK_VALIDATED from discovery
        return AttackGraphEdge(
            edge_id=edge_id,
            source_id=cap.node_id,
            destination_id=target_finding.node_id,
            edge_type=edge_type,
            state=RelationshipState.CONTEXTUALLY_ALIGNED,
            attributes={
                "inferred": True,
                "discovery_rule": rule_name,
                "source_capability": cap_type.value,
                "target_finding_id": target_finding.attributes.get("finding_id", ""),
            },
            created_at=now_iso,
        )

    @staticmethod
    def _parameters_match(param_a: str, param_b: str) -> bool:
        """Determines if two parameter names match exactly or through semantic alias sets."""
        clean_a = param_a.strip().lower()
        clean_b = param_b.strip().lower()
        if clean_a == clean_b:
            return True
        # Check alias dictionary
        aliases = _IDENTIFIER_ALIASES.get(clean_a, set())
        if clean_b in aliases:
            return True
        aliases_b = _IDENTIFIER_ALIASES.get(clean_b, set())
        if clean_a in aliases_b:
            return True
        return False
