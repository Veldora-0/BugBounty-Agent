"""
Phase 22.1: Finding Normalization & Capability Extraction.

Transforms security findings and EvidenceStore records into normalized
graph nodes (Asset, Endpoint, Finding, Capability) and semantic edges.
Enforces evidence-driven capability extraction, clock-skew freshness handling,
and strict zero-secret sanitization.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from framework.attack_path.model import (
    AttackGraph,
    AttackGraphEdge,
    AttackGraphNode,
    CapabilityType,
    EdgeType,
    ExtractedCapability,
    NodeType,
    RelationshipState,
    assert_no_raw_secrets,
)
from framework.common.evidence import EvidenceStore, sanitize_sensitive_data
from framework.findings.schema import Finding


class CapabilityExtractionError(ValueError):
    """Raised when capability extraction fails due to invalid schema or missing evidence."""
    pass


# Mapping from vulnerability_type to capability type and classification rules
_VULN_CAPABILITY_MAP: Dict[str, Tuple[CapabilityType, str]] = {
    "information_disclosure": (CapabilityType.KNOWLEDGE_EXPOSURE, "KNOWLEDGE"),
    "info_disclosure": (CapabilityType.KNOWLEDGE_EXPOSURE, "KNOWLEDGE"),
    "idor": (CapabilityType.KNOWLEDGE_EXPOSURE, "IDENTIFIER"),
    "bola": (CapabilityType.KNOWLEDGE_EXPOSURE, "IDENTIFIER"),
    "open_redirect": (CapabilityType.OPEN_REDIRECT, "REDIRECT"),
    "ssrf": (CapabilityType.SSRF_PIVOT, "NETWORK_PIVOT"),
    "blind_ssrf": (CapabilityType.SSRF_PIVOT, "NETWORK_PIVOT"),
    "session_fixation": (CapabilityType.SESSION_HIJACK, "SESSION"),
    "session_invalidation": (CapabilityType.SESSION_HIJACK, "SESSION"),
    "privilege_escalation": (CapabilityType.PRIVILEGE_ESCALATION, "PRIVILEGE"),
    "path_traversal": (CapabilityType.ARBITRARY_FILE_READ, "FILE_READ"),
    "local_file_exposure": (CapabilityType.ARBITRARY_FILE_READ, "FILE_READ"),
    "business_logic": (CapabilityType.WORKFLOW_BYPASS, "WORKFLOW"),
    "csrf": (CapabilityType.WORKFLOW_BYPASS, "WORKFLOW"),
    "token_leak": (CapabilityType.TOKEN_ACQUISITION, "TOKEN"),
}


class FindingNormalizer:
    """
    Normalizes findings and associated evidence into graph entities and capabilities.
    """

    def __init__(self, evidence_store: Optional[EvidenceStore] = None) -> None:
        self.evidence_store = evidence_store

    @staticmethod
    def generate_asset_node_id(asset_str: str) -> str:
        """Deterministic asset identifier AST-<sha256(normalized)>."""
        clean = asset_str.strip().lower()
        h = hashlib.sha256(clean.encode("utf-8")).hexdigest()[:16].upper()
        return f"AST-{h}"

    @staticmethod
    def generate_endpoint_node_id(method: str, endpoint_url: str) -> str:
        """Deterministic endpoint identifier EP-<sha256(method:path)>."""
        m = method.strip().upper()
        parsed = urlparse(endpoint_url.strip())
        path = parsed.path or "/"
        clean = f"{m}:{parsed.netloc.lower()}{path}"
        h = hashlib.sha256(clean.encode("utf-8")).hexdigest()[:16].upper()
        return f"EP-{h}"

    @staticmethod
    def generate_finding_node_id(finding_id: str) -> str:
        """Deterministic finding node identifier FND-<finding_id>."""
        return f"FND-{finding_id.strip().upper()}"

    @staticmethod
    def generate_capability_id(finding_id: str, cap_type: CapabilityType, subtype: str) -> str:
        """Deterministic capability identifier CAP-<sha256(finding:type:subtype)>."""
        raw = f"{finding_id.strip()}:{cap_type.value}:{subtype.strip().lower()}"
        h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16].upper()
        return f"CAP-{h}"

    @staticmethod
    def generate_edge_id(source_id: str, destination_id: str, edge_type: EdgeType) -> str:
        """Deterministic edge identifier EDGE-<sha256(src:dst:type)>."""
        raw = f"{source_id}:{destination_id}:{edge_type.value}"
        h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16].upper()
        return f"EDGE-{h}"

    def normalize_finding(
        self,
        finding: Finding,
        current_time: Optional[float] = None,
        clock_skew_seconds: float = 30.0,
    ) -> Tuple[List[AttackGraphNode], List[AttackGraphEdge], List[ExtractedCapability]]:
        """
        Normalizes a finding into:
        1. AssetNode
        2. EndpointNode
        3. FindingNode
        4. ExtractedCapability Node(s)
        5. Semantic Edges connecting them
        """
        now_ts = current_time if current_time is not None else time.time()
        now_iso = datetime.now(timezone.utc).isoformat()

        nodes: List[AttackGraphNode] = []
        edges: List[AttackGraphEdge] = []
        capabilities: List[ExtractedCapability] = []

        # 1. Asset Node
        asset_str = finding.affected_asset or "unknown-asset"
        asset_id = self.generate_asset_node_id(asset_str)
        asset_node = AttackGraphNode(
            node_id=asset_id,
            node_type=NodeType.ASSET,
            label=asset_str,
            attributes={
                "asset": asset_str,
                "scope_reference": finding.scope_reference,
            },
            scope_status="IN_SCOPE",
            created_at=finding.created_at or now_iso,
            updated_at=now_iso,
        )
        nodes.append(asset_node)

        # 2. Endpoint Node
        endpoint_url = finding.affected_endpoint or f"https://{asset_str}/"
        method = "POST" if (finding.parameter and "post" in finding.title.lower()) else "GET"
        endpoint_id = self.generate_endpoint_node_id(method, endpoint_url)
        clean_param = sanitize_sensitive_data(finding.parameter or "")
        endpoint_node = AttackGraphNode(
            node_id=endpoint_id,
            node_type=NodeType.ENDPOINT,
            label=f"{method} {endpoint_url}",
            attributes={
                "url": endpoint_url,
                "method": method,
                "asset": asset_str,
                "parameter": clean_param,
            },
            scope_status="IN_SCOPE",
            created_at=finding.created_at or now_iso,
            updated_at=now_iso,
        )
        nodes.append(endpoint_node)

        # Edge: Endpoint -> Asset (HOSTED_ON)
        e_hosted = AttackGraphEdge(
            edge_id=self.generate_edge_id(endpoint_id, asset_id, EdgeType.HOSTED_ON),
            source_id=endpoint_id,
            destination_id=asset_id,
            edge_type=EdgeType.HOSTED_ON,
            state=RelationshipState.LINK_VALIDATED,
            attributes={"inferred": False},
            created_at=now_iso,
        )
        edges.append(e_hosted)

        # 3. Finding Node
        fnd_id = self.generate_finding_node_id(finding.finding_id)
        finding_node = AttackGraphNode(
            node_id=fnd_id,
            node_type=NodeType.FINDING,
            label=finding.title,
            attributes={
                "finding_id": finding.finding_id,
                "vulnerability_type": finding.vulnerability_type,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "lifecycle_state": (
                    finding.lifecycle_state.value
                    if hasattr(finding.lifecycle_state, "value")
                    else str(finding.lifecycle_state)
                ),
                "parameter": clean_param,
                "root_cause": sanitize_sensitive_data(finding.root_cause),
                "prerequisites": sanitize_sensitive_data(finding.prerequisites),
            },
            scope_status="IN_SCOPE",
            created_at=finding.created_at or now_iso,
            updated_at=now_iso,
        )
        nodes.append(finding_node)

        # Edge: Finding -> Endpoint (TARGETS)
        e_targets = AttackGraphEdge(
            edge_id=self.generate_edge_id(fnd_id, endpoint_id, EdgeType.TARGETS),
            source_id=fnd_id,
            destination_id=endpoint_id,
            edge_type=EdgeType.TARGETS,
            state=RelationshipState.LINK_VALIDATED,
            attributes={"vulnerability_type": finding.vulnerability_type},
            created_at=now_iso,
        )
        edges.append(e_targets)

        # 4. Capability Extraction
        extracted_caps = self.extract_capabilities(finding, now_ts, clock_skew_seconds)
        for cap in extracted_caps:
            capabilities.append(cap)

            cap_node = AttackGraphNode(
                node_id=cap.capability_id,
                node_type=NodeType.CAPABILITY,
                label=f"{cap.capability_type.value}:{cap.target_asset}",
                attributes={
                    "capability_type": cap.capability_type.value,
                    "source_finding_id": cap.source_finding_id,
                    "evidence_ref": cap.evidence_ref,
                    "is_observed": cap.is_observed,
                    "provenance_status": cap.provenance_status,
                    "is_expired": cap.is_expired,
                    "descriptor": cap.yielded_descriptor,
                },
                scope_status="IN_SCOPE",
                created_at=cap.created_at,
                updated_at=now_iso,
            )
            nodes.append(cap_node)

            # Edge: Finding -> Capability (EXPOSES)
            e_exposes = AttackGraphEdge(
                edge_id=self.generate_edge_id(fnd_id, cap.capability_id, EdgeType.EXPOSES),
                source_id=fnd_id,
                destination_id=cap.capability_id,
                edge_type=EdgeType.EXPOSES,
                state=(
                    RelationshipState.LINK_VALIDATED
                    if cap.is_observed
                    else RelationshipState.THEORETICAL
                ),
                attributes={
                    "is_observed": cap.is_observed,
                    "evidence_ref": cap.evidence_ref,
                },
                created_at=now_iso,
            )
            edges.append(e_exposes)

        return nodes, edges, capabilities

    def extract_capabilities(
        self,
        finding: Finding,
        current_time: float,
        clock_skew_seconds: float,
    ) -> List[ExtractedCapability]:
        """
        Extracts evidence-driven ExtractedCapability records from finding and EvidenceStore.
        Ensures strict zero-secret sanitization and dynamic freshness evaluation.
        """
        vtype = (finding.vulnerability_type or "").strip().lower()
        mapping = _VULN_CAPABILITY_MAP.get(vtype)
        if not mapping:
            return []

        cap_type, sub_class = mapping
        cap_id = self.generate_capability_id(finding.finding_id, cap_type, sub_class)

        # Identify primary evidence reference
        evidence_ref = ""
        evidence_sha = ""
        is_observed = False
        provenance_status = "INFERRED"

        if finding.evidence and isinstance(finding.evidence, list):
            first_ev = finding.evidence[0]
            if isinstance(first_ev, dict):
                evidence_ref = first_ev.get("evidence_id") or first_ev.get("ref", "")

        # Verify evidence in EvidenceStore if available
        if self.evidence_store and evidence_ref:
            ev_meta = self.evidence_store.get_evidence(evidence_ref)
            if ev_meta:
                evidence_sha = ev_meta.get("sha256", "")
                capture_source = ev_meta.get("metadata", {}).get("capture_source", "CALLER_SUPPLIED")

                # If capture exists and has non-empty response, verify whether concrete value was observed
                if ev_meta.get("response_sha256"):
                    is_observed = True
                    provenance_status = "OBSERVED" if capture_source == "CONTROLLED_TRANSPORT_DISPATCH" else "SIMULATED"
            else:
                # Evidence referenced by finding does not exist on disk
                is_observed = False
                provenance_status = "INFERRED"
        elif evidence_ref:
            # Evidence reference string exists without active store verification
            is_observed = False
            provenance_status = "INFERRED"

        # Safe sanitized structural descriptor (NEVER raw secrets)
        yielded_desc: Dict[str, Any] = {
            "category": sub_class,
            "target_parameter": sanitize_sensitive_data(finding.parameter or ""),
            "format": "OPAQUE_DESCRIPTOR",
        }

        # Specific descriptor formatting based on capability type
        if cap_type == CapabilityType.KNOWLEDGE_EXPOSURE:
            yielded_desc["format"] = "IDENTIFIER_DESCRIPTOR"
            yielded_desc["scope"] = "INTRA_TENANT"
        elif cap_type == CapabilityType.SESSION_HIJACK:
            yielded_desc["format"] = "SESSION_STATE_DESCRIPTOR"
            yielded_desc["scope"] = "CROSS_SESSION"
        elif cap_type == CapabilityType.SSRF_PIVOT:
            yielded_desc["format"] = "NETWORK_PIVOT_DESCRIPTOR"
            yielded_desc["destination_class"] = "INTERNAL_OR_METADATA"

        # Preconditions required
        preconds: Dict[str, Any] = {
            "required_role": "USER" if "auth" in (finding.prerequisites or "").lower() else "ANONYMOUS",
            "prerequisites_summary": sanitize_sensitive_data(finding.prerequisites or "None"),
        }

        # Lifetimes
        ttl: Optional[float] = None
        if cap_type in (CapabilityType.SESSION_HIJACK, CapabilityType.TOKEN_ACQUISITION):
            ttl = 3600.0  # 1 hour default session TTL

        created_iso = (
            datetime.fromtimestamp(current_time, timezone.utc).isoformat()
            if current_time is not None
            else (finding.created_at or datetime.now(timezone.utc).isoformat())
        )

        cap = ExtractedCapability(
            capability_id=cap_id,
            capability_type=cap_type,
            source_finding_id=finding.finding_id,
            evidence_ref=evidence_ref,
            evidence_sha256=evidence_sha,
            target_asset=finding.affected_asset or "unknown-asset",
            scope_reference=finding.scope_reference or "in_scope",
            is_observed=is_observed,
            provenance_status=provenance_status,
            principal_context=None,
            session_ref=None,
            yielded_descriptor=yielded_desc,
            preconditions_required=preconds,
            created_at=created_iso,
            ttl_seconds=ttl,
        )

        # Check clock freshness with skew
        cap.check_freshness(current_time=current_time, skew_seconds=clock_skew_seconds)

        return [cap]

    def ingest_findings_into_graph(
        self,
        findings: List[Finding],
        graph: AttackGraph,
        current_time: Optional[float] = None,
        clock_skew_seconds: float = 30.0,
    ) -> AttackGraph:
        """
        Normalizes a batch of findings and populates the AttackGraph idempotently.
        """
        for f in findings:
            nodes, edges, _ = self.normalize_finding(
                f, current_time=current_time, clock_skew_seconds=clock_skew_seconds
            )
            for n in nodes:
                graph.add_node(n)
            for e in edges:
                graph.add_edge(e)
        return graph
