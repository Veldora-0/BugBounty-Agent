"""
API Relationship Graph for BugBounty-Agent.

Connects ApiApplications, ApiEndpoints, ApiParameters, Schemas, Auth Observations,
and Specifications to WebApplications, WebPages, and JavaScriptResources in an
integrated, directed relationship graph.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from framework.assets.provenance import ObservationProvenance


class ApiRelationType(str, Enum):
    """Semantic relationship types between API components and attack surface entities."""
    HAS_API = "HAS_API"                          # WebApplication -> ApiApplication
    HAS_ENDPOINT = "HAS_ENDPOINT"                # ApiApplication -> ApiEndpoint
    ACCEPTS_PARAMETER = "ACCEPTS_PARAMETER"      # ApiEndpoint -> ApiParameter
    USES_SCHEMA = "USES_SCHEMA"                  # ApiEndpoint -> Request/Response Schema
    REQUIRES_AUTH = "REQUIRES_AUTH"              # ApiEndpoint -> ApiAuthenticationObservation
    DOCUMENTS_ENDPOINT = "DOCUMENTS_ENDPOINT"    # ApiSpecification -> ApiEndpoint
    REFERENCES_ENDPOINT = "REFERENCES_ENDPOINT"  # JavaScriptResource / WebPage -> ApiEndpoint


@dataclass
class ApiRelationship:
    """Represents a directed relationship edge in the API graph."""
    source_id: str
    destination_id: str
    relation_type: ApiRelationType
    confidence: str = "CONFIRMED"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "destination_id": self.destination_id,
            "relation_type": self.relation_type.value,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "provenance": [p.to_dict() for p in self.provenance],
            "attributes": dict(self.attributes),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ApiRelationship:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        try:
            rtype = ApiRelationType(data.get("relation_type", ApiRelationType.HAS_ENDPOINT.value))
        except ValueError:
            rtype = ApiRelationType.HAS_ENDPOINT
        return cls(
            source_id=data.get("source_id", ""),
            destination_id=data.get("destination_id", ""),
            relation_type=rtype,
            confidence=data.get("confidence", "CONFIRMED"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
            attributes=data.get("attributes", {}) or {},
        )


class ApiGraph:
    """
    Directed, indexed in-memory relationship graph connecting API intelligence entities
    to the underlying web applications, pages, and JavaScript assets.
    """

    def __init__(self):
        self._relationships: List[ApiRelationship] = []
        self._rel_index: Set[tuple] = set()
        self._by_source: Dict[str, List[ApiRelationship]] = defaultdict(list)
        self._by_dest: Dict[str, List[ApiRelationship]] = defaultdict(list)

    def add_relationship(self, rel: ApiRelationship) -> ApiRelationship:
        """Inserts or merges a directed relationship edge."""
        edge_key = (rel.source_id, rel.destination_id, rel.relation_type.value)
        if edge_key in self._rel_index:
            for existing in self._relationships:
                if (existing.source_id, existing.destination_id, existing.relation_type.value) == edge_key:
                    for p in rel.provenance:
                        existing.provenance.append(p)
                    existing.attributes.update(rel.attributes)
                    return existing
            return rel

        self._rel_index.add(edge_key)
        self._relationships.append(rel)
        self._by_source[rel.source_id].append(rel)
        self._by_dest[rel.destination_id].append(rel)
        return rel

    def get_outgoing(self, source_id: str, relation_type: Optional[ApiRelationType] = None) -> List[ApiRelationship]:
        rels = self._by_source.get(source_id, [])
        if relation_type:
            return [r for r in rels if r.relation_type == relation_type]
        return list(rels)

    def get_incoming(self, dest_id: str, relation_type: Optional[ApiRelationType] = None) -> List[ApiRelationship]:
        rels = self._by_dest.get(dest_id, [])
        if relation_type:
            return [r for r in rels if r.relation_type == relation_type]
        return list(rels)

    def get_all_relationships(self) -> List[ApiRelationship]:
        return list(self._relationships)

    def to_dict(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self._relationships]

    @classmethod
    def from_dict(cls, data: List[Dict[str, Any]]) -> ApiGraph:
        graph = cls()
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    graph.add_relationship(ApiRelationship.from_dict(item))
        return graph
