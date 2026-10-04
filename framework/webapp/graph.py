"""
Web Application Relationship Graph for BugBounty-Agent.

Connects WebApplications, WebPages, WebEndpoints, Forms, Parameters, Cookies,
and Resources into an indexed, directed relationship graph associated directly with
underlying AssetGraph attack surface entities.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from framework.assets.provenance import ObservationProvenance
from framework.webapp.model import canonicalize_url


class AppRelationType(str, Enum):
    """Semantic relationship types between web application attack surface entities."""
    HOSTS_APPLICATION = "HOSTS_APPLICATION"  # Asset (Host/Service) -> WebApplication
    HAS_PAGE = "HAS_PAGE"                    # WebApplication -> WebPage
    HAS_ENDPOINT = "HAS_ENDPOINT"            # WebApplication -> WebEndpoint
    HAS_FORM = "HAS_FORM"                    # WebPage / WebApp -> Form
    ACCEPTS_PARAMETER = "ACCEPTS_PARAMETER"  # WebEndpoint / Form -> Parameter
    SETS_COOKIE = "SETS_COOKIE"              # WebApplication / Page -> Cookie
    LOADS_RESOURCE = "LOADS_RESOURCE"        # WebPage -> Resource
    LINKS_TO = "LINKS_TO"                    # WebPage -> WebPage / URL


@dataclass
class AppRelationship:
    """Represents a directed semantic relationship edge in the web application graph."""
    source_id: str
    destination_id: str
    relation_type: AppRelationType
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
    def from_dict(cls, data: Dict[str, Any]) -> AppRelationship:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        try:
            rtype = AppRelationType(data.get("relation_type", AppRelationType.HAS_PAGE.value))
        except ValueError:
            rtype = AppRelationType.HAS_PAGE
        return cls(
            source_id=data.get("source_id", ""),
            destination_id=data.get("destination_id", ""),
            relation_type=rtype,
            confidence=data.get("confidence", "CONFIRMED"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
            attributes=data.get("attributes", {}) or {},
        )


class WebAppGraph:
    """
    Directed, indexed in-memory graph connecting web application components.
    Provides fast relation queries, deduplicated edge indexing, and tree visualization.
    """

    def __init__(self):
        self._relationships: List[AppRelationship] = []
        self._rel_index: Set[tuple] = set()
        self._by_source: Dict[str, List[AppRelationship]] = defaultdict(list)
        self._by_dest: Dict[str, List[AppRelationship]] = defaultdict(list)

    def add_relationship(self, rel: AppRelationship) -> AppRelationship:
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

    def get_outgoing(self, source_id: str, relation_type: Optional[AppRelationType] = None) -> List[AppRelationship]:
        rels = self._by_source.get(source_id, [])
        if relation_type:
            return [r for r in rels if r.relation_type == relation_type]
        return list(rels)

    def get_incoming(self, dest_id: str, relation_type: Optional[AppRelationType] = None) -> List[AppRelationship]:
        rels = self._by_dest.get(dest_id, [])
        if relation_type:
            return [r for r in rels if r.relation_type == relation_type]
        return list(rels)

    def get_all_relationships(self) -> List[AppRelationship]:
        return list(self._relationships)

    def to_dict(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self._relationships]

    @classmethod
    def from_dict(cls, data: List[Dict[str, Any]]) -> WebAppGraph:
        graph = cls()
        for item in data:
            graph.add_relationship(AppRelationship.from_dict(item))
        return graph
