"""
Asset Relationship Model for BugBounty-Agent Asset Intelligence.

Defines directed semantic graph edges connecting assets (subdomains, DNS resolutions,
CNAME chains, TLS SAN presence, CDN edges, and ASN ownership).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from framework.assets.provenance import ObservationProvenance


class RelationType(str, Enum):
    """Canonical edge relationship types between security assets."""
    HAS_SUBDOMAIN = "HAS_SUBDOMAIN"
    RESOLVES_TO = "RESOLVES_TO"
    CNAME_TO = "CNAME_TO"
    PRESENT_IN_CERT = "PRESENT_IN_CERT"
    HOSTED_BY = "HOSTED_BY"
    BELONGS_TO_ASN = "BELONGS_TO_ASN"


@dataclass
class AssetRelationship:
    """Represents a directed relationship between two assets."""
    source_id: str
    destination_id: str
    relation_type: RelationType
    confidence: str = "CONFIRMED"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes relationship edge to a dictionary."""
        rel_type_val = (
            self.relation_type.value
            if isinstance(self.relation_type, RelationType)
            else str(self.relation_type)
        )
        data = {
            "source_id": self.source_id,
            "destination_id": self.destination_id,
            "relation_type": rel_type_val,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }
        if self.provenance:
            data["provenance"] = [p.to_dict() for p in self.provenance]
        if self.attributes:
            data["attributes"] = self.attributes
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AssetRelationship:
        """Deserializes relationship edge from a dictionary."""
        rel_type_raw = data.get("relation_type", "HAS_SUBDOMAIN")
        try:
            rel_type = RelationType(rel_type_raw)
        except ValueError:
            rel_type = RelationType.HAS_SUBDOMAIN

        provenances = [
            ObservationProvenance.from_dict(p)
            for p in data.get("provenance", [])
            if isinstance(p, dict)
        ]

        return cls(
            source_id=data.get("source_id", ""),
            destination_id=data.get("destination_id", ""),
            relation_type=rel_type,
            confidence=data.get("confidence", "CONFIRMED"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=provenances,
            attributes=data.get("attributes", {}) or {},
        )
