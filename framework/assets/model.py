"""
Core Asset Model for BugBounty-Agent Asset Intelligence.

Provides canonical normalization, type definitions, arbitrary recursion depth tracking,
multi-source provenance aggregation, and confidence calibration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union

from framework.assets.provenance import ObservationProvenance
from framework.scope.engine import ScopeStatus
from framework.scope.normalizer import (
    calculate_subdomain_depth,
    normalize_hostname,
    NormalizationError,
)


class AssetType(str, Enum):
    """Canonical classification for attack surface assets."""
    ROOT_DOMAIN = "ROOT_DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    HOSTNAME = "HOSTNAME"
    IP_ADDRESS = "IP_ADDRESS"
    SERVICE_ENDPOINT = "SERVICE_ENDPOINT"
    CERTIFICATE = "CERTIFICATE"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    INFRASTRUCTURE_REF = "INFRASTRUCTURE_REF"


class AssetConfidence(str, Enum):
    """Confidence levels based on provenance and verification."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"


class AssetStatus(str, Enum):
    """Lifecycle progression states for assets during intelligence gathering."""
    DISCOVERED = "DISCOVERED"
    VERIFIED = "VERIFIED"
    RECURSED = "RECURSED"
    SKIPPED = "SKIPPED"


class CDNAttribution(str, Enum):
    """Attribution certainty for content delivery networks and edge proxies."""
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    UNKNOWN = "UNKNOWN"


def generate_asset_id(asset_type: Union[AssetType, str], normalized_val: str) -> str:
    """Generates a stable, canonical unique ID for an asset."""
    t_str = asset_type.value if isinstance(asset_type, AssetType) else str(asset_type)
    val = normalized_val.strip().lower()
    if val.endswith("."):
        val = val[:-1]
    return f"asset:{t_str.lower()}:{val}"


@dataclass
class Asset:
    """Represents a discovered asset in the target intelligence graph."""
    id: str
    type: AssetType
    value: str
    normalized: str
    root_domain: Optional[str] = None
    parent_id: Optional[str] = None
    parent_hostname: Optional[str] = None
    discovery_depth: int = 0
    scope_status: str = ScopeStatus.IN_SCOPE.value
    confidence: str = AssetConfidence.MEDIUM.value
    status: str = AssetStatus.DISCOVERED.value
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        asset_type: AssetType,
        value: str,
        root_domain: Optional[str] = None,
        parent_id: Optional[str] = None,
        parent_hostname: Optional[str] = None,
        discovery_depth: int = 0,
        scope_status: str = ScopeStatus.IN_SCOPE.value,
        provenance: Optional[ObservationProvenance] = None,
        attributes: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> Asset:
        """Factory constructor ensuring canonical normalization and ID generation."""
        # Normalize value
        if asset_type in (AssetType.ROOT_DOMAIN, AssetType.SUBDOMAIN, AssetType.HOSTNAME):
            try:
                norm_val = normalize_hostname(value)
            except NormalizationError:
                norm_val = value.strip().lower()
        else:
            norm_val = value.strip().lower()

        # Calculate depth if root_domain provided and depth is default 0
        calc_depth = discovery_depth
        if root_domain and norm_val != root_domain and discovery_depth == 0:
            try:
                calc_depth, computed_parent = calculate_subdomain_depth(norm_val, root_domain)
                if not parent_hostname:
                    parent_hostname = computed_parent
            except Exception:
                calc_depth = 1

        asset_id = generate_asset_id(asset_type, norm_val)
        now_ts = datetime.now(timezone.utc).isoformat()

        prov_list = [provenance] if provenance else []
        initial_conf = provenance.confidence if provenance else AssetConfidence.MEDIUM.value

        asset_instance = cls(
            id=asset_id,
            type=asset_type,
            value=value,
            normalized=norm_val,
            root_domain=root_domain,
            parent_id=parent_id,
            parent_hostname=parent_hostname,
            discovery_depth=calc_depth,
            scope_status=scope_status,
            confidence=initial_conf,
            status=AssetStatus.DISCOVERED.value,
            first_seen=now_ts,
            last_seen=now_ts,
            provenance=prov_list,
            attributes=attributes or {},
            tags=tags or [],
        )
        asset_instance.recalculate_confidence()
        return asset_instance

    def update_last_seen(self) -> None:
        """Updates last_seen timestamp to current UTC time."""
        self.last_seen = datetime.now(timezone.utc).isoformat()

    def add_provenance(self, prov: ObservationProvenance) -> None:
        """Appends a new provenance observation and recalibrates confidence."""
        self.provenance.append(prov)
        self.update_last_seen()
        self.recalculate_confidence()

    def recalculate_confidence(self) -> None:
        """
        Calibrates confidence based on observation provenance:
        - CONFIRMED if active verification (e.g. active DNS, HTTP response) observed
        - HIGH if observed by >= 2 independent sources
        - MEDIUM if observed by 1 standard source
        - LOW if unverified passive third-party feed
        """
        if not self.provenance:
            return

        has_active = any(
            p.method in ("active_dns", "active_probe", "http_probe", "tls_verified")
            or p.confidence == AssetConfidence.CONFIRMED.value
            for p in self.provenance
        )
        if has_active:
            self.confidence = AssetConfidence.CONFIRMED.value
            return

        distinct_sources = {p.source for p in self.provenance if p.source}
        if len(distinct_sources) >= 2:
            self.confidence = AssetConfidence.HIGH.value
            return

        if any(p.confidence == AssetConfidence.HIGH.value for p in self.provenance):
            self.confidence = AssetConfidence.HIGH.value
            return

        if any(p.confidence == AssetConfidence.LOW.value for p in self.provenance):
            self.confidence = AssetConfidence.LOW.value
            return

        self.confidence = AssetConfidence.MEDIUM.value

    def to_dict(self) -> Dict[str, Any]:
        """Serializes asset to JSON-serializable dictionary."""
        type_str = self.type.value if isinstance(self.type, AssetType) else str(self.type)
        data: Dict[str, Any] = {
            "id": self.id,
            "type": type_str,
            "value": self.value,
            "normalized": self.normalized,
            "discovery_depth": self.discovery_depth,
            "scope_status": self.scope_status,
            "confidence": self.confidence,
            "status": self.status,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "provenance": [p.to_dict() for p in self.provenance],
            "attributes": self.attributes,
            "tags": self.tags,
        }
        # Backward compatibility with existing StateManager schema
        if type_str in (AssetType.ROOT_DOMAIN.value, AssetType.SUBDOMAIN.value, AssetType.HOSTNAME.value):
            data["hostname"] = self.normalized

        if self.root_domain is not None:
            data["root_domain"] = self.root_domain
        if self.parent_id is not None:
            data["parent_id"] = self.parent_id
        if self.parent_hostname is not None:
            data["parent"] = self.parent_hostname

        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Asset:
        """Constructs an Asset instance from serialized dictionary."""
        type_raw = data.get("type", AssetType.SUBDOMAIN.value)
        try:
            asset_type = AssetType(type_raw)
        except ValueError:
            asset_type = AssetType.SUBDOMAIN

        provenances = [
            ObservationProvenance.from_dict(p)
            for p in data.get("provenance", [])
            if isinstance(p, dict)
        ]

        normalized_val = data.get("normalized") or data.get("hostname") or data.get("value", "")
        asset_id = data.get("id") or generate_asset_id(asset_type, normalized_val)

        return cls(
            id=asset_id,
            type=asset_type,
            value=data.get("value", normalized_val),
            normalized=normalized_val,
            root_domain=data.get("root_domain"),
            parent_id=data.get("parent_id"),
            parent_hostname=data.get("parent") or data.get("parent_hostname"),
            discovery_depth=int(data.get("discovery_depth", data.get("depth", 0))),
            scope_status=data.get("scope_status", ScopeStatus.IN_SCOPE.value),
            confidence=data.get("confidence", AssetConfidence.MEDIUM.value),
            status=data.get("status", AssetStatus.DISCOVERED.value),
            first_seen=data.get("first_seen", datetime.now(timezone.utc).isoformat()),
            last_seen=data.get("last_seen", datetime.now(timezone.utc).isoformat()),
            provenance=provenances,
            attributes=data.get("attributes", {}) or {},
            tags=data.get("tags", []) or [],
        )
