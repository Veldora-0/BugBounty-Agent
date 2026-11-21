"""
BugBounty-Agent Asset Intelligence Framework.

Provides scoped asset graph construction, multi-source provenance, DNS/IP/TLS
enrichment, optional hook-provided ASN data, CNAME-based CDN signals, and offline
scope authorization.
"""

from framework.assets.engine import (
    AssetIntelligenceEngine,
    KNOWN_ASN_CDN_MAP,
    KNOWN_CDN_CNAME_PATTERNS,
)
from framework.assets.graph import AssetGraph
from framework.assets.model import (
    Asset,
    AssetConfidence,
    AssetStatus,
    AssetType,
    CDNAttribution,
    generate_asset_id,
)
from framework.assets.provenance import ObservationProvenance
from framework.assets.relationship import (
    AssetRelationship,
    RelationType,
)

__all__ = [
    "Asset",
    "AssetConfidence",
    "AssetGraph",
    "AssetIntelligenceEngine",
    "AssetRelationship",
    "AssetStatus",
    "AssetType",
    "CDNAttribution",
    "KNOWN_ASN_CDN_MAP",
    "KNOWN_CDN_CNAME_PATTERNS",
    "ObservationProvenance",
    "RelationType",
    "generate_asset_id",
]
