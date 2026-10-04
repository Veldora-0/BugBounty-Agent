"""
Unit tests for Asset Model, Provenance, and Relationships in BugBounty-Agent.
"""

import pytest

from framework.assets.model import (
    Asset,
    AssetConfidence,
    AssetStatus,
    AssetType,
    CDNAttribution,
    generate_asset_id,
)
from framework.assets.provenance import ObservationProvenance
from framework.assets.relationship import AssetRelationship, RelationType
from framework.scope.engine import ScopeStatus


def test_asset_id_generation():
    aid = generate_asset_id(AssetType.ROOT_DOMAIN, "Example.COM.")
    assert aid == "asset:root_domain:example.com"

    aid_ip = generate_asset_id(AssetType.IP_ADDRESS, "192.0.2.1")
    assert aid_ip == "asset:ip_address:192.0.2.1"


def test_asset_creation_and_normalization():
    asset = Asset.create(
        asset_type=AssetType.SUBDOMAIN,
        value="  API.Example.com. ",
        root_domain="example.com",
    )
    assert asset.normalized == "api.example.com"
    assert asset.discovery_depth == 1
    assert asset.parent_hostname == "example.com"
    assert asset.id == "asset:subdomain:api.example.com"
    assert asset.scope_status == ScopeStatus.IN_SCOPE.value
    assert asset.confidence == AssetConfidence.MEDIUM.value


def test_asset_provenance_and_confidence_calibration():
    asset = Asset.create(
        asset_type=AssetType.SUBDOMAIN,
        value="dev.example.com",
        root_domain="example.com",
        provenance=ObservationProvenance(
            source="subfinder",
            method="passive",
            confidence=AssetConfidence.LOW.value,
        ),
    )
    assert asset.confidence == AssetConfidence.LOW.value

    # Adding a second distinct source upgrades confidence to HIGH
    asset.add_provenance(
        ObservationProvenance(
            source="crtsh",
            method="passive",
            confidence=AssetConfidence.MEDIUM.value,
        )
    )
    assert asset.confidence == AssetConfidence.HIGH.value

    # Adding an active DNS observation upgrades confidence to CONFIRMED
    asset.add_provenance(
        ObservationProvenance(
            source="dns_resolver",
            method="active_dns",
        )
    )
    assert asset.confidence == AssetConfidence.CONFIRMED.value


def test_asset_serialization_roundtrip():
    asset = Asset.create(
        asset_type=AssetType.SUBDOMAIN,
        value="internal.dev.example.com",
        root_domain="example.com",
        discovery_depth=2,
        parent_id="asset:subdomain:dev.example.com",
        parent_hostname="dev.example.com",
        provenance=ObservationProvenance(
            source="amass",
            method="passive",
            details={"asn": "AS13335"},
        ),
        attributes={"cdn": "Cloudflare", "is_wildcard": False},
        tags=["critical", "api"],
    )

    data = asset.to_dict()
    assert data["hostname"] == "internal.dev.example.com"
    assert data["discovery_depth"] == 2
    assert data["parent"] == "dev.example.com"
    assert data["attributes"]["cdn"] == "Cloudflare"

    restored = Asset.from_dict(data)
    assert restored.id == asset.id
    assert restored.normalized == "internal.dev.example.com"
    assert restored.discovery_depth == 2
    assert restored.parent_hostname == "dev.example.com"
    assert restored.attributes["cdn"] == "Cloudflare"
    assert len(restored.provenance) == 1
    assert restored.provenance[0].source == "amass"


def test_asset_relationship_creation_and_serialization():
    rel = AssetRelationship(
        source_id="asset:subdomain:api.example.com",
        destination_id="asset:ip_address:192.0.2.1",
        relation_type=RelationType.RESOLVES_TO,
        confidence=AssetConfidence.CONFIRMED.value,
        attributes={"ttl": 300},
    )

    data = rel.to_dict()
    assert data["source_id"] == "asset:subdomain:api.example.com"
    assert data["destination_id"] == "asset:ip_address:192.0.2.1"
    assert data["relation_type"] == "RESOLVES_TO"
    assert data["attributes"]["ttl"] == 300

    restored = AssetRelationship.from_dict(data)
    assert restored.source_id == rel.source_id
    assert restored.destination_id == rel.destination_id
    assert restored.relation_type == RelationType.RESOLVES_TO
    assert restored.confidence == AssetConfidence.CONFIRMED.value
