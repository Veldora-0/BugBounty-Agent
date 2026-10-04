"""
Comprehensive unit tests for AssetIntelligenceEngine in BugBounty-Agent.

Tests arbitrary-depth recursion, scope boundary checks, DNS/IP/ASN/TLS/CDN enrichment,
wildcard detection, and state management using isolated offline mocks.
"""

import os
import tempfile
import pytest

from framework.assets.engine import AssetIntelligenceEngine
from framework.assets.graph import AssetGraph
from framework.assets.model import Asset, AssetConfidence, AssetStatus, AssetType, CDNAttribution
from framework.assets.relationship import RelationType
from framework.scope.engine import ScopeEngine, ScopeStatus
from framework.state.manager import StateManager


def test_engine_arbitrary_depth_recursion():
    """Verifies that discovery traverses through arbitrary depths without artificial ceilings."""
    engine = AssetIntelligenceEngine(max_depth=0)  # 0 = unlimited arbitrary depth

    discovery_map = {
        "example.com": ["api.example.com"],
        "api.example.com": ["v1.api.example.com"],
        "v1.api.example.com": ["users.v1.api.example.com"],
        "users.v1.api.example.com": ["internal.users.v1.api.example.com"],
        "internal.users.v1.api.example.com": ["service.internal.users.v1.api.example.com"],
    }

    engine.subdomain_discovery_hook = lambda host: discovery_map.get(host, [])
    engine.dns_resolver_hook = lambda host, rtype: []

    graph = engine.run_discovery(root_domains=["example.com"])

    # Depth progression:
    # example.com (0) -> api (1) -> v1 (2) -> users (3) -> internal (4) -> service (5)
    assert graph.get_max_depth() == 5
    assert len(graph.get_assets_by_type(AssetType.SUBDOMAIN)) == 5
    assert graph.has_asset("service.internal.users.v1.api.example.com")

    deepest = graph.get_asset("service.internal.users.v1.api.example.com")
    assert deepest.discovery_depth == 5
    assert deepest.parent_hostname == "internal.users.v1.api.example.com"


def test_engine_recursion_depth_limit_when_configured():
    """Verifies that engine respects explicit depth ceilings when configured."""
    engine = AssetIntelligenceEngine(max_depth=2)

    discovery_map = {
        "example.com": ["api.example.com"],
        "api.example.com": ["dev.api.example.com"],
        "dev.api.example.com": ["internal.dev.api.example.com"],
        "internal.dev.api.example.com": ["test.internal.dev.api.example.com"],
    }

    engine.subdomain_discovery_hook = lambda host: discovery_map.get(host, [])
    engine.dns_resolver_hook = lambda host, rtype: []

    graph = engine.run_discovery(root_domains=["example.com"])

    assert graph.get_max_depth() == 2
    assert graph.has_asset("dev.api.example.com")
    assert not graph.has_asset("internal.dev.api.example.com")


def test_engine_scope_enforcement_in_and_out_of_scope():
    """Ensures strict scope boundary enforcement and stops traversal on out-of-scope assets."""
    scope_config = {
        "program": {"name": "test-program"},
        "targets": {
            "domains": ["example.com"],
            "recursive_subdomains": {"enabled": True, "max_depth": 0},
        },
        "out_of_scope": {
            "domains": ["*.admin.example.com", "secret.example.com"],
        },
    }
    scope_engine = ScopeEngine(scope_config)
    engine = AssetIntelligenceEngine(scope_engine=scope_engine)

    discovery_map = {
        "example.com": ["api.example.com", "admin.example.com", "secret.example.com"],
        "api.example.com": ["public.api.example.com"],
        "admin.example.com": ["sub.admin.example.com"],
    }

    engine.subdomain_discovery_hook = lambda host: discovery_map.get(host, [])
    engine.dns_resolver_hook = lambda host, rtype: []

    graph = engine.run_discovery(root_domains=["example.com"])

    api_asset = graph.get_asset("api.example.com")
    assert api_asset.scope_status == ScopeStatus.IN_SCOPE.value

    # admin.example.com and secret.example.com are out of scope
    admin_asset = graph.get_asset("admin.example.com")
    assert admin_asset.scope_status == ScopeStatus.OUT_OF_SCOPE.value
    assert admin_asset.status == AssetStatus.SKIPPED.value

    secret_asset = graph.get_asset("secret.example.com")
    assert secret_asset.scope_status == ScopeStatus.OUT_OF_SCOPE.value
    assert secret_asset.status == AssetStatus.SKIPPED.value

    # Child of out-of-scope domain should NOT be recursed into
    assert not graph.has_asset("sub.admin.example.com")


def test_engine_dns_resolution_and_ip_linking():
    """Tests DNS record resolution, IP asset creation, and RESOLVES_TO edges."""
    engine = AssetIntelligenceEngine()

    def mock_dns(host, rtype):
        if host == "api.example.com" and rtype == "A":
            return ["198.51.100.1", "198.51.100.2"]
        return []

    engine.dns_resolver_hook = mock_dns
    graph = engine.run_discovery(
        root_domains=["example.com"],
        seed_subdomains=["api.example.com"],
    )

    api_asset = graph.get_asset("api.example.com")
    assert "198.51.100.1" in api_asset.attributes.get("ip_addresses", [])
    assert api_asset.confidence == AssetConfidence.CONFIRMED.value

    ip1_asset = graph.get_asset("198.51.100.1")
    assert ip1_asset is not None
    assert ip1_asset.type == AssetType.IP_ADDRESS

    rels = graph.get_relationships(
        source_id=api_asset.id,
        destination_id=ip1_asset.id,
        relation_type=RelationType.RESOLVES_TO,
    )
    assert len(rels) == 1


def test_engine_cname_chain_resolution():
    """Tests CNAME resolution and CNAME_TO relationships."""
    engine = AssetIntelligenceEngine()

    def mock_dns(host, rtype):
        if host == "cdn.example.com" and rtype == "CNAME":
            return ["edge.fastly.net"]
        return []

    engine.dns_resolver_hook = mock_dns
    graph = engine.run_discovery(
        root_domains=["example.com"],
        seed_subdomains=["cdn.example.com"],
    )

    cdn_asset = graph.get_asset("cdn.example.com")
    assert cdn_asset.attributes.get("cname") == "edge.fastly.net"

    fastly_asset = graph.get_asset("edge.fastly.net")
    assert fastly_asset is not None

    rels = graph.get_relationships(
        source_id=cdn_asset.id,
        destination_id=fastly_asset.id,
        relation_type=RelationType.CNAME_TO,
    )
    assert len(rels) == 1


def test_engine_asn_attribution():
    """Tests IP to ASN correlation and BELONGS_TO_ASN relationships."""
    engine = AssetIntelligenceEngine()

    engine.dns_resolver_hook = lambda h, t: ["203.0.113.10"] if t == "A" else []
    engine.asn_resolver_hook = lambda ip: {
        "asn": "AS13335",
        "org": "Cloudflare, Inc.",
        "cidr": "203.0.113.0/24",
    }

    graph = engine.run_discovery(root_domains=["example.com"])

    ip_asset = graph.get_asset("203.0.113.10")
    assert ip_asset is not None
    assert ip_asset.attributes.get("asn") == "AS13335"

    asn_asset = graph.get_asset("AS13335")
    assert asn_asset is not None
    assert asn_asset.type == AssetType.INFRASTRUCTURE_REF

    rels = graph.get_relationships(
        source_id=ip_asset.id,
        destination_id=asn_asset.id,
        relation_type=RelationType.BELONGS_TO_ASN,
    )
    assert len(rels) == 1


def test_engine_cdn_detection_cname_and_asn():
    """Tests CDN identification via CNAME patterns and ASN mapping."""
    engine = AssetIntelligenceEngine()

    def mock_dns(host, rtype):
        if host == "portal.example.com" and rtype == "CNAME":
            return ["portal.cloudflare.net"]
        if host == "portal.example.com" and rtype == "A":
            return ["104.16.1.1"]
        return []

    engine.dns_resolver_hook = mock_dns
    engine.asn_resolver_hook = lambda ip: {"asn": "AS13335", "org": "Cloudflare"}

    graph = engine.run_discovery(
        root_domains=["example.com"],
        seed_subdomains=["portal.example.com"],
    )

    portal_asset = graph.get_asset("portal.example.com")
    assert portal_asset.attributes.get("cdn") == "Cloudflare"
    assert portal_asset.attributes.get("cdn_attribution") == CDNAttribution.CONFIRMED.value

    # HOSTED_BY edge
    cf_asset = graph.get_asset("Cloudflare")
    assert cf_asset is not None
    assert cf_asset.type == AssetType.CLOUD_RESOURCE

    rels = graph.get_relationships(
        source_id=portal_asset.id,
        destination_id=cf_asset.id,
        relation_type=RelationType.HOSTED_BY,
    )
    assert len(rels) == 1


def test_engine_tls_san_extraction_and_requeue():
    """Tests extracting SANs from TLS certificate and queueing newly discovered in-scope names."""
    engine = AssetIntelligenceEngine()

    engine.dns_resolver_hook = lambda h, t: []
    engine.tls_san_hook = lambda host, port: [
        "auth.example.com",
        "docs.example.com",
        "thirdparty-vendor.com",
    ]

    graph = engine.run_discovery(root_domains=["example.com"])

    # In-scope SANs added to graph
    assert graph.has_asset("auth.example.com")
    assert graph.has_asset("docs.example.com")

    # PRESENT_IN_CERT edge
    root_asset = graph.get_asset("example.com")
    auth_asset = graph.get_asset("auth.example.com")
    rels = graph.get_relationships(
        source_id=root_asset.id,
        destination_id=auth_asset.id,
        relation_type=RelationType.PRESENT_IN_CERT,
    )
    assert len(rels) == 1

    # Out-of-scope external SAN must not be added to the target domain tree
    assert not graph.has_asset("thirdparty-vendor.com")


def test_engine_wildcard_dns_detection():
    """Tests active wildcard DNS detection probing."""
    engine = AssetIntelligenceEngine()

    def mock_dns(host, rtype):
        if "_bb_probe_" in host and rtype == "A":
            return ["198.51.100.99"]
        return []

    engine.dns_resolver_hook = mock_dns

    is_wc, ips = engine.check_wildcard("example.com")
    assert is_wc is True
    assert "198.51.100.99" in ips


def test_engine_budget_limit():
    """Tests safety limit on maximum discovered assets."""
    engine = AssetIntelligenceEngine(max_assets=3)

    seeds = [f"sub{i}.example.com" for i in range(10)]
    engine.dns_resolver_hook = lambda h, t: []

    graph = engine.run_discovery(root_domains=["example.com"], seed_subdomains=seeds)
    assert len(graph.get_all_assets()) <= 3


def test_statemanager_asset_graph_integration():
    """Tests StateManager saving and loading of the AssetGraph."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        state = StateManager(tmp_dir)

        graph = AssetGraph()
        root = Asset.create(AssetType.ROOT_DOMAIN, "target.com")
        sub = Asset.create(AssetType.SUBDOMAIN, "api.target.com", root_domain="target.com")
        graph.add_asset(root)
        graph.add_asset(sub)

        state.save_asset_graph(graph)

        loaded_graph = state.get_asset_graph()
        assert len(loaded_graph.get_all_assets()) == 2
        assert loaded_graph.has_asset("api.target.com")

        # Backwards compatible methods
        assets_list = state.get_assets()
        assert len(assets_list) == 2
        asset_obj = state.get_asset("api.target.com")
        assert asset_obj is not None
        assert asset_obj.get("hostname") == "api.target.com"


def test_engine_cycle_and_circular_cname_handling():
    """Tests that circular references between subdomains or CNAMEs do not cause infinite loops."""
    engine = AssetIntelligenceEngine()

    # Circular discoveries: a -> b.a, b.a -> a
    discovery_map = {
        "example.com": ["a.example.com"],
        "a.example.com": ["b.a.example.com"],
        "b.a.example.com": ["a.example.com"],
    }
    engine.subdomain_discovery_hook = lambda h: discovery_map.get(h, [])
    engine.dns_resolver_hook = lambda h, t: []

    graph = engine.run_discovery(root_domains=["example.com"])
    # Must terminate cleanly and contain exactly 3 assets: example.com, a.example.com, b.a.example.com
    assert len(graph.get_all_assets()) == 3
    assert graph.has_asset("a.example.com")
    assert graph.has_asset("b.a.example.com")


def test_engine_multiple_root_domains():
    """Tests discovery across multiple distinct in-scope root domains."""
    engine = AssetIntelligenceEngine()

    discovery_map = {
        "alpha.com": ["api.alpha.com"],
        "beta.org": ["web.beta.org"],
    }
    engine.subdomain_discovery_hook = lambda h: discovery_map.get(h, [])
    engine.dns_resolver_hook = lambda h, t: []

    graph = engine.run_discovery(root_domains=["alpha.com", "beta.org"])

    assert graph.has_asset("alpha.com")
    assert graph.has_asset("api.alpha.com")
    assert graph.has_asset("beta.org")
    assert graph.has_asset("web.beta.org")
    assert len(graph.get_all_assets()) == 4


def test_engine_passive_only_skips_active_and_tls():
    """Tests that passive_only=True skips TLS SAN extraction and active wildcard checks."""
    engine = AssetIntelligenceEngine(passive_only=True)

    san_called = []
    wc_called = []

    def mock_tls(host, port):
        san_called.append(host)
        return ["san.example.com"]

    def mock_wc(dom):
        wc_called.append(dom)
        return False, set()

    engine.tls_san_hook = mock_tls
    engine.check_wildcard = mock_wc
    engine.dns_resolver_hook = lambda h, t: []

    graph = engine.run_discovery(root_domains=["example.com"])

    assert len(san_called) == 0
    assert len(wc_called) == 0
    assert not graph.has_asset("san.example.com")

