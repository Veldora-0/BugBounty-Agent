"""
Unit tests for AssetGraph and tree hierarchy visualization in BugBounty-Agent.
"""

import os
import tempfile
import pytest

from framework.assets.graph import AssetGraph
from framework.assets.model import Asset, AssetConfidence, AssetType
from framework.assets.relationship import AssetRelationship, RelationType
from framework.scope.engine import ScopeStatus


def test_graph_add_and_retrieve_asset():
    graph = AssetGraph()
    asset1 = Asset.create(
        asset_type=AssetType.ROOT_DOMAIN,
        value="example.com",
    )
    graph.add_asset(asset1)

    assert graph.has_asset("example.com")
    assert graph.has_asset("asset:root_domain:example.com")
    retrieved = graph.get_asset("example.com")
    assert retrieved is not None
    assert retrieved.normalized == "example.com"


def test_graph_deduplication_and_merging():
    graph = AssetGraph()
    asset1 = Asset.create(
        asset_type=AssetType.SUBDOMAIN,
        value="api.example.com",
        attributes={"dns": ["192.0.2.1"]},
        tags=["api"],
    )
    graph.add_asset(asset1)

    asset2 = Asset.create(
        asset_type=AssetType.SUBDOMAIN,
        value="api.example.com",
        attributes={"cdn": "Cloudflare"},
        tags=["prod"],
    )
    graph.add_asset(asset2)

    assert len(graph.get_all_assets()) == 1
    merged = graph.get_asset("api.example.com")
    assert "dns" in merged.attributes
    assert merged.attributes["cdn"] == "Cloudflare"
    assert "api" in merged.tags
    assert "prod" in merged.tags


def test_graph_relationships_and_filtering():
    graph = AssetGraph()
    root = Asset.create(AssetType.ROOT_DOMAIN, "example.com")
    sub = Asset.create(AssetType.SUBDOMAIN, "api.example.com", root_domain="example.com")
    ip = Asset.create(AssetType.IP_ADDRESS, "192.0.2.1")

    graph.add_asset(root)
    graph.add_asset(sub)
    graph.add_asset(ip)

    rel1 = AssetRelationship(
        source_id=root.id,
        destination_id=sub.id,
        relation_type=RelationType.HAS_SUBDOMAIN,
    )
    rel2 = AssetRelationship(
        source_id=sub.id,
        destination_id=ip.id,
        relation_type=RelationType.RESOLVES_TO,
    )
    graph.add_relationship(rel1)
    graph.add_relationship(rel2)

    assert len(graph.get_relationships()) == 2
    sub_rels = graph.get_relationships(source_id=sub.id)
    assert len(sub_rels) == 1
    assert sub_rels[0].destination_id == ip.id

    ip_rels = graph.get_relationships(relation_type=RelationType.RESOLVES_TO)
    assert len(ip_rels) == 1


def test_graph_hierarchy_and_children():
    graph = AssetGraph()
    root = Asset.create(AssetType.ROOT_DOMAIN, "example.com")
    api = Asset.create(
        AssetType.SUBDOMAIN,
        "api.example.com",
        parent_id=root.id,
        root_domain="example.com",
    )
    dev = Asset.create(
        AssetType.SUBDOMAIN,
        "dev.api.example.com",
        parent_id=api.id,
        root_domain="example.com",
    )

    graph.add_asset(root)
    graph.add_asset(api)
    graph.add_asset(dev)

    children_of_root = graph.get_children(root.id)
    assert len(children_of_root) == 1
    assert children_of_root[0].normalized == "api.example.com"

    children_of_api = graph.get_children(api.id)
    assert len(children_of_api) == 1
    assert children_of_api[0].normalized == "dev.api.example.com"


def test_graph_arbitrary_depth_subdomain_tree_and_ascii():
    graph = AssetGraph()
    root = Asset.create(AssetType.ROOT_DOMAIN, "example.com", discovery_depth=0)
    sub1 = Asset.create(AssetType.SUBDOMAIN, "a.example.com", parent_id=root.id, root_domain="example.com", discovery_depth=1)
    sub2 = Asset.create(AssetType.SUBDOMAIN, "b.a.example.com", parent_id=sub1.id, root_domain="example.com", discovery_depth=2)
    sub3 = Asset.create(AssetType.SUBDOMAIN, "c.b.a.example.com", parent_id=sub2.id, root_domain="example.com", discovery_depth=3)
    sub4 = Asset.create(AssetType.SUBDOMAIN, "d.c.b.a.example.com", parent_id=sub3.id, root_domain="example.com", discovery_depth=4)
    sub5 = Asset.create(AssetType.SUBDOMAIN, "e.d.c.b.a.example.com", parent_id=sub4.id, root_domain="example.com", discovery_depth=5)

    for s in [root, sub1, sub2, sub3, sub4, sub5]:
        graph.add_asset(s)

    tree = graph.get_subdomain_tree()
    assert tree["total_assets"] == 6
    assert tree["max_depth"] == 5

    ascii_out = graph.render_tree_ascii()
    assert "example.com (Depth 0 - Root)" in ascii_out
    assert "a.example.com (Depth 1)" in ascii_out
    assert "b.a.example.com (Depth 2)" in ascii_out
    assert "c.b.a.example.com (Depth 3)" in ascii_out
    assert "d.c.b.a.example.com (Depth 4)" in ascii_out
    assert "e.d.c.b.a.example.com (Depth 5)" in ascii_out


def test_graph_save_load_file():
    graph = AssetGraph()
    root = Asset.create(AssetType.ROOT_DOMAIN, "target.org")
    sub = Asset.create(AssetType.SUBDOMAIN, "vpn.target.org", root_domain="target.org")
    graph.add_asset(root)
    graph.add_asset(sub)
    graph.add_relationship(
        AssetRelationship(
            source_id=root.id,
            destination_id=sub.id,
            relation_type=RelationType.HAS_SUBDOMAIN,
        )
    )

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tf:
        temp_file = tf.name

    try:
        graph.save_to_file(temp_file)
        loaded = AssetGraph.load_from_file(temp_file)
        assert len(loaded.get_all_assets()) == 2
        assert loaded.has_asset("vpn.target.org")
        assert len(loaded.get_relationships()) == 1
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)


def test_graph_merge():
    g1 = AssetGraph()
    g1.add_asset(Asset.create(AssetType.ROOT_DOMAIN, "one.com"))

    g2 = AssetGraph()
    g2.add_asset(Asset.create(AssetType.ROOT_DOMAIN, "two.com"))

    g1.merge(g2)
    assert len(g1.get_all_assets()) == 2
    assert g1.has_asset("one.com")
    assert g1.has_asset("two.com")
