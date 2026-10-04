"""
Asset Graph Model for BugBounty-Agent Asset Intelligence.

Maintains an in-memory, indexable, and JSON-serializable graph of attack surface assets,
supporting arbitrary recursive depths, parent-child hierarchies, directional relationships,
and formatted tree visualizer.
"""

from __future__ import annotations

from collections import defaultdict
import json
import os
import tempfile
from typing import Any, Dict, List, Optional, Set, Union

from framework.assets.model import (
    Asset,
    AssetConfidence,
    AssetStatus,
    AssetType,
    generate_asset_id,
)
from framework.assets.relationship import AssetRelationship, RelationType
from framework.scope.engine import ScopeStatus


class AssetGraph:
    """Graph structure managing assets, indices, and directional relationships."""

    def __init__(self):
        self._assets: Dict[str, Asset] = {}
        self._relationships: List[AssetRelationship] = []

        # Fast lookup indices
        self._by_normalized: Dict[str, str] = {}
        self._by_parent: Dict[str, Set[str]] = defaultdict(set)
        self._by_depth: Dict[int, Set[str]] = defaultdict(set)
        self._by_type: Dict[str, Set[str]] = defaultdict(set)
        self._rel_index: Set[tuple] = set()

    def add_asset(self, asset: Asset) -> Asset:
        """
        Inserts or merges an asset into the graph.
        If an asset with the same canonical ID or normalized value already exists,
        its provenance, attributes, and last_seen are merged and confidence recalibrated.
        """
        existing_id = self._by_normalized.get(asset.normalized) or (
            asset.id if asset.id in self._assets else None
        )

        if existing_id and existing_id in self._assets:
            existing = self._assets[existing_id]
            # Merge attributes
            for k, v in asset.attributes.items():
                if k not in existing.attributes or not existing.attributes[k]:
                    existing.attributes[k] = v
                elif isinstance(existing.attributes[k], list) and isinstance(v, list):
                    # Combine lists without duplicates while preserving order
                    combined = list(existing.attributes[k])
                    for item in v:
                        if item not in combined:
                            combined.append(item)
                    existing.attributes[k] = combined
                elif isinstance(existing.attributes[k], dict) and isinstance(v, dict):
                    existing.attributes[k].update(v)

            # Append new provenance items
            for p in asset.provenance:
                existing.add_provenance(p)

            # Merge tags
            for t in asset.tags:
                if t not in existing.tags:
                    existing.tags.append(t)

            # Fill missing hierarchy metadata
            if not existing.parent_id and asset.parent_id:
                existing.parent_id = asset.parent_id
                self._by_parent[asset.parent_id].add(existing.id)
            if not existing.parent_hostname and asset.parent_hostname:
                existing.parent_hostname = asset.parent_hostname
            if not existing.root_domain and asset.root_domain:
                existing.root_domain = asset.root_domain

            # Update depth if more specific or initialized
            if existing.discovery_depth == 0 and asset.discovery_depth > 0:
                self._by_depth[existing.discovery_depth].discard(existing.id)
                existing.discovery_depth = asset.discovery_depth
                self._by_depth[existing.discovery_depth].add(existing.id)

            existing.update_last_seen()
            existing.recalculate_confidence()
            return existing

        # New asset addition
        self._assets[asset.id] = asset
        self._by_normalized[asset.normalized] = asset.id
        self._by_depth[asset.discovery_depth].add(asset.id)

        type_key = asset.type.value if isinstance(asset.type, AssetType) else str(asset.type)
        self._by_type[type_key].add(asset.id)

        if asset.parent_id:
            self._by_parent[asset.parent_id].add(asset.id)

        return asset

    def get_asset(self, id_or_val: str) -> Optional[Asset]:
        """Retrieves an asset by canonical ID or normalized value."""
        if not id_or_val:
            return None
        if id_or_val in self._assets:
            return self._assets[id_or_val]
        norm = id_or_val.strip().lower()
        if norm in self._by_normalized:
            return self._assets[self._by_normalized[norm]]
        return None

    def has_asset(self, id_or_val: str) -> bool:
        """Checks if an asset exists in the graph."""
        return self.get_asset(id_or_val) is not None

    def add_relationship(self, rel: AssetRelationship) -> AssetRelationship:
        """Adds a directional relationship between two assets, deduplicating duplicates."""
        rel_type_val = (
            rel.relation_type.value
            if isinstance(rel.relation_type, RelationType)
            else str(rel.relation_type)
        )
        edge_key = (rel.source_id, rel.destination_id, rel_type_val)

        if edge_key in self._rel_index:
            # Already exists: find and update
            for existing in self._relationships:
                curr_type = (
                    existing.relation_type.value
                    if isinstance(existing.relation_type, RelationType)
                    else str(existing.relation_type)
                )
                if (
                    existing.source_id == rel.source_id
                    and existing.destination_id == rel.destination_id
                    and curr_type == rel_type_val
                ):
                    for p in rel.provenance:
                        existing.provenance.append(p)
                    existing.attributes.update(rel.attributes)
                    return existing

        self._rel_index.add(edge_key)
        self._relationships.append(rel)
        return rel

    def get_relationships(
        self,
        source_id: Optional[str] = None,
        destination_id: Optional[str] = None,
        relation_type: Optional[Union[RelationType, str]] = None,
    ) -> List[AssetRelationship]:
        """Filters relationships matching criteria."""
        type_str = None
        if relation_type:
            type_str = (
                relation_type.value
                if isinstance(relation_type, RelationType)
                else str(relation_type)
            )

        results = []
        for rel in self._relationships:
            if source_id and rel.source_id != source_id:
                continue
            if destination_id and rel.destination_id != destination_id:
                continue
            rel_type_val = (
                rel.relation_type.value
                if isinstance(rel.relation_type, RelationType)
                else str(rel.relation_type)
            )
            if type_str and rel_type_val != type_str:
                continue
            results.append(rel)
        return results

    def get_children(self, asset_id_or_val: str) -> List[Asset]:
        """Returns direct children of an asset."""
        asset = self.get_asset(asset_id_or_val)
        if not asset:
            return []
        child_ids = self._by_parent.get(asset.id, set())
        return [self._assets[cid] for cid in child_ids if cid in self._assets]

    def get_all_assets(self) -> List[Asset]:
        """Returns all assets in the graph."""
        return list(self._assets.values())

    def get_assets_by_depth(self, depth: int) -> List[Asset]:
        """Returns all assets at a specific recursion depth."""
        asset_ids = self._by_depth.get(depth, set())
        return [self._assets[aid] for aid in asset_ids if aid in self._assets]

    def get_max_depth(self) -> int:
        """Returns maximum discovery depth observed in the graph."""
        if not self._by_depth:
            return 0
        return max(self._by_depth.keys())

    def get_assets_by_type(self, asset_type: Union[AssetType, str]) -> List[Asset]:
        """Returns assets matching the given type."""
        type_str = asset_type.value if isinstance(asset_type, AssetType) else str(asset_type)
        asset_ids = self._by_type.get(type_str, set())
        return [self._assets[aid] for aid in asset_ids if aid in self._assets]

    def get_assets_by_scope(self, scope_status: Union[ScopeStatus, str]) -> List[Asset]:
        """Returns assets matching the specified scope status."""
        status_str = (
            scope_status.value
            if isinstance(scope_status, ScopeStatus)
            else str(scope_status)
        )
        return [a for a in self._assets.values() if a.scope_status == status_str]

    def get_subdomain_tree(self, root_id_or_val: Optional[str] = None) -> Dict[str, Any]:
        """
        Builds a recursive nested tree representation starting from the specified root,
        or from all depth-0 roots if none is specified.
        """
        roots = []
        if root_id_or_val:
            root = self.get_asset(root_id_or_val)
            if root:
                roots.append(root)
        else:
            roots = self.get_assets_by_type(AssetType.ROOT_DOMAIN)
            if not roots:
                roots = [
                    a for a in self.get_assets_by_depth(0)
                    if a.type in (AssetType.ROOT_DOMAIN, AssetType.SUBDOMAIN, AssetType.HOSTNAME)
                ]
            if not roots:
                roots = [
                    a for a in self._assets.values()
                    if not a.parent_id and a.type in (AssetType.ROOT_DOMAIN, AssetType.SUBDOMAIN, AssetType.HOSTNAME)
                ]

        def _build_node(asset: Asset) -> Dict[str, Any]:
            children = sorted(self.get_children(asset.id), key=lambda x: x.normalized)
            node = {
                "id": asset.id,
                "hostname": asset.normalized,
                "type": asset.type.value if isinstance(asset.type, AssetType) else str(asset.type),
                "depth": asset.discovery_depth,
                "scope_status": asset.scope_status,
                "confidence": asset.confidence,
                "children": [_build_node(c) for c in children],
            }
            if asset.attributes.get("ip_addresses"):
                node["ip_addresses"] = asset.attributes["ip_addresses"]
            if asset.attributes.get("cname"):
                node["cname"] = asset.attributes["cname"]
            if asset.attributes.get("cdn"):
                node["cdn"] = asset.attributes["cdn"]
            return node

        return {
            "total_assets": len(self._assets),
            "max_depth": self.get_max_depth(),
            "roots": [_build_node(r) for r in roots],
        }

    def render_tree_ascii(self, root_id_or_val: Optional[str] = None) -> str:
        """
        Renders an ASCII tree visualization of the asset graph, matching the project specification:
        example.com (Depth 0 - Root)
        └── api.example.com (Depth 1)
            └── dev.api.example.com (Depth 2)
                └── internal.dev.api.example.com (Depth 3)
        """
        roots = []
        if root_id_or_val:
            root = self.get_asset(root_id_or_val)
            if root:
                roots.append(root)
        else:
            roots = sorted(self.get_assets_by_type(AssetType.ROOT_DOMAIN), key=lambda x: x.normalized)
            if not roots:
                roots = sorted(
                    [
                        a for a in self.get_assets_by_depth(0)
                        if a.type in (AssetType.ROOT_DOMAIN, AssetType.SUBDOMAIN, AssetType.HOSTNAME)
                    ],
                    key=lambda x: x.normalized,
                )
            if not roots:
                roots = sorted(
                    [
                        a for a in self._assets.values()
                        if not a.parent_id and a.type in (AssetType.ROOT_DOMAIN, AssetType.SUBDOMAIN, AssetType.HOSTNAME)
                    ],
                    key=lambda x: x.normalized,
                )

        if not roots:
            return "No assets discovered in graph."

        lines: List[str] = []

        def _render_children(asset: Asset, prefix: str) -> None:
            children = sorted(self.get_children(asset.id), key=lambda x: x.normalized)
            total = len(children)
            for idx, child in enumerate(children):
                is_last = (idx == total - 1)
                connector = "└── " if is_last else "├── "
                child_prefix = prefix + ("    " if is_last else "│   ")

                meta_tags = []
                if child.attributes.get("cdn"):
                    meta_tags.append(f"CDN: {child.attributes['cdn']}")
                if child.attributes.get("is_wildcard"):
                    meta_tags.append("Wildcard")
                if child.scope_status != ScopeStatus.IN_SCOPE.value:
                    meta_tags.append(child.scope_status)

                meta_str = f" [{', '.join(meta_tags)}]" if meta_tags else ""
                lines.append(f"{prefix}{connector}{child.normalized} (Depth {child.discovery_depth}){meta_str}")
                _render_children(child, child_prefix)

        for root in roots:
            meta_tags = []
            if root.attributes.get("cdn"):
                meta_tags.append(f"CDN: {root.attributes['cdn']}")
            meta_str = f" [{', '.join(meta_tags)}]" if meta_tags else ""
            lines.append(f"{root.normalized} (Depth 0 - Root){meta_str}")
            _render_children(root, "")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes full graph to JSON-serializable dictionary."""
        return {
            "version": "1.0.0",
            "total_assets": len(self._assets),
            "max_depth": self.get_max_depth(),
            "assets": {aid: a.to_dict() for aid, a in self._assets.items()},
            "relationships": [r.to_dict() for r in self._relationships],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AssetGraph:
        """Constructs AssetGraph from serialized dictionary."""
        graph = cls()
        assets_data = data.get("assets", {})

        # Handle list or dict format
        if isinstance(assets_data, list):
            for a_item in assets_data:
                if isinstance(a_item, dict):
                    graph.add_asset(Asset.from_dict(a_item))
        elif isinstance(assets_data, dict):
            for a_item in assets_data.values():
                if isinstance(a_item, dict):
                    graph.add_asset(Asset.from_dict(a_item))

        # Backward compatibility with existing StateManager assets.json format:
        # {"sub.example.com": {"hostname": "sub.example.com", ...}}
        if not graph._assets and isinstance(data, dict):
            for key, val in data.items():
                if key not in ("version", "total_assets", "max_depth", "relationships") and isinstance(val, dict):
                    if "hostname" in val or "value" in val:
                        graph.add_asset(Asset.from_dict(val))

        # Relationships
        rels_data = data.get("relationships", [])
        if isinstance(rels_data, list):
            for r_item in rels_data:
                if isinstance(r_item, dict):
                    graph.add_relationship(AssetRelationship.from_dict(r_item))

        return graph

    def save_to_file(self, filepath: str) -> None:
        """Atomically saves graph state to a JSON file."""
        dir_name = os.path.dirname(os.path.abspath(filepath))
        os.makedirs(dir_name, exist_ok=True)
        data = self.to_dict()
        with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
            json.dump(data, tf, indent=2)
            temp_path = tf.name
        os.replace(temp_path, filepath)

    @classmethod
    def load_from_file(cls, filepath: str) -> AssetGraph:
        """Loads AssetGraph from a JSON file."""
        if not os.path.isfile(filepath):
            return cls()
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)

    def merge(self, other: AssetGraph) -> None:
        """Merges another AssetGraph into this one."""
        for asset in other.get_all_assets():
            self.add_asset(asset)
        for rel in other.get_relationships():
            self.add_relationship(rel)
