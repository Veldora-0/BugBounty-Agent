"""
JavaScript Intelligence State Management for BugBounty-Agent.

Provides atomic, resumable, and deduplicated storage of JavaScript analysis observations in:
~/BugBounty-Workspace/programs/<program>/state/javascript.json.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import tempfile
from typing import Any, Dict, List, Optional, Set

from framework.javascript.model import (
    DependencyObservation,
    DiscoveredEndpoint,
    DiscoveredRoute,
    InterestingString,
    JavaScriptResource,
    ParameterReference,
    SourceMapObservation,
)
from framework.webapp.model import canonicalize_url


class JavaScriptStateManager:
    """
    Manages persistent local state for JavaScript intelligence.
    Stores resources, content hashes, endpoints, routes, parameters, interesting strings,
    dependencies, and source maps atomically.
    """

    def __init__(self, program_dir: str):
        self.program_dir = os.path.abspath(program_dir)
        self.state_dir = os.path.join(self.program_dir, "state")
        os.makedirs(self.state_dir, exist_ok=True)
        self.js_file = os.path.join(self.state_dir, "javascript.json")

        self.resources: Dict[str, JavaScriptResource] = {}
        self.endpoints: Dict[str, DiscoveredEndpoint] = {}
        self.routes: Dict[str, DiscoveredRoute] = {}
        self.parameters: Dict[str, ParameterReference] = {}
        self.interesting_strings: Dict[str, InterestingString] = {}
        self.dependencies: Dict[str, DependencyObservation] = {}
        self.source_maps: Dict[str, SourceMapObservation] = {}

        self.processed_hashes: Set[str] = set()
        self.failed_urls: Set[str] = set()

        self.metadata: Dict[str, Any] = {
            "first_run": datetime.now(timezone.utc).isoformat(),
            "last_run": datetime.now(timezone.utc).isoformat(),
            "total_resources": 0,
            "total_endpoints": 0,
            "total_routes": 0,
            "total_interesting_strings": 0,
            "total_dependencies": 0,
        }

        self.load()

    def _atomic_write_json(self, filepath: str, data: Any) -> None:
        """Writes JSON data atomically using a temporary file replacement."""
        dir_name = os.path.dirname(filepath)
        with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
            json.dump(data, tf, indent=2)
            temp_path = tf.name
        os.replace(temp_path, filepath)

    def load(self) -> None:
        """Loads existing state from javascript.json if present."""
        if not os.path.isfile(self.js_file):
            return

        try:
            with open(self.js_file, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
        except (json.JSONDecodeError, OSError):
            return

        self.metadata = data.get("metadata", self.metadata)
        self.processed_hashes = set(data.get("processed_hashes", []))
        self.failed_urls = set(data.get("failed_urls", []))

        # Rehydrate Resources
        for item in data.get("resources", []):
            r = JavaScriptResource.from_dict(item)
            self.resources[r.key] = r

        # Rehydrate Endpoints
        for item in data.get("endpoints", []):
            e = DiscoveredEndpoint.from_dict(item)
            self.endpoints[e.key] = e

        # Rehydrate Routes
        for item in data.get("routes", []):
            ro = DiscoveredRoute.from_dict(item)
            self.routes[ro.key] = ro

        # Rehydrate Parameters
        for item in data.get("parameters", []):
            p = ParameterReference.from_dict(item)
            self.parameters[p.key] = p

        # Rehydrate Interesting Strings
        for item in data.get("interesting_strings", []):
            s = InterestingString.from_dict(item)
            self.interesting_strings[s.key] = s

        # Rehydrate Dependencies
        for item in data.get("dependencies", []):
            d = DependencyObservation.from_dict(item)
            self.dependencies[d.key] = d

        # Rehydrate Source Maps
        for item in data.get("source_maps", []):
            sm = SourceMapObservation.from_dict(item)
            self.source_maps[sm.key] = sm

    def save(self) -> None:
        """Saves current state atomically to javascript.json."""
        self.metadata["last_run"] = datetime.now(timezone.utc).isoformat()
        self.metadata["total_resources"] = len(self.resources)
        self.metadata["total_endpoints"] = len(self.endpoints)
        self.metadata["total_routes"] = len(self.routes)
        self.metadata["total_interesting_strings"] = len(self.interesting_strings)
        self.metadata["total_dependencies"] = len(self.dependencies)

        export_data = {
            "metadata": self.metadata,
            "processed_hashes": sorted(list(self.processed_hashes)),
            "failed_urls": sorted(list(self.failed_urls)),
            "resources": [r.to_dict() for r in sorted(self.resources.values(), key=lambda x: x.key)],
            "endpoints": [e.to_dict() for e in sorted(self.endpoints.values(), key=lambda x: x.key)],
            "routes": [ro.to_dict() for ro in sorted(self.routes.values(), key=lambda x: x.key)],
            "parameters": [p.to_dict() for p in sorted(self.parameters.values(), key=lambda x: x.key)],
            "interesting_strings": [s.to_dict() for s in sorted(self.interesting_strings.values(), key=lambda x: x.key)],
            "dependencies": [d.to_dict() for d in sorted(self.dependencies.values(), key=lambda x: x.key)],
            "source_maps": [sm.to_dict() for sm in sorted(self.source_maps.values(), key=lambda x: x.key)],
        }
        self._atomic_write_json(self.js_file, export_data)

    def is_processed(self, url_or_hash: str) -> bool:
        """Checks if a URL or content hash has already been processed."""
        clean = canonicalize_url(url_or_hash)
        return clean in self.resources or url_or_hash in self.processed_hashes

    def mark_failed(self, url: str) -> None:
        self.failed_urls.add(canonicalize_url(url))

    # ---------------- Add & Deduplicate Observations ----------------

    def add_resource(self, res: JavaScriptResource) -> bool:
        key = res.key
        if key in self.resources:
            existing = self.resources[key]
            existing.sha256_hash = res.sha256_hash or existing.sha256_hash
            existing.is_minified = res.is_minified or existing.is_minified
            existing.has_source_map = res.has_source_map or existing.has_source_map
            for p in res.provenance:
                existing.provenance.append(p)
            return False
        else:
            self.resources[key] = res
            if res.sha256_hash:
                self.processed_hashes.add(res.sha256_hash)
            return True

    def add_endpoint(self, ep: DiscoveredEndpoint) -> bool:
        key = ep.key
        if key in self.endpoints:
            return False
        self.endpoints[key] = ep
        return True

    def add_route(self, route: DiscoveredRoute) -> bool:
        key = route.key
        if key in self.routes:
            return False
        self.routes[key] = route
        return True

    def add_parameter(self, param: ParameterReference) -> bool:
        key = param.key
        if key in self.parameters:
            return False
        self.parameters[key] = param
        return True

    def add_interesting_string(self, item: InterestingString) -> bool:
        key = item.key
        if key in self.interesting_strings:
            return False
        self.interesting_strings[key] = item
        return True

    def add_dependency(self, dep: DependencyObservation) -> bool:
        key = dep.key
        if key in self.dependencies:
            existing = self.dependencies[key]
            if not existing.version and dep.version:
                existing.version = dep.version
            return False
        else:
            self.dependencies[key] = dep
            return True

    def add_source_map(self, sm: SourceMapObservation) -> bool:
        key = sm.key
        if key in self.source_maps:
            return False
        self.source_maps[key] = sm
        return True
