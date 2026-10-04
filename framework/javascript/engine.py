"""
JavaScript Intelligence Engine for BugBounty-Agent.

Consumes Phase 3 JavaScript ResourceObservations, performs bounded HTTP acquisition,
normalizes and deduplicates bundles, runs static analysis (endpoints, routes, parameters,
dependencies, source maps, interesting strings), and persists structured intelligence atomically.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
import ssl
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import urlsplit

from framework.assets.provenance import ObservationProvenance
from framework.javascript.analyzer import JavaScriptAnalyzer
from framework.javascript.model import (
    DependencyObservation,
    DiscoveredEndpoint,
    DiscoveredRoute,
    InterestingString,
    JavaScriptResource,
    ParameterReference,
    SourceMapObservation,
)
from framework.javascript.state import JavaScriptStateManager
from framework.scope.engine import ScopeEngine, ScopeStatus
from framework.webapp.model import ResourceObservation, canonicalize_url
from framework.webapp.state import WebAppStateManager


@dataclass
class JavaScriptPolicy:
    """Acquisition and analysis policy for JavaScript intelligence."""
    max_files: int = 200
    max_requests: int = 500
    max_bytes_per_file: int = 5 * 1024 * 1024  # 5 MB per JS file
    total_byte_budget: int = 50 * 1024 * 1024  # 50 MB total acquisition budget
    passive_only: bool = False
    fetch_source_maps: bool = False
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BugBounty-Agent/4.0"


class JavaScriptIntelligenceEngine:
    """
    Orchestrates static analysis and intelligence gathering across discovered JavaScript resources.
    Never executes target code, never performs intrusive security testing.
    """

    def __init__(
        self,
        scope_engine: Optional[ScopeEngine] = None,
        webapp_state: Optional[WebAppStateManager] = None,
        js_state: Optional[JavaScriptStateManager] = None,
        policy: Optional[JavaScriptPolicy] = None,
        dry_run: bool = False,
    ):
        self.scope_engine = scope_engine
        self.webapp_state = webapp_state
        self.js_state = js_state
        self.policy = policy or JavaScriptPolicy()
        self.dry_run = dry_run

        self.request_count = 0
        self.total_bytes_downloaded = 0
        self.files_analyzed = 0

        # Deterministic mock hook for 100% offline testing: (url) -> Optional[str]
        self.fetch_js_hook: Optional[Callable[[str], Optional[str]]] = None

    def _is_in_scope(self, url: str) -> bool:
        """Enforces ScopeEngine checks before ANY HTTP request or file ingestion."""
        if not self.scope_engine:
            return True
        host = urlsplit(url).hostname or url
        decision = self.scope_engine.check(host)
        return decision.status == ScopeStatus.IN_SCOPE

    def acquire_script(self, url: str) -> Optional[str]:
        """
        Fetches JavaScript content while respecting budgets and bounds.
        """
        if not self._is_in_scope(url) or self.policy.passive_only:
            return None

        if self.request_count >= self.policy.max_requests:
            return None
        if self.total_bytes_downloaded >= self.policy.total_byte_budget:
            return None

        self.request_count += 1
        canon_url = canonicalize_url(url)

        # 1. Use Mock Hook if registered
        if self.fetch_js_hook:
            content = self.fetch_js_hook(canon_url)
            if content is None:
                return None
            b_len = len(content.encode("utf-8"))
            if b_len > self.policy.max_bytes_per_file:
                return None
            self.total_bytes_downloaded += b_len
            return content

        # 2. Live HTTP Fetch using standard library safely
        import urllib.request
        try:
            req = urllib.request.Request(
                canon_url,
                headers={"User-Agent": self.policy.user_agent},
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=6.0, context=ctx if canon_url.startswith("https://") else None) as resp:
                raw = resp.read(self.policy.max_bytes_per_file)
                self.total_bytes_downloaded += len(raw)
                return raw.decode("utf-8", errors="ignore")
        except Exception:
            if self.js_state and not self.dry_run:
                self.js_state.mark_failed(canon_url)
            return None

    def get_candidate_js_resources(self) -> List[ResourceObservation]:
        """Collects JavaScript resources from Phase 3 WebAppStateManager."""
        candidates: List[ResourceObservation] = []
        seen_urls: Set[str] = set()

        if self.webapp_state:
            for res in self.webapp_state.resources.values():
                if res.resource_type == "js" and res.url not in seen_urls:
                    if self._is_in_scope(res.url):
                        seen_urls.add(res.url)
                        candidates.append(res)
        return candidates

    def run_analysis(
        self,
        target_resources: Optional[List[ResourceObservation]] = None,
        resume: bool = False,
    ) -> Dict[str, Any]:
        """
        Executes static intelligence analysis across target JavaScript resources.
        """
        candidates = target_resources or self.get_candidate_js_resources()
        if len(candidates) > self.policy.max_files:
            candidates = candidates[: self.policy.max_files]

        stats = {
            "resources_evaluated": 0,
            "resources_acquired": 0,
            "endpoints_extracted": 0,
            "routes_extracted": 0,
            "parameters_extracted": 0,
            "interesting_strings_found": 0,
            "dependencies_detected": 0,
            "source_maps_discovered": 0,
        }

        for res in candidates:
            canon_url = canonicalize_url(res.url)
            stats["resources_evaluated"] += 1

            if resume and self.js_state and self.js_state.is_processed(canon_url):
                continue

            content = self.acquire_script(canon_url)
            if not content:
                continue

            stats["resources_acquired"] += 1
            self.files_analyzed += 1

            # Compute content hash
            sha256_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

            # Skip if identical content hash has already been processed in resume mode
            if resume and self.js_state and sha256_hash in self.js_state.processed_hashes:
                continue

            # Run static analyzer
            analyzer = JavaScriptAnalyzer(source_url=canon_url, js_content=content)
            analysis = analyzer.analyze_all()

            split_res = urlsplit(canon_url)
            js_res = JavaScriptResource(
                url=canon_url,
                host=split_res.hostname or "",
                path=split_res.path or "/",
                scheme=split_res.scheme or "https",
                content_length=len(content),
                sha256_hash=sha256_hash,
                is_minified=analysis["is_minified"],
                has_source_map=analysis["source_map"] is not None,
                source_map_url=analysis["source_map"].source_map_url if analysis["source_map"] else None,
                source_page=res.source_page,
                provenance=[
                    ObservationProvenance(
                        source="js_intelligence",
                        method="static_bundle_analysis",
                        confidence="CONFIRMED",
                    )
                ],
            )

            if self.js_state and not self.dry_run:
                self.js_state.add_resource(js_res)

            # Record Endpoints
            for ep in analysis["endpoints"]:
                if self.js_state and not self.dry_run:
                    self.js_state.add_endpoint(ep)
                stats["endpoints_extracted"] += 1

            # Record Routes
            for ro in analysis["routes"]:
                if self.js_state and not self.dry_run:
                    self.js_state.add_route(ro)
                stats["routes_extracted"] += 1

            # Record Parameters
            for p in analysis["parameters"]:
                if self.js_state and not self.dry_run:
                    self.js_state.add_parameter(p)
                stats["parameters_extracted"] += 1

            # Record Interesting Strings
            for s in analysis["interesting_strings"]:
                if self.js_state and not self.dry_run:
                    self.js_state.add_interesting_string(s)
                stats["interesting_strings_found"] += 1

            # Record Dependencies
            for d in analysis["dependencies"]:
                if self.js_state and not self.dry_run:
                    self.js_state.add_dependency(d)
                stats["dependencies_detected"] += 1

            # Record Source Maps
            if analysis["source_map"]:
                if self.js_state and not self.dry_run:
                    self.js_state.add_source_map(analysis["source_map"])
                stats["source_maps_discovered"] += 1

        # Atomic persistence
        if self.js_state and not self.dry_run:
            self.js_state.save()

        return stats
