"""
Web Application Intelligence Engine for BugBounty-Agent.

Consumes Phase 1 AssetGraph assets and Phase 2 reconnaissance observations,
discovers canonical web applications, executes bounded HTML/robots/sitemap parsing,
extracts forms, parameters, cookies, and resources, constructs relationship graphs,
and persists structured attack surface intelligence atomically.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import os
import re
import ssl
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urljoin, urlparse, urlsplit
import xml.etree.ElementTree as ET

from framework.assets.graph import AssetGraph
from framework.assets.model import Asset, AssetType
from framework.assets.provenance import ObservationProvenance
from framework.recon.state import ReconStateManager
from framework.scope.engine import ScopeEngine, ScopeStatus
from framework.webapp.graph import AppRelationship, AppRelationType, WebAppGraph
from framework.webapp.model import (
    CookieObservation,
    FormObservation,
    LinkObservation,
    ParameterLocation,
    ParameterObservation,
    ResourceObservation,
    ResourceType,
    WebApplication,
    WebEndpoint,
    WebPage,
    canonicalize_url,
    is_same_origin,
)
from framework.webapp.parser import parse_page_html
from framework.webapp.policy import CrawlPolicy
from framework.webapp.state import WebAppStateManager


class WebApplicationIntelligenceEngine:
    """
    Orchestrates web application attack surface mapping and intelligence.
    Extracts pages, forms, parameters, cookies, and resources without vulnerability exploitation.
    """

    def __init__(
        self,
        scope_engine: Optional[ScopeEngine] = None,
        asset_graph: Optional[AssetGraph] = None,
        recon_state: Optional[ReconStateManager] = None,
        webapp_state: Optional[WebAppStateManager] = None,
        webapp_graph: Optional[WebAppGraph] = None,
        policy: Optional[CrawlPolicy] = None,
        dry_run: bool = False,
    ):
        self.scope_engine = scope_engine
        self.asset_graph = asset_graph or AssetGraph()
        self.recon_state = recon_state
        self.webapp_state = webapp_state
        self.webapp_graph = webapp_graph or WebAppGraph()
        self.policy = policy or CrawlPolicy()
        self.dry_run = dry_run

        self.request_count = 0
        self.pages_crawled = 0

        # Mock hooks for 100% offline deterministic testing
        # fetch_hook: (url, method) -> Optional[Dict[str, Any]]
        # where dict contains: {"status_code": int, "headers": dict, "body": str, "final_url": str}
        self.fetch_hook: Optional[Callable[[str, str], Optional[Dict[str, Any]]]] = None

    def _is_in_scope(self, url_or_host: str) -> bool:
        """Enforces ScopeEngine checks before ANY HTTP request or crawl queuing."""
        if not self.scope_engine:
            return True
        # Extract hostname if given full URL
        target = url_or_host
        if "://" in target:
            target = urlsplit(target).hostname or target
        decision = self.scope_engine.check(target)
        return decision.status == ScopeStatus.IN_SCOPE

    # ==========================================================================
    # 1. BOUNDED HTTP FETCH
    # ==========================================================================

    def fetch_url(self, url: str, method: str = "GET") -> Optional[Dict[str, Any]]:
        """
        Executes bounded, safe HTTP request.
        Validates target in-scope, enforces request budget and response size limits.
        """
        if not self._is_in_scope(url) or self.policy.passive_only:
            return None

        if self.request_count >= self.policy.max_requests:
            return None

        self.request_count += 1
        canon_url = canonicalize_url(url)

        # 1. Use Mock Hook if registered
        if self.fetch_hook:
            res = self.fetch_hook(canon_url, method.upper())
            if not res:
                return None
            final_url = res.get("final_url", canon_url)
            # Enforce scope check on redirected URL
            if not self._is_in_scope(final_url):
                if self.webapp_state and not self.dry_run:
                    self.webapp_state.mark_rejected(final_url)
                return None
            return {
                "status_code": int(res.get("status_code", 200)),
                "headers": dict(res.get("headers", {})),
                "body": str(res.get("body", "")),
                "final_url": canonicalize_url(final_url),
            }

        # 2. Live HTTP Fetch using standard library urllib safely
        import urllib.request
        try:
            req = urllib.request.Request(
                canon_url,
                headers={"User-Agent": self.policy.user_agent},
                method=method.upper(),
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=5.0, context=ctx if canon_url.startswith("https://") else None) as resp:
                final_url = canonicalize_url(resp.geturl())
                # Enforce scope check on redirected URL
                if not self._is_in_scope(final_url):
                    if self.webapp_state and not self.dry_run:
                        self.webapp_state.mark_rejected(final_url)
                    return None

                status = resp.status
                headers = dict(resp.headers)
                # Bounded read
                raw_bytes = resp.read(self.policy.max_response_bytes)
                body = raw_bytes.decode("utf-8", errors="ignore")
                return {
                    "status_code": status,
                    "headers": headers,
                    "body": body,
                    "final_url": final_url,
                }
        except Exception:
            return None

    # ==========================================================================
    # 2. COOKIE EXTRACTION
    # ==========================================================================

    def extract_cookies(self, headers: Dict[str, str], source_url: str) -> List[CookieObservation]:
        """Extracts and normalizes Set-Cookie headers from HTTP responses."""
        observations: List[CookieObservation] = []
        host = urlsplit(source_url).hostname or ""

        # Normalize header keys to lowercase
        set_cookie_headers = [v for k, v in headers.items() if k.lower() == "set-cookie"]
        for cookie_str in set_cookie_headers:
            # Set-Cookie: name=val; Path=/; Secure; HttpOnly; SameSite=Lax
            parts = [p.strip() for p in cookie_str.split(";") if p.strip()]
            if not parts:
                continue
            name_val = parts[0].split("=", 1)
            name = name_val[0].strip()
            if not name:
                continue

            c_domain = host
            c_path = "/"
            c_secure = False
            c_http_only = False
            c_same_site = None

            for attr in parts[1:]:
                attr_lower = attr.lower()
                if attr_lower.startswith("domain="):
                    c_domain = attr[7:].strip()
                elif attr_lower.startswith("path="):
                    c_path = attr[5:].strip()
                elif attr_lower.startswith("samesite="):
                    c_same_site = attr[9:].strip()
                elif attr_lower == "secure":
                    c_secure = True
                elif attr_lower == "httponly":
                    c_http_only = True

            obs = CookieObservation(
                name=name,
                domain=c_domain,
                path=c_path,
                secure=c_secure,
                http_only=c_http_only,
                same_site=c_same_site,
                source_url=source_url,
                provenance=[
                    ObservationProvenance(
                        source="http_header",
                        method="set-cookie",
                        confidence="CONFIRMED",
                    )
                ],
            )
            observations.append(obs)
        return observations

    # ==========================================================================
    # 3. ROBOTS.TXT & SITEMAP INTELLIGENCE
    # ==========================================================================

    def parse_robots_txt(self, app_base: str) -> List[str]:
        """Fetches and parses /robots.txt, extracting disallow/allow paths and sitemap URLs."""
        if not self.policy.include_robots or self.policy.passive_only:
            return []

        robots_url = urljoin(app_base, "/robots.txt")
        res = self.fetch_url(robots_url)
        if not res or res["status_code"] != 200:
            return []

        discovered: List[str] = []
        for line in res["body"].splitlines():
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue
            lower = clean.lower()
            if lower.startswith(("disallow:", "allow:")):
                parts = clean.split(":", 1)
                if len(parts) == 2:
                    path = parts[1].strip()
                    if path and not path.startswith("*") and not "$" in path:
                        target = urljoin(app_base, path)
                        if self._is_in_scope(target):
                            discovered.append(canonicalize_url(target))
            elif lower.startswith("sitemap:"):
                parts = clean.split(":", 1)
                if len(parts) == 2:
                    sitemap_url = parts[1].strip()
                    if sitemap_url and self._is_in_scope(sitemap_url):
                        discovered.append(canonicalize_url(sitemap_url))
        return discovered

    def parse_sitemap_xml(self, sitemap_url: str) -> List[str]:
        """Fetches and extracts in-scope URLs from an XML sitemap."""
        if not self.policy.include_sitemaps or self.policy.passive_only:
            return []

        res = self.fetch_url(sitemap_url)
        if not res or res["status_code"] != 200:
            return []

        discovered: List[str] = []
        try:
            root = ET.fromstring(res["body"])
            # Support xmlns prefixes by matching tag ends
            for elem in root.iter():
                if elem.tag.endswith("loc") and elem.text:
                    url = elem.text.strip()
                    if url and self._is_in_scope(url):
                        discovered.append(canonicalize_url(url))
        except Exception:
            # Fallback regex for loc tags in malformed XML
            for match in re.finditer(r"<loc>(https?://[^<]+)</loc>", res["body"], re.IGNORECASE):
                url = match.group(1).strip()
                if url and self._is_in_scope(url):
                    discovered.append(canonicalize_url(url))
        return discovered

    # ==========================================================================
    # 4. INITIALIZE APPLICATION ROOTS
    # ==========================================================================

    def identify_application_roots(self) -> List[WebApplication]:
        """
        Identifies eligible web application roots from AssetGraph and Phase 2 recon state.
        Preserves technologies and titles discovered during reconnaissance.
        """
        apps: List[WebApplication] = []
        seen_roots: Set[str] = set()

        # 1. From Phase 2 ReconStateManager HTTP services
        if self.recon_state:
            for http_obs in self.recon_state.http_services.values():
                base = f"{http_obs.scheme}://{http_obs.host}:{http_obs.port}/" if (http_obs.scheme == "http" and http_obs.port != 80) or (http_obs.scheme == "https" and http_obs.port != 443) else f"{http_obs.scheme}://{http_obs.host}/"
                canon_base = canonicalize_url(base)
                if canon_base in seen_roots or not self._is_in_scope(canon_base):
                    continue
                seen_roots.add(canon_base)

                techs = list(http_obs.technologies)
                # Supplement with technologies discovered for host
                for t in self.recon_state.get_technologies_for_host(http_obs.host):
                    if t.name not in techs:
                        techs.append(t.name)

                app = WebApplication(
                    base_url=canon_base,
                    host=http_obs.host,
                    scheme=http_obs.scheme,
                    port=http_obs.port,
                    title=http_obs.title,
                    technologies=techs,
                    server=http_obs.server_header,
                    provenance=[
                        ObservationProvenance(
                            source="recon_intelligence",
                            method="http_service_mapping",
                            confidence="CONFIRMED",
                        )
                    ],
                )
                apps.append(app)

        # 2. From AssetGraph in-scope assets if not already populated
        if not apps:
            for asset in self.asset_graph.get_all_assets():
                if asset.type in (AssetType.ROOT_DOMAIN, AssetType.SUBDOMAIN, AssetType.HOSTNAME):
                    if not self._is_in_scope(asset.value):
                        continue
                    # Default to HTTPS root
                    base = canonicalize_url(f"https://{asset.value}/")
                    if base not in seen_roots:
                        seen_roots.add(base)
                        apps.append(
                            WebApplication(
                                base_url=base,
                                host=asset.value,
                                scheme="https",
                                port=443,
                                title=asset.attributes.get("http_title"),
                                technologies=list(asset.attributes.get("technologies", [])),
                                provenance=[
                                    ObservationProvenance(
                                        source="asset_graph",
                                        method="asset_root",
                                        confidence="CONFIRMED",
                                    )
                                ],
                            )
                        )
        return apps

    # ==========================================================================
    # 5. MAIN APPLICATION CRAWL & MAPPING PIPELINE
    # ==========================================================================

    def run_discovery(
        self,
        target_applications: Optional[List[WebApplication]] = None,
        resume: bool = False,
    ) -> Dict[str, Any]:
        """
        Executes bounded web application intelligence crawl across target application roots.
        Extracts pages, forms, endpoints, parameters, cookies, and resources.
        """
        apps = target_applications or self.identify_application_roots()
        for app in apps:
            if self.webapp_state and not self.dry_run:
                self.webapp_state.add_application(app)
            # Link Asset to WebApp in graph
            self.webapp_graph.add_relationship(
                AppRelationship(
                    source_id=f"asset:hostname:{app.host}",
                    destination_id=app.key,
                    relation_type=AppRelationType.HOSTS_APPLICATION,
                )
            )

        queue: deque[Tuple[str, int, str, WebApplication]] = deque()
        # Tuple: (url, depth, parent_url, webapp)

        # Initialize crawl queue
        for app in apps:
            if resume and self.webapp_state and self.webapp_state.is_visited(app.base_url):
                continue
            queue.append((app.base_url, 0, "", app))

            # Robots & sitemap initial seeds
            if self.policy.include_robots and not self.policy.passive_only:
                robots_urls = self.parse_robots_txt(app.base_url)
                for r_url in robots_urls:
                    if r_url.endswith(".xml") and self.policy.include_sitemaps:
                        sitemap_items = self.parse_sitemap_xml(r_url)
                        for sm_url in sitemap_items:
                            if not self.webapp_state or not self.webapp_state.is_visited(sm_url):
                                queue.append((sm_url, 1, r_url, app))
                    else:
                        if not self.webapp_state or not self.webapp_state.is_visited(r_url):
                            queue.append((r_url, 1, app.base_url, app))

        stats = {
            "applications_mapped": len(apps),
            "pages_crawled": 0,
            "endpoints_found": 0,
            "parameters_found": 0,
            "forms_found": 0,
            "cookies_found": 0,
            "resources_found": 0,
            "links_found": 0,
        }

        while queue:
            if self.pages_crawled >= self.policy.max_pages:
                break
            if self.request_count >= self.policy.max_requests:
                break

            url, depth, parent_url, app = queue.popleft()
            canon_url = canonicalize_url(url)

            # Skip already visited
            if self.webapp_state and self.webapp_state.is_visited(canon_url):
                continue

            # Scope check
            if not self._is_in_scope(canon_url):
                if self.webapp_state and not self.dry_run:
                    self.webapp_state.mark_rejected(canon_url)
                continue

            # Same origin policy
            if self.policy.same_origin_only and not is_same_origin(canon_url, app.base_url):
                if self.webapp_state and not self.dry_run:
                    self.webapp_state.mark_rejected(canon_url)
                continue

            # Fetch page content
            res = self.fetch_url(canon_url)
            if self.webapp_state and not self.dry_run:
                self.webapp_state.mark_visited(canon_url)

            if not res:
                continue

            self.pages_crawled += 1
            stats["pages_crawled"] += 1

            status_code = res["status_code"]
            headers = res["headers"]
            body = res["body"]
            final_url = res["final_url"]

            content_type = headers.get("content-type") or headers.get("Content-Type") or "text/html"

            # 1. Parse HTML Elements
            parsed = parse_page_html(
                body,
                final_url,
                max_links=self.policy.max_links_per_page,
                max_forms=self.policy.max_forms_per_page,
                max_resources=self.policy.max_resources_per_page,
            )

            # 2. Record WebPage
            page_obj = WebPage(
                url=final_url,
                path=urlsplit(final_url).path or "/",
                method="GET",
                status_code=status_code,
                content_type=content_type,
                title=parsed["title"],
                parent_url=parent_url if parent_url else None,
                depth=depth,
                links_count=len(parsed["links"]),
                forms_count=len(parsed["forms"]),
                scripts_count=len([r for r in parsed["resources"] if r[1] == ResourceType.JS]),
                resources_count=len(parsed["resources"]),
                provenance=[
                    ObservationProvenance(
                        source="crawler",
                        method="http_get",
                        confidence="CONFIRMED",
                    )
                ],
            )
            if self.webapp_state and not self.dry_run:
                self.webapp_state.add_page(page_obj)

            self.webapp_graph.add_relationship(
                AppRelationship(
                    source_id=app.key,
                    destination_id=page_obj.key,
                    relation_type=AppRelationType.HAS_PAGE,
                )
            )

            # 3. Record WebEndpoint and Query Parameters
            parsed_split = urlsplit(final_url)
            query_pairs = parse_qsl(parsed_split.query, keep_blank_values=True)
            param_names = [k for k, _ in query_pairs]

            ep_obj = WebEndpoint(
                url=final_url,
                path=parsed_split.path or "/",
                method="GET",
                parameter_names=param_names,
                parameter_locations=[ParameterLocation.QUERY.value] if param_names else [],
                status_code=status_code,
                content_type=content_type,
                source="crawl",
                provenance=[
                    ObservationProvenance(
                        source="crawler",
                        method="route_discovery",
                        confidence="CONFIRMED",
                    )
                ],
            )
            if self.webapp_state and not self.dry_run:
                self.webapp_state.add_endpoint(ep_obj)
            stats["endpoints_found"] += 1

            self.webapp_graph.add_relationship(
                AppRelationship(
                    source_id=app.key,
                    destination_id=ep_obj.key,
                    relation_type=AppRelationType.HAS_ENDPOINT,
                )
            )

            # Extract Query Parameters
            for p_name, p_val in query_pairs:
                param_obs = ParameterObservation(
                    name=p_name,
                    location=ParameterLocation.QUERY.value,
                    method="GET",
                    endpoint_url=final_url,
                    datatype="int" if p_val.isdigit() else "string",
                    source="query_string",
                    provenance=[
                        ObservationProvenance(
                            source="crawler",
                            method="query_param_extraction",
                            confidence="CONFIRMED",
                        )
                    ],
                )
                if self.webapp_state and not self.dry_run:
                    self.webapp_state.add_parameter(param_obs)
                stats["parameters_found"] += 1

                self.webapp_graph.add_relationship(
                    AppRelationship(
                        source_id=ep_obj.key,
                        destination_id=param_obs.key,
                        relation_type=AppRelationType.ACCEPTS_PARAMETER,
                    )
                )

            # 4. Record Forms & Form Parameters
            for form_dict in parsed["forms"]:
                act = canonicalize_url(form_dict["action"], final_url)
                inputs = form_dict["inputs"]
                has_pw = any("password" in t for t in inputs.values())
                has_file = any("file" in t for t in inputs.values())

                form_obs = FormObservation(
                    page_url=final_url,
                    action=act,
                    method=form_dict["method"],
                    input_names=list(inputs.keys()),
                    input_types=inputs,
                    enctype=form_dict["enctype"],
                    has_password=has_pw,
                    has_file_upload=has_file,
                    provenance=[
                        ObservationProvenance(
                            source="html_parser",
                            method="form_extraction",
                            confidence="CONFIRMED",
                        )
                    ],
                )
                if self.webapp_state and not self.dry_run:
                    self.webapp_state.add_form(form_obs)
                stats["forms_found"] += 1

                self.webapp_graph.add_relationship(
                    AppRelationship(
                        source_id=page_obj.key,
                        destination_id=form_obs.key,
                        relation_type=AppRelationType.HAS_FORM,
                    )
                )

                # Form input parameters
                for iname, itype in inputs.items():
                    p_obs = ParameterObservation(
                        name=iname,
                        location=ParameterLocation.BODY.value if form_dict["method"] == "POST" else ParameterLocation.QUERY.value,
                        method=form_dict["method"],
                        endpoint_url=act,
                        datatype="file" if "file" in itype else "password" if "password" in itype else "string",
                        source="form_input",
                        provenance=[
                            ObservationProvenance(
                                source="html_parser",
                                method="form_input_extraction",
                                confidence="CONFIRMED",
                            )
                        ],
                    )
                    if self.webapp_state and not self.dry_run:
                        self.webapp_state.add_parameter(p_obs)
                    stats["parameters_found"] += 1

                    self.webapp_graph.add_relationship(
                        AppRelationship(
                            source_id=form_obs.key,
                            destination_id=p_obs.key,
                            relation_type=AppRelationType.ACCEPTS_PARAMETER,
                        )
                    )

            # 5. Record Cookies from HTTP Headers
            cookie_obs_list = self.extract_cookies(headers, final_url)
            for c_obs in cookie_obs_list:
                if self.webapp_state and not self.dry_run:
                    self.webapp_state.add_cookie(c_obs)
                stats["cookies_found"] += 1

                self.webapp_graph.add_relationship(
                    AppRelationship(
                        source_id=app.key,
                        destination_id=c_obs.key,
                        relation_type=AppRelationType.SETS_COOKIE,
                    )
                )

            # 6. Record Static / Dynamic Resources (Scripts, CSS, Images, etc.)
            for r_url, r_type, _ in parsed["resources"]:
                canon_res = canonicalize_url(r_url, final_url)
                res_obs = ResourceObservation(
                    url=canon_res,
                    resource_type=r_type.value,
                    source_page=final_url,
                    provenance=[
                        ObservationProvenance(
                            source="html_parser",
                            method="resource_extraction",
                            confidence="CONFIRMED",
                        )
                    ],
                )
                if self.webapp_state and not self.dry_run:
                    self.webapp_state.add_resource(res_obs)
                stats["resources_found"] += 1

                self.webapp_graph.add_relationship(
                    AppRelationship(
                        source_id=page_obj.key,
                        destination_id=res_obs.key,
                        relation_type=AppRelationType.LOADS_RESOURCE,
                    )
                )

            # 7. Record Links and Enqueue Candidate Pages
            for link_target in parsed["links"]:
                canon_dest = canonicalize_url(link_target, final_url)
                is_same_orig = is_same_origin(canon_dest, app.base_url)
                is_in_scp = self._is_in_scope(canon_dest)

                link_obs = LinkObservation(
                    source_url=final_url,
                    destination_url=link_target,
                    canonical_destination=canon_dest,
                    is_same_origin=is_same_orig,
                    is_in_scope=is_in_scp,
                    provenance=[
                        ObservationProvenance(
                            source="html_parser",
                            method="link_extraction",
                            confidence="CONFIRMED",
                        )
                    ],
                )
                if self.webapp_state and not self.dry_run:
                    self.webapp_state.add_link(link_obs)
                stats["links_found"] += 1

                self.webapp_graph.add_relationship(
                    AppRelationship(
                        source_id=page_obj.key,
                        destination_id=canon_dest,
                        relation_type=AppRelationType.LINKS_TO,
                    )
                )

                # Queue for crawling if within depth and scope
                if depth + 1 <= self.policy.max_depth:
                    if is_in_scp and (not self.policy.same_origin_only or is_same_orig):
                        if not self.webapp_state or not self.webapp_state.is_visited(canon_dest):
                            queue.append((canon_dest, depth + 1, final_url, app))
                    else:
                        if self.webapp_state and not self.dry_run:
                            self.webapp_state.mark_rejected(canon_dest)

        # Atomic state save
        if self.webapp_state and not self.dry_run:
            self.webapp_state.save()

        return stats
