"""
Web Application Intelligence State Manager for BugBounty-Agent.

Provides persistent, atomic, resumable, and deduplicated storage of web application
observations (WebApplications, WebPages, WebEndpoints, Parameters, Forms, Cookies,
Resources, Links, CrawlQueue, and VisitedURLs) in:
~/BugBounty-Workspace/programs/<program>/state/webapps.json.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import tempfile
from typing import Any, Dict, List, Optional, Set

from framework.webapp.model import (
    CookieObservation,
    FormObservation,
    LinkObservation,
    ParameterObservation,
    ResourceObservation,
    WebApplication,
    WebEndpoint,
    WebPage,
    canonicalize_url,
)


class WebAppStateManager:
    """
    Manages persistent, atomic local state for web application intelligence.
    Stores application models, pages, routes, parameters, forms, cookies, and resources.
    """

    def __init__(self, program_dir: str):
        self.program_dir = os.path.abspath(program_dir)
        self.state_dir = os.path.join(self.program_dir, "state")
        os.makedirs(self.state_dir, exist_ok=True)
        self.webapps_file = os.path.join(self.state_dir, "webapps.json")

        self.applications: Dict[str, WebApplication] = {}
        self.pages: Dict[str, WebPage] = {}
        self.endpoints: Dict[str, WebEndpoint] = {}
        self.parameters: Dict[str, ParameterObservation] = {}
        self.forms: Dict[str, FormObservation] = {}
        self.cookies: Dict[str, CookieObservation] = {}
        self.resources: Dict[str, ResourceObservation] = {}
        self.links: Dict[str, LinkObservation] = {}

        self.visited_urls: Set[str] = set()
        self.crawl_queue: List[Dict[str, Any]] = []  # items: {"url": str, "depth": int, "parent": str}
        self.rejected_urls: Set[str] = set()

        self.metadata: Dict[str, Any] = {
            "first_run": datetime.now(timezone.utc).isoformat(),
            "last_run": datetime.now(timezone.utc).isoformat(),
            "total_pages": 0,
            "total_endpoints": 0,
            "total_parameters": 0,
            "total_forms": 0,
        }

        self.load()

    def _atomic_write_json(self, filepath: str, data: Any) -> None:
        """Writes JSON data atomically via a temporary file."""
        dir_name = os.path.dirname(filepath)
        with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
            json.dump(data, tf, indent=2)
            temp_path = tf.name
        os.replace(temp_path, filepath)

    def load(self) -> None:
        """Loads existing web application intelligence state from webapps.json if present."""
        if not os.path.isfile(self.webapps_file):
            return

        try:
            with open(self.webapps_file, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
        except (json.JSONDecodeError, OSError):
            return

        self.metadata = data.get("metadata", self.metadata)
        self.visited_urls = set(data.get("visited_urls", []))
        self.rejected_urls = set(data.get("rejected_urls", []))
        self.crawl_queue = list(data.get("crawl_queue", []))

        # Rehydrate WebApplications
        for item in data.get("applications", []):
            app = WebApplication.from_dict(item)
            self.applications[app.key] = app

        # Rehydrate WebPages
        for item in data.get("pages", []):
            page = WebPage.from_dict(item)
            self.pages[page.key] = page

        # Rehydrate WebEndpoints
        for item in data.get("endpoints", []):
            ep = WebEndpoint.from_dict(item)
            self.endpoints[ep.key] = ep

        # Rehydrate Parameters
        for item in data.get("parameters", []):
            param = ParameterObservation.from_dict(item)
            self.parameters[param.key] = param

        # Rehydrate Forms
        for item in data.get("forms", []):
            form = FormObservation.from_dict(item)
            self.forms[form.key] = form

        # Rehydrate Cookies
        for item in data.get("cookies", []):
            cookie = CookieObservation.from_dict(item)
            self.cookies[cookie.key] = cookie

        # Rehydrate Resources
        for item in data.get("resources", []):
            res = ResourceObservation.from_dict(item)
            self.resources[res.key] = res

        # Rehydrate Links
        for item in data.get("links", []):
            link = LinkObservation.from_dict(item)
            self.links[link.key] = link

    def save(self) -> None:
        """Saves current state atomically to webapps.json."""
        self.metadata["last_run"] = datetime.now(timezone.utc).isoformat()
        self.metadata["total_pages"] = len(self.pages)
        self.metadata["total_endpoints"] = len(self.endpoints)
        self.metadata["total_parameters"] = len(self.parameters)
        self.metadata["total_forms"] = len(self.forms)

        export_data = {
            "metadata": self.metadata,
            "visited_urls": sorted(list(self.visited_urls)),
            "rejected_urls": sorted(list(self.rejected_urls)),
            "crawl_queue": list(self.crawl_queue),
            "applications": [a.to_dict() for a in sorted(self.applications.values(), key=lambda x: x.key)],
            "pages": [p.to_dict() for p in sorted(self.pages.values(), key=lambda x: x.key)],
            "endpoints": [e.to_dict() for e in sorted(self.endpoints.values(), key=lambda x: x.key)],
            "parameters": [p.to_dict() for p in sorted(self.parameters.values(), key=lambda x: x.key)],
            "forms": [f.to_dict() for f in sorted(self.forms.values(), key=lambda x: x.key)],
            "cookies": [c.to_dict() for c in sorted(self.cookies.values(), key=lambda x: x.key)],
            "resources": [r.to_dict() for r in sorted(self.resources.values(), key=lambda x: x.key)],
            "links": [l.to_dict() for l in sorted(self.links.values(), key=lambda x: x.key)],
        }
        self._atomic_write_json(self.webapps_file, export_data)

    # ---------------- Add & Deduplicate Observations ----------------

    def add_application(self, app: WebApplication) -> bool:
        """Adds or updates a WebApplication root."""
        key = app.key
        if key in self.applications:
            existing = self.applications[key]
            if not existing.title and app.title:
                existing.title = app.title
            if not existing.server and app.server:
                existing.server = app.server
            for t in app.technologies:
                if t not in existing.technologies:
                    existing.technologies.append(t)
            for p in app.provenance:
                existing.provenance.append(p)
            existing.last_seen = datetime.now(timezone.utc).isoformat()
            return False
        else:
            self.applications[key] = app
            return True

    def add_page(self, page: WebPage) -> bool:
        """Adds or updates a WebPage observation."""
        key = page.key
        if key in self.pages:
            existing = self.pages[key]
            if not existing.title and page.title:
                existing.title = page.title
            existing.links_count = max(existing.links_count, page.links_count)
            existing.forms_count = max(existing.forms_count, page.forms_count)
            existing.scripts_count = max(existing.scripts_count, page.scripts_count)
            existing.resources_count = max(existing.resources_count, page.resources_count)
            for p in page.provenance:
                existing.provenance.append(p)
            return False
        else:
            self.pages[key] = page
            return True

    def add_endpoint(self, ep: WebEndpoint) -> bool:
        """Adds or updates a WebEndpoint route."""
        key = ep.key
        if key in self.endpoints:
            existing = self.endpoints[key]
            for param in ep.parameter_names:
                if param not in existing.parameter_names:
                    existing.parameter_names.append(param)
            for loc in ep.parameter_locations:
                if loc not in existing.parameter_locations:
                    existing.parameter_locations.append(loc)
            for p in ep.provenance:
                existing.provenance.append(p)
            return False
        else:
            self.endpoints[key] = ep
            return True

    def add_parameter(self, param: ParameterObservation) -> bool:
        """Adds or updates a ParameterObservation."""
        key = param.key
        if key in self.parameters:
            existing = self.parameters[key]
            for p in param.provenance:
                existing.provenance.append(p)
            return False
        else:
            self.parameters[key] = param
            return True

    def add_form(self, form: FormObservation) -> bool:
        """Adds or updates a FormObservation."""
        key = form.key
        if key in self.forms:
            existing = self.forms[key]
            for p in form.provenance:
                existing.provenance.append(p)
            return False
        else:
            self.forms[key] = form
            return True

    def add_cookie(self, cookie: CookieObservation) -> bool:
        """Adds or updates a CookieObservation."""
        key = cookie.key
        if key in self.cookies:
            existing = self.cookies[key]
            for p in cookie.provenance:
                existing.provenance.append(p)
            return False
        else:
            self.cookies[key] = cookie
            return True

    def add_resource(self, res: ResourceObservation) -> bool:
        """Adds or updates a ResourceObservation."""
        key = res.key
        if key in self.resources:
            existing = self.resources[key]
            if not existing.content_type and res.content_type:
                existing.content_type = res.content_type
            if not existing.size and res.size:
                existing.size = res.size
            for p in res.provenance:
                existing.provenance.append(p)
            return False
        else:
            self.resources[key] = res
            return True

    def add_link(self, link: LinkObservation) -> bool:
        """Adds or updates a LinkObservation."""
        key = link.key
        if key in self.links:
            return False
        self.links[key] = link
        return True

    # ---------------- Crawl State & Deduplication ----------------

    def is_visited(self, url: str) -> bool:
        return canonicalize_url(url) in self.visited_urls

    def mark_visited(self, url: str) -> None:
        self.visited_urls.add(canonicalize_url(url))

    def mark_rejected(self, url: str) -> None:
        self.rejected_urls.add(canonicalize_url(url))

    def get_endpoints_for_app(self, app_base: str) -> List[WebEndpoint]:
        clean = canonicalize_url(app_base)
        return [e for e in self.endpoints.values() if e.url.startswith(clean)]

    def get_forms_for_app(self, app_base: str) -> List[FormObservation]:
        clean = canonicalize_url(app_base)
        return [f for f in self.forms.values() if f.page_url.startswith(clean)]

    def get_resources_for_app(self, app_base: str) -> List[ResourceObservation]:
        clean = canonicalize_url(app_base)
        return [r for r in self.resources.values() if r.source_page.startswith(clean) or r.url.startswith(clean)]
