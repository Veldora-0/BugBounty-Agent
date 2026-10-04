"""
SSRF Sink & Parameter Intelligence Engine (Phase 9).

Discovers, classifies, and prioritizes SSRF candidate parameters and sinks
from Web Applications (Phase 3), JavaScript endpoints (Phase 4), and
API schemas (Phase 5).
Assigns CANDIDATE lifecycle without falsely declaring every parameter a vulnerability.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlparse

from framework.ssrf.model import (
    SsrfCandidate,
    SsrfCategory,
    SsrfConfidence,
    SsrfSink,
    SsrfSource,
)


# Suspicious parameter names that frequently accept external URLs or destinations
SSRF_PARAM_KEYWORDS: Set[str] = {
    "url", "uri", "target", "dest", "destination", "endpoint", "callback",
    "webhook", "image", "avatar", "import", "source", "src", "fetch",
    "download", "proxy", "redirect", "redir", "link", "template", "remote",
    "resource", "feed", "preview", "pdf", "site", "service", "host", "domain",
    "rss", "webhook_url", "callback_url", "api_url", "return_url", "next",
    "continue", "ref", "document", "doc", "path", "href", "asset", "load",
    "view", "file", "page", "to", "out", "relay", "forward", "forward_to",
}

# Regex to detect URL values in parameters
URL_VALUE_PATTERN = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)

# Path keywords indicating server-side URL consumers
SINK_PATH_PATTERNS: List[Tuple[re.Pattern, str, SsrfCategory]] = [
    (re.compile(r"/(?:[^/]*[-_])?(?:webhook|callback|notify|notification|events?)(?:[-_][^/]*)?(?:/|$)", re.I), "WEBHOOK_DISPATCHER", SsrfCategory.WEBHOOK),
    (re.compile(r"/(?:image|avatar|media|asset)-proxy(?:/|$)", re.I), "IMAGE_PROXY", SsrfCategory.DIRECT),
    (re.compile(r"/(?:[^/]*[-_])?(?:fetch|download|pull|retrieve|get-url)(?:[-_][^/]*)?(?:/|$)", re.I), "URL_FETCHER", SsrfCategory.URL_FETCH),
    (re.compile(r"/(?:[^/]*[-_])?(?:import|upload-from-url|sync)(?:[-_][^/]*)?(?:/|$)", re.I), "REMOTE_IMPORTER", SsrfCategory.IMPORTER),
    (re.compile(r"/(?:[^/]*[-_])?(?:preview|unfurl|thumbnail|render|screenshot|pdf)(?:[-_][^/]*)?(?:/|$)", re.I), "PREVIEW_RENDERER", SsrfCategory.IMPORTER),
    (re.compile(r"/(?:[^/]*[-_])?(?:proxy|forward|relay)(?:[-_][^/]*)?(?:/|$)", re.I), "PROXY_FORWARDER", SsrfCategory.DIRECT),
    (re.compile(r"/(?:[^/]*[-_])?(?:feed|rss|atom)(?:[-_][^/]*)?(?:/|$)", re.I), "FEED_PARSER", SsrfCategory.IMPORTER),
]


class SsrfIntelligenceAnalyzer:
    """
    Analyzes endpoints, query strings, and schemas to discover and model
    potential SSRF candidate parameters.
    """

    @classmethod
    def is_candidate_parameter_name(cls, param_name: str) -> bool:
        """Checks if parameter name matches known SSRF candidate indicators."""
        clean = param_name.strip().lower()
        if clean in SSRF_PARAM_KEYWORDS:
            return True
        # Check subcomponents e.g. target_url, image_link, webhook_dest
        parts = re.split(r"[_\-\.]+", clean)
        return any(p in SSRF_PARAM_KEYWORDS for p in parts)

    @classmethod
    def infer_sink_and_category(
        cls,
        endpoint_url: str,
        param_name: str,
        param_value: Optional[str] = None,
    ) -> Tuple[SsrfSink, SsrfCategory]:
        """Infers likely backend sink mechanism and taxonomy category."""
        clean_param = param_name.lower()

        # Check path patterns first
        for pat, sink_type, cat in SINK_PATH_PATTERNS:
            if pat.search(endpoint_url):
                return (
                    SsrfSink(sink_type=sink_type, description=f"Inferred from route pattern matching '{pat.pattern}'"),
                    cat,
                )

        # Check parameter name heuristics
        if any(w in clean_param for w in ("webhook", "callback", "notify")):
            return (
                SsrfSink(sink_type="WEBHOOK_DISPATCHER", description="Webhook or callback delivery parameter"),
                SsrfCategory.WEBHOOK,
            )
        if any(w in clean_param for w in ("image", "avatar", "icon", "photo")):
            return (
                SsrfSink(sink_type="IMAGE_PROXY", description="Remote image/media fetch mechanism"),
                SsrfCategory.IMPORTER,
            )
        if any(w in clean_param for w in ("preview", "screenshot", "pdf", "unfurl", "render")):
            return (
                SsrfSink(sink_type="PREVIEW_RENDERER", description="Document/preview generator fetch sink"),
                SsrfCategory.IMPORTER,
            )
        if any(w in clean_param for w in ("redirect", "redir", "next", "return", "continue")):
            return (
                SsrfSink(sink_type="REDIRECT_HANDLER", description="Redirect-mediated fetch candidate"),
                SsrfCategory.REDIRECT_MEDIATED,
            )
        if any(w in clean_param for w in ("import", "sync", "feed", "rss")):
            return (
                SsrfSink(sink_type="REMOTE_IMPORTER", description="Remote resource or feed importer"),
                SsrfCategory.IMPORTER,
            )

        # Default fallback
        return (
            SsrfSink(sink_type="URL_FETCHER", description="Generic server-side URL fetch candidate"),
            SsrfCategory.DIRECT,
        )

    @classmethod
    def extract_from_url(
        cls,
        endpoint_url: str,
        method: str = "GET",
        application: str = "",
    ) -> List[SsrfCandidate]:
        """
        Parses query parameters from a URL and constructs candidates for matching parameters.
        """
        candidates: List[SsrfCandidate] = []
        parsed = urlparse(endpoint_url)
        app_name = application or parsed.netloc or "target.local"

        qsl = parse_qsl(parsed.query, keep_blank_values=True)
        for param, val in qsl:
            if cls.is_candidate_parameter_name(param) or (val and URL_VALUE_PATTERN.match(val)):
                sink, cat = cls.infer_sink_and_category(endpoint_url, param, val)
                source = SsrfSource(
                    source_type="QUERY",
                    parameter_name=param,
                    original_value=val,
                    context=f"Query parameter in {endpoint_url}",
                )
                url_type = "ABSOLUTE_URL" if (val and URL_VALUE_PATTERN.match(val)) else "URL_PARAMETER"

                candidates.append(
                    SsrfCandidate(
                        application=app_name,
                        endpoint=endpoint_url,
                        parameter=param,
                        param_location="QUERY",
                        method=method,
                        category=cat,
                        source_intel=source,
                        sink_intel=sink,
                        url_type=url_type,
                        confidence=SsrfConfidence.CANDIDATE,
                        lifecycle_state="CANDIDATE",
                        notes=f"Identified candidate parameter '{param}' in endpoint query string.",
                    )
                )

        return candidates

    @classmethod
    def discover_from_program_state(
        cls,
        program_dir: str,
        asset_filter: Optional[str] = None,
        endpoint_filter: Optional[str] = None,
    ) -> List[SsrfCandidate]:
        """
        Consumes Phase 3 (WebApps), Phase 4 (JavaScript), and Phase 5 (API) state files
        to discover comprehensive SSRF candidates.
        """
        candidates: List[SsrfCandidate] = []
        seen_keys: Set[str] = set()

        # 1. API state (state/api.json)
        api_path = os.path.join(program_dir, "state", "api.json")
        if os.path.exists(api_path):
            try:
                with open(api_path, "r", encoding="utf-8") as f:
                    api_data = json.load(f)
                catalog = api_data.get("catalog", {})
                for path_key, ep_data in catalog.items():
                    url = ep_data.get("url") or path_key
                    if endpoint_filter and endpoint_filter not in url:
                        continue
                    if asset_filter and asset_filter not in url:
                        continue

                    for op in ep_data.get("operations", []):
                        method = op.get("method", "GET")
                        for param in op.get("parameters", []):
                            pname = param.get("name") if isinstance(param, dict) else str(param)
                            ploc = param.get("in", "query").upper() if isinstance(param, dict) else "QUERY"
                            ptype = param.get("type", "") if isinstance(param, dict) else ""
                            pformat = param.get("format", "") if isinstance(param, dict) else ""

                            if (
                                cls.is_candidate_parameter_name(pname)
                                or pformat == "uri"
                                or ptype == "uri"
                            ):
                                key = f"{method}:{url}:{pname}:{ploc}"
                                if key not in seen_keys:
                                    seen_keys.add(key)
                                    sink, cat = cls.infer_sink_and_category(url, pname)
                                    source = SsrfSource(
                                        source_type=ploc,
                                        parameter_name=pname,
                                        context=f"API operation {method} {url}",
                                    )
                                    candidates.append(
                                        SsrfCandidate(
                                            application=urlparse(url).netloc or "target.local",
                                            endpoint=url,
                                            parameter=pname,
                                            param_location=ploc,
                                            method=method,
                                            category=cat,
                                            source_intel=source,
                                            sink_intel=sink,
                                            confidence=SsrfConfidence.CANDIDATE,
                                            lifecycle_state="CANDIDATE",
                                            notes=f"Discovered in Phase 5 API schema: parameter '{pname}' ({pformat or ptype or 'name match'}).",
                                        )
                                    )
            except Exception:
                pass

        # 2. Web Application state (state/webapps.json)
        web_path = os.path.join(program_dir, "state", "webapps.json")
        if os.path.exists(web_path):
            try:
                with open(web_path, "r", encoding="utf-8") as f:
                    web_data = json.load(f)
                for app in web_data.get("web_applications", {}).values():
                    for ep in app.get("endpoints", []):
                        url = ep.get("url", "")
                        method = ep.get("method", "GET")
                        if not url:
                            continue
                        if endpoint_filter and endpoint_filter not in url:
                            continue
                        if asset_filter and asset_filter not in url:
                            continue

                        extracted = cls.extract_from_url(url, method=method)
                        for c in extracted:
                            k = f"{c.method}:{c.endpoint}:{c.parameter}:{c.param_location}"
                            if k not in seen_keys:
                                seen_keys.add(k)
                                candidates.append(c)
            except Exception:
                pass

        # 3. JavaScript state (state/javascript.json)
        js_path = os.path.join(program_dir, "state", "javascript.json")
        if os.path.exists(js_path):
            try:
                with open(js_path, "r", encoding="utf-8") as f:
                    js_data = json.load(f)
                for route in js_data.get("routes", []):
                    r_path = route.get("path") or route.get("route", "")
                    if not r_path or not r_path.startswith("http"):
                        continue
                    if endpoint_filter and endpoint_filter not in r_path:
                        continue
                    if asset_filter and asset_filter not in r_path:
                        continue

                    extracted = cls.extract_from_url(r_path, method="GET")
                    for c in extracted:
                        k = f"{c.method}:{c.endpoint}:{c.parameter}:{c.param_location}"
                        if k not in seen_keys:
                            seen_keys.add(k)
                            c.notes = "Discovered in Phase 4 JavaScript routes."
                            candidates.append(c)
            except Exception:
                pass

        return candidates
