"""
Static Analysis and Pattern Matcher for JavaScript Intelligence.

Extracts endpoints, frontend routes, parameter references, dependencies,
source maps, and interesting/sensitive strings from JavaScript code without
executing target scripts.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from framework.assets.provenance import ObservationProvenance
from framework.javascript.model import (
    DependencyObservation,
    DiscoveredEndpoint,
    DiscoveredRoute,
    InterestingString,
    ParameterReference,
    SourceMapObservation,
    StringSensitivity,
    mask_sensitive_value,
)
from framework.webapp.model import canonicalize_url


# Regex patterns for detecting minified scripts
MINIFIED_LINE_THRESHOLD = 500  # Average characters per line exceeding this indicates minification

# Known dependency library signatures
DEPENDENCY_SIGNATURES: List[Tuple[str, str, Optional[str]]] = [
    # (name, pattern, version_group_regex)
    ("React", r"\bReact\s*=\s*\{|ReactDOM|react\.production\.min\.js|__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED", r"React v([\d\.]+)"),
    ("Vue.js", r"\bVue\s*=\s*function|Vue\.version\s*=|vue\.runtime\.esm|vue\.global\.prod", r"Vue\.js v([\d\.]+)"),
    ("Angular", r"\bng-version|angular\.module|@angular\/core", r"ng-version=\"([\d\.]+)\""),
    ("jQuery", r"jQuery\s*v([\d\.]+)|jQuery\s*=\s*function\(\s*selector", r"jQuery\s*v([\d\.]+)"),
    ("Axios", r"axios\.defaults|createInstance\(defaults\)|isAxiosError", r"axios\s+v([\d\.]+)"),
    ("Lodash", r"\b_\.VERSION\s*=\s*[\"']([\d\.]+)[\"']|lodash\.min\.js", r"lodash\s*v([\d\.]+)"),
    ("Next.js", r"__NEXT_DATA__|next\/router|_next\/static", None),
    ("Webpack", r"webpackChunk|__webpack_require__|webpackJsonp", None),
    ("Vite", r"__vite__mapDeps|__vite_plugin", None),
]

# Endpoint regex patterns (fetch, axios, ajax, websocket, absolute/relative API paths)
ENDPOINT_PATTERNS: List[Tuple[str, str]] = [
    # fetch("...")
    ("fetch", r"""fetch\s*\(\s*["']([^"'`\s]+)["']"""),
    # axios.get/post("...")
    ("axios", r"""axios(?:\.get|\.post|\.put|\.delete|\.patch)?\s*\(\s*["']([^"'`\s]+)["']"""),
    # $.ajax / $.get / $.post / $.ajax({ url: "..." })
    ("jquery_ajax", r"""\$\.(?:ajax|get|post|getJSON)\s*\(\s*(?:\{[^}]*?\burl\s*:\s*)?["']([^"'`\s]+)["']"""),
    # open("GET", "...")
    ("xhr", r"""\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["']([^"'`\s]+)["']"""),
    # WebSocket("ws://...")
    ("websocket", r"""new\s+WebSocket\s*\(\s*["']([^"'`\s]+)["']"""),
    # Common REST API string patterns (/api/v1/..., /v2/..., /graphql, /oauth/...)
    ("rest_path", r"""["'](\/(?:api|v[0-9]+|graphql|oauth|auth|rest|admin|user|users|webhook|webhooks)(?:\/[a-zA-Z0-9_\-\/\.\?=&]*)?)["']"""),
]

# Frontend SPA Route patterns
ROUTE_PATTERNS: List[Tuple[str, str]] = [
    # path: "/dashboard" or path: '/settings'
    ("router_path", r"""path\s*:\s*["'](\/[a-zA-Z0-9_\-\/:]+)["']"""),
    # <Route path="/..." ...>
    ("react_route", r"""<Route\s+[^>]*path=["'](\/[a-zA-Z0-9_\-\/:]+)["']"""),
    # href="/..." or to="/..."
    ("client_link", r"""to\s*=\s*["'](\/[a-zA-Z0-9_\-\/:]+)["']"""),
]

# Parameter name patterns
PARAMETER_PATTERNS: List[Tuple[str, str]] = [
    # URLSearchParams.get("...")
    ("urlsearchparams", r"""(?:URLSearchParams|params)\.get\s*\(\s*["']([a-zA-Z0-9_\-]+)["']"""),
    # req.query.param or req.body.param
    ("req_prop", r"""(?:query|body|params)\.([a-zA-Z0-9_]+)\b"""),
    # qs.parse("...") / query-string
    ("qs_param", r"""["']([a-zA-Z0-9_\-]+)["']\s*:\s*(?:req|req\.query|location)"""),
]

# Sensitive and interesting string classification signatures
INTERESTING_PATTERNS: List[Tuple[str, str, StringSensitivity, str]] = [
    # (category, regex, sensitivity, description)
    ("aws_key", r"\b(AKIA[0-9A-Z]{16})\b", StringSensitivity.HIGH_CONFIDENCE_SECRET, "AWS Access Key ID"),
    ("jwt_token", r"\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b", StringSensitivity.SENSITIVE_LOOKING, "JSON Web Token"),
    ("slack_webhook", r"https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8}\/B[0-9A-Z]{8}\/[a-zA-Z0-9]{24}", StringSensitivity.HIGH_CONFIDENCE_SECRET, "Slack Incoming Webhook"),
    ("google_api_key", r"\b(AIza[0-9A-Za-z\-_]{30,35})\b", StringSensitivity.SENSITIVE_LOOKING, "Google API Key"),
    ("github_pat", r"\b(ghp_[0-9a-zA-Z]{36})\b", StringSensitivity.HIGH_CONFIDENCE_SECRET, "GitHub Personal Access Token"),
    ("private_key", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", StringSensitivity.HIGH_CONFIDENCE_SECRET, "Private Key PEM block"),
    ("bearer_token", r"""(?:Bearer|bearer)\s+([a-zA-Z0-9_\-\.]{20,})""", StringSensitivity.SENSITIVE_LOOKING, "Bearer Token in Header/String"),
    ("env_var", r"\b(process\.env\.[A-Z0-9_]+)\b", StringSensitivity.INFORMATIONAL, "Node process.env reference"),
    ("internal_host", r"\b((?:[a-zA-Z0-9_\-]+\.)+(?:internal|corp|local|lan|priv))\b", StringSensitivity.INTERESTING, "Internal domain/host reference"),
    ("cloud_bucket", r"\b([a-z0-9\.\-_]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com)\b", StringSensitivity.INTERESTING, "Amazon S3 Bucket endpoint"),
    ("cloud_storage", r"\b(storage\.googleapis\.com\/[a-z0-9\.\-_]+)\b", StringSensitivity.INTERESTING, "Google Cloud Storage endpoint"),
    ("firebase_url", r"\b([a-z0-9\-]+\.firebaseio\.com)\b", StringSensitivity.INTERESTING, "Firebase database URL"),
]


class JavaScriptAnalyzer:
    """
    Analyzes JavaScript source code deterministically using regex pattern extraction,
    extracting endpoints, client routes, parameters, interesting strings, dependencies,
    and source maps.
    """

    def __init__(self, source_url: str, js_content: str):
        self.source_url = source_url
        self.content = js_content
        self.content_length = len(js_content)

    def is_minified(self) -> bool:
        """Determines whether content appears minified based on length and line count."""
        lines = self.content.splitlines()
        if not lines:
            return False
        avg_line_length = self.content_length / len(lines)
        return avg_line_length > MINIFIED_LINE_THRESHOLD or (len(lines) < 5 and self.content_length > 1000)

    def extract_source_map(self) -> Optional[SourceMapObservation]:
        """Detects //# sourceMappingURL=... references in the script."""
        # Find //# sourceMappingURL=... or //@ sourceMappingURL=...
        match = re.search(r"//[#@]\s*sourceMappingURL=([^\s]+)", self.content)
        if match:
            sm_url = match.group(1).strip()
            # Canonicalize or join against source script URL
            canon_sm = canonicalize_url(sm_url, self.source_url)
            return SourceMapObservation(
                source_js_url=self.source_url,
                source_map_url=canon_sm,
                provenance=[
                    ObservationProvenance(
                        source="js_analyzer",
                        method="sourcemap_directive",
                        confidence="CONFIRMED",
                    )
                ],
            )
        return None

    def extract_dependencies(self) -> List[DependencyObservation]:
        """Detects third-party libraries and frameworks from banners and global signatures."""
        dependencies: List[DependencyObservation] = []
        seen_names: Set[str] = set()

        # Check comment banner in first 2000 characters
        banner = self.content[:2000]

        for name, sig_pattern, ver_regex in DEPENDENCY_SIGNATURES:
            if name in seen_names:
                continue
            if re.search(sig_pattern, self.content, re.IGNORECASE):
                version = None
                if ver_regex:
                    ver_match = re.search(ver_regex, banner, re.IGNORECASE) or re.search(ver_regex, self.content, re.IGNORECASE)
                    if ver_match:
                        version = ver_match.group(1).strip()

                dependencies.append(
                    DependencyObservation(
                        name=name,
                        version=version,
                        detection_method="signature_match",
                        source_resource_url=self.source_url,
                        confidence="CONFIRMED" if version else "PROBABLE",
                        provenance=[
                            ObservationProvenance(
                                source="js_analyzer",
                                method="dependency_signature",
                                confidence="CONFIRMED" if version else "PROBABLE",
                            )
                        ],
                    )
                )
                seen_names.add(name)

        return dependencies

    def extract_endpoints(self) -> List[DiscoveredEndpoint]:
        """Extracts API endpoints, routes, and websocket URLs from script contents."""
        endpoints: List[DiscoveredEndpoint] = []
        seen_keys: Set[str] = set()

        for method_name, pattern in ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, self.content):
                raw = match.group(1).strip()
                # Exclude static image/font assets and non-endpoint extensions
                if raw.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".ico", ".woff", ".woff2")):
                    continue
                # Exclude invalid characters or template artifacts
                if any(c in raw for c in ("<", ">", "{", "}", ";", "\n", "\r")):
                    continue
                if len(raw) < 2 or raw == "/":
                    continue

                # Normalization
                if raw.startswith(("http://", "https://", "ws://", "wss://")):
                    norm = canonicalize_url(raw)
                elif raw.startswith("/"):
                    norm = raw
                else:
                    norm = f"/{raw}"

                # Infer HTTP method
                inferred_method = "UNKNOWN"
                if "get" in method_name:
                    inferred_method = "GET"
                elif "post" in method_name:
                    inferred_method = "POST"
                elif "websocket" in method_name:
                    inferred_method = "WS"
                elif "graphql" in norm.lower():
                    inferred_method = "POST"

                key = f"{inferred_method} {norm}"
                if key in seen_keys:
                    continue
                seen_keys.add(key)

                # Snippet context
                start = max(0, match.start() - 20)
                end = min(len(self.content), match.end() + 20)
                snippet = self.content[start:end].replace("\n", " ")

                endpoints.append(
                    DiscoveredEndpoint(
                        raw_endpoint=raw,
                        normalized_endpoint=norm,
                        method=inferred_method,
                        source_resource_url=self.source_url,
                        evidence_snippet=snippet,
                        confidence="PROBABLE" if inferred_method != "UNKNOWN" else "OBSERVED",
                        extraction_method=method_name,
                        provenance=[
                            ObservationProvenance(
                                source="js_analyzer",
                                method=f"endpoint_regex:{method_name}",
                                confidence="PROBABLE",
                            )
                        ],
                    )
                )

        return endpoints

    def extract_routes(self) -> List[DiscoveredRoute]:
        """Extracts frontend SPA routes and path templates."""
        routes: List[DiscoveredRoute] = []
        seen_patterns: Set[str] = set()

        for hint, pattern in ROUTE_PATTERNS:
            for match in re.finditer(pattern, self.content):
                r_path = match.group(1).strip()
                if not r_path.startswith("/") or len(r_path) < 2 or r_path == "/":
                    continue
                if r_path in seen_patterns:
                    continue
                seen_patterns.add(r_path)

                start = max(0, match.start() - 20)
                end = min(len(self.content), match.end() + 20)
                snippet = self.content[start:end].replace("\n", " ")

                routes.append(
                    DiscoveredRoute(
                        route_pattern=r_path,
                        framework_hint=hint,
                        source_resource_url=self.source_url,
                        evidence_snippet=snippet,
                        confidence="OBSERVED",
                        provenance=[
                            ObservationProvenance(
                                source="js_analyzer",
                                method=f"route_regex:{hint}",
                                confidence="OBSERVED",
                            )
                        ],
                    )
                )

        return routes

    def extract_parameters(self) -> List[ParameterReference]:
        """Extracts candidate parameter references from script logic."""
        parameters: List[ParameterReference] = []
        seen_keys: Set[str] = set()

        for loc_hint, pattern in PARAMETER_PATTERNS:
            for match in re.finditer(pattern, self.content):
                p_name = match.group(1).strip()
                if not p_name or len(p_name) < 2 or len(p_name) > 50:
                    continue
                if p_name.isdigit():
                    continue

                key = f"{loc_hint}:{p_name.lower()}"
                if key in seen_keys:
                    continue
                seen_keys.add(key)

                start = max(0, match.start() - 20)
                end = min(len(self.content), match.end() + 20)
                snippet = self.content[start:end].replace("\n", " ")

                parameters.append(
                    ParameterReference(
                        name=p_name,
                        location_hint="query" if "url" in loc_hint or "query" in loc_hint else "body",
                        source_resource_url=self.source_url,
                        evidence_snippet=snippet,
                        confidence="OBSERVED",
                        provenance=[
                            ObservationProvenance(
                                source="js_analyzer",
                                method=f"param_regex:{loc_hint}",
                                confidence="OBSERVED",
                            )
                        ],
                    )
                )

        return parameters

    def extract_interesting_strings(self) -> List[InterestingString]:
        """Classifies strings, API tokens, cloud endpoints, and public keys with masking."""
        results: List[InterestingString] = []
        seen_keys: Set[str] = set()

        for category, pattern, sensitivity, desc in INTERESTING_PATTERNS:
            for match in re.finditer(pattern, self.content):
                val = match.group(1).strip() if match.groups() else match.group(0).strip()
                if not val or len(val) < 4:
                    continue

                # Mask sensitive values
                masked = mask_sensitive_value(val) if sensitivity in (StringSensitivity.HIGH_CONFIDENCE_SECRET, StringSensitivity.SENSITIVE_LOOKING) else val

                key = f"{category}:{val}"
                if key in seen_keys:
                    continue
                seen_keys.add(key)

                start = max(0, match.start() - 20)
                end = min(len(self.content), match.end() + 20)
                # Replace real value with masked value in evidence snippet
                snippet = self.content[start:end].replace("\n", " ")
                snippet = snippet.replace(val, masked)

                results.append(
                    InterestingString(
                        category=category,
                        matched_value=val,
                        masked_value=masked,
                        sensitivity=sensitivity.value,
                        source_resource_url=self.source_url,
                        evidence_snippet=snippet,
                        confidence="CONFIRMED" if sensitivity == StringSensitivity.HIGH_CONFIDENCE_SECRET else "PROBABLE",
                        provenance=[
                            ObservationProvenance(
                                source="js_analyzer",
                                method=f"interesting_pattern:{category}",
                                confidence="CONFIRMED" if sensitivity == StringSensitivity.HIGH_CONFIDENCE_SECRET else "PROBABLE",
                            )
                        ],
                    )
                )

        return results

    def analyze_all(self) -> Dict[str, Any]:
        """Executes full static analysis pass across the JavaScript resource."""
        return {
            "is_minified": self.is_minified(),
            "source_map": self.extract_source_map(),
            "dependencies": self.extract_dependencies(),
            "endpoints": self.extract_endpoints(),
            "routes": self.extract_routes(),
            "parameters": self.extract_parameters(),
            "interesting_strings": self.extract_interesting_strings(),
        }
