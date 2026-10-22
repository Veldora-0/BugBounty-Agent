"""
API Security and Parameter Intelligence Engine for BugBounty-Agent.

Orchestrates multi-source API correlation:
- Phase 2 HTTP reconnaissance observations
- Phase 3 Web applications, endpoints, and form parameters
- Phase 4 JavaScript endpoints, routes, and parameter references
- OpenAPI / Swagger specification discovery and parsing
- GraphQL endpoint identification and controlled analysis
- Semantic parameter classification and schema extraction
- API relationship graph generation and atomic state persistence
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
import json
import os
import socket
import ssl
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urljoin, urlsplit, urlparse

from framework.api.graph import ApiGraph, ApiRelationship, ApiRelationType
from framework.api.model import (
    ApiApplication,
    ApiAuthenticationObservation,
    ApiEndpoint,
    ApiParameter,
    ApiRequestSchema,
    ApiResponseSchema,
    ApiSpecification,
    ApiStyle,
    AuthScheme,
    ParameterLocation,
    ParameterRole,
    ParameterUsageObservation,
    SpecFormat,
)
from framework.api.parser import (
    GraphQLAnalyzer,
    OpenApiParser,
    classify_parameter_role,
    infer_path_parameters,
)
from framework.api.state import ApiStateManager
from framework.assets.provenance import ObservationProvenance
from framework.common.transport import PinnedHTTPHandler, PinnedHTTPSConnection
from framework.javascript.state import JavaScriptStateManager
from framework.recon.state import ReconStateManager
from framework.scope.engine import ScopeEngine, ScopeStatus
from framework.validation.engine import ScopeViolationError, is_ssrf_prohibited_ip
from framework.webapp.model import canonicalize_url
from framework.webapp.state import WebAppStateManager


COMMON_SPEC_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/docs/openapi.json",
    "/api/openapi.json",
]


@dataclass
class ApiPolicy:
    """Operational constraints and safety ceilings for API intelligence."""
    max_endpoints: int = 500
    max_parameters: int = 5000
    max_parameters_per_endpoint: int = 100
    max_schemas_per_endpoint: int = 50
    max_requests: int = 200
    max_bytes: int = 10 * 1024 * 1024  # 10 MB total
    max_bytes_per_spec: int = 2 * 1024 * 1024  # 2 MB per specification
    safe_methods: Tuple[str, ...] = ("GET", "HEAD", "OPTIONS")
    passive_only: bool = False
    allow_graphql_introspection: bool = False
    correlate_js: bool = True
    probe_common_spec_paths: bool = True
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BugBounty-Agent/5.0"
    timeout: float = 5.0
    max_redirects: int = 5


class ApiSafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    HTTP redirect handler enforcing scope boundaries, anti-SSRF policies,
    protocol downgrade prevention, destination-IP pinning, and request budget accounting.
    """

    def __init__(
        self,
        engine: ApiIntelligenceEngine,
        ip_map: Dict[str, Sequence[str]],
        max_redirects: int = 5,
        original_url: Optional[str] = None,
    ):
        super().__init__()
        self.engine = engine
        self.ip_map = ip_map
        self.max_redirects = max_redirects
        self.redirect_count = 0
        self.current_url = original_url

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        self.redirect_count += 1
        if self.redirect_count > self.max_redirects:
            raise ScopeViolationError(f"Too many redirects: exceeded maximum of {self.max_redirects}")

        if not newurl or not isinstance(newurl, str):
            raise ScopeViolationError(f"Invalid redirect target URL: {newurl}")

        parsed_new = urlsplit(newurl)
        new_scheme = (parsed_new.scheme or "").lower()
        if new_scheme not in ("http", "https"):
            raise ScopeViolationError(f"Redirect to unsupported scheme: {new_scheme}")

        orig_url = self.current_url
        if req is not None and hasattr(req, "full_url"):
            orig_url = req.full_url
        elif req is not None and hasattr(req, "get_full_url"):
            orig_url = req.get_full_url()

        if orig_url:
            orig_scheme = urlsplit(orig_url).scheme.lower()
            if orig_scheme == "https" and new_scheme == "http":
                raise ScopeViolationError("Protocol downgrade from HTTPS to HTTP forbidden during redirect")

        # Request budget check and increment for the redirect hop
        if self.engine.request_count >= self.engine.policy.max_requests:
            raise ScopeViolationError(
                f"Request budget exhausted during redirect ({self.engine.request_count}/{self.engine.policy.max_requests})"
            )

        # Check global byte budget before following redirect
        effective_transferred = max(self.engine.total_bytes_transferred, self.engine.total_bytes)
        if effective_transferred >= self.engine.policy.max_bytes:
            raise ScopeViolationError(
                f"Global byte budget exhausted during redirect ({effective_transferred}/{self.engine.policy.max_bytes})"
            )

        self.engine.request_count += 1

        # Re-verify scope on redirect target (active network request)
        if not self.engine._is_in_scope(newurl, is_active=True):
            raise ScopeViolationError(f"Redirect destination '{newurl}' is out of scope")

        # Destination resolution and anti-SSRF verification
        verified_ips = self.engine._resolve_and_verify_destination(newurl)
        if not verified_ips:
            raise ScopeViolationError(f"Redirect destination '{newurl}' resolved to prohibited address space")

        new_host = (parsed_new.hostname or "").lower()
        if new_host:
            self.ip_map[new_host] = verified_ips

        self.current_url = newurl
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class ApiPinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """
    Pinned HTTPS handler routing requests through PinnedHTTPSConnection with destination-IP pinning.
    Ensures compatibility across Python 3.12, 3.13, and 3.14+ by safely omitting check_hostname kwarg.
    """

    def __init__(
        self,
        ip_map: Dict[str, Sequence[str]],
        context: Optional[ssl.SSLContext] = None,
        debuglevel: int = 0,
        check_hostname: Optional[bool] = None,
    ) -> None:
        super().__init__(debuglevel=debuglevel, context=context, check_hostname=check_hostname)
        self.ip_map = ip_map

    def https_open(self, req: urllib.request.Request) -> Any:
        def connection_factory(host: str, **kwargs: Any) -> http.client.HTTPSConnection:
            clean_host = host.split(":")[0] if ":" in host and not host.startswith("[") else host
            entry = self.ip_map.get(clean_host.lower())
            if isinstance(entry, (list, tuple)):
                pinned_ips = list(entry)
            elif isinstance(entry, str):
                pinned_ips = [entry] if entry else []
            else:
                pinned_ips = []
            pinned_ip = pinned_ips[0] if pinned_ips else None
            kwargs.pop("check_hostname", None)
            return PinnedHTTPSConnection(
                host,
                pinned_ip=pinned_ip,
                pinned_ips=pinned_ips,
                context=self._context,
                **kwargs,
            )
        return self.do_open(connection_factory, req)


class ApiIntelligenceEngine:
    """
    Core orchestrator for API discovery, correlation, and parameter intelligence.
    Enforces scope validation and never performs vulnerability exploitation.
    """

    def __init__(
        self,
        scope_engine: Optional[ScopeEngine] = None,
        api_state: Optional[ApiStateManager] = None,
        webapp_state: Optional[WebAppStateManager] = None,
        recon_state: Optional[ReconStateManager] = None,
        js_state: Optional[JavaScriptStateManager] = None,
        policy: Optional[ApiPolicy] = None,
        dry_run: bool = False,
        custom_ssl_context: Optional[ssl.SSLContext] = None,
    ):
        self.scope_engine = scope_engine
        self.api_state = api_state
        self.webapp_state = webapp_state
        self.recon_state = recon_state
        self.js_state = js_state
        self.policy = policy or ApiPolicy()
        self.dry_run = dry_run
        self.custom_ssl_context = custom_ssl_context

        self.request_count = 0
        self.total_bytes = 0
        self.total_bytes_transferred = 0
        self.allowed_fixture_ports: set[int] = set()

        # Deterministic mock hooks for 100% offline testing
        self.fetch_spec_hook: Optional[Callable[[str], Optional[str]]] = None
        self.http_probe_hook: Optional[Callable[[str, str], Optional[Dict[str, Any]]]] = None
        self.graphql_hook: Optional[Callable[[str, str], Optional[str]]] = None

    def allow_fixture_port(self, port: int) -> None:
        """Registers an ephemeral port for a local test fixture application during testing."""
        if not isinstance(port, int) or port < 1024 or port > 65535:
            raise ValueError(f"Invalid fixture port {port}: must be an unprivileged port (1024-65535)")
        self.allowed_fixture_ports.add(port)

    def _is_in_scope(self, url: str, is_active: bool = False) -> bool:
        """
        Enforces ScopeEngine checks before ANY HTTP request or file ingestion.
        For active network operations, scope enforcement strictly fails closed if ScopeEngine is absent.
        """
        if not self.scope_engine:
            # Active network requests FAIL CLOSED when no ScopeEngine is configured
            if is_active:
                return False
            return True

        parts = urlsplit(url)
        host = (parts.hostname or "").strip().lower()
        port = parts.port or (443 if parts.scheme == "https" else 80)

        # Active network operations targeting loopback (localhost / 127.0.0.1)
        # strictly require an authorized fixture port (1024-65535)
        if is_active and host in ("localhost", "127.0.0.1"):
            if port not in self.allowed_fixture_ports:
                return False

        # 1. Check explicit exclusions across exact URL, base with port, base root, and host
        # Explicit exclusions ALWAYS take strict precedence over any inclusion
        for cand in (url, f"{parts.scheme}://{host}:{port}", f"{parts.scheme}://{host}", host):
            cand_dec = self.scope_engine.check(cand)
            if cand_dec.status == ScopeStatus.OUT_OF_SCOPE and (
                cand_dec.rule_category in (
                    "EXPLICIT_EXCLUSION_URL",
                    "EXPLICIT_EXCLUSION_HOST",
                    "EXPLICIT_EXCLUSION_DOMAIN",
                    "EXPLICIT_EXCLUSION_CIDR",
                )
                or (cand_dec.rule_category or "").startswith("EXPLICIT_EXCLUSION_")
            ):
                return False

        # 2. Check local test fixture port allowance
        if host in ("localhost", "127.0.0.1") and port in self.allowed_fixture_ports:
            cand_base = self.scope_engine.check(f"{parts.scheme}://{host}:{port}")
            if cand_base.status == ScopeStatus.IN_SCOPE:
                return True
            cand_host = self.scope_engine.check(host)
            if cand_host.status == ScopeStatus.IN_SCOPE:
                return True

        # 3. Check standard target inclusions
        decision = self.scope_engine.check(url)
        if decision.status == ScopeStatus.IN_SCOPE:
            return True

        decision_host = self.scope_engine.check(host or url)
        return decision_host.status == ScopeStatus.IN_SCOPE

    def _resolve_and_verify_destination(self, url: str) -> List[str]:
        """
        Validates target URL against scope rules and anti-SSRF address space.
        Returns list of verified candidate destination IPs for destination pinning.
        Raises ScopeViolationError if forbidden or resolves to prohibited IPs.
        """
        parts = urlsplit(url)
        host = (parts.hostname or "").strip().lower()
        if not host:
            raise ScopeViolationError(f"Invalid URL missing hostname: '{url}'")

        port = parts.port or (443 if parts.scheme == "https" else 80)

        # Allow explicitly registered local test fixture
        if host in ("localhost", "127.0.0.1"):
            if port in self.allowed_fixture_ports:
                if self.scope_engine is None or not self._is_in_scope(url, is_active=True):
                    raise ScopeViolationError(f"Target fixture URL '{url}' is OUT_OF_SCOPE")
                return ["127.0.0.1"]
            raise ScopeViolationError(f"Target host '{host}:{port}' is not an authorized local fixture port")

        metadata_hosts = {
            "localhost",
            "metadata.google.internal",
            "instance-data",
            "169.254.169.254",
            "169.254.169.123",
        }
        if host in metadata_hosts or host.endswith(".metadata.google.internal"):
            raise ScopeViolationError(f"Target host '{host}' is in prohibited metadata address space")

        # Check if host is direct IP literal
        try:
            ip_obj = ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            ip_obj = None
            is_ip = False

        if is_ip and ip_obj is not None:
            prohibited, reason = is_ssrf_prohibited_ip(ip_obj)
            if prohibited:
                raise ScopeViolationError(f"Target host '{host}' is in prohibited address space ({reason})")
            return [str(ip_obj)]

        # Domain name: resolve candidate destination IPs
        try:
            addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            candidate_ips: List[str] = []
            for _, _, _, _, sa in addr_info:
                c_ip = sa[0]
                if c_ip not in candidate_ips:
                    candidate_ips.append(c_ip)

            if not candidate_ips:
                raise ScopeViolationError(f"DNS resolution failed for '{host}': zero addresses returned")

            verified_ips: List[str] = []
            for c_ip in candidate_ips:
                try:
                    resolved_ip = ipaddress.ip_address(c_ip)
                    prohibited, reason = is_ssrf_prohibited_ip(resolved_ip)
                    if prohibited:
                        raise ScopeViolationError(
                            f"Target host '{host}' resolves to prohibited address {c_ip} ({reason})"
                        )
                    verified_ips.append(c_ip)
                except ValueError:
                    pass

            if not verified_ips:
                raise ScopeViolationError(f"All resolved addresses for '{host}' are prohibited")

            return verified_ips
        except ScopeViolationError:
            raise
        except (socket.gaierror, OSError) as e:
            raise ScopeViolationError(f"DNS resolution error for '{host}': {e}") from e

    def acquire_spec_content(self, url_or_path: str) -> Optional[str]:
        """Safely fetches or reads specification content under budget ceilings."""
        if os.path.isfile(url_or_path):
            try:
                with open(url_or_path, "r", encoding="utf-8") as f:
                    return f.read(self.policy.max_bytes_per_spec)
            except Exception:
                return None

        canon_url = canonicalize_url(url_or_path)
        if self.policy.passive_only:
            return None

        # Fail-closed scope check for active requests
        if not self._is_in_scope(canon_url, is_active=True):
            return None

        if self.request_count >= self.policy.max_requests:
            return None
        effective_transferred = max(self.total_bytes_transferred, self.total_bytes)
        if effective_transferred >= self.policy.max_bytes:
            return None

        remaining_global = max(0, self.policy.max_bytes - effective_transferred)
        allowed_to_read = min(self.policy.max_bytes_per_spec, remaining_global)
        if allowed_to_read <= 0:
            return None

        self.request_count += 1

        # Use mock hook if registered (for deterministic offline tests)
        if self.fetch_spec_hook:
            content = self.fetch_spec_hook(canon_url)
            if content:
                b_bytes = content.encode("utf-8")
                b_len = len(b_bytes)
                self.total_bytes_transferred += b_len
                if b_len > allowed_to_read:
                    return None
                self.total_bytes += b_len
            return content

        # Live HTTP request using pinned transport and safe redirect handling
        try:
            verified_ips = self._resolve_and_verify_destination(canon_url)
            if not verified_ips:
                if self.api_state and not self.dry_run:
                    self.api_state.mark_failed(canon_url)
                return None

            host_key = (urlsplit(canon_url).hostname or "").lower()
            ip_map: Dict[str, Sequence[str]] = {host_key: verified_ips}

            if self.custom_ssl_context:
                ssl_ctx = self.custom_ssl_context
            else:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = True
                ssl_ctx.verify_mode = ssl.CERT_REQUIRED
                ca_bundle = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
                if ca_bundle and os.path.isfile(ca_bundle):
                    ssl_ctx.load_verify_locations(cafile=ca_bundle)

            redirect_handler = ApiSafeRedirectHandler(
                engine=self,
                ip_map=ip_map,
                max_redirects=self.policy.max_redirects,
                original_url=canon_url,
            )
            http_handler = PinnedHTTPHandler(ip_map=ip_map)
            https_handler = ApiPinnedHTTPSHandler(ip_map=ip_map, context=ssl_ctx, check_hostname=True)
            opener = urllib.request.build_opener(redirect_handler, http_handler, https_handler)

            req = urllib.request.Request(
                canon_url,
                headers={"User-Agent": self.policy.user_agent, "Accept": "application/json, application/yaml, */*"},
            )

            timeout_val = max(1.0, min(30.0, float(getattr(self.policy, "timeout", 5.0))))

            with opener.open(req, timeout=timeout_val) as resp:
                content_length_hdr = resp.headers.get("Content-Length")
                if content_length_hdr:
                    try:
                        content_len = int(content_length_hdr)
                        if content_len > allowed_to_read:
                            return None
                    except (ValueError, TypeError):
                        pass

                chunks: List[bytes] = []
                bytes_read = 0
                chunk_size = 64 * 1024

                while True:
                    remaining_budget = allowed_to_read - bytes_read
                    if remaining_budget <= 0:
                        break
                    to_read = min(chunk_size, remaining_budget)
                    chunk = resp.read(to_read)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    bytes_read += len(chunk)
                    self.total_bytes_transferred += len(chunk)

                self.total_bytes += bytes_read
                raw = b"".join(chunks)
                return raw.decode("utf-8", errors="ignore")
        except Exception:
            if self.api_state and not self.dry_run:
                self.api_state.mark_failed(canon_url)
            return None

    # ---------------- Correlation Pipelines ----------------

    def correlate_recon_observations(self) -> int:
        """Enriches API state from Phase 2 Recon HTTP observations."""
        count = 0
        if not self.recon_state:
            return count

        for obs in self.recon_state.http_services.values():
            url = obs.url
            if not self._is_in_scope(url):
                continue

            content_type = obs.content_type.lower()
            is_api = any(kw in url.lower() for kw in ("/api/", "/v1/", "/v2/", "/graphql", "/rest/")) or "application/json" in content_type

            if not is_api:
                continue

            host = obs.host
            base_url = f"{obs.scheme}://{host}"
            app = ApiApplication(
                base_url=base_url,
                host=host,
                scheme=obs.scheme,
                port=obs.port,
                api_style=ApiStyle.GRAPHQL.value if "graphql" in url.lower() else ApiStyle.REST.value,
                confidence="OBSERVED",
                provenance=[
                    ObservationProvenance(source="recon_intelligence", method="http_observation", confidence="OBSERVED")
                ],
            )
            # Infer path template
            canon_url = canonicalize_url(url)
            path_tmpl, path_params = infer_path_parameters(canon_url)
            endpoint = ApiEndpoint(
                canonical_url=path_tmpl,
                path_template=urlsplit(path_tmpl).path,
                method="GET",
                api_style=app.api_style,
                response_content_types=[content_type] if content_type else [],
                observed_urls=[canon_url],
                source="recon_http",
                confidence="OBSERVED",
                provenance=[
                    ObservationProvenance(source="recon_intelligence", method="http_probing", confidence="OBSERVED")
                ],
            )
            if self.api_state:
                if endpoint.key not in self.api_state.endpoints and len(self.api_state.endpoints) >= self.policy.max_endpoints:
                    continue
                self.api_state.add_application(app)
                self.api_state.add_endpoint(endpoint)
                for pp in path_params:
                    pp.endpoint_key = endpoint.key
                    if len(self.api_state.parameters) < getattr(self.policy, "max_parameters", 5000):
                        self.api_state.add_parameter(pp)
            count += 1

        return count

    def correlate_webapp_observations(self) -> int:
        """Enriches API state from Phase 3 WebApp endpoints, forms, and parameters."""
        count = 0
        if not self.webapp_state:
            return count

        for wep in self.webapp_state.endpoints.values():
            url = wep.url
            if not self._is_in_scope(url):
                continue

            is_api = any(kw in url.lower() for kw in ("/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/oauth/")) or (wep.content_type and "json" in wep.content_type.lower())

            if not is_api:
                continue

            parts = urlsplit(url)
            base_url = f"{parts.scheme}://{parts.netloc}"
            app = ApiApplication(
                base_url=base_url,
                host=parts.hostname or "",
                scheme=parts.scheme or "https",
                port=parts.port or (443 if parts.scheme == "https" else 80),
                api_style=ApiStyle.GRAPHQL.value if "graphql" in url.lower() else ApiStyle.REST.value,
                confidence="OBSERVED",
                provenance=[
                    ObservationProvenance(source="webapp_intelligence", method="web_endpoint", confidence="OBSERVED")
                ],
            )
            path_tmpl, path_params = infer_path_parameters(wep.url)
            endpoint = ApiEndpoint(
                canonical_url=path_tmpl,
                path_template=urlsplit(path_tmpl).path,
                method=wep.method.upper(),
                api_style=app.api_style,
                observed_urls=[canonicalize_url(wep.url)],
                source="webapp_endpoint",
                confidence="OBSERVED",
                provenance=[
                    ObservationProvenance(source="webapp_intelligence", method="crawler", confidence="OBSERVED")
                ],
            )
            if self.api_state:
                if endpoint.key not in self.api_state.endpoints and len(self.api_state.endpoints) >= self.policy.max_endpoints:
                    continue
                self.api_state.add_application(app)
                self.api_state.add_endpoint(endpoint)
                for pp in path_params:
                    pp.endpoint_key = endpoint.key
                    if len(self.api_state.parameters) < getattr(self.policy, "max_parameters", 5000):
                        self.api_state.add_parameter(pp)

                # Add observed query parameters
                for p_name in wep.parameter_names:
                    param = ApiParameter(
                        name=p_name,
                        location=ParameterLocation.QUERY.value,
                        endpoint_key=endpoint.key,
                        semantic_role=classify_parameter_role(p_name),
                        source="webapp_query",
                        confidence="OBSERVED",
                        provenance=[
                            ObservationProvenance(source="webapp_intelligence", method="url_query", confidence="OBSERVED")
                        ],
                    )
                    self.api_state.add_parameter(param)
            count += 1

        return count

    def correlate_javascript_observations(self) -> int:
        """Enriches API state from Phase 4 JavaScript endpoints, routes, and parameters."""
        count = 0
        if not self.js_state or not self.policy.correlate_js:
            return count

        for js_ep in self.js_state.endpoints.values():
            if self.api_state and len(self.api_state.endpoints) >= self.policy.max_endpoints:
                break
            raw = js_ep.normalized_endpoint or js_ep.raw_endpoint
            if not raw:
                continue

            # Check if relative or absolute
            if raw.startswith(("http://", "https://")):
                canon_url = canonicalize_url(raw)
            else:
                # Infer base from source JS resource URL
                src_parts = urlsplit(js_ep.source_resource_url)
                canon_url = canonicalize_url(f"{src_parts.scheme or 'https'}://{src_parts.netloc}/{raw.lstrip('/')}")

            if not self._is_in_scope(canon_url):
                continue

            is_api = any(kw in canon_url.lower() for kw in ("/api", "/v1", "/v2", "/graphql", "/oauth", "/rest", "/admin")) or js_ep.method in ("POST", "PUT", "DELETE", "PATCH")

            if not is_api:
                continue

            parts = urlsplit(canon_url)
            base_url = f"{parts.scheme}://{parts.netloc}"
            is_graphql = "graphql" in canon_url.lower()

            app = ApiApplication(
                base_url=base_url,
                host=parts.hostname or "",
                scheme=parts.scheme or "https",
                port=parts.port or (443 if parts.scheme == "https" else 80),
                api_style=ApiStyle.GRAPHQL.value if is_graphql else ApiStyle.REST.value,
                confidence="PROBABLE",
                provenance=[
                    ObservationProvenance(source="javascript_intelligence", method="static_js_analyzer", confidence="PROBABLE")
                ],
            )
            path_tmpl, path_params = infer_path_parameters(canon_url)
            endpoint = ApiEndpoint(
                canonical_url=path_tmpl,
                path_template=urlsplit(path_tmpl).path,
                method=js_ep.method.upper() if js_ep.method != "UNKNOWN" else "GET",
                api_style=app.api_style,
                observed_urls=[canon_url],
                source=f"javascript:{js_ep.extraction_method}",
                confidence="PROBABLE",
                provenance=[
                    ObservationProvenance(source="javascript_intelligence", method=js_ep.extraction_method, confidence="PROBABLE")
                ],
            )
            if self.api_state:
                if endpoint.key not in self.api_state.endpoints and len(self.api_state.endpoints) >= self.policy.max_endpoints:
                    continue
                self.api_state.add_application(app)
                self.api_state.add_endpoint(endpoint)
                for pp in path_params:
                    pp.endpoint_key = endpoint.key
                    if len(self.api_state.parameters) < getattr(self.policy, "max_parameters", 5000):
                        self.api_state.add_parameter(pp)

                # Link JavaScriptResource -> REFERENCES_ENDPOINT in Graph
                if js_ep.source_resource_url:
                    self.api_state.graph.add_relationship(
                        ApiRelationship(
                            source_id=js_ep.source_resource_url,
                            destination_id=endpoint.key,
                            relation_type=ApiRelationType.REFERENCES_ENDPOINT,
                            confidence="PROBABLE",
                            provenance=[
                                ObservationProvenance(source="javascript_intelligence", method="references_endpoint", confidence="PROBABLE")
                            ],
                        )
                    )

            count += 1

        # Correlate parameter references from JavaScript
        for param_ref in self.js_state.parameters.values():
            p_name = param_ref.name
            role = classify_parameter_role(p_name)
            p_loc = ParameterLocation.QUERY.value if param_ref.location_hint == "query" else ParameterLocation.BODY.value

            param = ApiParameter(
                name=p_name,
                location=p_loc,
                semantic_role=role,
                source="javascript_static",
                confidence="PROBABLE",
                provenance=[
                    ObservationProvenance(source="javascript_intelligence", method="parameter_reference", confidence="PROBABLE")
                ],
            )
            if self.api_state:
                if len(self.api_state.parameters) >= getattr(self.policy, "max_parameters", 5000):
                    break
                self.api_state.add_parameter(param)
                if param_ref.source_resource_url:
                    self.api_state.add_parameter_usage(
                        ParameterUsageObservation(
                            parameter_name=p_name,
                            source_resource=param_ref.source_resource_url,
                            endpoint_key="global",
                            usage_context=param_ref.location_hint,
                            confidence="PROBABLE",
                        )
                    )

        return count

    # ---------------- Specification Discovery & Ingestion ----------------

    def ingest_specification(self, spec_url_or_path: str) -> Optional[ApiSpecification]:
        """Ingests and parses an OpenAPI/Swagger specification file or URL."""
        content = self.acquire_spec_content(spec_url_or_path)
        if not content:
            return None

        parser = OpenApiParser(raw_content=content, spec_url=spec_url_or_path)
        if not parser.is_valid_spec():
            return None

        result = parser.parse()
        spec = result["specification"]
        app = result["application"]

        if self.api_state:
            if spec:
                self.api_state.add_specification(spec)
            if app:
                self.api_state.add_application(app)

            accepted_endpoint_keys: Set[str] = set()
            for ep in result["endpoints"]:
                if ep.key in self.api_state.endpoints:
                    self.api_state.add_endpoint(ep)
                    accepted_endpoint_keys.add(ep.key)
                else:
                    if len(self.api_state.endpoints) >= self.policy.max_endpoints:
                        continue
                    self.api_state.add_endpoint(ep)
                    accepted_endpoint_keys.add(ep.key)

                # Relationship: ApiSpecification -> DOCUMENTS_ENDPOINT
                if spec:
                    self.api_state.graph.add_relationship(
                        ApiRelationship(
                            source_id=spec.key,
                            destination_id=ep.key,
                            relation_type=ApiRelationType.DOCUMENTS_ENDPOINT,
                            confidence="CONFIRMED",
                        )
                    )
                # Relationship: ApiApplication -> HAS_ENDPOINT
                if app:
                    self.api_state.graph.add_relationship(
                        ApiRelationship(
                            source_id=app.key,
                            destination_id=ep.key,
                            relation_type=ApiRelationType.HAS_ENDPOINT,
                            confidence="CONFIRMED",
                        )
                    )

            params_per_ep: Dict[str, int] = {}
            for param in result["parameters"]:
                if param.endpoint_key and param.endpoint_key not in accepted_endpoint_keys and param.endpoint_key not in self.api_state.endpoints:
                    continue
                if len(self.api_state.parameters) >= getattr(self.policy, "max_parameters", 5000):
                    continue
                if param.endpoint_key:
                    c = params_per_ep.get(param.endpoint_key, 0)
                    if c >= getattr(self.policy, "max_parameters_per_endpoint", 100):
                        continue
                    params_per_ep[param.endpoint_key] = c + 1

                self.api_state.add_parameter(param)
                if param.endpoint_key:
                    self.api_state.graph.add_relationship(
                        ApiRelationship(
                            source_id=param.endpoint_key,
                            destination_id=param.key,
                            relation_type=ApiRelationType.ACCEPTS_PARAMETER,
                            confidence="CONFIRMED",
                        )
                    )

            schemas_per_ep: Dict[str, int] = {}
            for rs in result["request_schemas"]:
                if rs.endpoint_key not in accepted_endpoint_keys and rs.endpoint_key not in self.api_state.endpoints:
                    continue
                c = schemas_per_ep.get(rs.endpoint_key, 0)
                if c >= getattr(self.policy, "max_schemas_per_endpoint", 50):
                    continue
                schemas_per_ep[rs.endpoint_key] = c + 1

                self.api_state.add_request_schema(rs)
                self.api_state.graph.add_relationship(
                    ApiRelationship(
                        source_id=rs.endpoint_key,
                        destination_id=rs.key,
                        relation_type=ApiRelationType.USES_SCHEMA,
                        confidence="CONFIRMED",
                    )
                )

            for rps in result["response_schemas"]:
                if rps.endpoint_key not in accepted_endpoint_keys and rps.endpoint_key not in self.api_state.endpoints:
                    continue
                c = schemas_per_ep.get(rps.endpoint_key, 0)
                if c >= getattr(self.policy, "max_schemas_per_endpoint", 50):
                    continue
                schemas_per_ep[rps.endpoint_key] = c + 1

                self.api_state.add_response_schema(rps)
                self.api_state.graph.add_relationship(
                    ApiRelationship(
                        source_id=rps.endpoint_key,
                        destination_id=rps.key,
                        relation_type=ApiRelationType.USES_SCHEMA,
                        confidence="CONFIRMED",
                    )
                )

            accepted_auth_schemes: Set[str] = set()
            for ep in result["endpoints"]:
                if ep.key in accepted_endpoint_keys or ep.key in self.api_state.endpoints:
                    if ep.auth_required and ep.auth_scheme:
                        accepted_auth_schemes.add(ep.auth_scheme)

            for ao in result["auth_observations"]:
                if ao.scheme in accepted_auth_schemes:
                    self.api_state.add_auth_observation(ao)

            for ep in result["endpoints"]:
                if ep.key not in accepted_endpoint_keys and ep.key not in self.api_state.endpoints:
                    continue
                if ep.auth_required and ep.auth_scheme:
                    for ao in result["auth_observations"]:
                        if ao.scheme == ep.auth_scheme:
                            self.api_state.graph.add_relationship(
                                ApiRelationship(
                                    source_id=ep.key,
                                    destination_id=ao.key,
                                    relation_type=ApiRelationType.REQUIRES_AUTH,
                                    confidence="CONFIRMED",
                                )
                            )
                            break

        return spec

    def probe_conventional_specifications(self, target_host: str) -> List[ApiSpecification]:
        """Probes standard OpenAPI/Swagger spec endpoints on target host."""
        discovered: List[ApiSpecification] = []
        if self.policy.passive_only or not self.policy.probe_common_spec_paths:
            return discovered

        for path in COMMON_SPEC_PATHS:
            spec_url = f"https://{target_host}{path}"
            if not self._is_in_scope(spec_url, is_active=True):
                continue
            spec = self.ingest_specification(spec_url)
            if spec:
                discovered.append(spec)
                break  # Stop probing once valid spec discovered for this host
        return discovered

    def probe_graphql_introspection(self, graphql_url: str) -> Optional[Dict[str, Any]]:
        """
        Probes a discovered GraphQL endpoint using a safe, bounded introspection query.
        Strictly conditional on self.policy.allow_graphql_introspection=True.
        Enforces fail-closed scope checking and resource limits.
        """
        if not self.policy.allow_graphql_introspection:
            return None

        canon_url = canonicalize_url(graphql_url)
        if not self._is_in_scope(canon_url, is_active=True):
            return None

        if self.request_count >= self.policy.max_requests:
            return None
        effective_transferred = max(self.total_bytes_transferred, self.total_bytes)
        if effective_transferred >= self.policy.max_bytes:
            return None

        remaining_global = max(0, self.policy.max_bytes - effective_transferred)
        allowed_to_read = min(self.policy.max_bytes_per_spec, remaining_global)
        if allowed_to_read <= 0:
            return None

        self.request_count += 1
        query_payload = GraphQLAnalyzer.build_bounded_introspection_query()

        # Mock hook for offline testing
        if self.graphql_hook:
            raw_resp = self.graphql_hook(canon_url, query_payload)
            if raw_resp is not None:
                b_bytes = raw_resp.encode("utf-8")
                b_len = len(b_bytes)
                self.total_bytes_transferred += b_len
                if b_len > allowed_to_read:
                    return None
                try:
                    data = json.loads(raw_resp)
                    parsed = GraphQLAnalyzer.parse_introspection_result(canon_url, data)
                    if self.api_state:
                        accepted_ep_keys: Set[str] = set()
                        for ep in parsed["endpoints"]:
                            if ep.key in self.api_state.endpoints:
                                self.api_state.add_endpoint(ep)
                                accepted_ep_keys.add(ep.key)
                            else:
                                if len(self.api_state.endpoints) >= self.policy.max_endpoints:
                                    continue
                                self.api_state.add_endpoint(ep)
                                accepted_ep_keys.add(ep.key)
                        params_per_ep: Dict[str, int] = {}
                        for param in parsed["parameters"]:
                            if param.endpoint_key and param.endpoint_key not in accepted_ep_keys and param.endpoint_key not in self.api_state.endpoints:
                                continue
                            if len(self.api_state.parameters) >= getattr(self.policy, "max_parameters", 5000):
                                continue
                            if param.endpoint_key:
                                c = params_per_ep.get(param.endpoint_key, 0)
                                if c >= getattr(self.policy, "max_parameters_per_endpoint", 100):
                                    continue
                                params_per_ep[param.endpoint_key] = c + 1
                            self.api_state.add_parameter(param)
                    # Commit accepted byte budget strictly upon successful parsing and validation
                    self.total_bytes += b_len
                    return parsed
                except Exception:
                    return None
            return None

        # Live request using safe transport
        try:
            verified_ips = self._resolve_and_verify_destination(canon_url)
            if not verified_ips:
                return None

            host_key = (urlsplit(canon_url).hostname or "").lower()
            ip_map: Dict[str, Sequence[str]] = {host_key: verified_ips}

            if self.custom_ssl_context:
                ssl_ctx = self.custom_ssl_context
            else:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = True
                ssl_ctx.verify_mode = ssl.CERT_REQUIRED
                ca_bundle = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
                if ca_bundle and os.path.isfile(ca_bundle):
                    ssl_ctx.load_verify_locations(cafile=ca_bundle)

            redirect_handler = ApiSafeRedirectHandler(
                engine=self,
                ip_map=ip_map,
                max_redirects=self.policy.max_redirects,
                original_url=canon_url,
            )
            http_handler = PinnedHTTPHandler(ip_map=ip_map)
            https_handler = ApiPinnedHTTPSHandler(ip_map=ip_map, context=ssl_ctx, check_hostname=True)
            opener = urllib.request.build_opener(redirect_handler, http_handler, https_handler)

            body_bytes = query_payload.encode("utf-8")
            req = urllib.request.Request(
                canon_url,
                data=body_bytes,
                headers={
                    "User-Agent": self.policy.user_agent,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                method="POST",
            )
            timeout_val = max(1.0, min(30.0, float(getattr(self.policy, "timeout", 5.0))))

            with opener.open(req, timeout=timeout_val) as resp:
                content_length_hdr = resp.headers.get("Content-Length")
                if content_length_hdr:
                    try:
                        content_len = int(content_length_hdr)
                        if content_len > allowed_to_read:
                            return None
                    except (ValueError, TypeError):
                        pass

                chunks: List[bytes] = []
                bytes_read = 0
                chunk_size = 64 * 1024
                truncated = False

                while True:
                    remaining = allowed_to_read - bytes_read
                    if remaining <= 0:
                        extra = resp.read(1)
                        if extra:
                            self.total_bytes_transferred += len(extra)
                            truncated = True
                        break
                    to_read = min(chunk_size, remaining)
                    chunk = resp.read(to_read)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    bytes_read += len(chunk)
                    self.total_bytes_transferred += len(chunk)

                if truncated:
                    return None

                try:
                    data = json.loads(b"".join(chunks).decode("utf-8", errors="ignore"))
                    parsed = GraphQLAnalyzer.parse_introspection_result(canon_url, data)
                    if self.api_state:
                        accepted_ep_keys = set()
                        for ep in parsed["endpoints"]:
                            if ep.key in self.api_state.endpoints:
                                self.api_state.add_endpoint(ep)
                                accepted_ep_keys.add(ep.key)
                            else:
                                if len(self.api_state.endpoints) >= self.policy.max_endpoints:
                                    continue
                                self.api_state.add_endpoint(ep)
                                accepted_ep_keys.add(ep.key)
                        params_per_ep = {}
                        for param in parsed["parameters"]:
                            if param.endpoint_key and param.endpoint_key not in accepted_ep_keys and param.endpoint_key not in self.api_state.endpoints:
                                continue
                            if len(self.api_state.parameters) >= getattr(self.policy, "max_parameters", 5000):
                                continue
                            if param.endpoint_key:
                                c = params_per_ep.get(param.endpoint_key, 0)
                                if c >= getattr(self.policy, "max_parameters_per_endpoint", 100):
                                    continue
                                params_per_ep[param.endpoint_key] = c + 1
                            self.api_state.add_parameter(param)
                    # Commit accepted byte budget strictly upon successful validation
                    self.total_bytes += bytes_read
                    return parsed
                except Exception:
                    return None
        except Exception:
            return None

    # ---------------- Master Execution ----------------

    def run_analysis(
        self,
        domain: Optional[str] = None,
        asset: Optional[str] = None,
        spec_path: Optional[str] = None,
        resume: bool = False,
    ) -> Dict[str, Any]:
        """
        Executes end-to-end API and parameter intelligence analysis across all sources.
        """
        stats = {
            "recon_correlated": 0,
            "webapp_correlated": 0,
            "js_correlated": 0,
            "specs_ingested": 0,
            "total_endpoints": 0,
            "total_parameters": 0,
        }

        # 1. Ingest explicit specification if specified
        if spec_path:
            spec = self.ingest_specification(spec_path)
            if spec:
                stats["specs_ingested"] += 1

        # 2. Correlate existing observations from prior phases
        stats["recon_correlated"] = self.correlate_recon_observations()
        stats["webapp_correlated"] = self.correlate_webapp_observations()
        stats["js_correlated"] = self.correlate_javascript_observations()

        # 3. Probe conventional specifications for candidate API hosts
        if not self.policy.passive_only and self.policy.probe_common_spec_paths:
            candidate_hosts: Set[str] = set()
            if asset:
                candidate_hosts.add(asset)
            elif domain:
                candidate_hosts.add(domain)
                candidate_hosts.add(f"api.{domain}")
            elif self.api_state:
                for app in self.api_state.applications.values():
                    candidate_hosts.add(app.host)

            for h in candidate_hosts:
                if self.request_count >= self.policy.max_requests:
                    break
                specs = self.probe_conventional_specifications(h)
                stats["specs_ingested"] += len(specs)

        # 4. Save state atomically unless in dry-run mode
        if self.api_state:
            stats["total_endpoints"] = len(self.api_state.endpoints)
            stats["total_parameters"] = len(self.api_state.parameters)
            if not self.dry_run:
                self.api_state.save()

        return stats
