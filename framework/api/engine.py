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
import json
import os
import ssl
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlsplit

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
from framework.javascript.state import JavaScriptStateManager
from framework.recon.state import ReconStateManager
from framework.scope.engine import ScopeEngine, ScopeStatus
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
    max_requests: int = 200
    max_bytes: int = 10 * 1024 * 1024  # 10 MB total
    max_bytes_per_spec: int = 2 * 1024 * 1024  # 2 MB per specification
    safe_methods: Tuple[str, ...] = ("GET", "HEAD", "OPTIONS")
    passive_only: bool = False
    allow_graphql_introspection: bool = False
    correlate_js: bool = True
    probe_common_spec_paths: bool = True
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BugBounty-Agent/5.0"


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
    ):
        self.scope_engine = scope_engine
        self.api_state = api_state
        self.webapp_state = webapp_state
        self.recon_state = recon_state
        self.js_state = js_state
        self.policy = policy or ApiPolicy()
        self.dry_run = dry_run

        self.request_count = 0
        self.total_bytes = 0

        # Deterministic mock hooks for 100% offline testing
        self.fetch_spec_hook: Optional[Callable[[str], Optional[str]]] = None
        self.http_probe_hook: Optional[Callable[[str, str], Optional[Dict[str, Any]]]] = None

    def _is_in_scope(self, url: str) -> bool:
        """Enforces ScopeEngine checks before ANY HTTP request or file ingestion."""
        if not self.scope_engine:
            return True
        host = urlsplit(url).hostname or url
        decision = self.scope_engine.check(host)
        return decision.status == ScopeStatus.IN_SCOPE

    def acquire_spec_content(self, url_or_path: str) -> Optional[str]:
        """Safely fetches or reads specification content under budget ceilings."""
        if os.path.isfile(url_or_path):
            try:
                with open(url_or_path, "r", encoding="utf-8") as f:
                    return f.read(self.policy.max_bytes_per_spec)
            except Exception:
                return None

        canon_url = canonicalize_url(url_or_path)
        if not self._is_in_scope(canon_url) or self.policy.passive_only:
            return None

        if self.request_count >= self.policy.max_requests:
            return None
        if self.total_bytes >= self.policy.max_bytes:
            return None

        self.request_count += 1

        # Use mock hook if registered
        if self.fetch_spec_hook:
            content = self.fetch_spec_hook(canon_url)
            if content:
                b_len = len(content.encode("utf-8"))
                if b_len > self.policy.max_bytes_per_spec:
                    return None
                self.total_bytes += b_len
            return content

        # Live HTTP request using standard library
        import urllib.request
        try:
            req = urllib.request.Request(
                canon_url,
                headers={"User-Agent": self.policy.user_agent, "Accept": "application/json, application/yaml, */*"},
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=5.0, context=ctx if canon_url.startswith("https://") else None) as resp:
                raw = resp.read(self.policy.max_bytes_per_spec)
                self.total_bytes += len(raw)
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
            if self.api_state and not self.dry_run:
                self.api_state.add_application(app)

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
            if self.api_state and not self.dry_run:
                self.api_state.add_endpoint(endpoint)
                for pp in path_params:
                    pp.endpoint_key = endpoint.key
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
            if self.api_state and not self.dry_run:
                self.api_state.add_application(app)

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
            if self.api_state and not self.dry_run:
                self.api_state.add_endpoint(endpoint)
                for pp in path_params:
                    pp.endpoint_key = endpoint.key
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
            if self.api_state and not self.dry_run:
                self.api_state.add_application(app)

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
            if self.api_state and not self.dry_run:
                self.api_state.add_endpoint(endpoint)
                for pp in path_params:
                    pp.endpoint_key = endpoint.key
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
            if self.api_state and not self.dry_run:
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

        if self.api_state and not self.dry_run:
            if spec:
                self.api_state.add_specification(spec)
            if app:
                self.api_state.add_application(app)

            for ep in result["endpoints"]:
                self.api_state.add_endpoint(ep)
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

            for param in result["parameters"]:
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

            for rs in result["request_schemas"]:
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
                self.api_state.add_response_schema(rps)

            for ao in result["auth_observations"]:
                self.api_state.add_auth_observation(ao)

        return spec

    def probe_conventional_specifications(self, target_host: str) -> List[ApiSpecification]:
        """Probes standard OpenAPI/Swagger spec endpoints on target host."""
        discovered: List[ApiSpecification] = []
        if self.policy.passive_only or not self.policy.probe_common_spec_paths:
            return discovered

        for path in COMMON_SPEC_PATHS:
            spec_url = f"https://{target_host}{path}"
            if not self._is_in_scope(spec_url):
                continue
            spec = self.ingest_specification(spec_url)
            if spec:
                discovered.append(spec)
                break  # Stop probing once valid spec discovered for this host
        return discovered

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

        # 4. Save state atomically
        if self.api_state and not self.dry_run:
            self.api_state.save()
            stats["total_endpoints"] = len(self.api_state.endpoints)
            stats["total_parameters"] = len(self.api_state.parameters)

        return stats
