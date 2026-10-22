"""
Test suite for Phase 5 API Security & Parameter Intelligence Engine.

Validates:
- Data model serialization & deserialization.
- Parameter semantic role classification.
- REST path parameter inference & route normalization.
- Safe, bounded schema structure generation.
- OpenAPI 2.0 (Swagger) and OpenAPI 3.x specification parsing.
- GraphQL endpoint detection and safe model creation.
- ApiGraph relationship indexing and traversal.
- ApiStateManager atomic persistence and multi-source endpoint merging.
- ApiIntelligenceEngine multi-source correlation (Recon, WebApp, JS) and offline mock hooks.
- Security constraints: zero arbitrary subprocess execution, zero shell=True, zero os.system.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Dict, List, Optional
import pytest

from framework.api.engine import ApiIntelligenceEngine, ApiPolicy, ApiSafeRedirectHandler
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
    build_bounded_schema,
    classify_parameter_role,
    infer_path_parameters,
)
from framework.api.state import ApiStateManager
from framework.assets.provenance import ObservationProvenance
from framework.javascript.model import DiscoveredEndpoint, ParameterReference
from framework.javascript.state import JavaScriptStateManager
from framework.recon.model import HttpObservation
from framework.recon.state import ReconStateManager
from framework.scope.engine import ScopeEngine, ScopeStatus
from framework.validation.engine import ScopeViolationError
from unittest.mock import MagicMock, patch
import io
import socket
import ssl
import urllib.request
from framework.webapp.model import WebEndpoint
from framework.webapp.state import WebAppStateManager


class TestApiModel:
    """Tests for API intelligence data models and serialization."""

    def test_api_application_serialization(self):
        app = ApiApplication(
            base_url="https://api.example.com/v1",
            host="api.example.com",
            scheme="https",
            port=443,
            api_style=ApiStyle.REST.value,
            technologies=["FastAPI", "Uvicorn"],
        )
        d = app.to_dict()
        assert d["base_url"] == "https://api.example.com/v1"
        assert d["host"] == "api.example.com"
        assert "FastAPI" in d["technologies"]

        restored = ApiApplication.from_dict(d)
        assert restored.base_url == app.base_url
        assert restored.technologies == app.technologies

    def test_api_endpoint_serialization(self):
        ep = ApiEndpoint(
            canonical_url="https://api.example.com/v1/users/{user_id}",
            path_template="/v1/users/{user_id}",
            method="GET",
            operation_id="getUserById",
            auth_required=True,
            auth_scheme="bearer",
            observed_urls=["https://api.example.com/v1/users/123"],
            provenance=[ObservationProvenance(source="test", method="unit", confidence="CONFIRMED")],
        )
        d = ep.to_dict()
        assert d["operation_id"] == "getUserById"
        assert d["auth_required"] is True
        assert len(d["observed_urls"]) == 1

        restored = ApiEndpoint.from_dict(d)
        assert restored.path_template == ep.path_template
        assert restored.auth_scheme == "bearer"
        assert len(restored.provenance) == 1

    def test_api_parameter_serialization(self):
        param = ApiParameter(
            name="redirect_uri",
            location=ParameterLocation.QUERY.value,
            datatype="string",
            required=True,
            semantic_role=ParameterRole.REDIRECT.value,
            endpoint_key="GET https://example.com/oauth/authorize",
        )
        d = param.to_dict()
        assert d["name"] == "redirect_uri"
        assert d["semantic_role"] == ParameterRole.REDIRECT.value
        assert d["required"] is True

        restored = ApiParameter.from_dict(d)
        assert restored.name == param.name
        assert restored.semantic_role == ParameterRole.REDIRECT.value


class TestApiParser:
    """Tests for parameter classification, path inference, and schema bounding."""

    def test_parameter_role_classification(self):
        assert classify_parameter_role("user_id") == ParameterRole.USER_ID.value
        assert classify_parameter_role("uid") == ParameterRole.USER_ID.value
        assert classify_parameter_role("redirect_url") == ParameterRole.REDIRECT.value
        assert classify_parameter_role("return_to") == ParameterRole.REDIRECT.value
        assert classify_parameter_role("callback") == ParameterRole.CALLBACK.value
        assert classify_parameter_role("search_query") == ParameterRole.SEARCH.value
        assert classify_parameter_role("page") == ParameterRole.PAGE.value
        assert classify_parameter_role("limit") == ParameterRole.LIMIT.value
        assert classify_parameter_role("access_token") == ParameterRole.TOKEN.value
        assert classify_parameter_role("session_id") == ParameterRole.SESSION.value
        assert classify_parameter_role("arbitrary_arg") == ParameterRole.GENERIC.value

    def test_rest_path_parameter_inference(self):
        # Numeric ID
        tmpl1, p1 = infer_path_parameters("https://example.com/api/v1/users/12345")
        assert "{user_id}" in tmpl1
        assert len(p1) == 1
        assert p1[0].name == "user_id"
        assert p1[0].datatype == "integer"

        # UUID
        uuid_str = "550e8400-e29b-41d4-a716-446655440000"
        tmpl2, p2 = infer_path_parameters(f"https://example.com/api/orders/{uuid_str}")
        assert "{order_id}" in tmpl2
        assert len(p2) == 1
        assert p2[0].name == "order_id"
        assert p2[0].datatype == "string"

        # Non-dynamic path preserved
        tmpl3, p3 = infer_path_parameters("https://example.com/api/v1/users/me")
        assert tmpl3 == "https://example.com/api/v1/users/me"
        assert len(p3) == 0

    def test_bounded_schema_builder_recursion_safety(self):
        # Create deeply nested schema structure
        curr: Dict[str, Any] = {"type": "string"}
        for _ in range(10):
            curr = {"type": "object", "properties": {"child": curr}}

        bounded = build_bounded_schema(curr, current_depth=0)
        assert bounded["type"] == "object"
        # Verify it terminated cleanly without recursion limit error


class TestOpenApiParser:
    """Tests for OpenAPI 2.0 and OpenAPI 3.x document parsing."""

    def test_openapi_3_parsing(self):
        import textwrap

        sample_openapi_3 = textwrap.dedent("""
        openapi: "3.0.0"
        info:
          title: "User Management API"
          version: "1.0.0"
        servers:
          - url: "https://api.example.com/v1"
        paths:
          /users:
            get:
              operationId: "listUsers"
              parameters:
                - name: "limit"
                  in: "query"
                  schema:
                    type: "integer"
                - name: "role"
                  in: "query"
                  schema:
                    type: "string"
              responses:
                '200':
                  description: "Success"
                  content:
                    application/json:
                      schema:
                        type: "array"
            post:
              operationId: "createUser"
              requestBody:
                content:
                  application/json:
                    schema:
                      type: "object"
                      required: ["username", "email"]
                      properties:
                        username:
                          type: "string"
                        email:
                          type: "string"
              responses:
                '201':
                  description: "Created"
        components:
          securitySchemes:
            bearerAuth:
              type: "http"
              scheme: "bearer"
        """)
        parser = OpenApiParser(sample_openapi_3, "https://api.example.com/openapi.yaml")
        assert parser.is_valid_spec() is True
        assert parser.format == SpecFormat.OPENAPI

        result = parser.parse()
        assert result["application"] is not None
        assert result["application"].base_url == "https://api.example.com/v1"

        endpoints = result["endpoints"]
        assert len(endpoints) == 2
        methods = [e.method for e in endpoints]
        assert "GET" in methods
        assert "POST" in methods

        params = result["parameters"]
        param_names = [p.name for p in params]
        assert "limit" in param_names
        assert "role" in param_names

        req_schemas = result["request_schemas"]
        assert len(req_schemas) == 1
        assert "username" in req_schemas[0].required_fields

        auth_obs = result["auth_observations"]
        assert len(auth_obs) == 1
        assert auth_obs[0].scheme == AuthScheme.BEARER.value

    def test_swagger_2_parsing(self):
        sample_swagger_2 = """
        {
          "swagger": "2.0",
          "info": {
            "title": "Legacy Store API",
            "version": "2.0"
          },
          "host": "store.example.com",
          "basePath": "/api/v2",
          "schemes": ["https"],
          "paths": {
            "/products/{id}": {
              "get": {
                "operationId": "getProduct",
                "parameters": [
                  {
                    "name": "id",
                    "in": "path",
                    "required": true,
                    "type": "integer"
                  }
                ],
                "responses": {
                  "200": {
                    "description": "Product details"
                  }
                }
              }
            }
          },
          "securityDefinitions": {
            "apiKeyHeader": {
              "type": "apiKey",
              "name": "X-API-KEY",
              "in": "header"
            }
          }
        }
        """
        parser = OpenApiParser(sample_swagger_2, "https://store.example.com/swagger.json")
        assert parser.is_valid_spec() is True
        assert parser.format == SpecFormat.SWAGGER

        result = parser.parse()
        assert result["application"].base_url == "https://store.example.com/api/v2"
        assert len(result["endpoints"]) == 1
        assert result["endpoints"][0].path_template == "/products/{id}"

        auth_obs = result["auth_observations"]
        assert len(auth_obs) == 1
        assert auth_obs[0].scheme == AuthScheme.API_KEY.value
        assert auth_obs[0].name == "X-API-KEY"


class TestGraphQLAnalyzer:
    """Tests for GraphQL endpoint detection and model generation."""

    def test_graphql_detection(self):
        assert GraphQLAnalyzer.is_likely_graphql_endpoint("https://example.com/graphql") is True
        assert GraphQLAnalyzer.is_likely_graphql_endpoint("https://example.com/api/v1/graphql") is True
        assert GraphQLAnalyzer.is_likely_graphql_endpoint("https://example.com/api/v1/users") is False
        assert GraphQLAnalyzer.is_likely_graphql_endpoint("https://example.com/query", content_type="application/graphql") is True

    def test_graphql_endpoint_creation(self):
        ep = GraphQLAnalyzer.create_graphql_endpoint("https://example.com/api/graphql")
        assert ep.api_style == ApiStyle.GRAPHQL.value
        assert ep.method == "POST"
        assert "application/json" in ep.content_types


class TestApiGraphAndState:
    """Tests for API relationship graph and state persistence."""

    def test_api_graph_relationships(self):
        graph = ApiGraph()
        rel = ApiRelationship(
            source_id="https://example.com/api/v1",
            destination_id="GET https://example.com/api/v1/users",
            relation_type=ApiRelationType.HAS_ENDPOINT,
        )
        graph.add_relationship(rel)
        assert len(graph.get_all_relationships()) == 1

        outgoing = graph.get_outgoing("https://example.com/api/v1")
        assert len(outgoing) == 1
        assert outgoing[0].relation_type == ApiRelationType.HAS_ENDPOINT

    def test_api_state_persistence_and_merging(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = ApiStateManager(program_dir=tmpdir)

            # Insert application
            app = ApiApplication(
                base_url="https://api.example.com/v1",
                host="api.example.com",
            )
            mgr.add_application(app)

            # Insert endpoint from source 1 (JS)
            ep1 = ApiEndpoint(
                canonical_url="https://api.example.com/v1/users",
                path_template="/v1/users",
                method="GET",
                source="javascript",
                confidence="PROBABLE",
                observed_urls=["https://api.example.com/v1/users"],
            )
            mgr.add_endpoint(ep1)

            # Insert same endpoint from source 2 (OpenAPI Spec) -> should merge!
            ep2 = ApiEndpoint(
                canonical_url="https://api.example.com/v1/users",
                path_template="/v1/users",
                method="GET",
                operation_id="listUsers",
                auth_required=True,
                source="openapi",
                confidence="CONFIRMED",
                observed_urls=["https://api.example.com/v1/users?page=1"],
            )
            mgr.add_endpoint(ep2)

            assert len(mgr.endpoints) == 1
            merged = mgr.endpoints[ep1.key]
            # Verify merged attributes
            assert merged.confidence == "CONFIRMED"
            assert merged.operation_id == "listUsers"
            assert merged.auth_required is True
            assert len(merged.observed_urls) == 2

            # Save state
            mgr.save()
            assert os.path.exists(mgr.api_file)

            # Reload into new manager instance
            loaded_mgr = ApiStateManager(program_dir=tmpdir)
            assert len(loaded_mgr.applications) == 1
            assert len(loaded_mgr.endpoints) == 1
            assert loaded_mgr.endpoints[ep1.key].confidence == "CONFIRMED"


class TestApiIntelligenceEngine:
    """Tests for multi-source correlation and mock spec ingestion."""

    def test_engine_multi_source_correlation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Setup ScopeEngine
            scope_dict = {
                "program": {"name": "test-prog"},
                "targets": {"domains": ["example.com"], "recursive_subdomains": {"enabled": True}},
            }
            scope_engine = ScopeEngine(scope_dict)

            api_state = ApiStateManager(program_dir=tmpdir)
            webapp_state = WebAppStateManager(program_dir=tmpdir)
            recon_state = ReconStateManager(program_dir=tmpdir)
            js_state = JavaScriptStateManager(program_dir=tmpdir)

            # Seed Phase 2 Recon observation
            recon_obs = HttpObservation(
                url="https://api.example.com/v1/health",
                scheme="https",
                host="api.example.com",
                port=443,
                status_code=200,
                content_type="application/json",
            )
            recon_state.add_http_observation(recon_obs)

            # Seed Phase 3 WebApp endpoint
            webapp_ep = WebEndpoint(
                url="https://api.example.com/v1/items/42",
                path="/v1/items/42",
                method="GET",
                parameter_names=["category"],
            )
            webapp_state.add_endpoint(webapp_ep)

            # Seed Phase 4 JavaScript endpoint
            js_ep = DiscoveredEndpoint(
                raw_endpoint="/v1/profile",
                normalized_endpoint="/v1/profile",
                method="GET",
                source_resource_url="https://api.example.com/static/app.js",
                extraction_method="fetch",
            )
            js_state.add_endpoint(js_ep)

            # Seed Phase 4 JS parameter reference
            js_param = ParameterReference(
                name="auth_token",
                location_hint="query",
                source_resource_url="https://api.example.com/static/app.js",
            )
            js_state.add_parameter(js_param)

            # Mock spec content for offline ingestion
            mock_spec = """
            openapi: "3.0.0"
            info:
              title: "Mock API"
              version: "1.0.0"
            servers:
              - url: "https://api.example.com/v1"
            paths:
              /status:
                get:
                  responses:
                    '200':
                      description: "OK"
            """

            def mock_fetch(url: str) -> Optional[str]:
                if "openapi.json" in url:
                    return mock_spec
                return None

            engine = ApiIntelligenceEngine(
                scope_engine=scope_engine,
                api_state=api_state,
                webapp_state=webapp_state,
                recon_state=recon_state,
                js_state=js_state,
                policy=ApiPolicy(probe_common_spec_paths=False),
            )
            engine.fetch_spec_hook = mock_fetch

            # Execute run_analysis with mock spec
            stats = engine.run_analysis(
                spec_path="https://api.example.com/openapi.json",
            )

            assert stats["recon_correlated"] >= 1
            assert stats["webapp_correlated"] >= 1
            assert stats["js_correlated"] >= 1
            assert stats["specs_ingested"] == 1

            # Verify endpoints captured in API state
            endpoints = api_state.endpoints
            assert len(endpoints) >= 4  # health, items/{item_id}, profile, status

            # Verify path parameter inferred from /v1/items/42
            item_keys = [k for k in endpoints.keys() if "items" in k]
            assert len(item_keys) == 1
            assert "{item_id}" in item_keys[0] or "{id}" in item_keys[0]

            # Verify parameters
            params = api_state.parameters
            param_names = [p.name for p in params.values()]
            assert "category" in param_names
            assert "auth_token" in param_names

    def test_engine_passive_only_mode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api_state = ApiStateManager(program_dir=tmpdir)
            engine = ApiIntelligenceEngine(
                api_state=api_state,
                policy=ApiPolicy(passive_only=True),
            )
            # When passive_only is True, acquire_spec_content should not fetch
            content = engine.acquire_spec_content("https://example.com/openapi.json")
            assert content is None
            assert engine.request_count == 0


class TestSecurityInvariants:
    """Security audit tests verifying safe coding and subprocess practices."""

    def test_zero_shell_or_exec_in_api_module(self):
        """Verifies no shell=True, os.system, or dangerous execution exists in framework/api."""
        api_dir = os.path.join(os.path.dirname(__file__), "..", "framework", "api")
        for root, _, files in os.walk(api_dir):
            for file in files:
                if file.endswith(".py"):
                    fpath = os.path.join(root, file)
                    with open(fpath, "r", encoding="utf-8") as f:
                        code = f.read()
                        assert "shell=True" not in code, f"Forbidden shell=True in {fpath}"
                        assert "os.system(" not in code, f"Forbidden os.system in {fpath}"
                        assert "eval(" not in code, f"Forbidden eval in {fpath}"
                        assert "exec(" not in code, f"Forbidden exec in {fpath}"


class TestGateASecurityTransport:
    """Security tests validating Gate A: TLS verification, scope fail-closed, and redirect/SSRF protection."""

    def test_tls_verification_configuration_and_zero_cert_none(self):
        """Verifies ssl.CERT_NONE and check_hostname=False are absent and TLS verification is default."""
        api_engine_path = os.path.join(os.path.dirname(__file__), "..", "framework", "api", "engine.py")
        with open(api_engine_path, "r", encoding="utf-8") as f:
            code = f.read()
            assert "ssl.CERT_NONE" not in code, "Insecure ssl.CERT_NONE found in framework/api/engine.py"
            assert "check_hostname = False" not in code, "Insecure check_hostname = False found in framework/api/engine.py"
            assert "ctx.verify_mode = ssl.CERT_REQUIRED" in code or "ssl_ctx.verify_mode = ssl.CERT_REQUIRED" in code

    def test_missing_scope_engine_fails_closed_for_active_network_requests(self):
        """Proves active network requests fail closed when ScopeEngine is None."""
        engine = ApiIntelligenceEngine(scope_engine=None)
        # Active scope check must return False
        assert engine._is_in_scope("https://api.example.com/openapi.json", is_active=True) is False
        # Passive check without scope engine permits analyzing existing local data
        assert engine._is_in_scope("https://api.example.com/openapi.json", is_active=False) is True
        # acquire_spec_content without mock hook fails closed immediately
        assert engine.acquire_spec_content("https://api.example.com/openapi.json") is None

    def test_out_of_scope_target_rejected(self):
        """Proves destinations not matching ScopeEngine rules fail closed."""
        scope_dict = {
            "program": {"name": "test-prog"},
            "targets": {"domains": ["authorized.com"], "recursive_subdomains": {"enabled": False}},
        }
        scope_engine = ScopeEngine(scope_dict)
        engine = ApiIntelligenceEngine(scope_engine=scope_engine)
        assert engine._is_in_scope("https://evil.com/openapi.json", is_active=True) is False
        assert engine.acquire_spec_content("https://evil.com/openapi.json") is None

    def test_direct_prohibited_ip_literals_blocked(self):
        """Proves loopback, private, and metadata literal IPs raise ScopeViolationError."""
        engine = ApiIntelligenceEngine()
        for bad_url in [
            "http://127.0.0.1/spec.json",
            "http://10.0.0.1/spec.json",
            "http://192.168.1.1/spec.json",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/spec.json",
            "http://localhost/spec.json",
            "http://metadata.google.internal/spec.json",
        ]:
            with pytest.raises(ScopeViolationError):
                engine._resolve_and_verify_destination(bad_url)

    def test_domain_resolving_to_prohibited_ip_blocked(self):
        """Proves domain names resolving to prohibited IPs are blocked."""
        engine = ApiIntelligenceEngine()
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]):
            with pytest.raises(ScopeViolationError) as exc_info:
                engine._resolve_and_verify_destination("https://dns-rebind.example.com/spec.json")
            assert "prohibited" in str(exc_info.value).lower()

    def test_redirect_handler_blocks_protocol_downgrade(self):
        """Proves redirects from HTTPS to HTTP are blocked by safe redirect policy."""
        from framework.api.engine import ApiSafeRedirectHandler
        engine = ApiIntelligenceEngine()
        handler = ApiSafeRedirectHandler(
            engine=engine,
            ip_map={},
            max_redirects=5,
            original_url="https://api.example.com/spec.json",
        )
        dummy_req = urllib.request.Request("https://api.example.com/spec.json")
        with pytest.raises(ScopeViolationError) as exc:
            handler.redirect_request(dummy_req, None, 302, "Found", {}, "http://api.example.com/spec.json")
        assert "Protocol downgrade from HTTPS to HTTP forbidden" in str(exc.value)

    def test_redirect_handler_blocks_out_of_scope_destination(self):
        """Proves redirects to out-of-scope hostnames are rejected."""
        from framework.api.engine import ApiSafeRedirectHandler
        scope_dict = {
            "program": {"name": "test-prog"},
            "targets": {"domains": ["in-scope.com"], "recursive_subdomains": {"enabled": False}},
        }
        scope_engine = ScopeEngine(scope_dict)
        engine = ApiIntelligenceEngine(scope_engine=scope_engine)
        handler = ApiSafeRedirectHandler(
            engine=engine,
            ip_map={},
            max_redirects=5,
            original_url="https://in-scope.com/spec.json",
        )
        dummy_req = urllib.request.Request("https://in-scope.com/spec.json")
        with pytest.raises(ScopeViolationError) as exc:
            handler.redirect_request(dummy_req, None, 302, "Found", {}, "https://out-of-scope.com/spec.json")
        assert "out of scope" in str(exc.value)

    def test_redirect_handler_blocks_prohibited_ip_destination(self):
        """Proves redirects to private/metadata IP are blocked."""
        from framework.api.engine import ApiSafeRedirectHandler
        scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["*"]}})
        engine = ApiIntelligenceEngine(scope_engine=scope_engine)
        handler = ApiSafeRedirectHandler(
            engine=engine,
            ip_map={},
            max_redirects=5,
            original_url="https://example.com/spec.json",
        )
        dummy_req = urllib.request.Request("https://example.com/spec.json")
        with pytest.raises(ScopeViolationError) as exc:
            handler.redirect_request(dummy_req, None, 302, "Found", {}, "https://169.254.169.254/latest/meta-data/")
        err_msg = str(exc.value).lower()
        assert "prohibited" in err_msg or "out of scope" in err_msg

    def test_streaming_byte_budget_enforced(self):
        """Proves streaming response reading terminates at max_bytes_per_spec limit."""
        scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["example.com"]}})
        engine = ApiIntelligenceEngine(
            scope_engine=scope_engine,
            policy=ApiPolicy(max_bytes_per_spec=100, max_bytes=500),
        )
        # Mock opener to return a stream of 500 bytes
        large_data = b"A" * 500
        mock_resp = io.BytesIO(large_data)
        mock_resp.headers = {}
        mock_resp.status = 200

        with patch.object(engine, "_resolve_and_verify_destination", return_value=["93.184.216.34"]):
            with patch("urllib.request.build_opener") as mock_build_opener:
                mock_opener_inst = MagicMock()
                mock_opener_inst.open.return_value.__enter__.return_value = mock_resp
                mock_build_opener.return_value = mock_opener_inst

                content = engine.acquire_spec_content("https://example.com/openapi.json")
                assert content is not None
                assert len(content) == 100
                assert engine.total_bytes == 100

    def test_redirect_handler_enforces_max_redirect_limit(self):
        """Proves exceeding max_redirects triggers ScopeViolationError."""
        from framework.api.engine import ApiSafeRedirectHandler
        scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["example.com"]}})
        engine = ApiIntelligenceEngine(scope_engine=scope_engine)
        handler = ApiSafeRedirectHandler(
            engine=engine,
            ip_map={},
            max_redirects=2,
            original_url="https://example.com/spec1",
        )
        dummy_req = urllib.request.Request("https://example.com/spec1")
        with patch.object(engine, "_resolve_and_verify_destination", return_value=["93.184.216.34"]):
            handler.redirect_request(dummy_req, None, 302, "Found", {}, "https://example.com/spec2")
            handler.redirect_request(dummy_req, None, 302, "Found", {}, "https://example.com/spec3")
            with pytest.raises(ScopeViolationError) as exc:
                handler.redirect_request(dummy_req, None, 302, "Found", {}, "https://example.com/spec4")
            assert "Too many redirects" in str(exc.value)

    def test_redirect_handler_accounts_against_request_budget(self):
        """Proves redirect hops decrement available request budget and abort when exhausted."""
        from framework.api.engine import ApiSafeRedirectHandler
        scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["example.com"]}})
        engine = ApiIntelligenceEngine(scope_engine=scope_engine, policy=ApiPolicy(max_requests=2))
        engine.request_count = 2  # Already at budget limit
        handler = ApiSafeRedirectHandler(
            engine=engine,
            ip_map={},
            max_redirects=5,
            original_url="https://example.com/spec1",
        )
        dummy_req = urllib.request.Request("https://example.com/spec1")
        with pytest.raises(ScopeViolationError) as exc:
            handler.redirect_request(dummy_req, None, 302, "Found", {}, "https://example.com/spec2")
        assert "budget exhausted" in str(exc.value).lower()


class TestGateBCrossEngineCompatibility:
    """Tests verifying cross-engine API state compatibility across authz, validation, ssrf, and injection."""

    def test_api_state_exports_catalog_and_aliases(self):
        """Verifies state/api.json exports 'catalog', 'url', 'path', and embedded parameters."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = ApiStateManager(program_dir=tmpdir)
            ep = ApiEndpoint(
                canonical_url="https://api.example.com/v1/orders/{order_id}",
                path_template="/v1/orders/{order_id}",
                method="GET",
                operation_id="getOrder",
            )
            mgr.add_endpoint(ep)
            param = ApiParameter(
                name="order_id",
                location="path",
                datatype="string",
                required=True,
                endpoint_key=ep.key,
                semantic_role="resource_id",
            )
            mgr.add_parameter(param)
            mgr.save()

            with open(mgr.api_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Check catalog dict for authz and ssrf
            assert "catalog" in data
            assert "/v1/orders/{order_id}" in data["catalog"]
            cat_entry = data["catalog"]["/v1/orders/{order_id}"]
            assert cat_entry["url"] == "https://api.example.com/v1/orders/{order_id}"
            assert len(cat_entry["operations"]) == 1
            op = cat_entry["operations"][0]
            assert op["method"] == "GET"
            assert len(op["parameters"]) == 1
            assert op["parameters"][0]["name"] == "order_id"

            # Check endpoints list with url/path and parameters aliases
            assert "endpoints" in data
            assert len(data["endpoints"]) == 1
            ep_dict = data["endpoints"][0]
            assert ep_dict["url"] == "https://api.example.com/v1/orders/{order_id}"
            assert ep_dict["path"] == "/v1/orders/{order_id}"
            assert len(ep_dict["parameters"]) == 1
            assert ep_dict["parameters"][0]["name"] == "order_id"

    def test_api_state_loads_legacy_catalog_state(self):
        """Verifies ApiStateManager rehydrates endpoints and parameters from legacy catalog-only state."""
        with tempfile.TemporaryDirectory() as tmpdir:
            legacy_data = {
                "metadata": {},
                "catalog": {
                    "/api/v1/users/{id}": {
                        "url": "https://api.example.com/api/v1/users/{id}",
                        "operations": [
                            {
                                "method": "GET",
                                "operation_id": "getUser",
                                "parameters": [
                                    {"name": "id", "location": "path", "datatype": "integer"}
                                ],
                            }
                        ],
                    }
                },
            }
            state_dir = os.path.join(tmpdir, "state")
            os.makedirs(state_dir, exist_ok=True)
            with open(os.path.join(state_dir, "api.json"), "w", encoding="utf-8") as f:
                json.dump(legacy_data, f)

            mgr = ApiStateManager(program_dir=tmpdir)
            assert len(mgr.endpoints) == 1
            ep = list(mgr.endpoints.values())[0]
            assert ep.canonical_url == "https://api.example.com/api/v1/users/{id}"
            assert ep.method == "GET"
            assert ep.path == "/api/v1/users/{id}"
            assert len(mgr.parameters) == 1

    def test_authz_engine_candidate_discovery_from_api_state(self):
        """Verifies AuthorizationIntelligenceEngine discovers candidates from api.json catalog without errors."""
        from framework.authz.engine import AuthorizationIntelligenceEngine
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = ApiStateManager(program_dir=tmpdir)
            ep = ApiEndpoint(
                canonical_url="https://api.example.com/api/v1/accounts/12345",
                path_template="/api/v1/accounts/{account_id}",
                method="GET",
            )
            mgr.add_endpoint(ep)
            param = ApiParameter(
                name="account_id",
                location="path",
                datatype="integer",
                required=True,
                endpoint_key=ep.key,
                semantic_role="account_id",
            )
            mgr.add_parameter(param)
            mgr.save()

            authz_engine = AuthorizationIntelligenceEngine(program_dir=tmpdir)
            targets = authz_engine.discover_candidates_from_state()
            assert len(targets) >= 1
            assert any(t.resource_id == "account_id" or "account" in t.endpoint for t in targets)

    def test_validation_engine_ingests_api_state_via_get_endpoints(self):
        """Verifies SecurityValidationEngine consumes api.json endpoints via asm.get_endpoints() without AttributeError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = ApiStateManager(program_dir=tmpdir)
            ep = ApiEndpoint(
                canonical_url="https://api.example.com/api/v1/search",
                path_template="/api/v1/search",
                method="GET",
            )
            mgr.add_endpoint(ep)
            param = ApiParameter(
                name="q",
                location="query",
                datatype="string",
                endpoint_key=ep.key,
                semantic_role="search",
            )
            mgr.add_parameter(param)
            mgr.save()

            # Test get_endpoints contract directly
            eps = mgr.get_endpoints()
            assert len(eps) == 1
            ep_obj = eps[0]
            assert ep_obj.path == "/api/v1/search"
            assert ep_obj.app_id == "api:api.example.com"
            assert len(ep_obj.parameters) == 1
            assert ep_obj.parameters[0].name == "q"
            assert ep_obj.parameters[0].role.value == "search"

    def test_injection_engine_consumes_api_state(self):
        """Verifies InjectionIntelligenceEngine discovers injection candidates from api.json without exceptions."""
        from framework.injection.engine import InjectionIntelligenceEngine
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = ApiStateManager(program_dir=tmpdir)
            ep = ApiEndpoint(
                canonical_url="https://api.example.com/api/items?id=100",
                path_template="/api/items",
                method="GET",
            )
            mgr.add_endpoint(ep)
            mgr.save()

            inj_engine = InjectionIntelligenceEngine(program_dir=tmpdir)
            candidates = inj_engine.import_candidates_from_state()
            assert len(candidates) >= 1
            assert any(c.parameter == "id" for c in candidates)

    def test_authentication_discovery_consumes_api_state(self):
        """Verifies AuthenticationSurfaceDiscoverer ingests endpoints and auth observations from api.json."""
        from framework.authentication.discovery import AuthenticationSurfaceDiscoverer
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = ApiStateManager(program_dir=tmpdir)
            ep = ApiEndpoint(
                canonical_url="https://api.example.com/api/v1/login",
                path_template="/api/v1/login",
                method="POST",
            )
            mgr.add_endpoint(ep)
            mgr.save()

            steps = AuthenticationSurfaceDiscoverer.discover_all(program_dir=tmpdir)
            assert len(steps) >= 1
            assert any("/login" in s.endpoint for s in steps)


class TestGateCOpenApiParser:
    """Tests validating Gate C: OpenAPI/Swagger parser correctness, $ref resolution, and security propagation."""

    SAMPLE_SPEC_WITH_REFS = """
    openapi: 3.0.0
    info:
      title: Ref Test API
      version: 1.0.0
    components:
      schemas:
        User:
          type: object
          required: [id, username]
          properties:
            id:
              type: integer
            username:
              type: string
        Error:
          type: object
          properties:
            message:
              type: string
      parameters:
        QueryLimit:
          name: limit
          in: query
          schema:
            type: integer
            default: 20
      securitySchemes:
        bearerAuth:
          type: http
          scheme: bearer
        apiKeyAuth:
          type: apiKey
          name: X-API-Key
          in: header
    security:
      - bearerAuth: []
    paths:
      /users:
        parameters:
          - name: sort
            in: query
            schema:
              type: string
          - name: id
            in: path
            schema:
              type: integer
        get:
          operationId: listUsers
          parameters:
            - $ref: "#/components/parameters/QueryLimit"
          responses:
            200:
              description: OK
              content:
                application/json:
                  schema:
                    type: array
                    items:
                      $ref: "#/components/schemas/User"
        post:
          operationId: createUser
          requestBody:
            content:
              application/json:
                schema:
                  $ref: "#/components/schemas/User"
          responses:
            201:
              description: Created
              content:
                application/json:
                  schema:
                    $ref: "#/components/schemas/User"
      /public/ping:
        get:
          operationId: ping
          security: []
          responses:
            200:
              description: Pong
      /admin/config:
        get:
          operationId: getConfig
          security:
            - apiKeyAuth: []
          parameters:
            - name: id
              in: path
              schema:
                type: string
                default: "custom-id"
            - name: id
              in: query
              schema:
                type: integer
          responses:
            200:
              description: OK
    """

    def test_openapi_local_ref_resolution(self):
        """Verifies local $ref resolution for schemas, items, and parameters."""
        parser = OpenApiParser(raw_content=self.SAMPLE_SPEC_WITH_REFS, spec_url="https://api.example.com/openapi.yaml")
        assert parser.is_valid_spec()
        result = parser.parse()

        # Check request schema for POST /users resolved fields
        req_schemas = [rs for rs in result["request_schemas"] if "POST" in rs.endpoint_key]
        assert len(req_schemas) == 1
        assert "id" in req_schemas[0].fields
        assert "username" in req_schemas[0].fields
        assert req_schemas[0].fields["id"]["type"] == "integer"
        assert req_schemas[0].fields["username"]["type"] == "string"

        # Check response schema for POST /users
        resp_schemas = [rs for rs in result["response_schemas"] if "POST" in rs.endpoint_key and rs.status_code == 201]
        assert len(resp_schemas) == 1
        assert "username" in resp_schemas[0].fields

    def test_openapi_external_ref_rejected(self):
        """Verifies external network/file $ref pointers are rejected and not fetched."""
        spec_external = """
        openapi: 3.0.0
        info:
          title: External Ref Test
          version: 1.0.0
        paths:
          /test:
            post:
              requestBody:
                content:
                  application/json:
                    schema:
                      $ref: "https://evil.com/payload.json"
              responses:
                200:
                  description: OK
        """
        parser = OpenApiParser(raw_content=spec_external, spec_url="https://api.example.com/openapi.yaml")
        result = parser.parse()
        assert len(result["request_schemas"]) == 1
        assert "_unresolved_ref" in result["request_schemas"][0].fields or result["request_schemas"][0].fields == {}

    def test_openapi_cyclic_ref_handled_safely(self):
        """Verifies circular references terminate without RecursionError."""
        spec_cyclic = """
        openapi: 3.0.0
        info:
          title: Cyclic Ref Test
          version: 1.0.0
        components:
          schemas:
            Node:
              type: object
              properties:
                name:
                  type: string
                child:
                  $ref: "#/components/schemas/Node"
        paths:
          /tree:
            post:
              requestBody:
                content:
                  application/json:
                    schema:
                      $ref: "#/components/schemas/Node"
              responses:
                200:
                  description: OK
        """
        parser = OpenApiParser(raw_content=spec_cyclic, spec_url="https://api.example.com/openapi.yaml")
        result = parser.parse()
        req_schemas = result["request_schemas"]
        assert len(req_schemas) == 1
        props = req_schemas[0].fields
        assert "name" in props
        assert "child" in props
        # Cycle must terminate gracefully
        assert props["child"].get("_cyclic_ref") == "#/components/schemas/Node" or props["child"].get("type") in ("object", "unknown")

    def test_openapi_parameter_override_and_location_isolation(self):
        """
        Verifies:
        1. Operation-level parameter overrides path-level parameter with matching (name, location).
        2. Parameters with same name but distinct locations (path vs query) are both preserved.
        3. Parameter $ref is resolved.
        """
        parser = OpenApiParser(raw_content=self.SAMPLE_SPEC_WITH_REFS, spec_url="https://api.example.com/openapi.yaml")
        result = parser.parse()
        endpoints = result["endpoints"]
        parameters = result["parameters"]

        # 1. /users GET parameters: path has sort (query) and id (path); op has limit ($ref query)
        users_get_ep = [ep for ep in endpoints if ep.path_template == "/users" and ep.method == "GET"][0]
        users_get_params = [p for p in parameters if p.endpoint_key == users_get_ep.key]
        param_names = [p.name for p in users_get_params]
        assert "sort" in param_names
        assert "id" in param_names
        assert "limit" in param_names  # from resolved $ref

        # 2. /admin/config GET parameters:
        # Path-level has id (path: integer). Op-level has id (path: string) AND id (query: integer).
        admin_ep = [ep for ep in endpoints if ep.path_template == "/admin/config" and ep.method == "GET"][0]
        admin_params = [p for p in parameters if p.endpoint_key == admin_ep.key]

        path_id_params = [p for p in admin_params if p.name == "id" and p.location == "path"]
        query_id_params = [p for p in admin_params if p.name == "id" and p.location == "query"]

        # Must only have ONE path id parameter (the op-level one overriding path-level)
        assert len(path_id_params) == 1
        assert path_id_params[0].datatype == "string"
        assert path_id_params[0].default_value == "custom-id"

        # Must also preserve distinct query id parameter
        assert len(query_id_params) == 1
        assert query_id_params[0].datatype == "integer"

    def test_openapi_security_requirement_propagation_and_override(self):
        """
        Verifies:
        1. Top-level security inherited by default.
        2. Explicit empty security `security: []` overrides to unauthenticated.
        3. Operation-specific security overrides top-level.
        """
        parser = OpenApiParser(raw_content=self.SAMPLE_SPEC_WITH_REFS, spec_url="https://api.example.com/openapi.yaml")
        result = parser.parse()
        endpoints = {f"{ep.method} {ep.path_template}": ep for ep in result["endpoints"]}

        # GET /users inherits root bearerAuth
        assert endpoints["GET /users"].auth_required is True
        assert endpoints["GET /users"].auth_scheme == "bearer"

        # GET /public/ping has security: [] -> explicitly unauthenticated
        assert endpoints["GET /public/ping"].auth_required is False
        assert endpoints["GET /public/ping"].auth_scheme is None

        # GET /admin/config has apiKeyAuth -> overrides root
        assert endpoints["GET /admin/config"].auth_required is True
        assert endpoints["GET /admin/config"].auth_scheme == "api-key"

    def test_openapi_graph_relationships_for_schemas_and_auth(self):
        """Verifies USES_SCHEMA and REQUIRES_AUTH graph edges are created during spec ingestion."""
        with tempfile.TemporaryDirectory() as tmpdir:
            api_state = ApiStateManager(program_dir=tmpdir)
            spec_file = os.path.join(tmpdir, "openapi.yaml")
            with open(spec_file, "w", encoding="utf-8") as f:
                f.write(self.SAMPLE_SPEC_WITH_REFS)

            engine = ApiIntelligenceEngine(api_state=api_state)
            spec = engine.ingest_specification(spec_file)
            assert spec is not None

            # Verify USES_SCHEMA relationships in graph
            schema_edges = [
                rel for rel in api_state.graph.get_all_relationships()
                if rel.relation_type == ApiRelationType.USES_SCHEMA
            ]
            assert len(schema_edges) >= 2

            # Verify REQUIRES_AUTH relationships in graph
            auth_edges = [
                rel for rel in api_state.graph.get_all_relationships()
                if rel.relation_type == ApiRelationType.REQUIRES_AUTH
            ]
            assert len(auth_edges) >= 1


class TestGateDResourceLimitsAndDryRun:
    """Tests validating Gate D: max_endpoints enforcement and dry_run usability without disk mutation."""

    SPEC_MULTI_ENDPOINT = """
    openapi: 3.0.0
    info:
      title: Multi API
      version: 1.0.0
    paths:
      /ep1:
        get:
          responses:
            200:
              description: OK
      /ep2:
        get:
          responses:
            200:
              description: OK
      /ep3:
        get:
          responses:
            200:
              description: OK
      /ep4:
        get:
          responses:
            200:
              description: OK
      /ep5:
        get:
          responses:
            200:
              description: OK
    """

    def test_dry_run_populates_in_memory_state_without_writing_to_disk(self):
        """Verifies dry_run=True populates in-memory api_state without writing state/api.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            api_state = ApiStateManager(program_dir=tmpdir)
            spec_file = os.path.join(tmpdir, "multi.yaml")
            with open(spec_file, "w", encoding="utf-8") as f:
                f.write(self.SPEC_MULTI_ENDPOINT)

            engine = ApiIntelligenceEngine(
                api_state=api_state,
                dry_run=True,
            )
            stats = engine.run_analysis(spec_path=spec_file)

            # In-memory state and stats must be populated
            assert len(api_state.endpoints) == 5
            assert stats["total_endpoints"] == 5
            assert stats["specs_ingested"] == 1

            # Disk file MUST NOT exist in dry-run mode
            assert not os.path.exists(api_state.api_file)

    def test_max_endpoints_ceiling_enforced_in_spec_ingestion(self):
        """Verifies max_endpoints stops adding endpoints once the ceiling is reached."""
        with tempfile.TemporaryDirectory() as tmpdir:
            api_state = ApiStateManager(program_dir=tmpdir)
            spec_file = os.path.join(tmpdir, "multi.yaml")
            with open(spec_file, "w", encoding="utf-8") as f:
                f.write(self.SPEC_MULTI_ENDPOINT)

            policy = ApiPolicy(max_endpoints=2)
            engine = ApiIntelligenceEngine(
                api_state=api_state,
                policy=policy,
            )
            stats = engine.run_analysis(spec_path=spec_file)

            # Only 2 endpoints should be stored
            assert len(api_state.endpoints) == 2
            assert stats["total_endpoints"] == 2
            assert os.path.exists(api_state.api_file)

    def test_cli_wiring_timeout_and_max_endpoints(self):
        """Verifies bb-api argument parser handles --timeout and --max-endpoints."""
        import subprocess
        bb_api_script = os.path.join(os.path.dirname(__file__), "..", "scripts", "bb-api")
        result = subprocess.run(
            [sys.executable, bb_api_script, "--help"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "--timeout" in result.stdout
        assert "--max-endpoints" in result.stdout
        assert "--dry-run" in result.stdout


class TestGateEGraphQLIntrospection:
    """Tests validating Gate E: safe, conditional, opt-in GraphQL schema introspection."""

    MOCK_INTROSPECTION_DATA = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": [
                    {
                        "name": "Query",
                        "kind": "OBJECT",
                        "fields": [
                            {
                                "name": "getUser",
                                "args": [
                                    {"name": "id", "type": {"name": "Int", "kind": "SCALAR"}},
                                    {"name": "username", "type": {"name": "String", "kind": "SCALAR"}},
                                ],
                            },
                            {
                                "name": "listItems",
                                "args": [
                                    {"name": "limit", "type": {"name": "Int", "kind": "SCALAR"}},
                                ],
                            },
                        ],
                    },
                    {
                        "name": "Mutation",
                        "kind": "OBJECT",
                        "fields": [
                            {
                                "name": "createPost",
                                "args": [
                                    {"name": "title", "type": {"name": "String", "kind": "SCALAR"}},
                                    {"name": "auth_token", "type": {"name": "String", "kind": "SCALAR"}},
                                ],
                            },
                        ],
                    },
                ],
            }
        }
    }

    def test_graphql_introspection_disabled_by_default(self):
        """Verifies allow_graphql_introspection defaults to False and probes are inhibited."""
        policy = ApiPolicy()
        assert policy.allow_graphql_introspection is False

        engine = ApiIntelligenceEngine(policy=policy)
        result = engine.probe_graphql_introspection("https://api.example.com/graphql")
        assert result is None
        assert engine.request_count == 0

    def test_graphql_introspection_fails_closed_without_scope(self):
        """Verifies active GraphQL introspection fails closed when scope engine is absent."""
        policy = ApiPolicy(allow_graphql_introspection=True)
        engine = ApiIntelligenceEngine(scope_engine=None, policy=policy)
        result = engine.probe_graphql_introspection("https://api.example.com/graphql")
        assert result is None
        assert engine.request_count == 0

    def test_graphql_introspection_parsing_and_parameter_extraction(self):
        """Verifies safe introspection query parsing, operation generation, and semantic role assignment."""
        with tempfile.TemporaryDirectory() as tmpdir:
            api_state = ApiStateManager(program_dir=tmpdir)
            scope_dict = {
                "program": {"name": "graphql-test"},
                "targets": {"domains": ["api.example.com"], "recursive_subdomains": {"enabled": False}},
            }
            scope_engine = ScopeEngine(scope_dict)
            policy = ApiPolicy(allow_graphql_introspection=True)

            engine = ApiIntelligenceEngine(
                scope_engine=scope_engine,
                api_state=api_state,
                policy=policy,
            )
            engine.graphql_hook = lambda url, query: json.dumps(self.MOCK_INTROSPECTION_DATA)

            result = engine.probe_graphql_introspection("https://api.example.com/graphql")
            assert result is not None
            assert len(result["endpoints"]) == 3  # getUser, listItems, createPost
            assert len(result["parameters"]) == 5  # id, username, limit, title, auth_token

            # Check query endpoint
            get_user_ep = [ep for ep in result["endpoints"] if "getUser" in ep.canonical_url][0]
            assert get_user_ep.api_style == ApiStyle.GRAPHQL.value
            assert get_user_ep.operation_id == "query_getUser"

            # Check parameters attached and semantic roles
            id_param = [p for p in result["parameters"] if p.endpoint_key == get_user_ep.key and p.name == "id"][0]
            assert id_param.semantic_role == "identifier"
            assert id_param.datatype == "int"

            token_param = [p for p in result["parameters"] if p.name == "auth_token"][0]
            assert token_param.semantic_role == "token"

            # In-memory api_state must contain the parsed endpoints
            assert len(api_state.endpoints) == 3

    def test_graphql_query_builder_read_only(self):
        """Verifies build_bounded_introspection_query is non-destructive and queries metadata only."""
        query_str = GraphQLAnalyzer.build_bounded_introspection_query()
        assert "__schema" in query_str
        assert "queryType" in query_str
        assert "mutationType" in query_str
        # Must not contain destructive mutations or deep nesting
        assert "mutation {" not in query_str

    def test_cli_wiring_graphql_introspection_flag(self):
        """Verifies bb-api CLI includes --allow-graphql-introspection."""
        import subprocess
        bb_api_script = os.path.join(os.path.dirname(__file__), "..", "scripts", "bb-api")
        result = subprocess.run(
            [sys.executable, bb_api_script, "--help"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "--allow-graphql-introspection" in result.stdout


# ==============================================================================
# FINDINGS A - D TARGETED REGRESSION & INTEGRATION TESTS
# ==============================================================================

class TestFindingAGraphQLByteBudget:
    """Targeted regression tests for Finding A: GraphQL byte budget and truncation handling."""

    def test_1_nearly_exhausted_global_budget(self):
        """Verifies nearly exhausted global budget allows response fitting within remaining allowance."""
        scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["api.example.com"]}})
        policy = ApiPolicy(allow_graphql_introspection=True, max_bytes=1000)
        with tempfile.TemporaryDirectory() as tmpdir:
            api_state = ApiStateManager(program_dir=tmpdir)
            engine = ApiIntelligenceEngine(scope_engine=scope_engine, api_state=api_state, policy=policy)
            engine.total_bytes = 950  # 50 bytes remaining

            mock_data = {"data": {"__schema": {"types": [{"name": "A"}]}}}
            payload = json.dumps(mock_data)
            b_len = len(payload.encode("utf-8"))
            assert b_len <= 50

            engine.graphql_hook = lambda url, query: payload
            res = engine.probe_graphql_introspection("https://api.example.com/graphql")
            assert res is not None
            assert engine.total_bytes == 950 + b_len

    def test_2_response_larger_than_remaining_global_budget_rejected(self):
        """Verifies hook response exceeding remaining global max_bytes is rejected without state mutation."""
        scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["api.example.com"]}})
        policy = ApiPolicy(allow_graphql_introspection=True, max_bytes_per_spec=200, max_bytes=300)
        with tempfile.TemporaryDirectory() as tmpdir:
            api_state = ApiStateManager(program_dir=tmpdir)
            engine = ApiIntelligenceEngine(scope_engine=scope_engine, api_state=api_state, policy=policy)
            engine.total_bytes = 250  # Only 50 bytes remaining globally

            payload = json.dumps({"data": {"__schema": {"types": [{"name": "ItemWithLongerName"}]}}})
            b_len = len(payload.encode("utf-8"))
            assert b_len > 50

            engine.graphql_hook = lambda url, query: payload
            res = engine.probe_graphql_introspection("https://api.example.com/graphql")
            assert res is None
            assert engine.total_bytes == 250
            assert len(api_state.endpoints) == 0

    def test_3_multiple_responses_approaching_and_attempting_to_exceed_cumulative_limit(self):
        """Verifies multiple successive responses accumulate until limit is reached, rejecting the overshoot."""
        scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["api.example.com"]}})
        # Global limit 150 bytes, per-spec limit 100 bytes
        policy = ApiPolicy(allow_graphql_introspection=True, max_bytes=150, max_bytes_per_spec=100)
        with tempfile.TemporaryDirectory() as tmpdir:
            api_state = ApiStateManager(program_dir=tmpdir)
            engine = ApiIntelligenceEngine(scope_engine=scope_engine, api_state=api_state, policy=policy)

            # Response 1: ~50 bytes
            resp1 = json.dumps({"data": {"__schema": {"types": [{"name": "T1"}]}}})
            len1 = len(resp1.encode("utf-8"))
            engine.graphql_hook = lambda url, q: resp1
            res1 = engine.probe_graphql_introspection("https://api.example.com/graphql")
            assert res1 is not None
            assert engine.total_bytes == len1

            # Response 2: ~50 bytes
            resp2 = json.dumps({"data": {"__schema": {"types": [{"name": "T2"}]}}})
            len2 = len(resp2.encode("utf-8"))
            engine.graphql_hook = lambda url, q: resp2
            res2 = engine.probe_graphql_introspection("https://api.example.com/graphql")
            assert res2 is not None
            assert engine.total_bytes == len1 + len2

            # Response 3: ~60 bytes (len1 + len2 + len3 > 150) -> must be rejected
            resp3 = json.dumps({"data": {"__schema": {"types": [{"name": "T3LongTypeName"}]}}})
            len3 = len(resp3.encode("utf-8"))
            assert engine.total_bytes + len3 > 150
            engine.graphql_hook = lambda url, q: resp3
            res3 = engine.probe_graphql_introspection("https://api.example.com/graphql")
            assert res3 is None
            # Total bytes remains exactly sum of accepted responses
            assert engine.total_bytes == len1 + len2

    def test_4_per_spec_limit_reached_first(self):
        """Verifies per-spec limit rejects oversized response even when global budget has remaining space."""
        scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["api.example.com"]}})
        policy = ApiPolicy(allow_graphql_introspection=True, max_bytes_per_spec=50, max_bytes=10000)
        with tempfile.TemporaryDirectory() as tmpdir:
            api_state = ApiStateManager(program_dir=tmpdir)
            engine = ApiIntelligenceEngine(scope_engine=scope_engine, api_state=api_state, policy=policy)
            large_payload = json.dumps({"data": {"__schema": {"types": [{"name": "A" * 60}]}}})
            assert len(large_payload.encode("utf-8")) > 50

            engine.graphql_hook = lambda url, query: large_payload
            res = engine.probe_graphql_introspection("https://api.example.com/graphql")
            assert res is None
            assert engine.total_bytes == 0
            assert len(api_state.endpoints) == 0

    def test_5_zero_remaining_budget(self):
        """Verifies engine aborts immediately without dispatching request when remaining budget is zero."""
        scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["api.example.com"]}})
        policy = ApiPolicy(allow_graphql_introspection=True, max_bytes=500)
        with tempfile.TemporaryDirectory() as tmpdir:
            api_state = ApiStateManager(program_dir=tmpdir)
            engine = ApiIntelligenceEngine(scope_engine=scope_engine, api_state=api_state, policy=policy)
            engine.total_bytes = 500  # Zero remaining

            hook_called = False
            def hook(url, q):
                nonlocal hook_called
                hook_called = True
                return "{}"

            engine.graphql_hook = hook
            res = engine.probe_graphql_introspection("https://api.example.com/graphql")
            assert res is None
            assert hook_called is False
            assert engine.request_count == 0

    def test_6_truncated_response_rejection_live(self):
        """Verifies live response exceeding budget is detected as truncated and rejected."""
        import http.server
        import threading

        class OversizedStreamHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                clen = int(self.headers.get("Content-Length", 0))
                if clen > 0:
                    self.rfile.read(clen)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                # Send body in chunks that exceed 50 bytes
                self.wfile.write(b'{"data": {"__schema": {"types": [' + b'{"name": "X"},' * 20 + b']}}}')
            def log_message(self, *args): pass

        server = http.server.HTTPServer(("127.0.0.1", 0), OversizedStreamHandler)
        port = server.server_port
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        import time
        time.sleep(0.05)

        try:
            scope_engine = ScopeEngine({
                "program": {"name": "test"},
                "targets": {"domains": ["127.0.0.1"], "urls": [f"http://127.0.0.1:{port}"]},
            })
            policy = ApiPolicy(
                allow_graphql_introspection=True,
                max_bytes_per_spec=50,  # 50 bytes max
                max_bytes=1000,
            )
            engine = ApiIntelligenceEngine(scope_engine=scope_engine, policy=policy)
            engine.allow_fixture_port(port)

            res = engine.probe_graphql_introspection(f"http://127.0.0.1:{port}/graphql")
            assert res is None
            # Accepted bytes budget must remain 0
            assert engine.total_bytes == 0
            # Transferred bytes records wire read including truncation check
            assert engine.total_bytes_transferred > 0
        finally:
            server.shutdown()
            server.server_close()

    def test_7_accounting_after_errors_and_early_returns(self):
        """Verifies malformed JSON does not crash, does not corrupt total_bytes, and leaves zero mutations."""
        scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["api.example.com"]}})
        policy = ApiPolicy(allow_graphql_introspection=True, max_bytes_per_spec=500, max_bytes=1000)
        with tempfile.TemporaryDirectory() as tmpdir:
            api_state = ApiStateManager(program_dir=tmpdir)
            engine = ApiIntelligenceEngine(scope_engine=scope_engine, api_state=api_state, policy=policy)
            engine.graphql_hook = lambda url, query: "NOT_VALID_JSON{__schema: broken"

            res = engine.probe_graphql_introspection("https://api.example.com/graphql")
            assert res is None
            assert engine.total_bytes == 0
            assert len(api_state.endpoints) == 0

    def test_8_equivalent_enforcement_hook_and_live(self):
        """Verifies hook-based and live HTTP paths enforce byte limits equivalently and exclude 1-byte read."""
        import http.server
        import threading

        payload = json.dumps({"data": {"__schema": {"types": [{"name": "Test"}]}}})
        payload_bytes = payload.encode("utf-8")
        payload_len = len(payload_bytes)

        class LiveHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                clen = int(self.headers.get("Content-Length", 0))
                if clen > 0:
                    self.rfile.read(clen)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(payload_len))
                self.end_headers()
                self.wfile.write(payload_bytes)
            def log_message(self, *args): pass

        server = http.server.HTTPServer(("127.0.0.1", 0), LiveHandler)
        port = server.server_port
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        time.sleep(0.05)

        try:
            scope_engine = ScopeEngine({
                "program": {"name": "test"},
                "targets": {"domains": ["127.0.0.1", "api.example.com"], "urls": [f"http://127.0.0.1:{port}"]},
            })

            # Case A: Both succeed within budget
            policy_ok = ApiPolicy(allow_graphql_introspection=True, max_bytes=1000, max_bytes_per_spec=500)
            engine_hook = ApiIntelligenceEngine(scope_engine=scope_engine, policy=policy_ok)
            engine_hook.graphql_hook = lambda u, q: payload
            res_hook = engine_hook.probe_graphql_introspection("https://api.example.com/graphql")
            assert res_hook is not None
            assert engine_hook.total_bytes == payload_len

            engine_live = ApiIntelligenceEngine(scope_engine=scope_engine, policy=policy_ok)
            engine_live.allow_fixture_port(port)
            res_live = engine_live.probe_graphql_introspection(f"http://127.0.0.1:{port}/graphql")
            assert res_live is not None
            assert engine_live.total_bytes == payload_len

            # Case B: Both reject when payload exceeds allowed budget
            policy_small = ApiPolicy(allow_graphql_introspection=True, max_bytes_per_spec=payload_len - 5)
            engine_hook_reject = ApiIntelligenceEngine(scope_engine=scope_engine, policy=policy_small)
            engine_hook_reject.graphql_hook = lambda u, q: payload
            assert engine_hook_reject.probe_graphql_introspection("https://api.example.com/graphql") is None
            assert engine_hook_reject.total_bytes == 0

            engine_live_reject = ApiIntelligenceEngine(scope_engine=scope_engine, policy=policy_small)
            engine_live_reject.allow_fixture_port(port)
            assert engine_live_reject.probe_graphql_introspection(f"http://127.0.0.1:{port}/graphql") is None
            assert engine_live_reject.total_bytes == 0
        finally:
            server.shutdown()
            server.server_close()


class TestFindingBEndpointLimitsState:
    """Targeted regression tests for Finding B: Endpoint limits must bound associated state."""

    OPENAPI_FIVE_ENDPOINTS = json.dumps({
        "openapi": "3.0.0",
        "info": {"title": "Multi-Endpoint API", "version": "1.0.0"},
        "paths": {
            f"/api/resource_{i}": {
                "get": {
                    "operationId": f"getResource{i}",
                    "parameters": [
                        {"name": f"param_{i}", "in": "query", "schema": {"type": "string"}},
                    ],
                    "responses": {
                        "200": {
                            "description": "OK",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {f"field_{i}": {"type": "string"}},
                                    }
                                }
                            },
                        }
                    },
                }
            }
            for i in range(1, 6)
        },
    })

    def test_openapi_endpoint_limit_bounds_parameters_and_schemas(self):
        """Verifies that when max_endpoints is reached, rejected endpoints do not leave orphan params/schemas/edges."""
        with tempfile.TemporaryDirectory() as tmpdir:
            api_state = ApiStateManager(program_dir=tmpdir)
            scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["api.example.com"]}})
            policy = ApiPolicy(max_endpoints=2)
            engine = ApiIntelligenceEngine(scope_engine=scope_engine, api_state=api_state, policy=policy)
            engine.fetch_spec_hook = lambda url: self.OPENAPI_FIVE_ENDPOINTS

            spec = engine.ingest_specification("https://api.example.com/openapi.json")
            assert spec is not None

            # Exactly 2 endpoints must be accepted
            assert len(api_state.endpoints) == 2
            accepted_keys = set(api_state.endpoints.keys())

            # All parameters must belong exclusively to accepted endpoints
            assert len(api_state.parameters) == 2
            for param in api_state.parameters.values():
                assert param.endpoint_key in accepted_keys

            # All response schemas must belong exclusively to accepted endpoints
            assert len(api_state.response_schemas) == 2
            for rs in api_state.response_schemas.values():
                assert rs.endpoint_key in accepted_keys

            # In the graph, verify no relationships reference rejected endpoints
            for rel in api_state.graph._relationships:
                if rel.relation_type in (
                    ApiRelationType.DOCUMENTS_ENDPOINT,
                    ApiRelationType.HAS_ENDPOINT,
                ):
                    assert rel.destination_id in accepted_keys
                elif rel.relation_type in (
                    ApiRelationType.ACCEPTS_PARAMETER,
                    ApiRelationType.USES_SCHEMA,
                ):
                    assert rel.source_id in accepted_keys

    def test_openapi_duplicate_endpoint_updates_without_consuming_extra_slot(self):
        """Verifies duplicate endpoint merges without consuming additional quota."""
        with tempfile.TemporaryDirectory() as tmpdir:
            api_state = ApiStateManager(program_dir=tmpdir)
            scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["api.example.com"]}})
            policy = ApiPolicy(max_endpoints=2)
            engine = ApiIntelligenceEngine(scope_engine=scope_engine, api_state=api_state, policy=policy)

            # Ingest first spec with 1 endpoint
            spec_1 = json.dumps({
                "openapi": "3.0.0",
                "info": {"title": "Spec 1", "version": "1.0"},
                "paths": {"/api/items": {"get": {"operationId": "getItems"}}},
            })
            engine.fetch_spec_hook = lambda url: spec_1
            engine.ingest_specification("https://api.example.com/openapi1.json")
            assert len(api_state.endpoints) == 1

            # Ingest second spec updating /api/items and adding /api/users
            spec_2 = json.dumps({
                "openapi": "3.0.0",
                "info": {"title": "Spec 2", "version": "2.0"},
                "paths": {
                    "/api/items": {"get": {"operationId": "getItems"}},
                    "/api/users": {"get": {"operationId": "getUsers"}},
                },
            })
            engine.fetch_spec_hook = lambda url: spec_2
            engine.ingest_specification("https://api.example.com/openapi2.json")

            assert len(api_state.endpoints) == 2
            assert any(ep.operation_id == "getItems" for ep in api_state.endpoints.values())
            assert any(ep.operation_id == "getUsers" for ep in api_state.endpoints.values())

    def test_graphql_introspection_endpoint_limit_bounds_parameters(self):
        """Verifies that max_endpoints limits parameters in GraphQL introspection."""
        scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["api.example.com"]}})
        with tempfile.TemporaryDirectory() as tmpdir:
            api_state = ApiStateManager(program_dir=tmpdir)
            policy = ApiPolicy(allow_graphql_introspection=True, max_endpoints=1)
            engine = ApiIntelligenceEngine(scope_engine=scope_engine, api_state=api_state, policy=policy)

            mock_data = {
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "types": [
                            {
                                "name": "Query",
                                "fields": [
                                    {
                                        "name": "op1",
                                        "args": [{"name": "arg1", "type": {"name": "String"}}],
                                    },
                                    {
                                        "name": "op2",
                                        "args": [{"name": "arg2", "type": {"name": "String"}}],
                                    },
                                ],
                            }
                        ],
                    }
                }
            }
            engine.graphql_hook = lambda url, q: json.dumps(mock_data)
            res = engine.probe_graphql_introspection("https://api.example.com/graphql")
            assert res is not None

            # Only 1 endpoint accepted into api_state
            assert len(api_state.endpoints) == 1
            accepted_ep_key = list(api_state.endpoints.keys())[0]

            # Only parameters for the 1 accepted endpoint present
            assert len(api_state.parameters) == 1
            assert list(api_state.parameters.values())[0].endpoint_key == accepted_ep_key

    def test_openapi_endpoint_limit_bounds_auth_observations(self):
        """Verifies auth observations associated exclusively with rejected endpoints are not added to state."""
        spec_with_auth = json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "Auth API", "version": "1.0"},
            "components": {
                "securitySchemes": {
                    "basicAuth": {"type": "http", "scheme": "basic"},
                    "bearerAuth": {"type": "http", "scheme": "bearer"},
                }
            },
            "paths": {
                "/api/public": {
                    "get": {
                        "operationId": "getPublic",
                        "security": [],  # explicitly public
                        "responses": {"200": {"description": "OK"}},
                    }
                },
                "/api/basic_secure": {
                    "get": {
                        "operationId": "getBasic",
                        "security": [{"basicAuth": []}],
                        "responses": {"200": {"description": "OK"}},
                    }
                },
                "/api/bearer_secure": {
                    "get": {
                        "operationId": "getBearer",
                        "security": [{"bearerAuth": []}],
                        "responses": {"200": {"description": "OK"}},
                    }
                },
            },
        })

        with tempfile.TemporaryDirectory() as tmpdir:
            api_state = ApiStateManager(program_dir=tmpdir)
            scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["api.example.com"]}})

            # Case A: max_endpoints=1 -> only /api/public accepted -> 0 auth observations added
            policy1 = ApiPolicy(max_endpoints=1)
            engine1 = ApiIntelligenceEngine(scope_engine=scope_engine, api_state=api_state, policy=policy1)
            engine1.fetch_spec_hook = lambda url: spec_with_auth
            engine1.ingest_specification("https://api.example.com/openapi.json")

            assert len(api_state.endpoints) == 1
            assert len(api_state.auth_observations) == 0

        with tempfile.TemporaryDirectory() as tmpdir:
            api_state2 = ApiStateManager(program_dir=tmpdir)
            # Case B: max_endpoints=2 -> public and basic accepted -> only basic added, bearer omitted
            policy2 = ApiPolicy(max_endpoints=2)
            engine2 = ApiIntelligenceEngine(scope_engine=scope_engine, api_state=api_state2, policy=policy2)
            engine2.fetch_spec_hook = lambda url: spec_with_auth
            engine2.ingest_specification("https://api.example.com/openapi.json")

            assert len(api_state2.endpoints) == 2
            assert len(api_state2.auth_observations) == 1
            assert list(api_state2.auth_observations.values())[0].scheme == "basic"

    def test_independent_limits_max_parameters(self):
        """Verifies max_parameters policy strictly bounds total parameter count across all endpoints."""
        spec_many_params = json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "Many Params API", "version": "1.0"},
            "paths": {
                "/api/search": {
                    "get": {
                        "operationId": "search",
                        "parameters": [
                            {"name": f"param_{i}", "in": "query", "schema": {"type": "string"}}
                            for i in range(20)
                        ],
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            },
        })
        with tempfile.TemporaryDirectory() as tmpdir:
            api_state = ApiStateManager(program_dir=tmpdir)
            scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["api.example.com"]}})
            policy = ApiPolicy(max_parameters=5)
            engine = ApiIntelligenceEngine(scope_engine=scope_engine, api_state=api_state, policy=policy)
            engine.fetch_spec_hook = lambda url: spec_many_params
            engine.ingest_specification("https://api.example.com/openapi.json")

            assert len(api_state.endpoints) == 1
            assert len(api_state.parameters) == 5

    def test_independent_limits_max_parameters_per_endpoint(self):
        """Verifies max_parameters_per_endpoint bounds parameters on an individual endpoint."""
        spec_many_params = json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "Per Endpoint Params API", "version": "1.0"},
            "paths": {
                "/api/items": {
                    "get": {
                        "operationId": "getItems",
                        "parameters": [
                            {"name": f"p_{i}", "in": "query", "schema": {"type": "string"}}
                            for i in range(10)
                        ],
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            },
        })
        with tempfile.TemporaryDirectory() as tmpdir:
            api_state = ApiStateManager(program_dir=tmpdir)
            scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["api.example.com"]}})
            policy = ApiPolicy(max_parameters_per_endpoint=3)
            engine = ApiIntelligenceEngine(scope_engine=scope_engine, api_state=api_state, policy=policy)
            engine.fetch_spec_hook = lambda url: spec_many_params
            engine.ingest_specification("https://api.example.com/openapi.json")

            assert len(api_state.endpoints) == 1
            assert len(api_state.parameters) == 3

    def test_independent_limits_max_schemas_per_endpoint(self):
        """Verifies max_schemas_per_endpoint bounds response schemas on an individual endpoint."""
        spec_many_responses = json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "Many Responses API", "version": "1.0"},
            "paths": {
                "/api/test": {
                    "get": {
                        "operationId": "testOp",
                        "responses": {
                            "200": {
                                "description": "200",
                                "content": {"application/json": {"schema": {"type": "object"}}},
                            },
                            "400": {
                                "description": "400",
                                "content": {"application/json": {"schema": {"type": "object"}}},
                            },
                            "500": {
                                "description": "500",
                                "content": {"application/json": {"schema": {"type": "object"}}},
                            },
                        },
                    }
                }
            },
        })
        with tempfile.TemporaryDirectory() as tmpdir:
            api_state = ApiStateManager(program_dir=tmpdir)
            scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["api.example.com"]}})
            policy = ApiPolicy(max_schemas_per_endpoint=1)
            engine = ApiIntelligenceEngine(scope_engine=scope_engine, api_state=api_state, policy=policy)
            engine.fetch_spec_hook = lambda url: spec_many_responses
            engine.ingest_specification("https://api.example.com/openapi.json")

            assert len(api_state.endpoints) == 1
            assert len(api_state.response_schemas) == 1


class TestFindingCGraphQLDepth:
    """Targeted regression tests for Finding C: GraphQL query depth implementation and documentation."""

    def test_graphql_introspection_query_depth_deterministic(self):
        """Verifies deterministic selection set nesting depth equals 6 and schema navigation depth equals 3."""
        query_payload = GraphQLAnalyzer.build_bounded_introspection_query()
        measured_depth = GraphQLAnalyzer.calculate_query_depth(query_payload)

        assert measured_depth == 6
        assert GraphQLAnalyzer.MAX_INTROSPECTION_SELECTION_DEPTH == 6
        assert GraphQLAnalyzer.MAX_INTROSPECTION_SCHEMA_DEPTH == 3

    def test_calculate_query_depth_handles_comments_and_strings(self):
        """Verifies calculate_query_depth ignores braces inside comments and string literals."""
        q1 = """
        # { Comment with brace
        query MyQuery {
            user(name: "{literal_brace}") {
                id
            }
        }
        """
        assert GraphQLAnalyzer.calculate_query_depth(q1) == 2

    def test_graphql_introspection_disabled_by_default(self):
        """Verifies GraphQL introspection is strictly disabled by default."""
        policy = ApiPolicy()
        assert policy.allow_graphql_introspection is False

        scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["api.example.com"]}})
        engine = ApiIntelligenceEngine(scope_engine=scope_engine, policy=policy)
        hook_called = False
        def hook(u, q):
            nonlocal hook_called
            hook_called = True
            return "{}"
        engine.graphql_hook = hook

        res = engine.probe_graphql_introspection("https://api.example.com/graphql")
        assert res is None
        assert hook_called is False

    def test_graphql_introspection_requires_explicit_opt_in(self):
        """Verifies GraphQL introspection requires explicit opt-in policy flag."""
        scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["api.example.com"]}})
        policy = ApiPolicy(allow_graphql_introspection=True)
        engine = ApiIntelligenceEngine(scope_engine=scope_engine, policy=policy)
        engine.graphql_hook = lambda u, q: json.dumps({"data": {"__schema": {"types": [{"name": "Query"}]}}})

        res = engine.probe_graphql_introspection("https://api.example.com/graphql")
        assert res is not None
        assert "endpoints" in res


class TestFindingDTransportSecurity:
    """Targeted integration tests for Finding D: Loopback transport security and certificate verification."""

    @staticmethod
    def _get_openssl() -> Optional[str]:
        found = shutil.which("openssl")
        if found:
            return found
        win_git = r"C:\Applications\Git\usr\bin\openssl.exe"
        if os.path.isfile(win_git):
            return win_git
        return None

    @classmethod
    def _generate_cert(cls, tmpdir: str, cn: str, san_ip: Optional[str] = None) -> tuple[str, str]:
        openssl = cls._get_openssl()
        if not openssl:
            pytest.skip("OpenSSL executable not found for TLS integration test")

        key_path = os.path.join(tmpdir, "key.pem")
        cert_path = os.path.join(tmpdir, "cert.pem")
        cmd = [
            openssl, "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "1", "-nodes",
            "-subj", f"/CN={cn}",
        ]
        if san_ip:
            cmd.extend(["-addext", f"subjectAltName=IP:{san_ip}"])

        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return cert_path, key_path

    def test_transport_tls_valid_cert_with_custom_context_succeeds(self):
        """Verifies live HTTPS request with valid trusted certificate succeeds over local socket."""
        import http.server
        import threading

        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path, key_path = self._generate_cert(tmpdir, cn="127.0.0.1", san_ip="127.0.0.1")

            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(cert_path, key_path)

            class SpecHandler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"openapi": "3.0.0", "paths": {}}')
                def log_message(self, *args): pass

            server = http.server.HTTPServer(("127.0.0.1", 0), SpecHandler)
            server.socket = server_ctx.wrap_socket(server.socket, server_side=True)
            port = server.server_port
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()

            try:
                client_ctx = ssl.create_default_context(cafile=cert_path)
                client_ctx.check_hostname = True
                scope_engine = ScopeEngine({
                    "program": {"name": "test"},
                    "targets": {"domains": ["127.0.0.1"], "urls": [f"https://127.0.0.1:{port}"]},
                })
                engine = ApiIntelligenceEngine(scope_engine=scope_engine, custom_ssl_context=client_ctx)
                engine.allow_fixture_port(port)

                content = engine.acquire_spec_content(f"https://127.0.0.1:{port}/openapi.json")
                assert content is not None
                assert "3.0.0" in content
                assert engine.total_bytes > 0
            finally:
                server.shutdown()
                server.server_close()

    def test_transport_tls_untrusted_cert_default_mode_fails_closed(self):
        """Verifies default engine configuration fails closed and rejects self-signed certificates."""
        import http.server
        import threading

        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path, key_path = self._generate_cert(tmpdir, cn="127.0.0.1", san_ip="127.0.0.1")

            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(cert_path, key_path)

            class SpecHandler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{"openapi": "3.0.0", "paths": {}}')
                def log_message(self, *args): pass

            server = http.server.HTTPServer(("127.0.0.1", 0), SpecHandler)
            server.socket = server_ctx.wrap_socket(server.socket, server_side=True)
            port = server.server_port
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()

            try:
                # Default SSL context without custom CA -> certificate verification must fail closed
                scope_engine = ScopeEngine({
                    "program": {"name": "test"},
                    "targets": {"domains": ["127.0.0.1"], "urls": [f"https://127.0.0.1:{port}"]},
                })
                engine = ApiIntelligenceEngine(scope_engine=scope_engine)
                engine.allow_fixture_port(port)

                content = engine.acquire_spec_content(f"https://127.0.0.1:{port}/openapi.json")
                assert content is None
            finally:
                server.shutdown()
                server.server_close()

    def test_transport_tls_hostname_mismatch_rejected(self):
        """Verifies hostname mismatch between target URL and TLS certificate is rejected."""
        import http.server
        import threading

        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path, key_path = self._generate_cert(tmpdir, cn="mismatch.example.com")

            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(cert_path, key_path)

            class SpecHandler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{"openapi": "3.0.0", "paths": {}}')
                def log_message(self, *args): pass

            server = http.server.HTTPServer(("127.0.0.1", 0), SpecHandler)
            server.socket = server_ctx.wrap_socket(server.socket, server_side=True)
            port = server.server_port
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()

            try:
                client_ctx = ssl.create_default_context(cafile=cert_path)
                client_ctx.check_hostname = True
                scope_engine = ScopeEngine({
                    "program": {"name": "test"},
                    "targets": {"domains": ["127.0.0.1"], "urls": [f"https://127.0.0.1:{port}"]},
                })
                engine = ApiIntelligenceEngine(scope_engine=scope_engine, custom_ssl_context=client_ctx)
                engine.allow_fixture_port(port)

                content = engine.acquire_spec_content(f"https://127.0.0.1:{port}/openapi.json")
                assert content is None
            finally:
                server.shutdown()
                server.server_close()

    def test_transport_live_redirect_to_out_of_scope_rejected(self):
        """Verifies live redirect to out-of-scope target is rejected on the wire before second request."""
        import http.server
        import threading

        class RedirectHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "https://unauthorized-evil.com/spec.json")
                self.end_headers()
            def log_message(self, *args): pass

        server = http.server.HTTPServer(("127.0.0.1", 0), RedirectHandler)
        port = server.server_port
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        try:
            scope_engine = ScopeEngine({
                "program": {"name": "test"},
                "targets": {"domains": ["127.0.0.1"], "urls": [f"http://127.0.0.1:{port}"]},
            })
            engine = ApiIntelligenceEngine(scope_engine=scope_engine)
            engine.allow_fixture_port(port)

            content = engine.acquire_spec_content(f"http://127.0.0.1:{port}/start")
            assert content is None
        finally:
            server.shutdown()
            server.server_close()

    def test_transport_live_redirect_accounting_and_limit(self):
        """Verifies redirect following increments request budget and terminates at max_redirects."""
        import http.server
        import threading

        class MultiHopHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/hop1":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/hop2")
                    self.end_headers()
                elif self.path == "/hop2":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/final.json")
                    self.end_headers()
                elif self.path == "/final.json":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"openapi": "3.0.0", "paths": {}}')
            def log_message(self, *args): pass

        server = http.server.HTTPServer(("127.0.0.1", 0), MultiHopHandler)
        port = server.server_port
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        try:
            # 1. Successful 2-hop redirect with max_redirects=3
            scope_engine = ScopeEngine({
                "program": {"name": "test"},
                "targets": {"domains": ["127.0.0.1"], "urls": [f"http://127.0.0.1:{port}"]},
            })
            engine = ApiIntelligenceEngine(
                scope_engine=scope_engine,
                policy=ApiPolicy(max_redirects=3),
            )
            engine.allow_fixture_port(port)

            content = engine.acquire_spec_content(f"http://127.0.0.1:{port}/hop1")
            assert content is not None
            assert "3.0.0" in content
            assert engine.request_count == 3

            # 2. Exceeded redirect limit: max_redirects=1 fails on hop 2
            engine_limited = ApiIntelligenceEngine(
                scope_engine=scope_engine,
                policy=ApiPolicy(max_redirects=1),
            )
            engine_limited.allow_fixture_port(port)

            content_limited = engine_limited.acquire_spec_content(f"http://127.0.0.1:{port}/hop1")
            assert content_limited is None
        finally:
            server.shutdown()
            server.server_close()

    def test_transport_https_to_http_downgrade_rejected(self):
        """Verifies redirect handler strictly prohibits HTTPS to HTTP protocol downgrade."""
        mock_engine = ApiIntelligenceEngine()
        redirect_handler = ApiSafeRedirectHandler(
            engine=mock_engine,
            ip_map={},
            max_redirects=3,
            original_url="https://api.example.com/spec",
        )
        with pytest.raises(ScopeViolationError, match="downgrade"):
            redirect_handler.redirect_request(
                req=None,
                fp=None,
                code=302,
                msg="Found",
                headers={},
                newurl="http://api.example.com/spec_insecure",
            )

    def test_allow_fixture_port_does_not_authorize_external_hosts(self):
        """Verifies allow_fixture_port cannot authorize external hosts or bypass anti-SSRF protections."""
        scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["127.0.0.1"]}})
        engine = ApiIntelligenceEngine(scope_engine=scope_engine)
        engine.allow_fixture_port(8080)

        # External host matching the fixture port must NOT be authorized
        assert engine._is_in_scope("https://evil.com:8080", is_active=True) is False
        assert engine._is_in_scope("http://api.target.com:8080", is_active=True) is False

    def test_allow_fixture_port_strictly_rejects_metadata(self):
        """Verifies allow_fixture_port cannot authorize cloud metadata endpoints."""
        scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["127.0.0.1"]}})
        engine = ApiIntelligenceEngine(scope_engine=scope_engine)
        engine.allow_fixture_port(8080)

        with pytest.raises(ScopeViolationError, match="prohibited metadata"):
            engine._resolve_and_verify_destination("http://169.254.169.254:8080/meta")

        with pytest.raises(ScopeViolationError, match="prohibited metadata"):
            engine._resolve_and_verify_destination("http://metadata.google.internal:8080/computeMetadata")

    def test_unregistered_loopback_port_fails_closed(self):
        """Verifies unregistered loopback port fails closed for active network operations."""
        engine = ApiIntelligenceEngine()  # No scope engine -> active network fails closed
        assert engine._is_in_scope("http://127.0.0.1:9999", is_active=True) is False

    def test_allow_fixture_port_validates_port_range(self):
        """Verifies allow_fixture_port enforces unprivileged integer port ranges (1024-65535)."""
        engine = ApiIntelligenceEngine()
        engine.allow_fixture_port(1024)
        engine.allow_fixture_port(8080)
        engine.allow_fixture_port(65535)

        with pytest.raises(ValueError, match="unprivileged"):
            engine.allow_fixture_port(80)

        with pytest.raises(ValueError, match="unprivileged"):
            engine.allow_fixture_port(70000)

        with pytest.raises(ValueError, match="unprivileged"):
            engine.allow_fixture_port("8080")  # type: ignore


class TestFindingARegressionByteBudgetAccounting:
    """
    Focused regression suite for Finding A: Global response-byte budget accounting.
    Validates that:
    - Actual response bytes consumed count against global budget even when parsing or validation fails.
    - Malformed, oversized, truncated, and rejected responses cannot repeatedly reuse the same budget.
    - Accepted-result accounting (total_bytes) remains distinct from transferred-byte accounting (total_bytes_transferred).
    - Exhausted budgets block subsequent requests without network dispatch.
    - Symmetrical enforcement across both GraphQL introspection and specification acquisition.
    """

    def test_repeated_malformed_graphql_responses_exhaust_global_budget(self):
        """Verifies repeated malformed GraphQL responses consume wire budget and exhaust max_bytes."""
        scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["api.example.com"]}})
        # Global budget: 100 bytes, per-spec limit: 60 bytes
        policy = ApiPolicy(allow_graphql_introspection=True, max_bytes=100, max_bytes_per_spec=60)
        with tempfile.TemporaryDirectory() as tmpdir:
            api_state = ApiStateManager(program_dir=tmpdir)
            engine = ApiIntelligenceEngine(scope_engine=scope_engine, api_state=api_state, policy=policy)

            # Response 1: 40 bytes of malformed JSON
            bad_json_1 = "NOT_JSON_BODY_12345678901234567890123456"
            assert len(bad_json_1.encode("utf-8")) == 40
            engine.graphql_hook = lambda u, q: bad_json_1

            res1 = engine.probe_graphql_introspection("https://api.example.com/graphql")
            assert res1 is None
            assert engine.total_bytes == 0  # Zero accepted bytes
            assert engine.total_bytes_transferred == 40  # Wire bytes charged

            # Response 2: 40 bytes of malformed JSON
            bad_json_2 = "ANOTHER_BAD_JSON_12345678901234567890123"
            assert len(bad_json_2.encode("utf-8")) == 40
            engine.graphql_hook = lambda u, q: bad_json_2

            res2 = engine.probe_graphql_introspection("https://api.example.com/graphql")
            assert res2 is None
            assert engine.total_bytes == 0
            assert engine.total_bytes_transferred == 80  # Cumulative wire bytes charged

            # Response 3: 35 bytes of valid JSON, but remaining budget is 100 - 80 = 20 bytes
            valid_payload = json.dumps({"data": {"__schema": {"types": []}}})
            valid_len = len(valid_payload.encode("utf-8"))
            assert valid_len > 20
            engine.graphql_hook = lambda u, q: valid_payload

            res3 = engine.probe_graphql_introspection("https://api.example.com/graphql")
            assert res3 is None  # Exceeds remaining budget
            assert engine.total_bytes == 0
            assert engine.total_bytes_transferred == 80 + valid_len

            # Subsequent requests must abort immediately because total_bytes_transferred >= max_bytes
            hook_invoked = False
            def spy_hook(u, q):
                nonlocal hook_invoked
                hook_invoked = True
                return "{}"
            engine.graphql_hook = spy_hook

            res4 = engine.probe_graphql_introspection("https://api.example.com/graphql")
            assert res4 is None
            assert not hook_invoked  # Aborted without network/hook dispatch

    def test_repeated_oversized_graphql_responses_exhaust_budget(self):
        """Verifies oversized GraphQL responses consume wire budget and exhaust global max_bytes."""
        scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["api.example.com"]}})
        # Global budget: 150 bytes, per-spec limit: 100 bytes
        policy = ApiPolicy(allow_graphql_introspection=True, max_bytes=150, max_bytes_per_spec=100)
        with tempfile.TemporaryDirectory() as tmpdir:
            api_state = ApiStateManager(program_dir=tmpdir)
            engine = ApiIntelligenceEngine(scope_engine=scope_engine, api_state=api_state, policy=policy)

            # Response 1: 110 bytes (oversized relative to max_bytes_per_spec=100)
            oversized = json.dumps({"data": {"__schema": {"types": [{"name": "A" * 70}]}}})
            b_len1 = len(oversized.encode("utf-8"))
            assert b_len1 > 100
            engine.graphql_hook = lambda u, q: oversized

            res1 = engine.probe_graphql_introspection("https://api.example.com/graphql")
            assert res1 is None
            assert engine.total_bytes == 0
            assert engine.total_bytes_transferred == b_len1

            # Response 2: 50 bytes, but remaining budget is 150 - b_len1 < 50
            valid_payload = json.dumps({"data": {"__schema": {"types": [{"name": "B"}]}}})
            b_len2 = len(valid_payload.encode("utf-8"))
            engine.graphql_hook = lambda u, q: valid_payload

            res2 = engine.probe_graphql_introspection("https://api.example.com/graphql")
            assert res2 is None
            assert engine.total_bytes == 0

    def test_repeated_spec_acquisition_exhausts_global_budget(self):
        """Verifies repeated rejected spec responses consume wire budget and block subsequent requests."""
        scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["api.example.com"]}})
        # Global budget: 120 bytes, per-spec limit: 60 bytes
        policy = ApiPolicy(max_bytes=120, max_bytes_per_spec=60)
        engine = ApiIntelligenceEngine(scope_engine=scope_engine, policy=policy)

        # Spec 1: 70 bytes (> 60 bytes limit)
        oversized_spec = "openapi: 3.0.0\ninfo:\n  title: Oversized\n  version: 1.0.0\npaths:\n  /test: {}"
        b_len1 = len(oversized_spec.encode("utf-8"))
        assert b_len1 > 60
        engine.fetch_spec_hook = lambda u: oversized_spec

        res1 = engine.acquire_spec_content("https://api.example.com/openapi.yaml")
        assert res1 is None
        assert engine.total_bytes == 0
        assert engine.total_bytes_transferred == b_len1

        # Spec 2: 50 bytes, but remaining budget is 120 - b_len1 (~45 bytes)
        spec_2 = "openapi: 3.0.0\ninfo:\n  title: B\n  version: 1.0\npaths: {}"
        b_len2 = len(spec_2.encode("utf-8"))
        engine.fetch_spec_hook = lambda u: spec_2

        res2 = engine.acquire_spec_content("https://api.example.com/openapi.yaml")
        assert res2 is None
        assert engine.total_bytes == 0
        assert engine.total_bytes_transferred == b_len1 + b_len2

        # Spec 3: Budget fully exhausted -> zero dispatch
        hook_called = False
        def spy_fetch(u):
            nonlocal hook_called
            hook_called = True
            return "openapi: 3.0.0"
        engine.fetch_spec_hook = spy_fetch

        res3 = engine.acquire_spec_content("https://api.example.com/openapi.yaml")
        assert res3 is None
        assert not hook_called

    def test_live_http_malformed_graphql_charges_transferred_bytes_and_exhausts_budget(self):
        """Verifies live HTTP server returning malformed JSON charges transferred bytes and exhausts budget."""
        import http.server
        import threading

        bad_bytes = b"BROKEN_NON_JSON_RESPONSE_PAYLOAD_FOR_TESTING_1234567890"
        bad_len = len(bad_bytes)

        class MalformedHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                clen = int(self.headers.get("Content-Length", 0))
                if clen > 0:
                    self.rfile.read(clen)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(bad_len))
                self.end_headers()
                self.wfile.write(bad_bytes)
            def log_message(self, *args): pass

        server = http.server.HTTPServer(("127.0.0.1", 0), MalformedHandler)
        port = server.server_port
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        time.sleep(0.05)

        try:
            scope_engine = ScopeEngine({
                "program": {"name": "test"},
                "targets": {"domains": ["127.0.0.1"], "urls": [f"http://127.0.0.1:{port}"]},
            })
            policy = ApiPolicy(
                allow_graphql_introspection=True,
                max_bytes_per_spec=100,
                max_bytes=bad_len,  # Budget exactly matches 1 request
            )
            engine = ApiIntelligenceEngine(scope_engine=scope_engine, policy=policy)
            engine.allow_fixture_port(port)

            res1 = engine.probe_graphql_introspection(f"http://127.0.0.1:{port}/graphql")
            assert res1 is None
            assert engine.total_bytes == 0
            assert engine.total_bytes_transferred == bad_len

            # Budget is now exhausted; second request must abort immediately without dispatching
            assert engine.total_bytes_transferred >= policy.max_bytes
            res2 = engine.probe_graphql_introspection(f"http://127.0.0.1:{port}/graphql")
            assert res2 is None
            assert engine.total_bytes == 0
            assert engine.total_bytes_transferred == bad_len
        finally:
            server.shutdown()
            server.server_close()

    def test_redirect_handler_strictly_aborts_when_byte_budget_exhausted(self):
        """Verifies redirect handler aborts redirect hops when byte budget is exhausted."""
        scope_engine = ScopeEngine({"program": {"name": "test"}, "targets": {"domains": ["example.com"]}})
        engine = ApiIntelligenceEngine(scope_engine=scope_engine, policy=ApiPolicy(max_bytes=500))
        engine.total_bytes_transferred = 500  # Budget exhausted

        handler = ApiSafeRedirectHandler(engine=engine, ip_map={"example.com": ["93.184.216.34"]})
        with pytest.raises(ScopeViolationError, match="byte budget exhausted"):
            handler.redirect_request(
                req=urllib.request.Request("http://example.com/orig"),
                fp=None,
                code=302,
                msg="Found",
                headers={},
                newurl="http://example.com/redirected",
            )


class TestFindingBFixturePortSecurity:
    """
    Focused regression suite for Finding B: allow_fixture_port() production call site and scope hardening.
    Validates that:
    - Fixture port allowance strictly respects explicit scope exclusions.
    - Fixture port cannot authorize non-loopback hosts, private RFC 1918 IPs, or cloud metadata.
    - Unregistered loopback ports fail closed.
    - CLI tool (bb-validate) rejects --fixture-port against targets whose scope lacks loopback.
    - CLI tool (bb-validate) accepts --fixture-port for legitimate local fixture scope.
    """

    def test_fixture_port_strictly_respects_explicit_scope_exclusions(self):
        """Verifies explicit scope exclusion rules override allow_fixture_port."""
        scope_config = {
            "program": {"name": "fixture-exclusion-test"},
            "targets": {
                "domains": ["127.0.0.1"],
                "urls": ["http://127.0.0.1:8080"],
            },
            "out_of_scope": {
                "urls": ["http://127.0.0.1:8080/admin", "http://127.0.0.1:8080/internal"],
            },
        }
        scope_engine = ScopeEngine(scope_config)
        engine = ApiIntelligenceEngine(scope_engine=scope_engine)
        engine.allow_fixture_port(8080)

        # Permitted fixture endpoint
        assert engine._is_in_scope("http://127.0.0.1:8080/api/v1/users", is_active=True) is True

        # Explicitly excluded fixture endpoints must be rejected
        assert engine._is_in_scope("http://127.0.0.1:8080/admin", is_active=True) is False
        assert engine._is_in_scope("http://127.0.0.1:8080/internal/secret", is_active=True) is False

        # Destination resolution must also fail closed for excluded fixture URLs
        with pytest.raises(ScopeViolationError, match="OUT_OF_SCOPE"):
            engine._resolve_and_verify_destination("http://127.0.0.1:8080/admin")

    def test_in_scope_loopback_with_unregistered_port_fails_closed(self):
        """
        Adversarial test: Proves an in-scope loopback host/CIDR with an unregistered port
        fails closed for all active operations before scope inclusion can take effect.
        """
        scope_engine = ScopeEngine({
            "program": {"name": "unregistered-port-test"},
            "targets": {
                "domains": ["127.0.0.1", "localhost"],
                "cidrs": ["127.0.0.0/8"],
                "urls": ["http://127.0.0.1:9999/api/v1"],
            },
        })
        engine = ApiIntelligenceEngine(scope_engine=scope_engine)
        # Port 9999 is NOT registered in allowed_fixture_ports
        assert 9999 not in engine.allowed_fixture_ports

        # Active network checks must return False
        assert engine._is_in_scope("http://127.0.0.1:9999/api/v1", is_active=True) is False
        assert engine._is_in_scope("http://localhost:9999/api/v1", is_active=True) is False

        # Destination resolution must fail closed
        with pytest.raises(ScopeViolationError, match="not an authorized local fixture port"):
            engine._resolve_and_verify_destination("http://127.0.0.1:9999/api/v1")
        with pytest.raises(ScopeViolationError, match="not an authorized local fixture port"):
            engine._resolve_and_verify_destination("http://localhost:9999/api/v1")

        # Active operations must fail closed without attempting network dispatch
        assert engine.acquire_spec_content("http://127.0.0.1:9999/api/v1") is None
        assert engine.probe_graphql_introspection("http://127.0.0.1:9999/graphql") is None

        # Passive checks remain True for safe offline inspection of existing data
        assert engine._is_in_scope("http://127.0.0.1:9999/api/v1", is_active=False) is True

    def test_in_scope_loopback_with_registered_fixture_port_allowed(self):
        """
        Verifies that an in-scope loopback host with a registered fixture port is permitted.
        """
        scope_engine = ScopeEngine({
            "program": {"name": "registered-port-test"},
            "targets": {
                "domains": ["127.0.0.1"],
                "urls": ["http://127.0.0.1:8080"],
            },
        })
        engine = ApiIntelligenceEngine(scope_engine=scope_engine)
        engine.allow_fixture_port(8080)

        assert engine._is_in_scope("http://127.0.0.1:8080/api/v1", is_active=True) is True
        assert engine._resolve_and_verify_destination("http://127.0.0.1:8080/api/v1") == ["127.0.0.1"]

    def test_in_scope_loopback_with_excluded_host_or_cidr_fails_closed(self):
        """
        Adversarial test: Proves that explicit host/domain/CIDR exclusions take strict
        precedence over registered fixture ports.
        """
        # Excluded domain/host
        scope_engine_host = ScopeEngine({
            "program": {"name": "excluded-host-test"},
            "targets": {"domains": ["localhost"], "cidrs": ["127.0.0.1/32"]},
            "out_of_scope": {"domains": ["localhost"]},
        })
        engine = ApiIntelligenceEngine(scope_engine=scope_engine_host)
        engine.allow_fixture_port(8080)

        assert engine._is_in_scope("http://127.0.0.1:8080/api", is_active=True) is True
        assert engine._is_in_scope("http://localhost:8080/api", is_active=True) is False
        with pytest.raises(ScopeViolationError, match="OUT_OF_SCOPE"):
            engine._resolve_and_verify_destination("http://localhost:8080/api")

        # Excluded CIDR
        scope_engine_cidr = ScopeEngine({
            "program": {"name": "excluded-cidr-test"},
            "targets": {"cidrs": ["127.0.0.0/8"]},
            "out_of_scope": {"cidrs": ["127.0.0.1/32"]},
        })
        engine_cidr = ApiIntelligenceEngine(scope_engine=scope_engine_cidr)
        engine_cidr.allow_fixture_port(8080)

        assert engine_cidr._is_in_scope("http://127.0.0.1:8080/api", is_active=True) is False
        with pytest.raises(ScopeViolationError, match="OUT_OF_SCOPE"):
            engine_cidr._resolve_and_verify_destination("http://127.0.0.1:8080/api")

    def test_redirect_to_unauthorized_loopback_port_aborted_and_never_reaches_server(self):
        """
        Adversarial test: Proves an HTTP redirect to an unauthorized loopback port
        is aborted by ApiSafeRedirectHandler, raising ScopeViolationError, and that
        the prohibited request NEVER reaches the unauthorized loopback server.
        """
        import http.server
        import threading

        unauthorized_hits = []
        authorized_hits = []

        class UnauthorizedServerHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                unauthorized_hits.append(self.path)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"secret": "leaked"}')

            def log_message(self, *args):
                pass

        class AuthorizedServerHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                authorized_hits.append(self.path)
                unauth_port = self.server.unauth_port
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{unauth_port}/forbidden-target")
                self.end_headers()

            def log_message(self, *args):
                pass

        server_unauth = http.server.HTTPServer(("127.0.0.1", 0), UnauthorizedServerHandler)
        unauth_port = server_unauth.server_port
        t_unauth = threading.Thread(target=server_unauth.serve_forever, daemon=True)
        t_unauth.start()

        server_auth = http.server.HTTPServer(("127.0.0.1", 0), AuthorizedServerHandler)
        server_auth.unauth_port = unauth_port
        auth_port = server_auth.server_port
        t_auth = threading.Thread(target=server_auth.serve_forever, daemon=True)
        t_auth.start()

        try:
            scope_engine = ScopeEngine({
                "program": {"name": "loopback-redirect-test"},
                "targets": {
                    "domains": ["127.0.0.1"],
                    "urls": [f"http://127.0.0.1:{auth_port}", f"http://127.0.0.1:{unauth_port}"],
                },
            })
            engine = ApiIntelligenceEngine(scope_engine=scope_engine)
            # ONLY auth_port is registered in allowed_fixture_ports
            engine.allow_fixture_port(auth_port)

            # Direct handler check
            redirect_handler = ApiSafeRedirectHandler(
                engine=engine,
                ip_map={"127.0.0.1": ["127.0.0.1"]},
                original_url=f"http://127.0.0.1:{auth_port}/start",
            )
            dummy_req = urllib.request.Request(f"http://127.0.0.1:{auth_port}/start")
            with pytest.raises(ScopeViolationError, match="out of scope"):
                redirect_handler.redirect_request(
                    dummy_req, None, 302, "Found", {}, f"http://127.0.0.1:{unauth_port}/forbidden-target"
                )

            # Live network dispatch: acquire_spec_content follows redirect using opener with redirect_handler
            result = engine.acquire_spec_content(f"http://127.0.0.1:{auth_port}/start")
            assert result is None
            assert len(authorized_hits) == 1
            # CRITICAL ASSERTION: The unauthorized loopback port must have received ZERO requests!
            assert len(unauthorized_hits) == 0, f"Prohibited request reached unauthorized loopback server: {unauthorized_hits}"
        finally:
            server_auth.shutdown()
            server_auth.server_close()
            server_unauth.shutdown()
            server_unauth.server_close()

    def test_bb_validate_cli_rejects_fixture_port_when_scope_lacks_loopback(self):
        """Verifies bb-validate CLI rejects --fixture-port when target scope has no loopback authorization."""
        script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts", "bb-validate"))
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a mock program scope with only production external target
            prog_dir = os.path.join(tmpdir, "prod-program")
            os.makedirs(prog_dir, exist_ok=True)
            scope_file = os.path.join(prog_dir, "scope.yaml")
            with open(scope_file, "w", encoding="utf-8") as f:
                f.write("""program:
  name: prod-program
targets:
  domains:
    - api.target.com
""")

            env = dict(os.environ)
            env["BB_PROGRAM_DIR"] = tmpdir
            cmd = [
                sys.executable,
                script_path,
                "--program", "prod-program",
                "--scope", scope_file,
                "--fixture-port", "8080",
                "--dry-run",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
            assert proc.returncode == 1
            assert "rejected: target scope does not authorize 127.0.0.1 or localhost" in proc.stderr

    def test_bb_validate_cli_accepts_fixture_port_when_scope_authorizes_loopback(self):
        """Verifies bb-validate CLI accepts --fixture-port when scope explicitly authorizes loopback."""
        script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts", "bb-validate"))
        with tempfile.TemporaryDirectory() as tmpdir:
            prog_dir = os.path.join(tmpdir, "local-fixture-program")
            os.makedirs(prog_dir, exist_ok=True)
            scope_file = os.path.join(prog_dir, "scope.yaml")
            with open(scope_file, "w", encoding="utf-8") as f:
                f.write("""program:
  name: local-fixture-program
targets:
  domains:
    - 127.0.0.1
  urls:
    - http://127.0.0.1:8080
""")

            env = dict(os.environ)
            env["BB_PROGRAM_DIR"] = tmpdir
            cmd = [
                sys.executable,
                script_path,
                "--program", "local-fixture-program",
                "--scope", scope_file,
                "--fixture-port", "8080",
                "--dry-run",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
            assert proc.returncode == 0
