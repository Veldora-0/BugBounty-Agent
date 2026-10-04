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
import tempfile
from typing import Dict, List, Optional
import pytest

from framework.api.engine import ApiIntelligenceEngine, ApiPolicy
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
from framework.scope.engine import ScopeEngine
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
