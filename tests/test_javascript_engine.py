"""
Test suite for Phase 4 JavaScript Intelligence Engine.

Validates:
- Data model serialization & deserialization.
- Sensitive credential masking (AWS keys, JWT, Slack webhooks, etc.).
- Static analyzer extraction: endpoints, routes, parameters, dependencies,
  source maps, minification heuristic, and interesting strings.
- JavaScriptStateManager atomic persistence and deduplication.
- JavaScriptIntelligenceEngine bounded ingestion, mock hooks, scope gating, and resume.
- Security constraints: zero arbitrary script execution, zero shell=True, zero os.system.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Dict, List, Optional
import pytest

from framework.assets.provenance import ObservationProvenance
from framework.javascript.analyzer import JavaScriptAnalyzer
from framework.javascript.engine import JavaScriptIntelligenceEngine, JavaScriptPolicy
from framework.javascript.model import (
    DependencyObservation,
    DiscoveredEndpoint,
    DiscoveredRoute,
    InterestingString,
    JavaScriptResource,
    ParameterReference,
    SourceMapObservation,
    StringSensitivity,
    mask_sensitive_value,
)
from framework.javascript.state import JavaScriptStateManager
from framework.scope.engine import ScopeEngine
from framework.webapp.model import ResourceObservation


class TestJavaScriptModel:
    """Tests for JavaScript intelligence data models and masking."""

    def test_mask_sensitive_value(self):
        # AWS Key (> 8 chars)
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
        masked = mask_sensitive_value(aws_key)
        assert masked == "AKIA...MPLE"
        assert aws_key not in masked

        # Value with length > 8
        long_val = "123456789"
        assert mask_sensitive_value(long_val) == "1234...6789"

        # Short value (<= 8 chars)
        short_val = "secret"
        assert mask_sensitive_value(short_val) == "****"

        # Very short or empty string
        assert mask_sensitive_value("abc") == "****"
        assert mask_sensitive_value("") == "****"

    def test_discovered_endpoint_serialization(self):
        ep = DiscoveredEndpoint(
            raw_endpoint="/api/v1/users",
            normalized_endpoint="/api/v1/users",
            method="GET",
            source_resource_url="https://example.com/app.js",
            extraction_method="fetch",
            provenance=[
                ObservationProvenance(source="js_analyzer", method="fetch", confidence="CONFIRMED")
            ],
        )
        data = ep.to_dict()
        assert data["raw_endpoint"] == "/api/v1/users"
        assert data["normalized_endpoint"] == "/api/v1/users"
        assert data["method"] == "GET"

        restored = DiscoveredEndpoint.from_dict(data)
        assert restored.raw_endpoint == ep.raw_endpoint
        assert restored.normalized_endpoint == ep.normalized_endpoint
        assert restored.method == "GET"
        assert len(restored.provenance) == 1

    def test_interesting_string_serialization(self):
        item = InterestingString(
            category="aws_key",
            matched_value="AKIAIOSFODNN7EXAMPLE",
            masked_value="AKIA...MPLE",
            sensitivity=StringSensitivity.HIGH_CONFIDENCE_SECRET.value,
            source_resource_url="https://example.com/app.js",
            evidence_snippet="const key = 'AKIA...MPLE';",
            confidence="CONFIRMED",
        )
        d = item.to_dict()
        assert d["category"] == "aws_key"
        assert d["masked_value"] == "AKIA...MPLE"
        # Secret matched_value should NOT leak in serialized output
        assert "matched_value" not in d

        restored = InterestingString.from_dict(d)
        assert restored.masked_value == "AKIA...MPLE"
        assert restored.matched_value == "AKIA...MPLE"

    def test_dependency_observation_serialization(self):
        dep = DependencyObservation(
            name="React",
            version="18.2.0",
            detection_method="banner_comment",
            source_resource_url="https://example.com/bundle.js",
        )
        data = dep.to_dict()
        assert data["name"] == "React"
        assert data["version"] == "18.2.0"
        restored = DependencyObservation.from_dict(data)
        assert restored.name == "React"
        assert restored.version == "18.2.0"


class TestJavaScriptAnalyzer:
    """Tests for static pattern analysis of JavaScript code."""

    def test_minification_detection(self):
        # Long single line -> minified
        minified_code = "var a=1;function b(){return a+2;}" * 100
        analyzer1 = JavaScriptAnalyzer("https://example.com/app.min.js", minified_code)
        assert analyzer1.is_minified() is True

        # Multiline code -> not minified
        beautified_code = "\n".join([f"const x{i} = {i};" for i in range(50)])
        analyzer2 = JavaScriptAnalyzer("https://example.com/app.js", beautified_code)
        assert analyzer2.is_minified() is False

    def test_source_map_extraction(self):
        code = "console.log('test');\n//# sourceMappingURL=bundle.js.map"
        analyzer = JavaScriptAnalyzer("https://example.com/static/bundle.js", code)
        sm = analyzer.extract_source_map()
        assert sm is not None
        assert sm.source_map_url == "https://example.com/static/bundle.js.map"

        # Absolute URL source map
        code2 = "console.log('test');\n//@ sourceMappingURL=https://cdn.example.com/maps/app.js.map"
        analyzer2 = JavaScriptAnalyzer("https://example.com/static/bundle.js", code2)
        sm2 = analyzer2.extract_source_map()
        assert sm2 is not None
        assert sm2.source_map_url == "https://cdn.example.com/maps/app.js.map"

    def test_endpoint_extraction_various_patterns(self):
        sample_code = """
        // Fetch call
        fetch('/api/v1/auth/login', { method: 'POST' });

        // Axios call
        axios.get('https://api.example.com/v2/products?category=electronics');

        // JQuery Ajax
        $.ajax({ url: '/graphql', type: 'POST' });

        // XHR
        var xhr = new XMLHttpRequest();
        xhr.open('PUT', '/api/users/profile');

        // WebSocket
        var ws = new WebSocket('wss://stream.example.com/feed');

        // Embedded REST string
        const target = "/admin/internal/metrics";
        """
        analyzer = JavaScriptAnalyzer("https://example.com/app.js", sample_code)
        endpoints = analyzer.extract_endpoints()
        raw_eps = [ep.raw_endpoint for ep in endpoints]

        assert "/api/v1/auth/login" in raw_eps
        assert "https://api.example.com/v2/products?category=electronics" in raw_eps
        assert "/graphql" in raw_eps
        assert "/api/users/profile" in raw_eps
        assert "wss://stream.example.com/feed" in raw_eps
        assert "/admin/internal/metrics" in raw_eps

    def test_route_extraction(self):
        sample_code = """
        import { Route, BrowserRouter as Router } from 'react-router-dom';

        function AppRoutes() {
            return (
                <Router>
                    <Route path="/dashboard/overview" component={Overview} />
                    <Route path="/billing/invoices" component={Invoices} />
                    <Route path="/superadmin/tenants" component={Admin} />
                </Router>
            );
        }

        const vueRoutes = [
            { path: '/settings/security', component: Security },
            { path: '/audit-logs', component: Logs }
        ];
        """
        analyzer = JavaScriptAnalyzer("https://example.com/app.js", sample_code)
        routes = analyzer.extract_routes()
        route_patterns = [r.route_pattern for r in routes]

        assert "/dashboard/overview" in route_patterns
        assert "/billing/invoices" in route_patterns
        assert "/superadmin/tenants" in route_patterns
        assert "/settings/security" in route_patterns
        assert "/audit-logs" in route_patterns

    def test_parameter_extraction(self):
        sample_code = """
        const params = new URLSearchParams(window.location.search);
        const redirectUrl = params.get('redirect_uri');
        const token = params.get('session_token');
        const role = req.query.filter_role;
        const uid = req.body.user_id;
        """
        analyzer = JavaScriptAnalyzer("https://example.com/app.js", sample_code)
        params = analyzer.extract_parameters()
        names = [p.name for p in params]

        assert "redirect_uri" in names
        assert "session_token" in names
        assert "filter_role" in names
        assert "user_id" in names

    def test_dependency_identification(self):
        sample_code = """
        /*! React v18.2.0 | MIT License */
        var React = { version: '18.2.0' };
        var ReactDOM = {};

        /*! Lodash v4.17.21 | MIT License */
        var _ = {};
        _.VERSION = '4.17.21';

        // Axios library
        axios.defaults = {};

        // Next.js runtime marker
        window.__NEXT_DATA__ = {};
        """
        analyzer = JavaScriptAnalyzer("https://example.com/bundle.js", sample_code)
        deps = analyzer.extract_dependencies()
        dep_names = {d.name: d.version for d in deps}

        assert "React" in dep_names
        assert dep_names["React"] == "18.2.0"
        assert "Lodash" in dep_names
        assert dep_names["Lodash"] == "4.17.21"
        assert "Axios" in dep_names
        assert "Next.js" in dep_names

    def test_interesting_strings_classification_and_masking(self):
        fake_aws = "AKIA" + "IOSFODNN7EXAMPLE"
        fake_slack = "https://" + "hooks." + "slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx"
        fake_gkey = "AIza" + "SyD1234567890abcdef1234567890abc"
        sample_code = f"""
        // AWS Key
        const awsKey = "{fake_aws}";

        // Slack Webhook
        const webhook = "{fake_slack}";

        // Google API key
        const gkey = "{fake_gkey}";

        // Internal host
        const internal = "database.backend.corp";

        // S3 bucket
        const bucket = "company-private-backups.s3.amazonaws.com";

        // Node process env
        const secret = process.env.DATABASE_PASSWORD;
        """
        analyzer = JavaScriptAnalyzer("https://example.com/config.js", sample_code)
        strings = analyzer.extract_interesting_strings()
        cat_map = {s.category: s for s in strings}

        # AWS Key check
        assert "aws_key" in cat_map
        aws_entry = cat_map["aws_key"]
        assert aws_entry.sensitivity == StringSensitivity.HIGH_CONFIDENCE_SECRET.value
        assert aws_entry.masked_value == "AKIA...MPLE"
        assert "AKIAIOSFODNN7EXAMPLE" not in aws_entry.evidence_snippet

        # Slack Webhook check
        assert "slack_webhook" in cat_map
        slack_entry = cat_map["slack_webhook"]
        assert slack_entry.sensitivity == StringSensitivity.HIGH_CONFIDENCE_SECRET.value
        assert "..." in slack_entry.masked_value

        # Google API Key check
        assert "google_api_key" in cat_map

        # Internal host check
        assert "internal_host" in cat_map
        assert cat_map["internal_host"].matched_value == "database.backend.corp"
        assert cat_map["internal_host"].sensitivity == StringSensitivity.INTERESTING.value

        # S3 bucket check
        assert "cloud_bucket" in cat_map
        assert "company-private-backups.s3.amazonaws.com" in cat_map["cloud_bucket"].matched_value

        # Process.env check
        assert "env_var" in cat_map
        assert cat_map["env_var"].matched_value == "process.env.DATABASE_PASSWORD"


class TestJavaScriptStateManager:
    """Tests for state management and atomic file storage."""

    def test_state_persistence_and_deduplication(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_mgr = JavaScriptStateManager(program_dir=tmpdir)

            # Record resources
            res = JavaScriptResource(
                url="https://example.com/static/app.js",
                host="example.com",
                path="/static/app.js",
                sha256_hash="abc123hash",
                content_length=1024,
                is_minified=False,
            )
            assert state_mgr.add_resource(res) is True
            # Record duplicate (should not add as new)
            assert state_mgr.add_resource(res) is False
            assert len(state_mgr.resources) == 1

            # Record endpoints
            ep1 = DiscoveredEndpoint(
                raw_endpoint="/api/v1/test",
                normalized_endpoint="/api/v1/test",
                method="GET",
                source_resource_url=res.url,
                extraction_method="fetch",
            )
            ep2 = DiscoveredEndpoint(
                raw_endpoint="/api/v1/test",
                normalized_endpoint="/api/v1/test",
                method="GET",
                source_resource_url=res.url,
                extraction_method="fetch",
            )
            assert state_mgr.add_endpoint(ep1) is True
            assert state_mgr.add_endpoint(ep2) is False
            assert len(state_mgr.endpoints) == 1

            # Record routes
            route = DiscoveredRoute(
                route_pattern="/dashboard/analytics",
                source_resource_url=res.url,
                framework_hint="react-router",
            )
            assert state_mgr.add_route(route) is True
            assert state_mgr.add_route(route) is False
            assert len(state_mgr.routes) == 1

            # Save state and reload
            state_mgr.save()
            assert os.path.exists(state_mgr.js_file)

            # Create fresh manager pointing to same program_dir
            loaded_mgr = JavaScriptStateManager(program_dir=tmpdir)
            assert len(loaded_mgr.resources) == 1
            assert len(loaded_mgr.endpoints) == 1
            assert len(loaded_mgr.routes) == 1


class TestJavaScriptIntelligenceEngine:
    """Tests for the engine orchestration, bounds, and mock hooks."""

    def test_engine_offline_mock_analysis(self):
        mock_scripts = {
            "https://app.example.com/static/main.js": """
                /*! React v18.2.0 */
                var React = { version: '18.2.0' };
                fetch('/api/v1/user/profile');
                const adminRoute = '/admin/portal/dashboard';
                const token = new URLSearchParams(location.search).get('auth_token');
                //# sourceMappingURL=main.js.map
            """,
            "https://app.example.com/static/vendor.js": f"""
                /*! Axios v1.4.0 */
                axios.defaults = {{}};
                const apiHost = "https://internal-api.example.com/v1/health";
                const awsKey = "{"AKIA" + "IOSFODNN7EXAMPLE"}";
            """,
        }

        def mock_fetch(url: str) -> Optional[str]:
            return mock_scripts.get(url)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create scope config allowing app.example.com
            scope_dict = {
                "program": {"name": "test-prog"},
                "targets": {
                    "domains": ["example.com"],
                    "recursive_subdomains": {"enabled": True},
                },
                "out_of_scope": {
                    "domains": ["out-of-scope.example.com"],
                },
            }
            scope_engine = ScopeEngine(scope_dict)
            state_mgr = JavaScriptStateManager(program_dir=tmpdir)
            policy = JavaScriptPolicy(max_files=10, max_requests=10)

            engine = JavaScriptIntelligenceEngine(
                scope_engine=scope_engine,
                js_state=state_mgr,
                policy=policy,
            )
            engine.fetch_js_hook = mock_fetch

            targets = [
                ResourceObservation(url="https://app.example.com/static/main.js", resource_type="js", source_page="https://app.example.com/"),
                ResourceObservation(url="https://app.example.com/static/vendor.js", resource_type="js", source_page="https://app.example.com/"),
                ResourceObservation(url="https://out-of-scope.example.com/evil.js", resource_type="js", source_page="https://out-of-scope.example.com/"),
            ]

            stats = engine.run_analysis(target_resources=targets)

            assert stats["resources_acquired"] == 2
            assert engine.files_analyzed == 2

            # Verify state manager was enriched
            endpoints = list(state_mgr.endpoints.values())
            raw_eps = [ep.raw_endpoint for ep in endpoints]
            assert "/api/v1/user/profile" in raw_eps

            deps = list(state_mgr.dependencies.values())
            dep_names = [d.name for d in deps]
            assert "React" in dep_names
            assert "Axios" in dep_names

            source_maps = list(state_mgr.source_maps.values())
            assert len(source_maps) == 1
            assert source_maps[0].source_map_url == "https://app.example.com/static/main.js.map"

            # Check sensitive strings
            strings = list(state_mgr.interesting_strings.values())
            secrets = [s for s in strings if s.sensitivity == StringSensitivity.HIGH_CONFIDENCE_SECRET.value]
            assert len(secrets) == 1
            assert secrets[0].masked_value == "AKIA...MPLE"

    def test_engine_byte_budget_enforcement(self):
        large_script = "var x = 1;\n" * 1000

        def mock_fetch(url: str) -> Optional[str]:
            return large_script

        with tempfile.TemporaryDirectory() as tmpdir:
            state_mgr = JavaScriptStateManager(program_dir=tmpdir)
            policy = JavaScriptPolicy(
                max_files=5,
                max_bytes_per_file=500,  # Strict 500 byte limit
            )
            engine = JavaScriptIntelligenceEngine(
                js_state=state_mgr,
                policy=policy,
            )
            engine.fetch_js_hook = mock_fetch

            targets = [ResourceObservation(url="https://example.com/large.js", resource_type="js", source_page="https://example.com/")]
            stats = engine.run_analysis(target_resources=targets)

            # Should skip file due to size exceeding budget
            assert stats["resources_acquired"] == 0
            assert engine.files_analyzed == 0

    def test_engine_resume_functionality(self):
        mock_scripts = {
            "https://example.com/1.js": "fetch('/api/one');",
            "https://example.com/2.js": "fetch('/api/two');",
        }

        call_count = 0

        def mock_fetch(url: str) -> Optional[str]:
            nonlocal call_count
            call_count += 1
            return mock_scripts.get(url)

        with tempfile.TemporaryDirectory() as tmpdir:
            state_mgr = JavaScriptStateManager(program_dir=tmpdir)
            engine = JavaScriptIntelligenceEngine(
                js_state=state_mgr,
            )
            engine.fetch_js_hook = mock_fetch

            targets = [
                ResourceObservation(url="https://example.com/1.js", resource_type="js", source_page="https://example.com/"),
                ResourceObservation(url="https://example.com/2.js", resource_type="js", source_page="https://example.com/"),
            ]

            # First run: analyze only 1.js
            engine.run_analysis(target_resources=[targets[0]])
            assert call_count == 1
            assert len(state_mgr.resources) == 1

            # Second run: analyze 1.js and 2.js with resume=True
            engine.run_analysis(target_resources=targets, resume=True)
            # Only 2.js should have been fetched
            assert call_count == 2
            assert len(state_mgr.resources) == 2


class TestCodeSecurityAndInvariants:
    """Security tests to guarantee safe execution practices."""

    def test_zero_shell_or_exec_in_javascript_module(self):
        """Validates that no shell=True or os.system exists in framework/javascript."""
        js_module_dir = os.path.join(os.path.dirname(__file__), "..", "framework", "javascript")
        for root, _, files in os.walk(js_module_dir):
            for file in files:
                if file.endswith(".py"):
                    filepath = os.path.join(root, file)
                    with open(filepath, "r", encoding="utf-8") as f:
                        content = f.read()
                        assert "shell=True" not in content, f"Forbidden shell=True in {filepath}"
                        assert "os.system(" not in content, f"Forbidden os.system in {filepath}"
                        # Ensure no dynamic JS code evaluation
                        assert "eval(" not in content, f"Dangerous eval in {filepath}"
                        assert "exec(" not in content, f"Dangerous exec in {filepath}"
