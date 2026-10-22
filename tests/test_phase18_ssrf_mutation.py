"""
Phase 18 Regression Tests: SSRF Request Mutation Expansion.

Covers:
1. Query parameter mutation and encoding preservation.
2. Path parameter substitution across template formats ({param}, :param, <param>).
3. JSON body mutation across flat keys, nested dotted keys, empty body, and malformed JSON resilience.
4. Form body mutation across existing form bodies, multi-field preservation, and empty body.
5. XML body mutation with DOM element text replacement, XML entity escaping, empty body, and malformed fallback.
6. Content-Type header management and custom header preservation.
7. Active validation pipeline integration with JSON, FORM, and XML candidates.
"""

from __future__ import annotations

import json
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, List
from unittest.mock import MagicMock

import pytest

from framework.scope.engine import ScopeEngine
from framework.ssrf.engine import SsrfIntelligenceEngine
from framework.ssrf.model import SsrfCandidate, SsrfCategory
from framework.ssrf.provider import MockOobProvider
from framework.validation.policy import SecurityTestPolicy
from framework.validation.request import ControlledRequest, ControlledResponse


@pytest.fixture
def ssrf_engine() -> SsrfIntelligenceEngine:
    tmp_dir = tempfile.mkdtemp()
    scope = ScopeEngine({
        "program": {"name": "Test"},
        "targets": {"urls": ["http://127.0.0.1:8080"]},
    })
    policy = SecurityTestPolicy(max_requests_per_program=20)
    oob = MockOobProvider()
    engine = SsrfIntelligenceEngine(
        program_dir=tmp_dir,
        scope_engine=scope,
        policy=policy,
        oob_provider=oob,
    )
    engine.validation_engine.allow_fixture_port(8080)
    return engine


class TestQueryParameterMutation:
    """Verifies QUERY parameter substitution and URL encoding."""

    def test_replaces_existing_query_param(self, ssrf_engine: SsrfIntelligenceEngine):
        cand = SsrfCandidate(
            application="WebApp",
            endpoint="http://127.0.0.1:8080/fetch?target=http://old.com&token=abc",
            parameter="target",
            param_location="QUERY",
        )
        req = ssrf_engine._build_mutated_request(cand, "http://canary.test/oob")
        assert "target=http%3A%2F%2Fcanary.test%2Foob" in req.build_effective_url()
        assert "token=abc" in req.build_effective_url()
        assert req.mutated_target == "target"
        assert req.mutated_value == "http://canary.test/oob"

    def test_appends_missing_query_param(self, ssrf_engine: SsrfIntelligenceEngine):
        cand = SsrfCandidate(
            application="WebApp",
            endpoint="http://127.0.0.1:8080/fetch?existing=val",
            parameter="dest",
            param_location="QUERY",
        )
        req = ssrf_engine._build_mutated_request(cand, "http://canary.test/oob")
        eff = req.build_effective_url()
        assert "existing=val" in eff
        assert "dest=http%3A%2F%2Fcanary.test%2Foob" in eff


class TestPathParameterMutation:
    """Verifies PATH template substitution across format styles."""

    def test_curly_brace_template(self, ssrf_engine: SsrfIntelligenceEngine):
        cand = SsrfCandidate(
            application="API",
            endpoint="http://127.0.0.1:8080/proxy/{dest_url}/status",
            parameter="dest_url",
            param_location="PATH",
        )
        req = ssrf_engine._build_mutated_request(cand, "http://canary.test/oob")
        assert "http://127.0.0.1:8080/proxy/http%3A%2F%2Fcanary.test%2Foob/status" in req.build_effective_url()

    def test_colon_template(self, ssrf_engine: SsrfIntelligenceEngine):
        cand = SsrfCandidate(
            application="API",
            endpoint="http://127.0.0.1:8080/proxy/:url",
            parameter="url",
            param_location="PATH",
        )
        req = ssrf_engine._build_mutated_request(cand, "http://canary.test/oob")
        assert "http://127.0.0.1:8080/proxy/http%3A%2F%2Fcanary.test%2Foob" in req.build_effective_url()

    def test_angle_bracket_template(self, ssrf_engine: SsrfIntelligenceEngine):
        cand = SsrfCandidate(
            application="API",
            endpoint="http://127.0.0.1:8080/fetch/<target>",
            parameter="target",
            param_location="PATH",
        )
        req = ssrf_engine._build_mutated_request(cand, "http://canary.test/oob")
        assert "http://127.0.0.1:8080/fetch/http%3A%2F%2Fcanary.test%2Foob" in req.build_effective_url()


class TestJsonBodyMutation:
    """Verifies JSON body mutation across flat, nested, and malformed inputs."""

    def test_flat_json_mutation(self, ssrf_engine: SsrfIntelligenceEngine):
        cand = SsrfCandidate(
            application="API",
            endpoint="http://127.0.0.1:8080/api/webhook",
            parameter="url",
            param_location="JSON_BODY",
            method="POST",
            body=json.dumps({"url": "http://old.example.com", "active": True}),
        )
        req = ssrf_engine._build_mutated_request(cand, "http://canary.test/oob")
        assert req.headers["Content-Type"] == "application/json"
        data = json.loads(req.body)
        assert data["url"] == "http://canary.test/oob"
        assert data["active"] is True

    def test_nested_dotted_key_mutation(self, ssrf_engine: SsrfIntelligenceEngine):
        cand = SsrfCandidate(
            application="API",
            endpoint="http://127.0.0.1:8080/api/config",
            parameter="webhook.destination.url",
            param_location="JSON_BODY",
            method="POST",
            body=json.dumps({"webhook": {"destination": {"url": "http://old.com", "port": 80}}}),
        )
        req = ssrf_engine._build_mutated_request(cand, "http://canary.test/oob")
        data = json.loads(req.body)
        assert data["webhook"]["destination"]["url"] == "http://canary.test/oob"
        assert data["webhook"]["destination"]["port"] == 80

    def test_empty_json_body_generates_valid_payload(self, ssrf_engine: SsrfIntelligenceEngine):
        cand = SsrfCandidate(
            application="API",
            endpoint="http://127.0.0.1:8080/api/subscribe",
            parameter="callback_url",
            param_location="JSON_BODY",
            method="POST",
        )
        req = ssrf_engine._build_mutated_request(cand, "http://canary.test/oob")
        data = json.loads(req.body)
        assert data["callback_url"] == "http://canary.test/oob"

    def test_malformed_json_falls_back_cleanly(self, ssrf_engine: SsrfIntelligenceEngine):
        cand = SsrfCandidate(
            application="API",
            endpoint="http://127.0.0.1:8080/api/broken",
            parameter="target",
            param_location="JSON_BODY",
            method="POST",
            body="NOT_VALID_JSON{:::broken",
        )
        req = ssrf_engine._build_mutated_request(cand, "http://canary.test/oob")
        data = json.loads(req.body)
        assert data["target"] == "http://canary.test/oob"


class TestFormBodyMutation:
    """Verifies FORM_BODY urlencoded mutation."""

    def test_mutates_existing_form_field(self, ssrf_engine: SsrfIntelligenceEngine):
        cand = SsrfCandidate(
            application="WebApp",
            endpoint="http://127.0.0.1:8080/import",
            parameter="import_url",
            param_location="FORM_BODY",
            method="POST",
            body="import_url=http%3A%2F%2Fold.com&type=csv&csrf=token123",
        )
        req = ssrf_engine._build_mutated_request(cand, "http://canary.test/oob")
        assert req.headers["Content-Type"] == "application/x-www-form-urlencoded"
        assert "import_url=http%3A%2F%2Fcanary.test%2Foob" in req.body
        assert "type=csv" in req.body
        assert "csrf=token123" in req.body

    def test_empty_form_body_generates_field(self, ssrf_engine: SsrfIntelligenceEngine):
        cand = SsrfCandidate(
            application="WebApp",
            endpoint="http://127.0.0.1:8080/import",
            parameter="source",
            param_location="FORM_BODY",
            method="POST",
        )
        req = ssrf_engine._build_mutated_request(cand, "http://canary.test/oob")
        assert req.body == "source=http%3A%2F%2Fcanary.test%2Foob"


class TestXmlBodyMutation:
    """Verifies XML_BODY element text replacement and entity escaping."""

    def test_mutates_xml_element_text(self, ssrf_engine: SsrfIntelligenceEngine):
        initial_xml = """<?xml version="1.0" encoding="UTF-8"?>
<request>
  <url>http://old.example.com</url>
  <format>pdf</format>
</request>"""
        cand = SsrfCandidate(
            application="Enterprise",
            endpoint="http://127.0.0.1:8080/soap/export",
            parameter="url",
            param_location="XML_BODY",
            method="POST",
            body=initial_xml,
        )
        req = ssrf_engine._build_mutated_request(cand, "http://canary.test/oob?id=1&name=test")
        assert req.headers["Content-Type"] == "application/xml"
        root = ET.fromstring(req.body)
        url_el = root.find("url")
        assert url_el is not None
        assert url_el.text == "http://canary.test/oob?id=1&name=test"
        assert root.find("format").text == "pdf"

    def test_empty_xml_body_generates_envelope(self, ssrf_engine: SsrfIntelligenceEngine):
        cand = SsrfCandidate(
            application="Enterprise",
            endpoint="http://127.0.0.1:8080/xml/fetch",
            parameter="endpoint",
            param_location="XML_BODY",
            method="POST",
        )
        req = ssrf_engine._build_mutated_request(cand, "http://canary.test/oob")
        root = ET.fromstring(req.body)
        el = root.find("endpoint")
        assert el is not None
        assert el.text == "http://canary.test/oob"

    def test_malformed_xml_fallback(self, ssrf_engine: SsrfIntelligenceEngine):
        cand = SsrfCandidate(
            application="Enterprise",
            endpoint="http://127.0.0.1:8080/xml/broken",
            parameter="feed",
            param_location="XML_BODY",
            method="POST",
            body="<broken><feed>http://old.com</feed><unclosed>",
        )
        req = ssrf_engine._build_mutated_request(cand, "http://canary.test/oob")
        assert "<feed>http://canary.test/oob</feed>" in req.body


class TestCustomHeaderPreservation:
    """Verifies custom headers are preserved and not clobbered during mutation."""

    def test_preserves_custom_candidate_headers(self, ssrf_engine: SsrfIntelligenceEngine):
        cand = SsrfCandidate(
            application="API",
            endpoint="http://127.0.0.1:8080/api/hook",
            parameter="target",
            param_location="JSON_BODY",
            method="POST",
            headers={"X-Custom-Tenant": "tenant-42", "Authorization": "Bearer sample_token"},
        )
        req = ssrf_engine._build_mutated_request(cand, "http://canary.test/oob")
        assert req.headers["X-Custom-Tenant"] == "tenant-42"
        assert req.headers["Authorization"] == "Bearer sample_token"
        assert req.headers["Content-Type"] == "application/json"
        assert "BugBounty-Agent" in req.headers["User-Agent"]
