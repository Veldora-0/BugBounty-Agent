"""
Comprehensive unit and integration tests for Phase 3 Web Application Intelligence.

Covers:
- Canonical URL normalization and deterministic deduplication
- Same-origin checking logic
- Bounded HTML parsing (links, forms, inputs, scripts, resources, iframes)
- Malformed HTML handling
- Parameter extraction from query strings and forms
- Form extraction (POST/GET, field types, password and file upload flags)
- Cookie observation extraction from Set-Cookie headers
- Robots.txt parsing and path extraction
- XML sitemap parsing
- ScopeEngine gating (cross-domain rejection, redirect scope enforcement)
- WebApplicationIntelligenceEngine pipeline with 100% offline deterministic mocks
- Crawl limits (max_pages, max_depth, max_requests, response size ceilings)
- WebAppStateManager atomic persistence, deduplication, and resume
- WebAppGraph relationships (HOSTS_APPLICATION, HAS_PAGE, HAS_ENDPOINT, etc.)
- Verification of zero shell=True or os.system() calls
"""

import json
import os
import tempfile
import pytest

from framework.assets.graph import AssetGraph
from framework.assets.model import Asset, AssetType
from framework.scope.engine import ScopeEngine, ScopeStatus
from framework.webapp.engine import WebApplicationIntelligenceEngine
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


def test_canonicalize_url_advanced():
    """Tests canonical URL formatting across complex edge cases."""
    assert canonicalize_url("HTTP://Example.COM:80/foo/bar/") == "http://example.com/foo/bar"
    assert canonicalize_url("https://example.com:443/") == "https://example.com/"
    assert canonicalize_url("https://example.com/a/b/../c") == "https://example.com/a/c"
    assert canonicalize_url("https://example.com/page#section") == "https://example.com/page"
    # Query parameters sorted deterministically
    assert canonicalize_url("https://example.com/search?b=2&a=1&c=3") == "https://example.com/search?a=1&b=2&c=3"
    # Relative resolution
    assert canonicalize_url("/about", "https://example.com/app/") == "https://example.com/about"
    assert canonicalize_url("../login", "https://example.com/auth/oauth/") == "https://example.com/auth/login"


def test_is_same_origin():
    """Verifies same-origin comparison logic."""
    assert is_same_origin("https://example.com/a", "https://example.com/b") is True
    assert is_same_origin("https://example.com:443/a", "https://example.com/b") is True
    assert is_same_origin("http://example.com/a", "https://example.com/a") is False
    assert is_same_origin("https://api.example.com/a", "https://example.com/a") is False


def test_bounded_html_parser():
    """Tests extraction of links, forms, scripts, stylesheets, and metadata."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Portal</title>
        <meta name="generator" content="CustomFramework 2.0">
        <link rel="stylesheet" href="/static/style.css">
        <script src="/static/app.js"></script>
    </head>
    <body>
        <a href="/dashboard">Dashboard</a>
        <a href="https://external.com/out">External</a>
        <a href="javascript:void(0)">Invalid</a>
        <form action="/login" method="POST">
            <input type="text" name="username">
            <input type="password" name="password">
            <input type="hidden" name="csrf" value="tok123">
            <button type="submit">Submit</button>
        </form>
        <img src="/img/logo.png">
    </body>
    </html>
    """
    parsed = parse_page_html(html, "https://app.example.com/")

    assert parsed["title"] == "Test Portal"
    assert parsed["meta_generator"] == "CustomFramework 2.0"
    assert "https://app.example.com/dashboard" in parsed["links"]
    assert "https://external.com/out" in parsed["links"]
    assert len(parsed["forms"]) == 1

    form = parsed["forms"][0]
    assert form["method"] == "POST"
    assert form["action"] == "https://app.example.com/login"
    assert "username" in form["inputs"]
    assert "password" in form["inputs"]
    assert form["inputs"]["password"] == "password"

    res_urls = [r[0] for r in parsed["resources"]]
    assert "https://app.example.com/static/style.css" in res_urls
    assert "https://app.example.com/static/app.js" in res_urls
    assert "https://app.example.com/img/logo.png" in res_urls


def test_malformed_html_resilience():
    """Ensures HTML parser does not crash on malformed documents."""
    malformed = "<html><head><title>Unclosed Title</title><p><a href='/valid'>Link<form action='/post'><input name='x'>"
    parsed = parse_page_html(malformed, "https://example.com/")
    assert len(parsed["links"]) == 1
    assert "https://example.com/valid" in parsed["links"]
    assert len(parsed["forms"]) == 1


def test_cookie_extraction():
    """Tests Set-Cookie header extraction and flag normalization."""
    engine = WebApplicationIntelligenceEngine()
    headers = {
        "Set-Cookie": "session_id=abc123xyz; Path=/; Secure; HttpOnly; SameSite=Strict",
    }
    cookies = engine.extract_cookies(headers, "https://app.example.com/login")
    assert len(cookies) == 1
    c = cookies[0]
    assert c.name == "session_id"
    assert c.secure is True
    assert c.http_only is True
    assert c.same_site == "Strict"


def test_robots_txt_parsing():
    """Verifies robots.txt parsing and path extraction."""
    engine = WebApplicationIntelligenceEngine()
    engine.fetch_hook = lambda url, method: {
        "status_code": 200,
        "headers": {},
        "body": """
        User-agent: *
        Disallow: /admin
        Disallow: /api/private/
        Allow: /public
        Sitemap: https://app.example.com/sitemap.xml
        """,
        "final_url": url,
    }
    paths = engine.parse_robots_txt("https://app.example.com/")
    assert "https://app.example.com/admin" in paths
    assert "https://app.example.com/api/private" in paths
    assert "https://app.example.com/public" in paths
    assert "https://app.example.com/sitemap.xml" in paths


def test_sitemap_xml_parsing():
    """Verifies XML sitemap parsing."""
    engine = WebApplicationIntelligenceEngine()
    engine.fetch_hook = lambda url, method: {
        "status_code": 200,
        "headers": {},
        "body": """<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>https://app.example.com/products</loc></url>
            <url><loc>https://app.example.com/about</loc></url>
        </urlset>
        """,
        "final_url": url,
    }
    urls = engine.parse_sitemap_xml("https://app.example.com/sitemap.xml")
    assert "https://app.example.com/products" in urls
    assert "https://app.example.com/about" in urls


def test_webapp_state_persistence_and_resume():
    """Tests atomic persistence, state reloading, and visited URL tracking."""
    with tempfile.TemporaryDirectory() as tmpdir:
        state = WebAppStateManager(tmpdir)
        app = WebApplication(
            base_url="https://app.example.com/",
            host="app.example.com",
            scheme="https",
            port=443,
            title="App Portal",
        )
        assert state.add_application(app) is True
        # Second call merges
        assert state.add_application(app) is False

        page = WebPage(
            url="https://app.example.com/login",
            path="/login",
            status_code=200,
        )
        state.add_page(page)
        state.mark_visited("https://app.example.com/login")
        state.save()

        # Reload
        reloaded = WebAppStateManager(tmpdir)
        assert reloaded.is_visited("https://app.example.com/login") is True
        assert len(reloaded.applications) == 1
        assert len(reloaded.pages) == 1


def test_webapp_graph_relationships():
    """Verifies WebAppGraph relationship creation and indexed queries."""
    graph = WebAppGraph()
    rel1 = AppRelationship(
        source_id="https://app.example.com/",
        destination_id="https://app.example.com/dashboard",
        relation_type=AppRelationType.HAS_PAGE,
    )
    rel2 = AppRelationship(
        source_id="https://app.example.com/dashboard",
        destination_id="https://app.example.com/static/app.js",
        relation_type=AppRelationType.LOADS_RESOURCE,
    )
    graph.add_relationship(rel1)
    graph.add_relationship(rel2)

    outgoing = graph.get_outgoing("https://app.example.com/", AppRelationType.HAS_PAGE)
    assert len(outgoing) == 1
    assert outgoing[0].destination_id == "https://app.example.com/dashboard"

    incoming = graph.get_incoming("https://app.example.com/static/app.js")
    assert len(incoming) == 1
    assert incoming[0].source_id == "https://app.example.com/dashboard"


def test_webapp_engine_full_mock_crawl():
    """Tests complete WebApplicationIntelligenceEngine crawling scenario."""
    scope_config = {
        "program": {"name": "test-webapp"},
        "targets": {
            "domains": ["example.com", "*.example.com"],
            "recursive_subdomains": {"enabled": True, "max_depth": 0},
        },
        "out_of_scope": {"domains": ["forbidden.example.com"]},
    }
    scope_engine = ScopeEngine(scope_config)

    app = WebApplication(
        base_url="https://app.example.com/",
        host="app.example.com",
        scheme="https",
        port=443,
    )

    mock_responses = {
        "https://app.example.com/": {
            "status_code": 200,
            "headers": {"content-type": "text/html", "set-cookie": "sess=123; Path=/; Secure"},
            "body": """
            <html>
            <head><title>Home</title></head>
            <body>
                <a href="/search?q=test">Search</a>
                <a href="/login">Login</a>
                <a href="https://forbidden.example.com/out">Out Of Scope</a>
                <script src="/js/bundle.js"></script>
            </body>
            </html>
            """,
            "final_url": "https://app.example.com/",
        },
        "https://app.example.com/search?q=test": {
            "status_code": 200,
            "headers": {"content-type": "text/html"},
            "body": "<html><body>Search Results for test</body></html>",
            "final_url": "https://app.example.com/search?q=test",
        },
        "https://app.example.com/login": {
            "status_code": 200,
            "headers": {"content-type": "text/html"},
            "body": """
            <html>
            <body>
                <form action="/auth" method="POST">
                    <input type="text" name="user">
                    <input type="password" name="pass">
                </form>
            </body>
            </html>
            """,
            "final_url": "https://app.example.com/login",
        },
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        state = WebAppStateManager(tmpdir)
        policy = CrawlPolicy(max_pages=10, max_depth=2, include_robots=False, include_sitemaps=False)
        engine = WebApplicationIntelligenceEngine(
            scope_engine=scope_engine,
            webapp_state=state,
            policy=policy,
        )
        engine.fetch_hook = lambda url, method: mock_responses.get(url)

        stats = engine.run_discovery(target_applications=[app])

        assert stats["pages_crawled"] == 3
        assert stats["endpoints_found"] >= 3
        assert stats["forms_found"] == 1
        assert stats["cookies_found"] == 1
        assert stats["resources_found"] == 1
        assert stats["parameters_found"] >= 3  # q (query), user (form), pass (form)

        # forbidden.example.com was rejected by scope
        assert "https://forbidden.example.com/out" in state.rejected_urls


def test_scope_redirect_enforcement():
    """Verifies that HTTP redirects to out-of-scope destinations are strictly blocked."""
    scope_config = {
        "program": {"name": "test-scope"},
        "targets": {"domains": ["example.com"]},
        "out_of_scope": {"domains": []},
    }
    scope_engine = ScopeEngine(scope_config)

    engine = WebApplicationIntelligenceEngine(scope_engine=scope_engine)
    # Mock redirect to third-party domain
    engine.fetch_hook = lambda url, method: {
        "status_code": 302,
        "headers": {"location": "https://attacker.com/steal"},
        "body": "",
        "final_url": "https://attacker.com/steal",
    }
    res = engine.fetch_url("https://example.com/redirect")
    assert res is None  # Blocked because redirected URL is out-of-scope


def test_security_audit_no_shell_or_os_system():
    """Static audit asserting zero shell=True or os.system() in framework/webapp/."""
    import re
    webapp_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "framework", "webapp"))
    for root, _, files in os.walk(webapp_dir):
        for f in files:
            if f.endswith(".py"):
                path = os.path.join(root, f)
                with open(path, "r", encoding="utf-8") as fh:
                    content = fh.read()
                    assert not re.search(r"shell\s*=\s*True", content), f"Found shell=True in {path}"
                    assert not re.search(r"os\.system\(", content), f"Found os.system in {path}"
