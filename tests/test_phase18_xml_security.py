"""
Regression and Security Test Suite for Phase 18: Agent-Side Safe XML Parsing.

Validates:
1. Standard valid XML parsing and namespace preservation.
2. DOCTYPE and ENTITY declaration rejection in strict mode (disallow_dtd=True).
3. Immediate interception and blocking of external entities (SYSTEM and PUBLIC references).
4. Entity expansion / Billion Laughs defense via bounded entity declaration counts.
5. Hard maximum input size bound enforcement.
6. Graceful fail-closed handling of malformed XML syntax.
7. WebAppIntelligenceEngine sitemap parsing safety (zero entity execution, fails closed).
"""

from __future__ import annotations

import os
import shutil
import tempfile
import pytest

from framework.common.xml_safe import (
    SafeXMLParseError,
    safe_extract_sitemap_urls,
    safe_parse_xml,
)
from framework.scope.engine import ScopeEngine
from framework.webapp.engine import WebApplicationIntelligenceEngine
from framework.webapp.policy import CrawlPolicy


@pytest.fixture
def temp_program_dir():
    d = tempfile.mkdtemp(prefix="bb_test_xml_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


# ==============================================================================
# 1. Core safe_parse_xml Unit Tests
# ==============================================================================

def test_safe_parse_xml_valid_document():
    """Verifies that well-formed XML parses correctly with attributes and children."""
    xml_data = """<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url id="u1">
            <loc>https://example.com/home</loc>
            <changefreq>daily</changefreq>
        </url>
        <url id="u2">
            <loc>https://example.com/about</loc>
        </url>
    </urlset>
    """
    root = safe_parse_xml(xml_data, disallow_dtd=True)
    assert root.tag.endswith("urlset")
    urls = [elem.text for elem in root.iter() if elem.tag.endswith("loc")]
    assert urls == ["https://example.com/home", "https://example.com/about"]


def test_safe_parse_xml_rejects_doctype_in_strict_mode():
    """Verifies that strict mode (disallow_dtd=True) immediately rejects DOCTYPE declarations."""
    xml_doctype = """<?xml version="1.0"?>
    <!DOCTYPE sitemap [
        <!ELEMENT sitemap ANY>
        <!ENTITY internal "injected_val">
    ]>
    <sitemap>&internal;</sitemap>
    """
    with pytest.raises(SafeXMLParseError, match="DOCTYPE and ENTITY declarations are forbidden"):
        safe_parse_xml(xml_doctype, disallow_dtd=True)


def test_safe_parse_xml_blocks_external_system_entity():
    """
    Verifies that even when DTDs are inspected (disallow_dtd=False),
    external SYSTEM entities (XXE) are immediately intercepted and blocked.
    """
    xml_xxe = """<?xml version="1.0"?>
    <!DOCTYPE root [
        <!ENTITY ext SYSTEM "http://127.0.0.1:9999/prohibited_callback">
    ]>
    <root>&ext;</root>
    """
    with pytest.raises(SafeXMLParseError, match="External entity 'ext' is forbidden"):
        safe_parse_xml(xml_xxe, disallow_dtd=False)


def test_safe_parse_xml_blocks_external_public_entity():
    """Verifies that external PUBLIC entities are immediately intercepted and blocked."""
    xml_public = """<?xml version="1.0"?>
    <!DOCTYPE root [
        <!ENTITY ext PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://evil.com/dtd">
    ]>
    <root>&ext;</root>
    """
    with pytest.raises(SafeXMLParseError, match="External entity 'ext' is forbidden"):
        safe_parse_xml(xml_public, disallow_dtd=False)


def test_safe_parse_xml_entity_expansion_count_limit():
    """
    Verifies protection against entity expansion bombs (Billion Laughs / quadratic blowup)
    by strictly bounding the number of allowed entity declarations.
    """
    declarations = "\n".join(f'<!ENTITY entity_{i} "val_{i}">' for i in range(60))
    xml_bomb = f"""<?xml version="1.0"?>
    <!DOCTYPE root [
        {declarations}
    ]>
    <root>content</root>
    """
    with pytest.raises(SafeXMLParseError, match="Exceeded maximum entity declaration limit"):
        safe_parse_xml(xml_bomb, disallow_dtd=False, max_entity_declarations=50)


def test_safe_parse_xml_oversized_input_rejection():
    """Verifies that input exceeding the configured max_bytes is rejected without parsing."""
    large_xml = "<root>" + ("a" * 1000) + "</root>"
    with pytest.raises(SafeXMLParseError, match="exceeds maximum allowed size bound"):
        safe_parse_xml(large_xml, max_bytes=500)


def test_safe_parse_xml_malformed_syntax_fails_closed():
    """Verifies that malformed or truncated XML raises SafeXMLParseError cleanly."""
    malformed_xml = "<root><unclosed_tag>data</root>"
    with pytest.raises(SafeXMLParseError, match="Malformed XML syntax"):
        safe_parse_xml(malformed_xml)

    with pytest.raises(SafeXMLParseError, match="Empty XML document"):
        safe_parse_xml("   ")


def test_safe_extract_sitemap_urls_helper():
    """Verifies helper extracts valid URLs and returns empty list on invalid or attacked inputs."""
    valid_sitemap = """
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url><loc>https://target.com/page1</loc></url>
        <url><loc>https://target.com/page2</loc></url>
    </urlset>
    """
    urls = safe_extract_sitemap_urls(valid_sitemap)
    assert urls == ["https://target.com/page1", "https://target.com/page2"]

    # Attacked with DOCTYPE -> returns empty list (fails closed)
    attacked = """<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com">]><urlset><url><loc>http://target.com</loc></url></urlset>"""
    assert safe_extract_sitemap_urls(attacked) == []


# ==============================================================================
# 2. WebAppIntelligenceEngine Sitemap Integration
# ==============================================================================

def test_webapp_sitemap_parsing_normal():
    """Verifies normal sitemap ingestion in WebApplicationIntelligenceEngine."""
    scope_engine = ScopeEngine({
        "program": {"name": "test"},
        "targets": {"domains": ["app.target.com"], "recursive_subdomains": {"enabled": False}},
    })
    engine = WebApplicationIntelligenceEngine(
        scope_engine=scope_engine,
        policy=CrawlPolicy(include_sitemaps=True, passive_only=False),
    )

    sample_sitemap = """<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url><loc>https://app.target.com/catalog</loc></url>
        <url><loc>https://app.target.com/products</loc></url>
        <url><loc>https://out-of-scope.com/external</loc></url>
    </urlset>
    """
    engine.fetch_hook = lambda url, method: {"status_code": 200, "body": sample_sitemap, "headers": {}}

    urls = engine.parse_sitemap_xml("https://app.target.com/sitemap.xml")
    assert "https://app.target.com/catalog" in urls
    assert "https://app.target.com/products" in urls
    # Out of scope URL filtered
    assert "https://out-of-scope.com/external" not in urls


def test_webapp_sitemap_parsing_rejects_xxe_payload():
    """Verifies WebApplicationIntelligenceEngine aborts sitemap parsing when DOCTYPE/XXE is detected."""
    scope_engine = ScopeEngine({
        "program": {"name": "test"},
        "targets": {"domains": ["app.target.com"]},
    })
    engine = WebApplicationIntelligenceEngine(
        scope_engine=scope_engine,
        policy=CrawlPolicy(include_sitemaps=True, passive_only=False),
    )

    xxe_sitemap = """<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE urlset [
        <!ENTITY xxe SYSTEM "http://127.0.0.1:9999/leak">
    ]>
    <urlset>
        <url><loc>https://app.target.com/evil</loc></url>
    </urlset>
    """
    engine.fetch_hook = lambda url, method: {"status_code": 200, "body": xxe_sitemap, "headers": {}}

    urls = engine.parse_sitemap_xml("https://app.target.com/sitemap.xml")
    # Must fail closed: returns zero URLs
    assert urls == []
