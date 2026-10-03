"""
Tests for Scope Engine and Authorization Verification.
"""

import pytest

from framework.scope.engine import ScopeEngine, ScopeStatus


@pytest.fixture
def base_scope_config():
    return {
        "program": {"name": "test-program"},
        "targets": {
            "domains": [
                "example.com",
                "*.example.org",
            ],
            "urls": [
                "https://service.example.net/api/v1",
            ],
            "cidrs": [
                "192.168.100.0/24",
            ],
            "recursive_subdomains": {
                "enabled": True,
                "max_depth": 0,  # unlimited
            },
        },
        "out_of_scope": {
            "domains": [
                "admin.example.com",
                "internal.example.org",
            ],
            "urls": [
                "https://example.com/logout",
            ],
            "cidrs": [
                "192.168.100.128/28",
            ],
        },
    }


def test_scope_exact_domain(base_scope_config):
    engine = ScopeEngine(base_scope_config)
    res = engine.check("example.com")
    assert res.status == ScopeStatus.IN_SCOPE
    assert res.depth == 0
    assert res.root_domain == "example.com"


def test_scope_recursive_subdomains(base_scope_config):
    engine = ScopeEngine(base_scope_config)
    
    # 1 label depth
    res1 = engine.check("api.example.com")
    assert res1.status == ScopeStatus.IN_SCOPE
    assert res1.depth == 1
    assert res1.parent == "example.com"

    # 2 label depth
    res2 = engine.check("dev.api.example.com")
    assert res2.status == ScopeStatus.IN_SCOPE
    assert res2.depth == 2
    assert res2.parent == "api.example.com"

    # 3 label depth
    res3 = engine.check("a.b.c.example.com")
    assert res3.status == ScopeStatus.IN_SCOPE
    assert res3.depth == 3


def test_scope_dns_boundary_attacks(base_scope_config):
    engine = ScopeEngine(base_scope_config)

    # Malicious domain suffixes that end in example.com syntactically
    res1 = engine.check("example.com.attacker.com")
    assert res1.status == ScopeStatus.OUT_OF_SCOPE

    res2 = engine.check("attackerexample.com")
    assert res2.status == ScopeStatus.OUT_OF_SCOPE

    res3 = engine.check("evil-example.com")
    assert res3.status == ScopeStatus.OUT_OF_SCOPE


def test_scope_exclusions_precedence(base_scope_config):
    engine = ScopeEngine(base_scope_config)

    # admin.example.com is explicitly excluded
    res_admin = engine.check("admin.example.com")
    assert res_admin.status == ScopeStatus.OUT_OF_SCOPE
    assert "EXPLICIT_EXCLUSION" in res_admin.rule_category

    # Descendants under excluded subdomain are also excluded
    res_sub_admin = engine.check("auth.admin.example.com")
    assert res_sub_admin.status == ScopeStatus.OUT_OF_SCOPE

    # Non-excluded siblings remain in scope
    res_other = engine.check("portal.example.com")
    assert res_other.status == ScopeStatus.IN_SCOPE


def test_scope_urls(base_scope_config):
    engine = ScopeEngine(base_scope_config)

    # Explicitly authorized URL
    res1 = engine.check("https://service.example.net/api/v1/users")
    assert res1.status == ScopeStatus.IN_SCOPE

    # Explicitly excluded URL
    res2 = engine.check("https://example.com/logout")
    assert res2.status == ScopeStatus.OUT_OF_SCOPE

    # Regular in-scope URL under authorized domain
    res3 = engine.check("https://api.example.com/v2/items")
    assert res3.status == ScopeStatus.IN_SCOPE

    # Excluded host URL
    res4 = engine.check("https://admin.example.com/dashboard")
    assert res4.status == ScopeStatus.OUT_OF_SCOPE


def test_scope_cidr_and_ips(base_scope_config):
    engine = ScopeEngine(base_scope_config)

    # In authorized CIDR
    res_in = engine.check("192.168.100.50")
    assert res_in.status == ScopeStatus.IN_SCOPE

    # In excluded sub-CIDR (192.168.100.128/28 -> .128 to .143)
    res_ex = engine.check("192.168.100.130")
    assert res_ex.status == ScopeStatus.OUT_OF_SCOPE

    # Outside CIDR
    res_out = engine.check("10.0.0.1")
    assert res_out.status == ScopeStatus.OUT_OF_SCOPE


def test_scope_ambiguous_and_malformed(base_scope_config):
    engine = ScopeEngine(base_scope_config)

    res1 = engine.check("")
    assert res1.status == ScopeStatus.AMBIGUOUS

    res2 = engine.check("invalid..domain..")
    assert res2.status == ScopeStatus.AMBIGUOUS
