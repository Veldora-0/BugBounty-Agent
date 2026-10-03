"""
Tests for Recursive Subdomain Support and Depth Tracking.
"""

import pytest

from framework.scope.engine import ScopeEngine, ScopeStatus
from framework.scope.normalizer import calculate_subdomain_depth


def test_depth_calculation():
    # depth 0
    d0, p0 = calculate_subdomain_depth("example.com", "example.com")
    assert d0 == 0
    assert p0 is None

    # depth 1
    d1, p1 = calculate_subdomain_depth("api.example.com", "example.com")
    assert d1 == 1
    assert p1 == "example.com"

    # depth 2
    d2, p2 = calculate_subdomain_depth("dev.api.example.com", "example.com")
    assert d2 == 2
    assert p2 == "api.example.com"

    # depth 3
    d3, p3 = calculate_subdomain_depth("v2.dev.api.example.com", "example.com")
    assert d3 == 3
    assert p3 == "dev.api.example.com"

    # depth 5
    d5, p5 = calculate_subdomain_depth("a.b.c.d.e.example.com", "example.com")
    assert d5 == 5
    assert p5 == "b.c.d.e.example.com"


def test_recursive_subdomains_limited_depth():
    config = {
        "program": {"name": "depth-test"},
        "targets": {
            "domains": ["target.com"],
            "recursive_subdomains": {
                "enabled": True,
                "max_depth": 2,
            },
        },
    }
    engine = ScopeEngine(config)

    # depth 0
    res0 = engine.check("target.com")
    assert res0.status == ScopeStatus.IN_SCOPE
    assert res0.depth == 0

    # depth 1
    res1 = engine.check("api.target.com")
    assert res1.status == ScopeStatus.IN_SCOPE
    assert res1.depth == 1

    # depth 2
    res2 = engine.check("dev.api.target.com")
    assert res2.status == ScopeStatus.IN_SCOPE
    assert res2.depth == 2

    # depth 3 (exceeds max_depth: 2)
    res3 = engine.check("v1.dev.api.target.com")
    assert res3.status == ScopeStatus.OUT_OF_SCOPE
    assert "exceeds" in res3.reason.lower()


def test_recursive_subdomains_disabled():
    config = {
        "program": {"name": "no-recursion-test"},
        "targets": {
            "domains": ["exact-only.com"],
            "recursive_subdomains": {
                "enabled": False,
                "max_depth": 0,
            },
        },
    }
    engine = ScopeEngine(config)

    # depth 0 is in scope
    res0 = engine.check("exact-only.com")
    assert res0.status == ScopeStatus.IN_SCOPE

    # depth 1 must be rejected because recursion is disabled
    res1 = engine.check("sub.exact-only.com")
    assert res1.status == ScopeStatus.OUT_OF_SCOPE


def test_structured_metadata_representation():
    config = {
        "program": {"name": "meta-test"},
        "targets": {
            "domains": ["example.com"],
            "recursive_subdomains": {
                "enabled": True,
                "max_depth": 0,
            },
        },
    }
    engine = ScopeEngine(config)
    res = engine.check("dev.api.example.com")
    d = res.to_dict()

    assert d["target"] == "dev.api.example.com"
    assert d["hostname"] if "hostname" in d else d["normalized_target"] == "dev.api.example.com"
    assert d["root_domain"] == "example.com"
    assert d["parent"] == "api.example.com"
    assert d["depth"] == 2
    assert d["scope_status"] == "IN_SCOPE"
