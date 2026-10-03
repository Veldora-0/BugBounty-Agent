"""
Tests for Target Normalization and Canonical Validation.
"""

import pytest

from framework.scope.normalizer import (
    NormalizationError,
    normalize_hostname,
    normalize_url,
    parse_and_normalize_target,
)


def test_hostname_normalization_case_and_dots():
    # Uppercase
    assert normalize_hostname("EXAMPLE.COM") == "example.com"
    assert normalize_hostname("Sub.Api.Example.Com") == "sub.api.example.com"

    # Trailing dot (DNS root)
    assert normalize_hostname("example.com.") == "example.com"
    assert normalize_hostname("API.EXAMPLE.COM.") == "api.example.com"

    # Leading/trailing whitespace
    assert normalize_hostname("   example.com \t\n") == "example.com"


def test_hostname_with_ports():
    # If host:port string is passed to normalizer
    assert normalize_hostname("example.com:8080") == "example.com"
    assert normalize_hostname("api.example.com:443") == "api.example.com"


def test_malformed_hostnames():
    # Empty
    with pytest.raises(NormalizationError):
        normalize_hostname("")

    # Spaces only
    with pytest.raises(NormalizationError):
        normalize_hostname("   ")

    # Double dots / empty labels
    with pytest.raises(NormalizationError):
        normalize_hostname("example..com")

    # Invalid characters
    with pytest.raises(NormalizationError):
        normalize_hostname("example$.com")

    # Label starting or ending with hyphen
    with pytest.raises(NormalizationError):
        normalize_hostname("-example.com")
    with pytest.raises(NormalizationError):
        normalize_hostname("example-.com")

    # Exceeding label length (> 63 chars)
    long_label = "a" * 64 + ".com"
    with pytest.raises(NormalizationError):
        normalize_hostname(long_label)


def test_url_normalization():
    # Scheme lowercasing and default port removal
    u1 = normalize_url("HTTP://EXAMPLE.COM:80/path/to/resource")
    assert u1 == "http://example.com/path/to/resource"

    u2 = normalize_url("HTTPS://API.EXAMPLE.COM:443/v1/users/")
    assert u2 == "https://api.example.com/v1/users/"

    # Custom port preservation
    u3 = normalize_url("https://example.com:8443/api")
    assert u3 == "https://example.com:8443/api"

    # Redundant consecutive slashes
    u4 = normalize_url("https://example.com//foo///bar")
    assert u4 == "https://example.com/foo/bar"

    # Dropping fragment
    u5 = normalize_url("https://example.com/page#section")
    assert u5 == "https://example.com/page"


def test_target_categorization():
    t_url = parse_and_normalize_target("https://example.com/api")
    assert t_url["type"] == "URL"
    assert t_url["hostname"] == "example.com"

    t_cidr = parse_and_normalize_target("10.10.0.0/16")
    assert t_cidr["type"] == "CIDR"

    t_ip = parse_and_normalize_target("192.168.1.1")
    assert t_ip["type"] == "IP"

    t_dom = parse_and_normalize_target("*.SUB.EXAMPLE.COM")
    assert t_dom["type"] == "DOMAIN"
    assert t_dom["is_wildcard"] is True
    assert t_dom["clean_host"] == "sub.example.com"
