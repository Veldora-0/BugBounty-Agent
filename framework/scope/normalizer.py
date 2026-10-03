"""
Target Normalizer for BugBounty-Agent.

Provides canonical normalization, DNS-label boundary checks, and input validation
for domains, hostnames, URLs, IPs, and CIDRs.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse, urlunparse


_HOSTNAME_LABEL_REGEX = re.compile(r"^(?!-)[a-zA-Z0-9-_]{1,63}(?<!-)$")
_IPV4_SEGMENT_REGEX = re.compile(r"^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")


class NormalizationError(ValueError):
    """Raised when a target cannot be normalized or is malformed."""
    pass


def normalize_hostname(raw_host: str) -> str:
    """
    Normalizes a hostname or domain:
    1. Strip leading and trailing whitespace
    2. Lowercase
    3. Strip trailing dot (DNS root label)
    4. Handle IDN (internationalized domain names) via punycode/idna
    5. Validate syntax and label lengths
    """
    if not raw_host or not isinstance(raw_host, str):
        raise NormalizationError("Hostname must be a non-empty string.")

    host = raw_host.strip().lower()

    # Remove trailing dot if present (standard DNS FQDN representation)
    if host.endswith("."):
        host = host[:-1]

    if not host:
        raise NormalizationError("Hostname cannot be empty after stripping.")

    # Remove leading wildcard if checking a pattern
    is_wildcard = False
    validation_host = host
    if validation_host.startswith("*."):
        is_wildcard = True
        validation_host = validation_host[2:]
    elif validation_host.startswith("."):
        validation_host = validation_host[1:]

    # Remove port if accidentally passed in hostname string
    if ":" in validation_host and not validation_host.startswith("["):
        # Check if IPv6 or host:port
        parts = validation_host.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            validation_host = parts[0]
            host = f"*.{parts[0]}" if is_wildcard else parts[0]

    # Convert IDN / Punycode
    try:
        # Encode to idna ASCII representation and back to unicode string
        encoded = validation_host.encode("idna").decode("ascii")
    except Exception as e:
        raise NormalizationError(f"Invalid internationalized domain name: {raw_host}") from e

    # Check overall length (RFC 1035 max 253 characters)
    if len(encoded) > 253:
        raise NormalizationError(f"Hostname exceeds maximum length of 253 characters: {raw_host}")

    # Check if host is an IP address
    if is_valid_ip(validation_host):
        return validation_host

    # Check DNS labels
    labels = encoded.split(".")
    if not labels or any(not label for label in labels):
        raise NormalizationError(f"Hostname has empty DNS labels: {raw_host}")

    for label in labels:
        if len(label) > 63:
            raise NormalizationError(f"DNS label '{label}' exceeds 63 characters in: {raw_host}")
        if not _HOSTNAME_LABEL_REGEX.match(label):
            raise NormalizationError(f"DNS label '{label}' contains invalid characters in: {raw_host}")

    return host


def normalize_url(raw_url: str) -> str:
    """
    Normalizes a URL:
    1. Parse scheme, netloc, path, query
    2. Lowercase scheme and hostname
    3. Remove default ports (80 for http, 443 for https)
    4. Remove trailing slash if root path or preserve meaningful paths
    5. Discard fragment
    """
    if not raw_url or not isinstance(raw_url, str):
        raise NormalizationError("URL must be a non-empty string.")

    cleaned = raw_url.strip()
    parsed = urlparse(cleaned)

    if not parsed.scheme or not parsed.netloc:
        raise NormalizationError(f"URL missing scheme or netloc: {raw_url}")

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https", "ws", "wss"):
        raise NormalizationError(f"Unsupported URL scheme '{scheme}' in: {raw_url}")

    hostname = parsed.hostname
    if not hostname:
        raise NormalizationError(f"URL missing valid hostname: {raw_url}")

    norm_host = normalize_hostname(hostname)

    port = parsed.port
    netloc = norm_host
    if port is not None:
        if (scheme in ("http", "ws") and port != 80) or (scheme in ("https", "wss") and port != 443):
            netloc = f"{norm_host}:{port}"

    path = parsed.path
    if not path:
        path = "/"
    
    # Normalize consecutive slashes in path
    path = re.sub(r"/{2,}", "/", path)

    # Reconstruct normalized URL (drop fragments)
    return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))


def is_valid_ip(value: str) -> bool:
    """Returns True if the string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_valid_cidr(value: str) -> bool:
    """Returns True if the string is a valid IPv4 or IPv6 network in CIDR notation."""
    try:
        ipaddress.ip_network(value.strip(), strict=False)
        return True
    except ValueError:
        return False


def is_dns_label_descendant(child_host: str, parent_host: str) -> bool:
    """
    Strict DNS-label boundary verification.
    Ensures that 'child_host' is an authentic DNS descendant of 'parent_host'.

    Examples:
    - 'api.example.com' is a descendant of 'example.com' -> True
    - 'dev.api.example.com' is a descendant of 'example.com' -> True
    - 'example.com' is a descendant of 'example.com' -> True (depth 0)
    - 'example.com.attacker.com' is a descendant of 'example.com' -> False
    - 'attackerexample.com' is a descendant of 'example.com' -> False
    """
    norm_child = normalize_hostname(child_host)
    norm_parent = normalize_hostname(parent_host)

    if norm_child == norm_parent:
        return True

    # Must end with dot + parent_host to respect label boundary
    expected_suffix = f".{norm_parent}"
    return norm_child.endswith(expected_suffix)


def calculate_subdomain_depth(hostname: str, root_domain: str) -> Tuple[int, Optional[str]]:
    """
    Calculates the subdomain depth relative to root_domain and identifies parent hostname.

    Depth Semantics:
    - example.com                 depth 0, parent None
    - api.example.com             depth 1, parent example.com
    - dev.api.example.com         depth 2, parent api.example.com
    - v2.dev.api.example.com      depth 3, parent dev.api.example.com

    Returns (depth, parent_hostname)
    """
    norm_host = normalize_hostname(hostname)
    norm_root = normalize_hostname(root_domain)

    if not is_dns_label_descendant(norm_host, norm_root):
        raise ValueError(f"'{norm_host}' is not a descendant of '{norm_root}'")

    if norm_host == norm_root:
        return 0, None

    # Calculate difference in DNS labels
    host_labels = norm_host.split(".")
    root_labels = norm_root.split(".")

    depth = len(host_labels) - len(root_labels)
    # The direct parent has one less leftmost label
    parent = ".".join(host_labels[1:])

    return depth, parent


def parse_and_normalize_target(raw_target: str) -> Dict[str, Any]:
    """
    Analyzes, categorizes, and canonicalizes any raw target input.
    Returns structured target information.
    """
    cleaned = raw_target.strip()
    if not cleaned:
        raise NormalizationError("Target string cannot be empty.")

    # Check if target is a URL
    if cleaned.startswith(("http://", "https://", "ws://", "wss://")):
        normalized_url = normalize_url(cleaned)
        parsed = urlparse(normalized_url)
        return {
            "type": "URL",
            "raw": raw_target,
            "normalized": normalized_url,
            "hostname": parsed.hostname,
            "port": parsed.port or (443 if parsed.scheme in ("https", "wss") else 80),
            "scheme": parsed.scheme,
            "path": parsed.path,
        }

    # Check if target is a CIDR network
    if "/" in cleaned and is_valid_cidr(cleaned):
        network = ipaddress.ip_network(cleaned, strict=False)
        return {
            "type": "CIDR",
            "raw": raw_target,
            "normalized": str(network),
            "network": network,
        }

    # Check if target is a single IP address
    if is_valid_ip(cleaned):
        ip = ipaddress.ip_address(cleaned)
        return {
            "type": "IP",
            "raw": raw_target,
            "normalized": str(ip),
            "ip": ip,
        }

    # Otherwise treat as Hostname/Domain
    norm_host = normalize_hostname(cleaned)
    is_wildcard = norm_host.startswith("*.") or cleaned.startswith("*.")
    clean_host = norm_host[2:] if norm_host.startswith("*.") else norm_host

    return {
        "type": "DOMAIN",
        "raw": raw_target,
        "normalized": norm_host,
        "clean_host": clean_host,
        "is_wildcard": is_wildcard,
    }
