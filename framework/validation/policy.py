"""
Safe Testing Policy for BugBounty-Agent Security Validation.

Enforces conservative ceilings, allowed HTTP methods, maximum response and payload
bounds, and state-changing endpoint detection to guarantee non-destructive research.
"""

from __future__ import annotations

from enum import Enum
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from framework.common.transport import parse_alternate_ip


class EndpointSafetyClass(str, Enum):
    """Explicit safety classification for endpoints."""
    SAFE = "SAFE"
    READ_ONLY = "READ_ONLY"
    STATE_CHANGING = "STATE_CHANGING"
    UNKNOWN = "UNKNOWN"
    BLOCKED = "BLOCKED"


# Patterns indicating potentially state-changing actions even if invoked via GET
STATE_CHANGING_PATH_PATTERNS = [
    re.compile(r"/(?:delete|destroy|remove|purge|drop|wipe)\b", re.IGNORECASE),
    re.compile(r"/(?:logout|signout|revoke)\b", re.IGNORECASE),
    re.compile(r"/(?:reset-password|change-password|update-password)\b", re.IGNORECASE),
    re.compile(r"/(?:transfer|pay|checkout|purchase|subscribe)\b", re.IGNORECASE),
    re.compile(r"/(?:admin/shutdown|admin/kill|admin/restart)\b", re.IGNORECASE),
    re.compile(r"/(?:disable|deactivate|terminate)\b", re.IGNORECASE),
]

# Patterns recognized as read-only / safe query endpoints
READ_ONLY_PATH_PATTERNS = [
    re.compile(r"/(?:search|query|items|products|articles|docs|view|get|list|catalog|feed|faq|help|about)\b", re.IGNORECASE),
    re.compile(r"\.(?:html|htm|json|js|css|xml|txt|png|jpg|svg)$", re.IGNORECASE),
]

# Sensitive headers and parameter patterns that must be sanitized before recording
SENSITIVE_HEADER_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "session",
    "x-csrf-token",
    "csrf-token",
}

# Default trusted out-of-band callback provider domains
DEFAULT_TRUSTED_OOB_DOMAINS: Set[str] = {
    "oob.local",
    "bugbounty-agent.local",
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.fun",
    "oast.me",
    "burpcollaborator.net",
    "oastify.com",
}


class PolicyViolationError(ValueError):
    """Raised when a security validation action violates the safe testing policy."""
    pass


class SecurityTestPolicy:
    """
    Centralized policy engine governing all security validation operations.
    Conservative by default: strictly limits methods, budgets, and response sizes.
    """

    def __init__(
        self,
        allowed_methods: Optional[Set[str]] = None,
        max_requests_per_test: int = 5,
        max_requests_per_endpoint: int = 20,
        max_requests_per_program: int = 200,
        timeout: float = 5.0,
        max_response_bytes: int = 100_000,
        max_total_bytes: int = 10 * 1024 * 1024,
        max_payload_size: int = 512,
        max_evidence_size: int = 4096,
        max_redirects: int = 5,
        concurrency: int = 1,
        delay_seconds: float = 0.0,
        block_destructive_actions: bool = True,
        block_state_changing_get: bool = True,
        block_unknown_endpoints: bool = False,
        endpoint_classifications: Optional[Dict[str, EndpointSafetyClass | str]] = None,
        trusted_oob_domains: Optional[Set[str]] = None,
    ):
        self.allowed_methods: Set[str] = {
            m.strip().upper() for m in (allowed_methods or {"GET", "HEAD", "OPTIONS"})
        }
        self.max_requests_per_test = max(1, int(max_requests_per_test))
        self.max_requests_per_endpoint = max(1, int(max_requests_per_endpoint))
        self.max_requests_per_program = max(1, int(max_requests_per_program))
        self.timeout = max(0.5, float(timeout))
        self.max_response_bytes = max(1024, int(max_response_bytes))
        self.max_total_bytes = max(1, int(max_total_bytes))
        self.max_payload_size = max(32, int(max_payload_size))
        self.max_evidence_size = max(512, int(max_evidence_size))
        self.max_redirects = max(0, int(max_redirects))
        self.concurrency = max(1, int(concurrency))
        self.delay_seconds = max(0.0, float(delay_seconds))
        self.block_destructive_actions = bool(block_destructive_actions)
        self.block_state_changing_get = bool(block_state_changing_get)
        self.block_unknown_endpoints = bool(block_unknown_endpoints)
        self.endpoint_classifications: Dict[str, EndpointSafetyClass] = {}
        if endpoint_classifications:
            for k, v in endpoint_classifications.items():
                self.endpoint_classifications[k] = (
                    v if isinstance(v, EndpointSafetyClass) else EndpointSafetyClass(str(v).upper())
                )
        self.trusted_oob_domains: Set[str] = {
            d.strip().lower() for d in (trusted_oob_domains or DEFAULT_TRUSTED_OOB_DOMAINS)
        }

    def is_method_allowed(self, method: str) -> bool:
        """Verifies if HTTP method is permitted under this policy."""
        return method.strip().upper() in self.allowed_methods

    def is_state_changing_path(self, path_or_url: str) -> Tuple[bool, Optional[str]]:
        """
        Inspects path/URL for keywords suggesting destructive or state-changing actions.
        Returns (is_state_changing, matched_pattern).
        """
        clean = path_or_url.strip()
        for pattern in STATE_CHANGING_PATH_PATTERNS:
            match = pattern.search(clean)
            if match:
                return True, match.group(0)
        return False, None

    def classify_endpoint(self, method: str, url_or_path: str) -> EndpointSafetyClass:
        """
        Classifies an endpoint based on explicit map, HTTP method, and path patterns.
        """
        norm_method = method.strip().upper()
        clean = url_or_path.strip().split("?")[0].lower()

        # 1. Explicit override in classifications
        for ep, cls in self.endpoint_classifications.items():
            if ep.lower() in clean or clean in ep.lower():
                return cls

        # 2. Check state-changing path keywords
        is_sc, _ = self.is_state_changing_path(url_or_path)
        if is_sc:
            return EndpointSafetyClass.STATE_CHANGING

        # 3. Method-based classification
        if norm_method in ("POST", "PUT", "PATCH", "DELETE"):
            return EndpointSafetyClass.STATE_CHANGING

        # 4. Known read-only path patterns
        for pattern in READ_ONLY_PATH_PATTERNS:
            if pattern.search(clean):
                return EndpointSafetyClass.SAFE

        if norm_method in ("GET", "HEAD", "OPTIONS"):
            return EndpointSafetyClass.READ_ONLY

        return EndpointSafetyClass.UNKNOWN

    def validate_request_safety(self, method: str, url_or_path: str, payload_size: int = 0) -> None:
        """
        Validates safety invariants before any request is dispatched.
        Raises PolicyViolationError on any violation.
        """
        norm_method = method.strip().upper()

        # 1. Allowed method check
        if not self.is_method_allowed(norm_method):
            raise PolicyViolationError(
                f"HTTP method '{norm_method}' is blocked by policy. "
                f"Permitted methods: {sorted(list(self.allowed_methods))}"
            )

        # 2. Safety classification check
        safety_class = self.classify_endpoint(norm_method, url_or_path)
        if safety_class == EndpointSafetyClass.BLOCKED:
            raise PolicyViolationError(f"Endpoint '{url_or_path}' is explicitly BLOCKED by policy.")

        if self.block_destructive_actions and safety_class == EndpointSafetyClass.STATE_CHANGING:
            if norm_method not in ("GET", "HEAD", "OPTIONS") or self.block_state_changing_get:
                raise PolicyViolationError(
                    f"Request to '{url_or_path}' blocked: classified as STATE_CHANGING and destructive actions are blocked."
                )

        if self.block_unknown_endpoints and safety_class == EndpointSafetyClass.UNKNOWN:
            raise PolicyViolationError(
                f"Request to '{url_or_path}' blocked: classified as UNKNOWN and block_unknown_endpoints is enabled."
            )

        # 3. State-changing GET check
        if self.block_state_changing_get and norm_method in ("GET", "HEAD"):
            is_sc, matched = self.is_state_changing_path(url_or_path)
            if is_sc:
                raise PolicyViolationError(
                    f"GET request to '{url_or_path}' blocked: matches state-changing pattern '{matched}'"
                )

        # 4. Payload size check
        if payload_size > self.max_payload_size:
            raise PolicyViolationError(
                f"Payload size {payload_size} bytes exceeds maximum policy bound of {self.max_payload_size} bytes."
            )

    def is_trusted_oob_host(self, host: str) -> bool:
        """
        Evaluates whether a host matches the configured trusted OOB domain list
        (either as an exact domain match or as a valid subdomain).
        """
        clean_host = host.strip().lower()
        if clean_host.startswith("[") and clean_host.endswith("]"):
            clean_host = clean_host[1:-1]
        for trusted in self.trusted_oob_domains:
            trusted_clean = trusted.strip().lower()
            if clean_host == trusted_clean or clean_host.endswith("." + trusted_clean):
                return True
        return False

    def validate_oob_destination(self, canary_url: str) -> None:
        """
        Validates that an Out-of-Band canary callback destination adheres to strict safety boundaries.
        Enforces:
        1. Non-empty string and valid URL structure.
        2. Permitted scheme: only http and https are allowed.
        3. Prohibits credentials (user:password in URL).
        4. Prohibits IP literals: loopback, private RFC 1918, link-local, carrier-grade NAT, or cloud metadata.
        5. Prohibits prohibited hostnames (e.g. metadata.google.internal, localhost).
        6. Hostname MUST match the configured trusted OOB provider domains (exact or subdomain).
        Raises PolicyViolationError on any violation.
        """
        if not canary_url or not isinstance(canary_url, str):
            raise PolicyViolationError("OOB destination URL cannot be empty or non-string.")

        clean_url = canary_url.strip()
        parsed = urlparse(clean_url)

        # 1. Permitted scheme
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise PolicyViolationError(
                f"Unsupported OOB scheme '{scheme}': only http and https are permitted."
            )

        # 2. Hostname presence
        host = (parsed.hostname or "").strip().lower()
        if not host:
            raise PolicyViolationError(f"OOB canary destination '{clean_url}' has no valid hostname.")

        # 3. Prohibit credentials in URL
        if parsed.username or parsed.password:
            raise PolicyViolationError(
                "OOB canary destination must not contain embedded user credentials."
            )

        # 4. Prohibit prohibited hostnames
        prohibited_hostnames = {
            "localhost",
            "metadata.google.internal",
            "metadata",
            "instance-data",
        }
        if host in prohibited_hostnames:
            raise PolicyViolationError(
                f"Prohibited host '{host}' cannot be used as an OOB canary destination."
            )

        # 5. Prohibit IP literals (including alternate IP encodings and trailing IP literals)
        alt_ip = parse_alternate_ip(host)
        if alt_ip is None and len(host.split(".")) >= 4:
            trailing_four = ".".join(host.split(".")[-4:])
            alt_ip = parse_alternate_ip(trailing_four)

        if alt_ip is not None:
            # IP literal detected - check if prohibited
            if (
                alt_ip.is_loopback
                or alt_ip.is_private
                or alt_ip.is_link_local
                or alt_ip.is_reserved
                or alt_ip.is_multicast
                or alt_ip.is_unspecified
            ):
                raise PolicyViolationError(
                    f"Prohibited IP address '{host}' ({alt_ip}) in OOB canary destination: "
                    f"loopback, private, and metadata IP addresses are strictly forbidden."
                )
            # Even if public IP literal, OOB destinations must use registered domain names
            # matching trusted OOB provider policy, not raw IP literals
            raise PolicyViolationError(
                f"Raw IP literal '{host}' is not permitted as an OOB canary destination. "
                f"Must use a trusted OOB domain name."
            )

        # 6. Validate port if present
        if parsed.port is not None:
            if parsed.port < 1 or parsed.port > 65535:
                raise PolicyViolationError(
                    f"Invalid port {parsed.port} in OOB canary destination."
                )

        # 7. Check trusted OOB domain whitelist
        if not self.is_trusted_oob_host(host):
            raise PolicyViolationError(
                f"Untrusted OOB destination host '{host}'. "
                f"Domain is not in the trusted OOB provider policy: {sorted(list(self.trusted_oob_domains))}"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes policy configuration to dictionary."""
        return {
            "allowed_methods": sorted(list(self.allowed_methods)),
            "trusted_oob_domains": sorted(list(self.trusted_oob_domains)),
            "max_requests_per_test": self.max_requests_per_test,
            "max_requests_per_endpoint": self.max_requests_per_endpoint,
            "max_requests_per_program": self.max_requests_per_program,
            "timeout": self.timeout,
            "max_response_bytes": self.max_response_bytes,
            "max_total_bytes": self.max_total_bytes,
            "max_payload_size": self.max_payload_size,
            "max_evidence_size": self.max_evidence_size,
            "concurrency": self.concurrency,
            "delay_seconds": self.delay_seconds,
            "block_destructive_actions": self.block_destructive_actions,
            "block_state_changing_get": self.block_state_changing_get,
            "block_unknown_endpoints": self.block_unknown_endpoints,
        }
