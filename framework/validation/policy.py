"""
Safe Testing Policy for BugBounty-Agent Security Validation.

Enforces conservative ceilings, allowed HTTP methods, maximum response and payload
bounds, and state-changing endpoint detection to guarantee non-destructive research.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple


# Patterns indicating potentially state-changing actions even if invoked via GET
STATE_CHANGING_PATH_PATTERNS = [
    re.compile(r"/(?:delete|destroy|remove|purge|drop|wipe)\b", re.IGNORECASE),
    re.compile(r"/(?:logout|signout|revoke)\b", re.IGNORECASE),
    re.compile(r"/(?:reset-password|change-password|update-password)\b", re.IGNORECASE),
    re.compile(r"/(?:transfer|pay|checkout|purchase|subscribe)\b", re.IGNORECASE),
    re.compile(r"/(?:admin/shutdown|admin/kill|admin/restart)\b", re.IGNORECASE),
    re.compile(r"/(?:disable|deactivate|terminate)\b", re.IGNORECASE),
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
        max_payload_size: int = 512,
        max_evidence_size: int = 4096,
        concurrency: int = 1,
        delay_seconds: float = 0.0,
        block_destructive_actions: bool = True,
        block_state_changing_get: bool = True,
    ):
        self.allowed_methods: Set[str] = {
            m.strip().upper() for m in (allowed_methods or {"GET", "HEAD", "OPTIONS"})
        }
        self.max_requests_per_test = max(1, int(max_requests_per_test))
        self.max_requests_per_endpoint = max(1, int(max_requests_per_endpoint))
        self.max_requests_per_program = max(1, int(max_requests_per_program))
        self.timeout = max(0.5, float(timeout))
        self.max_response_bytes = max(1024, int(max_response_bytes))
        self.max_payload_size = max(32, int(max_payload_size))
        self.max_evidence_size = max(512, int(max_evidence_size))
        self.concurrency = max(1, int(concurrency))
        self.delay_seconds = max(0.0, float(delay_seconds))
        self.block_destructive_actions = bool(block_destructive_actions)
        self.block_state_changing_get = bool(block_state_changing_get)

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

        # 2. State-changing GET check
        if self.block_state_changing_get and norm_method in ("GET", "HEAD"):
            is_sc, matched = self.is_state_changing_path(url_or_path)
            if is_sc:
                raise PolicyViolationError(
                    f"GET request to '{url_or_path}' blocked: matches state-changing pattern '{matched}'"
                )

        # 3. Payload size check
        if payload_size > self.max_payload_size:
            raise PolicyViolationError(
                f"Payload size {payload_size} bytes exceeds maximum policy bound of {self.max_payload_size} bytes."
            )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes policy configuration to dictionary."""
        return {
            "allowed_methods": sorted(list(self.allowed_methods)),
            "max_requests_per_test": self.max_requests_per_test,
            "max_requests_per_endpoint": self.max_requests_per_endpoint,
            "max_requests_per_program": self.max_requests_per_program,
            "timeout": self.timeout,
            "max_response_bytes": self.max_response_bytes,
            "max_payload_size": self.max_payload_size,
            "max_evidence_size": self.max_evidence_size,
            "concurrency": self.concurrency,
            "delay_seconds": self.delay_seconds,
            "block_destructive_actions": self.block_destructive_actions,
            "block_state_changing_get": self.block_state_changing_get,
        }
