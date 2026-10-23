"""
Safety, Concurrency Bounds, and Anti-SSRF Policy for Phase 20 Intelligence.

Enforces strictly bounded concurrent bursts (2-10 requests), prevents Denial-of-Service,
prohibits destructive HTTP methods (TRACE), and enforces fail-closed scope/SSRF rules.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Optional, Set
from urllib.parse import urlparse

from framework.validation.policy import PolicyViolationError


class ConcurrencySafetyPolicy:
    """Policy bounds and safety rules for concurrent race-condition probing."""

    DEFAULT_BURST_SIZE = 4
    MAX_BURST_SIZE = 10
    MIN_BURST_SIZE = 2
    DEFAULT_TIMEOUT = 5.0
    MAX_REQUESTS_PER_TEST = 15

    PROHIBITED_METHODS: Set[str] = {"TRACE"}
    PROHIBITED_HOSTS: Set[str] = {
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.internal",
        "instance-data",
    }

    def __init__(
        self,
        max_burst_size: int = DEFAULT_BURST_SIZE,
        timeout: float = DEFAULT_TIMEOUT,
        max_requests_per_test: int = MAX_REQUESTS_PER_TEST,
        require_approval: bool = True,
        lab_mode: bool = False,
    ):
        self.burst_size = max(self.MIN_BURST_SIZE, min(self.MAX_BURST_SIZE, int(max_burst_size)))
        self.timeout = max(1.0, min(30.0, float(timeout)))
        self.max_requests_per_test = max(self.MIN_BURST_SIZE, min(30, int(max_requests_per_test)))
        self.require_approval = require_approval
        self.lab_mode = lab_mode
        self._allowed_fixture_ports: Set[int] = set()

    def allow_fixture_port(self, port: int) -> None:
        """Explicitly whitelists a deterministic local test fixture port."""
        if 1 <= port <= 65535:
            self._allowed_fixture_ports.add(port)

    def validate_burst_size(self, count: int) -> int:
        """Validates and bounds requested concurrency burst."""
        if count > self.MAX_BURST_SIZE:
            raise PolicyViolationError(
                f"Requested burst size {count} exceeds maximum safety limit ({self.MAX_BURST_SIZE}). "
                "Flooding/DoS testing is strictly prohibited."
            )
        if count < self.MIN_BURST_SIZE:
            return self.MIN_BURST_SIZE
        return count

    def validate_request_safety(self, method: str, url: str) -> None:
        """
        Enforces strict safety checks before any concurrent request is dispatched.
        """
        meth_clean = (method or "POST").strip().upper()
        if meth_clean in self.PROHIBITED_METHODS:
            raise PolicyViolationError(
                f"HTTP method '{meth_clean}' is prohibited by ConcurrencySafetyPolicy."
            )

        parsed = urlparse(url)
        if not parsed.scheme or parsed.scheme.lower() not in ("http", "https"):
            raise PolicyViolationError(f"Invalid URL scheme '{parsed.scheme}'; only HTTP/HTTPS allowed.")

        hostname = (parsed.hostname or "").lower().strip()
        if not hostname:
            raise PolicyViolationError("Missing hostname in target URL.")

        if hostname in self.PROHIBITED_HOSTS:
            raise PolicyViolationError(f"Target host '{hostname}' is in prohibited cloud metadata list.")

        # Lab mode fixture handling
        if self.lab_mode:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if hostname in ("127.0.0.1", "localhost", "::1"):
                if port in self._allowed_fixture_ports:
                    return
                raise PolicyViolationError(
                    f"Port {port} on loopback is not whitelisted in LocalConcurrencyLab."
                )

        # Anti-SSRF production verification: block private / loopback / link-local addresses
        is_ip = False
        try:
            ip_obj = ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
                raise PolicyViolationError(
                    f"Prohibited destination IP '{hostname}' (private/loopback/link-local address)."
                )
        else:
            # Domain name, not raw IP literal
            if hostname in ("localhost", "local", "loopback"):
                raise PolicyViolationError(f"Target host '{hostname}' resolves to loopback space.")
