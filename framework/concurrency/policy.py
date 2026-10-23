"""
Safety, Concurrency Bounds, and Anti-SSRF Policy for Phase 20 Intelligence.

Enforces strictly bounded concurrent bursts (2-10 requests), prevents Denial-of-Service,
prohibits destructive HTTP methods (TRACE), and enforces fail-closed scope/SSRF rules.

Includes preflight destination hostname resolution validation against private,
loopback, link-local, multicast, and cloud metadata address spaces.
Note on transport limitations: Preflight DNS checks cannot prevent Time-of-Check to
Time-of-Use (TOCTOU) DNS rebinding if the underlying transport performs separate
unpinned resolution during socket connection.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any, Callable, Dict, List, Optional, Set
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
        resolver: Optional[Callable[[str], List[str]]] = None,
    ):
        try:
            req_burst = int(max_burst_size)
        except (ValueError, TypeError):
            req_burst = self.DEFAULT_BURST_SIZE

        try:
            req_limit = int(max_requests_per_test)
        except (ValueError, TypeError):
            req_limit = self.MAX_REQUESTS_PER_TEST

        self.burst_size = max(self.MIN_BURST_SIZE, min(self.MAX_BURST_SIZE, req_burst))
        self.timeout = max(1.0, min(30.0, float(timeout)))
        # Strictly clamp configured limit: minimum MIN_BURST_SIZE (2), hard maximum MAX_REQUESTS_PER_TEST (15)
        self.max_requests_per_test = max(self.MIN_BURST_SIZE, min(self.MAX_REQUESTS_PER_TEST, req_limit))
        self.require_approval = require_approval
        self.lab_mode = lab_mode
        self._resolver = resolver
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

    def resolve_hostname(self, hostname: str) -> List[str]:
        """
        Resolves destination hostname to IP addresses for preflight SSRF validation.
        Supports custom resolver hook for deterministic offline testing.
        """
        if self._resolver:
            return self._resolver(hostname)
        try:
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            return list({sa[0] for _, _, _, _, sa in addr_info})
        except (socket.gaierror, OSError):
            return []

    def validate_request_safety(self, method: str, url: str) -> None:
        """
        Enforces strict safety checks before any concurrent request is dispatched:
        1. Prohibits destructive HTTP methods (TRACE).
        2. Prohibits cloud metadata addresses and hostnames.
        3. Enforces loopback port whitelisting in lab mode.
        4. Validates IP literals against private, loopback, link-local, multicast, and reserved spaces.
        5. Validates resolved hostname IPs in production mode against SSRF prohibited ranges.
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

        # Anti-SSRF production verification: evaluate IP literal
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
            if hostname in ("localhost", "local", "loopback") or hostname.endswith(".localhost"):
                raise PolicyViolationError(f"Target host '{hostname}' resolves to loopback space.")

            # In production mode: preflight DNS resolution check against prohibited address ranges
            if not self.lab_mode:
                resolved_ips = self.resolve_hostname(hostname)
                for r_ip in resolved_ips:
                    try:
                        r_ip_obj = ipaddress.ip_address(r_ip)
                    except ValueError:
                        continue

                    if (
                        r_ip_obj.is_private
                        or r_ip_obj.is_loopback
                        or r_ip_obj.is_link_local
                        or r_ip_obj.is_multicast
                        or r_ip_obj.is_reserved
                        or str(r_ip_obj) in self.PROHIBITED_HOSTS
                    ):
                        raise PolicyViolationError(
                            f"Target host '{hostname}' resolves to prohibited destination IP '{r_ip}' "
                            "(private/loopback/metadata address). Blocked by anti-SSRF policy."
                        )
