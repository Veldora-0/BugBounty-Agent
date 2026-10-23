"""
Infrastructure & Configuration Exposure Policy for BugBounty-Agent.

Subclasses and configures SecurityTestPolicy with conservative parameters:
- Strictly permits only safe, read-only methods: GET, HEAD, OPTIONS.
- Prohibits active TRACE, POST, PUT, DELETE requests.
- Enforces strict 32 KB response ceilings and granular sub-limits (8 KB config, 1 KB archives).
- Applies state-changing GET protections and anti-SSRF boundaries to every probe.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Set

from framework.validation.policy import (
    EndpointSafetyClass,
    PolicyViolationError,
    SecurityTestPolicy,
)


class InfrastructureExposurePolicy(SecurityTestPolicy):
    """
    Safe testing policy for infrastructure and configuration exposure validation.
    Inherits all core SSRF prevention, method enforcement, and endpoint safety rules.
    """

    def __init__(
        self,
        allowed_methods: Optional[Set[str]] = None,
        max_requests_per_test: int = 3,
        max_requests_per_endpoint: int = 10,
        max_requests_per_program: int = 150,
        timeout: float = 4.0,
        max_response_bytes: int = 32_768,         # 32 KB global ceiling
        max_total_bytes: int = 10 * 1024 * 1024,
        max_payload_size: int = 512,
        max_evidence_size: int = 2048,            # 2 KB sanitized excerpt
        max_manifest_bytes: int = 8192,           # 8 KB manifest ceiling
        max_binary_magic_bytes: int = 1024,       # 1 KB archive magic bytes ceiling
        concurrency: int = 1,
        delay_seconds: float = 0.5,
        block_destructive_actions: bool = True,
        block_state_changing_get: bool = True,
        trusted_oob_domains: Optional[Set[str]] = None,
    ):
        # Enforce that methods are strictly within safe read-only set
        requested_methods = allowed_methods or {"GET", "HEAD", "OPTIONS"}
        sanitized_methods = {m.strip().upper() for m in requested_methods}

        # Hard boundary: active TRACE, POST, PUT, DELETE are forbidden
        prohibited = {"TRACE", "POST", "PUT", "DELETE", "PATCH", "CONNECT"}
        intersect = sanitized_methods.intersection(prohibited)
        if intersect:
            raise PolicyViolationError(
                f"Prohibited HTTP methods in infrastructure policy: {sorted(list(intersect))}. "
                f"Phase 19 strictly permits only: GET, HEAD, OPTIONS."
            )

        super().__init__(
            allowed_methods=sanitized_methods,
            max_requests_per_test=max_requests_per_test,
            max_requests_per_endpoint=max_requests_per_endpoint,
            max_requests_per_program=max_requests_per_program,
            timeout=timeout,
            max_response_bytes=max_response_bytes,
            max_total_bytes=max_total_bytes,
            max_payload_size=max_payload_size,
            max_evidence_size=max_evidence_size,
            concurrency=concurrency,
            delay_seconds=delay_seconds,
            block_destructive_actions=block_destructive_actions,
            block_state_changing_get=block_state_changing_get,
            trusted_oob_domains=trusted_oob_domains,
        )

        self.max_manifest_bytes = max(512, int(max_manifest_bytes))
        self.max_binary_magic_bytes = max(128, int(max_binary_magic_bytes))
