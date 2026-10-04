"""
Canary Token & Correlation Manager for SSRF Intelligence (Phase 9).

Generates deterministic, bounded, non-sensitive correlation identifiers and
tracks the complete verification lifecycle:
  test case → canary token → OOB interaction → correlation matching

Enforces strict timestamp correlation windows to eliminate stale callbacks
and false associations.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple
import uuid

from framework.ssrf.model import (
    OobInteractionType,
    SsrfConfidence,
    SsrfInteraction,
)
from framework.ssrf.provider import OobProvider


class CanaryRecord:
    """Tracks metadata and lifecycle for an active canary token."""

    def __init__(
        self,
        canary_token: str,
        canary_url: str,
        test_id: str,
        program_id: str,
        created_at: Optional[str] = None,
        correlation_window_seconds: float = 60.0,
    ):
        self.canary_token = canary_token
        self.canary_url = canary_url
        self.test_id = test_id
        self.program_id = program_id
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.correlation_window_seconds = float(correlation_window_seconds)
        self.interactions: List[SsrfInteraction] = []

    def is_stale(self, check_time: Optional[datetime] = None) -> bool:
        """Determines if the correlation window has expired for this canary."""
        now = check_time or datetime.now(timezone.utc)
        try:
            created = datetime.fromisoformat(self.created_at)
            elapsed = (now - created).total_seconds()
            return elapsed > self.correlation_window_seconds
        except Exception:
            return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "canary_token": self.canary_token,
            "canary_url": self.canary_url,
            "test_id": self.test_id,
            "program_id": self.program_id,
            "created_at": self.created_at,
            "correlation_window_seconds": self.correlation_window_seconds,
            "interactions_count": len(self.interactions),
        }


class CanaryManager:
    """
    Manages generation, registry, and correlation matching for SSRF canaries.
    """

    def __init__(
        self,
        provider: OobProvider,
        program_id: str = "default",
        correlation_window_seconds: float = 60.0,
    ):
        self.provider = provider
        self.program_id = re.sub(r"[^a-zA-Z0-9_-]", "", program_id)[:16] or "default"
        self.correlation_window_seconds = float(correlation_window_seconds)
        self._active_canaries: Dict[str, CanaryRecord] = {}

    def issue_canary(self, test_id: str) -> Tuple[str, str]:
        """
        Requests a new canary token and target URL from the OOB provider.
        Registers the canary in local tracking registry.
        """
        prefix = f"bb9-{self.program_id}"
        token, canary_url = self.provider.generate_canary(prefix=prefix, test_id=test_id)

        record = CanaryRecord(
            canary_token=token,
            canary_url=canary_url,
            test_id=test_id,
            program_id=self.program_id,
            correlation_window_seconds=self.correlation_window_seconds,
        )
        self._active_canaries[token] = record
        return token, canary_url

    def get_canary_record(self, canary_token: str) -> Optional[CanaryRecord]:
        """Retrieves active canary metadata."""
        return self._active_canaries.get(canary_token)

    def correlate_interactions(
        self,
        canary_token: str,
        timeout: float = 5.0,
        exclude_source_ips: Optional[Set[str]] = None,
    ) -> List[SsrfInteraction]:
        """
        Polls OOB provider and returns verified, non-stale interactions for a canary token.
        Filters out self/browser callbacks matching exclude_source_ips.
        """
        record = self.get_canary_record(canary_token)
        raw_interactions = self.provider.poll(token=canary_token, timeout=timeout)
        matched_valid: List[SsrfInteraction] = []

        now = datetime.now(timezone.utc)
        excluded_ips = set(exclude_source_ips or [])

        for inter in raw_interactions:
            # 1. Exact token match check
            if inter.canary_token != canary_token:
                continue

            # 2. Origin check: ignore browser/scanner self-callbacks
            if inter.source_ip_metadata in excluded_ips:
                continue

            # 3. Timestamp correlation window check: reject stale callbacks
            if record and record.is_stale(now):
                continue

            matched_valid.append(inter)
            if record and inter not in record.interactions:
                record.interactions.append(inter)

        return matched_valid

    def classify_interaction_type(self, interactions: List[SsrfInteraction]) -> OobInteractionType:
        """Determines the strongest verified interaction level across observations."""
        if not interactions:
            return OobInteractionType.NO_INTERACTION

        has_https = any(i.protocol == "HTTPS" or i.interaction_type == OobInteractionType.HTTPS_INTERACTION for i in interactions)
        if has_https:
            return OobInteractionType.HTTPS_INTERACTION

        has_http = any(i.protocol == "HTTP" or i.interaction_type == OobInteractionType.HTTP_INTERACTION for i in interactions)
        if has_http:
            return OobInteractionType.HTTP_INTERACTION

        has_dns = any(i.protocol == "DNS" or i.interaction_type == OobInteractionType.DNS_ONLY for i in interactions)
        if has_dns:
            return OobInteractionType.DNS_ONLY

        return OobInteractionType.UNKNOWN
