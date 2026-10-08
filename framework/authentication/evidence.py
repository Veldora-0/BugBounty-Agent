"""
Cryptographic Evidence Management Engine for Authentication (Phase 14).

Captures and formats sanitized evidence records with cryptographic SHA-256 digests.
Strictly redacts passwords, session secrets, bearer tokens, refresh tokens, OTPs, and API keys.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Dict, List, Optional

from framework.common.evidence import sanitize_sensitive_data


class AuthenticationEvidenceManager:
    """Creates, sanitizes, and signs authentication testing evidence records."""

    # Extended sensitive patterns specific to authentication testing
    EXTRA_PATTERNS = [
        (re.compile(r"((?:password|passwd|pwd|pass)=)[^&\s\r\n]+", re.IGNORECASE), r"\1[REDACTED_PASSWORD]"),
        (re.compile(r"((?:\"password\"|\"passwd\"|\"pwd\")\s*:\s*\")[^\"]+(\")", re.IGNORECASE), r"\1[REDACTED_PASSWORD]\2"),
        (re.compile(r"((?:otp|code|token|totp)=)[^&\s\r\n]+", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
        (re.compile(r"((?:\"otp\"|\"code\"|\"token\"|\"totp\")\s*:\s*\")[^\"]+(\")", re.IGNORECASE), r"\1[REDACTED_TOKEN]\2"),
    ]

    @classmethod
    def sanitize(cls, text: str) -> str:
        """Sanitizes text using framework patterns and extra authentication redactions."""
        if not text:
            return ""
        clean = sanitize_sensitive_data(text)
        for pat, repl in cls.EXTRA_PATTERNS:
            clean = pat.sub(repl, clean)
        return clean

    @classmethod
    def record_evidence(
        cls,
        endpoint: str,
        method: str,
        status_code: int,
        request_summary: str,
        response_summary: str,
        auth_state_before: str,
        auth_state_after: str,
        identity_role: str = "ANONYMOUS",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Creates a signed, sanitized evidence dictionary with a SHA-256 checksum.
        """
        clean_req = cls.sanitize(request_summary)
        clean_res = cls.sanitize(response_summary)

        timestamp = datetime.now(timezone.utc).isoformat()
        digest_input = f"{endpoint}|{method}|{status_code}|{clean_req}|{clean_res}|{timestamp}"
        sha256_digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()

        return {
            "evidence_id": f"ev_{sha256_digest[:16]}",
            "endpoint": endpoint,
            "method": method.upper(),
            "status_code": status_code,
            "auth_state_before": auth_state_before,
            "auth_state_after": auth_state_after,
            "identity_role": identity_role,
            "request_redacted": clean_req,
            "response_redacted": clean_res,
            "sha256_digest": sha256_digest,
            "timestamp": timestamp,
            "metadata": metadata or {},
        }
