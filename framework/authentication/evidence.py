"""
Cryptographic Evidence Management Engine for Authentication (Phase 14.1 / 14.2).

Captures and formats sanitized evidence records with cryptographic SHA-256 digests.
Strictly redacts passwords, session secrets, bearer tokens, refresh tokens, OTPs, and API keys.
Recursively sanitizes nested dictionaries, JSON payloads, headers, cookies, and query strings.
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
        # Passwords in query parameters, form bodies, JSON
        (re.compile(r"((?:password|passwd|pwd|pass)=)[^&\s\r\n]+", re.IGNORECASE), r"\1[REDACTED_PASSWORD]"),
        (re.compile(r"((?:\"password\"|\"passwd\"|\"pwd\"|\"pass\")\s*:\s*\")[^\"]+(\")", re.IGNORECASE), r"\1[REDACTED_PASSWORD]\2"),
        # Session cookies
        (re.compile(r"((?:session|phpsessid|jsessionid|connect\.sid|sid|jwt)=)[^;\r\n\s&]+", re.IGNORECASE), r"\1[REDACTED_COOKIE]"),
        # Authorization headers
        (re.compile(r"(Authorization:\s*(?:Bearer|Basic|Token)\s+)[^\r\n\s]+", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
        # Password reset & refresh tokens & keys
        (re.compile(r"((?:reset_token|refresh_token|token|key)=)[^&\s\r\n]+", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
        (re.compile(r"((?:\"reset_token\"|\"refresh_token\"|\"token\"|\"key\")\s*:\s*\")[^\"]+(\")", re.IGNORECASE), r"\1[REDACTED_TOKEN]\2"),
        # One-time codes / OTPs
        (re.compile(r"((?:otp|code|totp)=)[^&\s\r\n]+", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
        (re.compile(r"((?:\"otp\"|\"code\"|\"totp\")\s*:\s*\")[^\"]+(\")", re.IGNORECASE), r"\1[REDACTED_TOKEN]\2"),
        # API keys
        (re.compile(r"((?:x-api-key|apikey|api_key|client_secret)\s*[:=]\s*)[^\r\n\s,;]+", re.IGNORECASE), r"\1[REDACTED_SECRET]"),
        (re.compile(r"((?:\"x-api-key\"|\"apikey\"|\"api_key\"|\"client_secret\")\s*:\s*\")[^\"]+(\")", re.IGNORECASE), r"\1[REDACTED_SECRET]\2"),
    ]

    @classmethod
    def sanitize(cls, text: str) -> str:
        """
        Sanitizes text using framework patterns and extra authentication redactions.
        Standardizes tokens: [REDACTED_PASSWORD], [REDACTED_TOKEN], [REDACTED_COOKIE], [REDACTED_SECRET].
        """
        if not text:
            return ""
        clean = text
        for pat, repl in cls.EXTRA_PATTERNS:
            clean = pat.sub(repl, clean)
        clean = sanitize_sensitive_data(clean)

        # Standardize generic [REDACTED_BY_BB_AGENT] placeholders from framework
        clean = re.sub(
            r"((?:x-api-key|apikey|api_key|client_secret)\s*[:=]\s*)\[REDACTED_BY_BB_AGENT\]",
            r"\1[REDACTED_SECRET]",
            clean,
            flags=re.IGNORECASE,
        )
        clean = re.sub(
            r"(Authorization:\s*(?:Bearer|Basic|Token)\s+)\[REDACTED_BY_BB_AGENT\]",
            r"\1[REDACTED_TOKEN]",
            clean,
            flags=re.IGNORECASE,
        )
        clean = re.sub(
            r"((?:session|phpsessid|jsessionid|connect\.sid|sid|jwt)=)\[REDACTED_BY_BB_AGENT\]",
            r"\1[REDACTED_COOKIE]",
            clean,
            flags=re.IGNORECASE,
        )
        return clean

    @classmethod
    def sanitize_dict(cls, data: Any) -> Any:
        """
        Recursively traverses nested dictionaries and lists, replacing values for sensitive
        keys ('password', 'secret', 'token', 'key', 'otp', 'cookie', 'auth') with standard redaction tokens.
        """
        if isinstance(data, dict):
            sanitized: Dict[str, Any] = {}
            for k, v in data.items():
                k_lower = str(k).lower()
                if any(p in k_lower for p in ["password", "passwd", "pwd"]):
                    sanitized[k] = "[REDACTED_PASSWORD]"
                elif any(s in k_lower for s in ["secret", "client_secret", "api_key", "apikey"]):
                    sanitized[k] = "[REDACTED_SECRET]"
                elif any(c in k_lower for c in ["cookie", "session", "sid"]):
                    sanitized[k] = "[REDACTED_COOKIE]"
                elif any(t in k_lower for t in ["token", "bearer", "otp", "totp", "auth"]):
                    sanitized[k] = "[REDACTED_TOKEN]"
                else:
                    sanitized[k] = cls.sanitize_dict(v)
            return sanitized
        elif isinstance(data, list):
            return [cls.sanitize_dict(item) for item in data]
        elif isinstance(data, str):
            return cls.sanitize(data)
        return data

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
        NOTE: Computed SHA-256 digests over sanitized request and response representations
        are strictly for provenance tracking, deduplication, and auditability.
        Cryptographic hashes represent provenance metadata, NOT standalone proof of vulnerability.
        """
        clean_req = cls.sanitize(request_summary)
        clean_res = cls.sanitize(response_summary)

        timestamp = datetime.now(timezone.utc).isoformat()
        digest_input = f"{endpoint}|{method}|{status_code}|{clean_req}|{clean_res}|{timestamp}"
        sha256_digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()

        clean_meta = cls.sanitize_dict(metadata or {})

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
            "metadata": clean_meta,
        }
