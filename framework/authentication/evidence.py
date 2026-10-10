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
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

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
        # Password reset & refresh tokens & keys in query params or bodies
        (re.compile(r"((?:reset_token|refresh_token|access_token|id_token|token|key)=)[^&\s\r\n\"'>]+", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
        (re.compile(r"((?:\"reset_token\"|\"refresh_token\"|\"access_token\"|\"token\"|\"key\")\s*:\s*\")[^\"]+(\")", re.IGNORECASE), r"\1[REDACTED_TOKEN]\2"),
        # One-time codes / OTPs
        (re.compile(r"((?:otp|code|totp)=)[^&\s\r\n\"'>]+", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
        (re.compile(r"((?:\"otp\"|\"code\"|\"totp\")\s*:\s*\")[^\"]+(\")", re.IGNORECASE), r"\1[REDACTED_TOKEN]\2"),
        # API keys
        (re.compile(r"((?:x-api-key|apikey|api_key|client_secret)\s*[:=]\s*)[^\r\n\s,;]+", re.IGNORECASE), r"\1[REDACTED_SECRET]"),
        (re.compile(r"((?:\"x-api-key\"|\"apikey\"|\"api_key\"|\"client_secret\")\s*:\s*\")[^\"]+(\")", re.IGNORECASE), r"\1[REDACTED_SECRET]\2"),
        # Sensitive tokens and keys in plain identifiers or strings
        (re.compile(r"((?:user|identity|principal|id)[_-])(?:jwt|token|secret|api[_-]?key)[_-][a-zA-Z0-9_-]+", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
        (re.compile(r"\b(?:jwt|token|secret|reset_token|refresh_token|api[_-]?key)[_-][a-zA-Z0-9_-]{6,}\b", re.IGNORECASE), "[REDACTED_TOKEN]"),
    ]

    @classmethod
    def sanitize_url(cls, url: str) -> str:
        """
        Sanitizes sensitive query parameters, fragments, and credentials in URLs.
        Preserves scheme, host, path, and non-sensitive query parameters while redacting
        passwords, reset tokens, session identifiers, API keys, OTPs, and secrets.
        """
        if not url:
            return ""
        try:
            parts = urlsplit(url)
            # Redact user info in netloc (e.g. user:pass@host)
            netloc = parts.netloc
            if "@" in netloc:
                userinfo, host = netloc.rsplit("@", 1)
                if ":" in userinfo:
                    uname, _ = userinfo.split(":", 1)
                    netloc = f"{uname}:[REDACTED_PASSWORD]@{host}"
                else:
                    netloc = f"[REDACTED_USER]@{host}"

            # Redact query parameters
            query_items = parse_qsl(parts.query, keep_blank_values=True)
            sanitized_qsl: List[Tuple[str, str]] = []
            for k, v in query_items:
                k_lower = k.lower()
                if any(p in k_lower for p in ["password", "passwd", "pwd", "pass"]):
                    sanitized_qsl.append((k, "[REDACTED_PASSWORD]"))
                elif any(s in k_lower for s in ["secret", "client_secret", "api_key", "apikey"]):
                    sanitized_qsl.append((k, "[REDACTED_SECRET]"))
                elif any(c in k_lower for c in ["cookie", "session", "sid", "phpsessid", "jsessionid"]):
                    sanitized_qsl.append((k, "[REDACTED_COOKIE]"))
                elif any(t in k_lower for t in ["token", "reset_token", "refresh_token", "access_token", "key", "otp", "code", "totp", "auth", "sig", "signature"]):
                    sanitized_qsl.append((k, "[REDACTED_TOKEN]"))
                else:
                    sanitized_qsl.append((k, cls.sanitize(v)))

            clean_query = urlencode(sanitized_qsl, safe="[]") if query_items else ""
            clean_frag = cls.sanitize(parts.fragment) if parts.fragment else ""

            return urlunsplit((parts.scheme, netloc, parts.path, clean_query, clean_frag))
        except Exception:
            # Fallback to regex-based sanitization if urlsplit fails
            return cls.sanitize(url)

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
        Recursively traverses nested dictionaries, lists, and primitives, replacing values
        for sensitive keys ('password', 'secret', 'token', 'key', 'otp', 'cookie', 'auth')
        and sensitive query parameters with standard redaction tokens.
        """
        if isinstance(data, dict):
            sanitized: Dict[str, Any] = {}
            container_keys = {"surfaces", "identities", "flows", "sessions", "hypotheses", "findings", "tokens", "evidence", "attributes", "metadata", "cookies", "headers"}
            for k, v in data.items():
                k_lower = str(k).lower()
                if isinstance(v, (dict, list)):
                    sanitized[k] = cls.sanitize_dict(v)
                elif k_lower in container_keys:
                    sanitized[k] = cls.sanitize_dict(v)
                elif any(p in k_lower for p in ["password", "passwd", "pwd"]):
                    sanitized[k] = "[REDACTED_PASSWORD]"
                elif any(s in k_lower for s in ["secret", "client_secret", "api_key", "apikey"]):
                    sanitized[k] = "[REDACTED_SECRET]"
                elif any(c in k_lower for c in ["cookie", "session", "sid", "phpsessid", "jsessionid"]):
                    sanitized[k] = "[REDACTED_COOKIE]"
                elif any(t in k_lower for t in ["token", "bearer", "otp", "totp", "auth"]) and not k_lower.endswith("_status") and not k_lower.endswith("_type"):
                    sanitized[k] = "[REDACTED_TOKEN]"
                elif k_lower in ("url", "endpoint", "target", "uri", "redirect", "location"):
                    sanitized[k] = cls.sanitize_url(str(v)) if isinstance(v, str) else cls.sanitize_dict(v)
                else:
                    sanitized[k] = cls.sanitize_dict(v)
            return sanitized
        elif isinstance(data, list):
            return [cls.sanitize_dict(item) for item in data]
        elif isinstance(data, str):
            if "://" in data or "?" in data:
                return cls.sanitize_url(data)
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
        clean_endpoint = cls.sanitize_url(endpoint)
        clean_req = cls.sanitize(request_summary)
        clean_res = cls.sanitize(response_summary)

        timestamp = datetime.now(timezone.utc).isoformat()
        digest_input = f"{clean_endpoint}|{method}|{status_code}|{clean_req}|{clean_res}|{timestamp}"
        sha256_digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()

        clean_meta = cls.sanitize_dict(metadata or {})

        return {
            "evidence_id": f"ev_{sha256_digest[:16]}",
            "endpoint": clean_endpoint,
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

