"""
Evidence Manager and Data Sanitizer for BugBounty-Agent.

Preserves raw HTTP captures, requests, responses, and screenshots with cryptographic
hash integrity while redacting sensitive tokens, session cookies, and API keys.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import re
from typing import Any, Dict, Optional


# Regex patterns to sanitize sensitive tokens
_SENSITIVE_PATTERNS = [
    # Authorization headers (Bearer, Basic, Token, or raw credentials)
    (re.compile(r"((?:Authorization|Proxy-Authorization)\s*:\s*(?:Bearer|Basic|Token)?\s*)[^\r\n\s]+", re.IGNORECASE), r"\1[REDACTED_BY_BB_AGENT]"),
    # Cookie session tokens and identifiers
    (re.compile(r"((?<![a-zA-Z0-9_-])(?:session|sessionid|sess|jwt|token|access_token|auth|phpsessid|jsessionid|connect\.sid|sid)=)(?!(?:true|false|null|none|undefined)\b)[^;\r\n\s&]+", re.IGNORECASE), r"\1[REDACTED_BY_BB_AGENT]"),
    # API key patterns in headers / params
    (re.compile(r"((?<![a-zA-Z0-9_-])(?:x-api-key|api[_-]?key|secret[_-]?key|client[_-]?secret)\s*[:=]\s*)(?!(?:true|false|null|none|undefined)\b)[^\r\n\s,;\"'&]+", re.IGNORECASE), r"\1[REDACTED_BY_BB_AGENT]"),
    # Passwords and credentials in query params or form bodies
    (re.compile(r"((?<![a-zA-Z0-9_-])(?:password|passwd|pwd|pass|client_secret|access_key|secret_key)\s*[:=]\s*)(?!(?:true|false|null|none|undefined)\b)[^\r\n\s,;\"'&]+", re.IGNORECASE), r"\1[REDACTED_BY_BB_AGENT]"),
    # JSON / quoted credentials and secrets
    (re.compile(r"((?:\"(?:password|passwd|pwd|pass|client_secret|access_key|secret_key|api[_-]?key|apikey|reset_token|refresh_token|token|access_token)\"|'(?:password|passwd|pwd|pass|client_secret|access_key|secret_key|api[_-]?key|apikey|reset_token|refresh_token|token|access_token)')\s*:\s*[\"'])(?!(?:true|false|null|none|undefined)[\"'])[^\r\n\"']+([\"'])", re.IGNORECASE), r"\1[REDACTED_BY_BB_AGENT]\2"),
    # Private keys (RSA, EC, OPENSSH, DSA, ENCRYPTED, or any PEM private key)
    (re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----", re.IGNORECASE), "[REDACTED_PRIVATE_KEY_BY_BB_AGENT]"),
]



def sanitize_sensitive_data(text: str) -> str:
    """Replaces credentials, authorization tokens, and session cookies with redaction placeholder."""
    if not text:
        return ""
    sanitized = text
    for pattern, replacement in _SENSITIVE_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


class EvidenceStore:
    """Manages evidence files inside the local program workspace."""

    def __init__(self, evidence_dir: str):
        self.evidence_dir = os.path.abspath(evidence_dir)
        os.makedirs(self.evidence_dir, exist_ok=True)

    def save_http_capture(
        self,
        request_text: str,
        response_text: str,
        metadata: Optional[Dict[str, Any]] = None,
        prefix: str = "http",
    ) -> Dict[str, Any]:
        """
        Sanitizes and saves an HTTP request/response transaction.
        Calculates SHA-256 hash for provenance and non-repudiation.
        """
        clean_req = sanitize_sensitive_data(request_text)
        clean_res = sanitize_sensitive_data(response_text)

        combined = f"--- REQUEST ---\n{clean_req}\n\n--- RESPONSE ---\n{clean_res}\n"
        digest = hashlib.sha256(combined.encode("utf-8")).hexdigest()

        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{prefix}_{timestamp_str}_{digest[:8]}.txt"
        file_path = os.path.join(self.evidence_dir, filename)

        with open(file_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(combined)

        # Meta descriptor
        meta_filename = f"{prefix}_{timestamp_str}_{digest[:8]}.meta.json"
        meta_path = os.path.join(self.evidence_dir, meta_filename)
        meta_info = {
            "evidence_id": f"EVID-{digest[:12].upper()}",
            "filename": filename,
            "sha256": digest,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {},
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta_info, f, indent=2)

        return {
            "evidence_id": meta_info["evidence_id"],
            "path": file_path,
            "sha256": digest,
            "meta_path": meta_path,
        }
