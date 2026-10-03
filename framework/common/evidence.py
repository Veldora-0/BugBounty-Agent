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
    # Authorization Bearer / Basic
    (re.compile(r"(Authorization:\s*(?:Bearer|Basic|Token)\s+)[^\r\n\s]+", re.IGNORECASE), r"\1[REDACTED_BY_BB_AGENT]"),
    # Cookie session tokens
    (re.compile(r"((?:session|sessionid|sess|jwt|token|access_token|auth|phpsessid|jsessionid)=)[^;\r\n\s]+", re.IGNORECASE), r"\1[REDACTED_BY_BB_AGENT]"),
    # API key patterns in headers / params
    (re.compile(r"((?:api[_-]?key|secret[_-]?key|client[_-]?secret)\s*[:=]\s*)[^\r\n\s,;]+", re.IGNORECASE), r"\1[REDACTED_BY_BB_AGENT]"),
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

        with open(file_path, "w", encoding="utf-8") as f:
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
