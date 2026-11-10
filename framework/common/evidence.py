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
    (re.compile(r"((?:Authorization|Proxy-Authorization|X-Auth-Token|X-Api-Key)\s*:\s*(?:Bearer|Basic|Token)?\s*)[^\r\n\s]+", re.IGNORECASE), r"\1[REDACTED_BY_BB_AGENT]"),
    # Cookie session tokens and identifiers
    (re.compile(r"((?<![a-zA-Z0-9_-])(?:session|sessionid|sess|jwt|token|access_token|auth|phpsessid|jsessionid|connect\.sid|sid)=)(?!(?:true|false|null|none|undefined)\b)[^;\r\n\s&]+", re.IGNORECASE), r"\1[REDACTED_BY_BB_AGENT]"),
    # API key patterns in headers / params
    (re.compile(r"((?<![a-zA-Z0-9_-])(?:x-api-key|x-auth-token|api[_-]?key|api[_-]?token|secret[_-]?key|client[_-]?secret|token|access_token|auth_token|id_token|jwt|auth)\s*[:=]\s*)(?!(?:true|false|null|none|undefined)\b)[^\r\n\s,;\"'&]+", re.IGNORECASE), r"\1[REDACTED_BY_BB_AGENT]"),
    # Standalone JSON Web Tokens / tokens starting with eyJ (2 or 3 segments)
    (re.compile(r"\beyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)?\b"), "[REDACTED_JWT_BY_BB_AGENT]"),
    # Passwords and credentials in query params or form bodies
    (re.compile(r"((?<![a-zA-Z0-9_-])(?:password|passwd|pwd|pass|client_secret|access_key|secret_key)\s*[:=]\s*)(?!(?:true|false|null|none|undefined)\b)[^\r\n\s,;\"'&]+", re.IGNORECASE), r"\1[REDACTED_BY_BB_AGENT]"),
    # URL embedded credentials (e.g. http://user:password@domain)
    (re.compile(r"((?:https?|wss?|ftp)://[^:/?#\s]+:)[^@/?#\s]+(@)", re.IGNORECASE), r"\1[REDACTED_BY_BB_AGENT]\2"),
    # Sensitive URL query parameters in plain strings
    (re.compile(r"([?&](?:access_token|api[_-]?key|apikey|x-auth-token|api[_-]?token|auth_token|id_token|token|auth|secret|password|pwd|jwt)=)[^&#\s]+", re.IGNORECASE), r"\1[REDACTED_BY_BB_AGENT]"),
    # JSON / quoted credentials, headers, and secrets
    (re.compile(r"((?:\"(?:Authorization|Proxy-Authorization|X-Auth-Token|X-Api-Key|password|passwd|pwd|pass|client_secret|access_key|secret_key|api[_-]?key|apikey|api[_-]?token|auth_token|id_token|reset_token|refresh_token|token|access_token)\"|'(?:Authorization|Proxy-Authorization|X-Auth-Token|X-Api-Key|password|passwd|pwd|pass|client_secret|access_key|secret_key|api[_-]?key|apikey|api[_-]?token|auth_token|id_token|reset_token|refresh_token|token|access_token)')\s*:\s*[\"'])(?!(?:true|false|null|none|undefined)[\"'])[^\r\n\"']+([\"'])", re.IGNORECASE), r"\1[REDACTED_BY_BB_AGENT]\2"),
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

    def get_evidence(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves evidence descriptor by evidence ID from the evidence directory.
        Returns meta dict if found, or None if not found or malformed.
        """
        if not evidence_id or not isinstance(evidence_id, str):
            return None
        target_id = evidence_id.upper().strip()
        if not os.path.isdir(self.evidence_dir):
            return None

        try:
            for fname in sorted(os.listdir(self.evidence_dir)):
                if fname.endswith(".meta.json"):
                    meta_path = os.path.join(self.evidence_dir, fname)
                    try:
                        with open(meta_path, "r", encoding="utf-8") as f:
                            meta = json.load(f)
                        if isinstance(meta, dict) and meta.get("evidence_id") == target_id:
                            meta_copy = dict(meta)
                            meta_copy["meta_path"] = meta_path
                            filename = meta_copy.get("filename")
                            if filename and isinstance(filename, str):
                                meta_copy["capture_path"] = os.path.join(self.evidence_dir, os.path.basename(filename))
                            return meta_copy
                    except Exception:
                        continue
        except Exception:
            return None
        return None

    def save_invalidation_attestation(self, attestation_record: Dict[str, Any]) -> str:
        """
        Persists an authenticated invalidation event attestation record.
        Saves as attestation_<original_evidence_ref>.att.json in evidence_dir.
        Returns attestation_id.
        """
        if not isinstance(attestation_record, dict):
            raise ValueError("Attestation record must be a dictionary")
        att_id = attestation_record.get("attestation_id")
        orig_ref = attestation_record.get("original_evidence_ref")
        if not att_id or not orig_ref:
            raise ValueError("Attestation record missing required attestation_id or original_evidence_ref")

        orig_clean = str(orig_ref).strip().upper()
        att_clean = str(att_id).strip().upper()
        filename = f"attestation_{att_clean}.att.json"
        att_path = os.path.join(self.evidence_dir, filename)

        with open(att_path, "w", encoding="utf-8") as f:
            json.dump(attestation_record, f, indent=2)

        # Also persist direct lookup alias by original evidence reference
        orig_alias_path = os.path.join(self.evidence_dir, f"attestation_{orig_clean}.att.json")
        try:
            with open(orig_alias_path, "w", encoding="utf-8") as f:
                json.dump(attestation_record, f, indent=2)
        except Exception:
            pass

        return str(att_id)

    def get_invalidation_attestation(self, reference: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves an invalidation event attestation record by attestation ID (ATT-...)
        or by associated original evidence reference (EVID-...).
        Returns dict copy with att_path, or None if not found or malformed.
        """
        if not reference or not isinstance(reference, str):
            return None
        target_ref = reference.strip().upper()
        if not os.path.isdir(self.evidence_dir):
            return None

        # 1. Direct lookup by original_evidence_ref
        direct_path = os.path.join(self.evidence_dir, f"attestation_{target_ref}.att.json")
        if os.path.isfile(direct_path):
            try:
                with open(direct_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    data_copy = dict(data)
                    data_copy["att_path"] = direct_path
                    return data_copy
            except Exception:
                pass

        # 2. Iterate all .att.json files for matching attestation_id or original_evidence_ref
        try:
            for fname in sorted(os.listdir(self.evidence_dir)):
                if fname.endswith(".att.json"):
                    att_path = os.path.join(self.evidence_dir, fname)
                    try:
                        with open(att_path, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        if isinstance(data, dict):
                            stored_att_id = str(data.get("attestation_id", "")).strip().upper()
                            stored_orig_ref = str(data.get("original_evidence_ref", "")).strip().upper()
                            if stored_att_id == target_ref or stored_orig_ref == target_ref:
                                data_copy = dict(data)
                                data_copy["att_path"] = att_path
                                return data_copy
                    except Exception:
                        continue
        except Exception:
            return None
        return None
