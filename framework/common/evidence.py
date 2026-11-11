"""
Evidence Manager and Data Sanitizer for BugBounty-Agent.

Preserves raw HTTP captures, requests, responses, and screenshots with cryptographic
hash integrity while redacting sensitive tokens, session cookies, and API keys.
Enforces private permissions, symlink rejection, atomic writes, and fail-closed digest verification.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import re
import secrets
import stat
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

SAFE_PREFIX_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


class EvidencePersistenceError(Exception):
    """Raised when evidence persistence, permission setting, or integrity verification fails."""
    pass


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
        self._enforce_directory_security()

    def _enforce_directory_security(self) -> None:
        """Verifies that evidence_dir is secure, rejecting symlinks and loose permissions."""
        if os.path.islink(self.evidence_dir):
            raise ValueError(f"Evidence directory '{self.evidence_dir}' is a symbolic link")
        if os.name == "nt":
            from framework.auth_correlation.state import _enforce_windows_directory_dacl, _verify_windows_directory_security
            _enforce_windows_directory_dacl(self.evidence_dir)
            _verify_windows_directory_security(self.evidence_dir)
        else:
            st = os.lstat(self.evidence_dir)
            if st.st_uid != os.getuid():
                raise ValueError("Evidence directory ownership mismatch")
            if st.st_mode & 0o077 != 0:
                try:
                    os.chmod(self.evidence_dir, 0o700)
                except OSError:
                    pass
            st_after = os.lstat(self.evidence_dir)
            if st_after.st_mode & 0o077 != 0:
                raise ValueError("Evidence directory permissions are not private (0700 required)")

    def is_writable(self) -> bool:
        """Verifies that the evidence directory exists, is secure, and is writable."""
        try:
            if not os.path.isdir(self.evidence_dir) or os.path.islink(self.evidence_dir):
                return False
            test_fname = f".write_test_{os.getpid()}_{secrets.token_hex(4)}.tmp"
            test_path = os.path.join(self.evidence_dir, test_fname)
            with open(test_path, "w", encoding="utf-8") as f:
                f.write("probe")
            os.remove(test_path)
            return True
        except Exception:
            return False

    def _save_capture_internal(
        self,
        request_text: str,
        response_text: str,
        metadata: Optional[Dict[str, Any]] = None,
        prefix: str = "http",
    ) -> Dict[str, Any]:
        """Internal atomic capture writer applying OS-specific file security."""
        clean_prefix = prefix.strip()
        if not SAFE_PREFIX_PATTERN.match(clean_prefix):
            clean_prefix = "http"

        clean_req = sanitize_sensitive_data(request_text)
        clean_res = sanitize_sensitive_data(response_text)

        req_digest = hashlib.sha256(clean_req.encode("utf-8")).hexdigest()
        res_digest = hashlib.sha256(clean_res.encode("utf-8")).hexdigest()

        combined = f"--- REQUEST ---\n{clean_req}\n\n--- RESPONSE ---\n{clean_res}\n"
        digest = hashlib.sha256(combined.encode("utf-8")).hexdigest()

        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{clean_prefix}_{timestamp_str}_{digest[:8]}.txt"
        file_path = os.path.join(self.evidence_dir, filename)

        # Atomic write of capture content
        tmp_capture = f"{file_path}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
        with open(tmp_capture, "w", encoding="utf-8", newline="\n") as f:
            f.write(combined)
        if os.name == "nt":
            from framework.auth_correlation.state import _enforce_windows_file_dacl, _verify_windows_file_security
            _enforce_windows_file_dacl(tmp_capture)
            _verify_windows_file_security(tmp_capture)
        else:
            try:
                os.chmod(tmp_capture, 0o600)
                st = os.stat(tmp_capture)
                if (st.st_mode & 0o077 != 0) or ((st.st_mode & 0o777) != 0o600):
                    raise EvidencePersistenceError("Failed to enforce private POSIX permissions (0o600) on capture")
            except Exception as e:
                if os.path.exists(tmp_capture):
                    try:
                        os.remove(tmp_capture)
                    except OSError:
                        pass
                if isinstance(e, EvidencePersistenceError):
                    raise
                raise EvidencePersistenceError(f"Failed to set private POSIX file permissions on capture: {e}")
        os.replace(tmp_capture, file_path)

        # Meta descriptor
        meta_filename = f"{clean_prefix}_{timestamp_str}_{digest[:8]}.meta.json"
        meta_path = os.path.join(self.evidence_dir, meta_filename)
        meta_info = {
            "evidence_id": f"EVID-{digest[:12].upper()}",
            "filename": filename,
            "sha256": digest,
            "request_sha256": req_digest,
            "response_sha256": res_digest,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {},
        }
        tmp_meta = f"{meta_path}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
        with open(tmp_meta, "w", encoding="utf-8") as f:
            json.dump(meta_info, f, indent=2)
        if os.name == "nt":
            from framework.auth_correlation.state import _enforce_windows_file_dacl, _verify_windows_file_security
            _enforce_windows_file_dacl(tmp_meta)
            _verify_windows_file_security(tmp_meta)
        else:
            try:
                os.chmod(tmp_meta, 0o600)
                st = os.stat(tmp_meta)
                if (st.st_mode & 0o077 != 0) or ((st.st_mode & 0o777) != 0o600):
                    raise EvidencePersistenceError("Failed to enforce private POSIX permissions (0o600) on metadata")
            except Exception as e:
                if os.path.exists(tmp_meta):
                    try:
                        os.remove(tmp_meta)
                    except OSError:
                        pass
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except OSError:
                        pass
                if isinstance(e, EvidencePersistenceError):
                    raise
                raise EvidencePersistenceError(f"Failed to set private POSIX file permissions on metadata: {e}")
        os.replace(tmp_meta, meta_path)

        return {
            "evidence_id": meta_info["evidence_id"],
            "path": file_path,
            "sha256": digest,
            "meta_path": meta_path,
            "request_sha256": req_digest,
            "response_sha256": res_digest,
        }

    def save_http_capture(
        self,
        request_text: str,
        response_text: str,
        metadata: Optional[Dict[str, Any]] = None,
        prefix: str = "http",
    ) -> Dict[str, Any]:
        """
        Sanitizes and saves an HTTP request/response transaction atomically.
        Calculates SHA-256 hash for provenance and non-repudiation.
        Enforces that ordinary callers cannot forge transport provenance metadata.
        """
        user_meta = dict(metadata or {})
        # Reject attempts by ordinary callers to forge transport provenance
        if (
            user_meta.get("capture_source") == "CONTROLLED_TRANSPORT_DISPATCH"
            or user_meta.get("evidence_class") == "CONTROLLED_TRANSPORT_DISPATCH"
        ):
            raise ValueError("Ordinary callers cannot specify controlled transport capture_source metadata")

        user_meta.setdefault("capture_source", "CALLER_SUPPLIED")
        user_meta.setdefault("evidence_class", "CALLER_SUPPLIED")
        return self._save_capture_internal(
            request_text=request_text,
            response_text=response_text,
            metadata=user_meta,
            prefix=prefix,
        )

    def save_transport_dispatch_capture(
        self,
        request: Any,
        response: Any,
        action_id: str,
        approval_id: str,
        session_ref: str,
        principal_id: str,
        program_id: str,
        dispatch_op_id: str,
        is_verification: bool = False,
        verification_method: Optional[str] = None,
        prefix: str = "controlled_transport",
    ) -> Dict[str, Any]:
        """
        Trusted transport boundary evidence writer.
        Invoked strictly during active, verified controlled transport dispatch by ControlledDispatchWorkflow.
        Extracts application-level transport representations from authentic ControlledRequest and ControlledResponse objects,
        binds dispatch_op_id and attribution metadata, and marks capture_source and evidence_class
        as CONTROLLED_TRANSPORT_DISPATCH.
        """
        raise EvidencePersistenceError(
            "Trusted transport capture is disabled: caller-supplied request/response objects cannot prove transport dispatch"
        )

        if not dispatch_op_id or not isinstance(dispatch_op_id, str) or not dispatch_op_id.startswith("DISP-OP-"):
            raise ValueError("Invalid dispatch_op_id: must be a valid DISP-OP identifier")
        if not action_id or not isinstance(action_id, str) or not action_id.startswith("ACT-"):
            raise ValueError("Invalid action_id for controlled transport capture")
        if not approval_id or not isinstance(approval_id, str):
            raise ValueError("Invalid approval_id for controlled transport capture")
        if not session_ref or not isinstance(session_ref, str):
            raise ValueError("Invalid session_ref for controlled transport capture")
        if not principal_id or not isinstance(principal_id, str):
            raise ValueError("Invalid principal_id for controlled transport capture")
        if not program_id or not isinstance(program_id, str):
            raise ValueError("Invalid program_id for controlled transport capture")

        if not hasattr(request, "get_sanitized_representation"):
            raise ValueError("request must be an authentic ControlledRequest object")
        if not hasattr(response, "get_sanitized_representation"):
            raise ValueError("response must be an authentic ControlledResponse object")

        req_text = request.get_sanitized_representation()
        res_text = response.get_sanitized_representation()

        metadata: Dict[str, Any] = {
            "capture_source": "CONTROLLED_TRANSPORT_DISPATCH",
            "evidence_class": "CONTROLLED_TRANSPORT_DISPATCH",
            "dispatch_op_id": dispatch_op_id,
            "action_id": action_id,
            "approval_id": approval_id,
            "session_ref": session_ref,
            "principal_id": principal_id,
            "program_id": program_id,
            "event_type": "SESSION_REVOCATION",
            "is_verification": bool(is_verification),
        }
        if verification_method:
            metadata["verification_method"] = verification_method

        return self._save_capture_internal(
            request_text=req_text,
            response_text=res_text,
            metadata=metadata,
            prefix=prefix,
        )

    def get_evidence(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves evidence descriptor by evidence ID from the evidence directory.
        Verifies that the capture file exists on disk, is a regular file within evidence_dir,
        and recomputes SHA-256 byte digest to ensure byte integrity.
        Also recomputes and verifies individual request and response SHA-256 digests.
        Returns meta dict if valid and uncorrupted, or None if not found, malformed, or tampered.
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
                    if os.path.islink(meta_path):
                        continue
                    if os.name == "nt":
                        m_stat = os.lstat(meta_path)
                        if hasattr(m_stat, "st_file_attributes") and (m_stat.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
                            continue
                    try:
                        with open(meta_path, "r", encoding="utf-8") as f:
                            meta = json.load(f)
                        if isinstance(meta, dict) and meta.get("evidence_id") == target_id:
                            filename = meta.get("filename")
                            if not filename or not isinstance(filename, str):
                                continue
                            # Prevent directory traversal
                            base_filename = os.path.basename(filename)
                            if base_filename != filename or ".." in filename or "/" in filename or "\\" in filename:
                                continue

                            capture_path = os.path.join(self.evidence_dir, base_filename)
                            if not os.path.isfile(capture_path) or os.path.islink(capture_path):
                                continue
                            if os.name == "nt":
                                c_stat = os.lstat(capture_path)
                                if hasattr(c_stat, "st_file_attributes") and (c_stat.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
                                    continue

                            # Verify capture file is inside evidence_dir
                            real_dir = os.path.realpath(self.evidence_dir)
                            real_cap = os.path.realpath(capture_path)
                            if os.path.commonpath([real_dir, real_cap]) != real_dir:
                                continue

                            # Recompute SHA-256 byte digest
                            stored_sha256 = meta.get("sha256", "")
                            with open(capture_path, "rb") as cf:
                                actual_digest = hashlib.sha256(cf.read()).hexdigest()
                            if actual_digest.lower() != stored_sha256.lower():
                                continue

                            # Recompute request and response SHA-256 digests
                            with open(capture_path, "r", encoding="utf-8", errors="replace") as cf_text:
                                combined_content = cf_text.read()
                            parts = combined_content.split("\n\n--- RESPONSE ---\n", 1)
                            if len(parts) == 2 and parts[0].startswith("--- REQUEST ---\n"):
                                req_part = parts[0][len("--- REQUEST ---\n"):]
                                res_part = parts[1]
                                if res_part.endswith("\n"):
                                    res_part = res_part[:-1]
                                act_req_sha = hashlib.sha256(req_part.encode("utf-8")).hexdigest()
                                act_res_sha = hashlib.sha256(res_part.encode("utf-8")).hexdigest()
                                stored_req_sha = meta.get("request_sha256", "")
                                stored_res_sha = meta.get("response_sha256", "")
                                if act_req_sha.lower() != stored_req_sha.lower() or act_res_sha.lower() != stored_res_sha.lower():
                                    continue
                            else:
                                continue

                            meta_copy = dict(meta)
                            meta_copy["meta_path"] = meta_path
                            meta_copy["capture_path"] = capture_path
                            return meta_copy
                    except Exception:
                        continue
        except Exception:
            return None
        return None

    def save_invalidation_attestation(self, attestation_record: Dict[str, Any]) -> str:
        """
        Persists an authenticated invalidation event attestation record atomically.
        Saves as attestation_<attestation_id>.att.json in evidence_dir with an alias
        attestation_<original_evidence_ref>.att.json.
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

        # Atomic write of primary attestation record
        tmp_att = f"{att_path}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
        with open(tmp_att, "w", encoding="utf-8") as f:
            json.dump(attestation_record, f, indent=2)
        if os.name == "nt":
            from framework.auth_correlation.state import _enforce_windows_file_dacl, _verify_windows_file_security
            _enforce_windows_file_dacl(tmp_att)
            _verify_windows_file_security(tmp_att)
        os.replace(tmp_att, att_path)

        # Also persist direct lookup alias by original evidence reference atomically
        orig_alias_path = os.path.join(self.evidence_dir, f"attestation_{orig_clean}.att.json")
        try:
            tmp_alias = f"{orig_alias_path}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
            with open(tmp_alias, "w", encoding="utf-8") as f:
                json.dump(attestation_record, f, indent=2)
            os.replace(tmp_alias, orig_alias_path)
        except Exception:
            pass

        return str(att_id)

    def get_invalidation_attestation(self, reference: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves an invalidation event attestation record by attestation ID (ATT-...)
        or by associated original evidence reference (EVID-...).
        Verifies that the attestation file is a regular file within evidence_dir and not a symlink.
        Returns dict copy with att_path, or None if not found or malformed.
        """
        if not reference or not isinstance(reference, str):
            return None
        target_ref = reference.strip().upper()
        if not os.path.isdir(self.evidence_dir):
            return None

        # 1. Direct lookup by original_evidence_ref
        direct_path = os.path.join(self.evidence_dir, f"attestation_{target_ref}.att.json")
        if os.path.isfile(direct_path) and not os.path.islink(direct_path):
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
                    if os.path.islink(att_path) or not os.path.isfile(att_path):
                        continue
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
