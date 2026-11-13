"""
Phase 21: Isolated Execution Dispatcher Service.

The independent execution authority that owns:
1. Operator approval verification and atomic single-use consumption.
2. Immediate pre-execution scope and destination validation (SSRF defense).
3. Network transport execution (mutation and verification probe).
4. Raw transport evidence capture and disk persistence.
5. Cryptographic signing of ExecutionReceipts using a dedicated private key.

Operates over Unix Domain Sockets on Linux/POSIX and Named Pipes on Windows.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import stat
import struct
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from framework.auth_correlation.ipc.protocol import (
    MAX_MESSAGE_BYTES,
    PROTOCOL_VERSION,
    ALLOWED_ACTION_TYPES,
    ALLOWED_DOSSIER_KEYS,
    ALLOWED_MUTATION_METHODS,
    IPCProtocolError,
    IPCValidationError,
    pack_message,
    read_framed_message,
    validate_request_frame,
)
from framework.auth_correlation.ipc.receipt import (
    canonicalize_receipt,
    sign_execution_receipt,
)
from framework.auth_correlation.state import (
    CrossProcessFileLock,
    _enforce_windows_directory_dacl,
    _enforce_windows_file_dacl,
    _verify_windows_directory_security,
    _verify_windows_file_security,
)
from framework.common.evidence import sanitize_sensitive_data
from framework.validation.request import ControlledRequest, ControlledResponse


CANONICAL_ACTION_FIELDS = (
    "action_type",
    "created_at",
    "method",
    "program_id",
    "target_endpoint",
    "test_account",
    "ttl",
    "unique_approval_id",
)

NEGATIVE_REVOCATION_PHRASES = (
    "not revoked",
    "was not revoked",
    "is not revoked",
    "has not been revoked",
    "never revoked",
    "failed to revoke",
    "could not revoke",
    "revocation failed",
    "session active",
    "session still active",
    "still logged in",
    "not logged out",
    "logout failed",
    "logout unsuccessful",
    "logout error",
    "unable to logout",
    "token is valid",
    "token still valid",
    "unauthorized access denied",
)

PROHIBITED_METADATA_HOSTS = frozenset({
    "169.254.169.254",
    "metadata.google.internal",
    "100.100.100.200",
    "fd00:ec2::254",
})


class IsolatedExecutionDispatcher:
    """
    Dedicated execution authority service for Mode B controlled invalidation.
    """

    def __init__(
        self,
        program_id: str = "default-program",
        socket_path: Optional[str] = None,
        pipe_name: Optional[str] = None,
        key_dir: Optional[str] = None,
        state_dir: Optional[str] = None,
        evidence_dir: Optional[str] = None,
        signing_key: Optional[bytes] = None,
        approval_key: Optional[bytes] = None,
        transport_engine: Optional[Any] = None,
        scope_engine: Optional[Any] = None,
        is_lab: bool = False,
    ):
        self.program_id = program_id
        self.is_lab = is_lab
        self.transport_engine = transport_engine
        self.scope_engine = scope_engine

        # Configure directories
        base_dir = os.path.expanduser("~/.config/bugbounty-agent") if os.name != "nt" else os.environ.get("TEMP", "C:\\temp")
        self.key_dir = os.path.abspath(key_dir or os.path.join(base_dir, "dispatcher_keys"))
        self.state_dir = os.path.abspath(state_dir or os.path.join(base_dir, "dispatcher_state"))
        self.evidence_dir = os.path.abspath(evidence_dir or os.path.join(base_dir, "dispatcher_evidence"))

        os.makedirs(self.key_dir, exist_ok=True)
        os.makedirs(self.state_dir, exist_ok=True)
        os.makedirs(self.evidence_dir, exist_ok=True)

        if os.name == "nt":
            _enforce_windows_directory_dacl(self.key_dir)
            _enforce_windows_directory_dacl(self.state_dir)
        else:
            try:
                os.chmod(self.key_dir, 0o700)
                os.chmod(self.state_dir, 0o700)
            except OSError as e:
                raise PermissionError(f"Failed to enforce private permissions (0700) on dispatcher directory: {e}")

        from framework.common.evidence import EvidenceStore
        self._authority_token = secrets.token_hex(32)
        self._evidence_store = EvidenceStore(self.evidence_dir, authority_token=self._authority_token)

        # Operator approval key and Dispatcher private signing key
        self.approval_key = approval_key
        if self.approval_key is None and not self.is_lab:
            key_file = os.path.join(self.key_dir, "operator_approval.key")
            if os.path.exists(key_file):
                with open(key_file, "rb") as f:
                    self.approval_key = f.read().strip()
        self.signing_key = signing_key or self._get_or_create_signing_key()
        self.dispatcher_id = f"DISPATCHER-{secrets.token_hex(8).upper()}"
        self.dispatcher_key_id = "KEY-DISPATCHER-V1"

        # IPC endpoint setup
        self.endpoint_type = "pipe" if os.name == "nt" else "unix"
        if self.endpoint_type == "pipe":
            self.endpoint_address = pipe_name or rf"\\.\pipe\bugbounty_dispatcher_{secrets.token_hex(4)}"
        else:
            self.endpoint_address = socket_path or os.path.join(self.state_dir, "dispatcher.sock")

        self._server_thread: Optional[threading.Thread] = None
        self._running = False
        self._listener_obj: Optional[Any] = None
        self._consumed_lock = threading.Lock()

    def _get_or_create_signing_key(self) -> bytes:
        """Loads or securely provisions the private dispatcher signing key."""
        key_file = os.path.join(self.key_dir, "dispatcher_signing_key.bin")
        if os.path.exists(key_file):
            if os.name == "nt":
                _enforce_windows_file_dacl(key_file)
            else:
                try:
                    os.chmod(key_file, 0o600)
                except OSError as e:
                    raise PermissionError(f"Failed to enforce private permissions (0600) on dispatcher key file: {e}")
            with open(key_file, "rb") as f:
                key = f.read()
            if len(key) >= 32:
                return key

        key = secrets.token_bytes(32)
        flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        fd = os.open(key_file, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(key)
            if os.name == "nt":
                _enforce_windows_file_dacl(key_file)
            else:
                try:
                    os.chmod(key_file, 0o600)
                except OSError as e:
                    raise PermissionError(f"Failed to enforce private permissions (0600) on dispatcher key file: {e}")
        except Exception as e:
            if os.path.exists(key_file):
                try:
                    os.remove(key_file)
                except OSError:
                    pass
            raise PermissionError(f"Failed to initialize dispatcher signing key: {e}")
        return key

    def _get_consumed_registry_path(self) -> str:
        return os.path.join(self.state_dir, "consumed_approvals.json")

    def _get_consumed_lock_path(self) -> str:
        return os.path.join(self.state_dir, "consumed_approvals.lock")

    def _validate_scope_and_destination(self, target_endpoint: str) -> None:
        """
        Validates target destination immediately before transport dispatch:
        - Scheme must be http or https
        - Port must be valid (1-65535)
        - Hostname cannot be a prohibited cloud metadata IP or loopback escape
        - Passes ScopeEngine (mandatory for production dispatches)
        """
        parsed = urlparse(target_endpoint)
        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError(f"Target endpoint specifies unsupported scheme: '{parsed.scheme}'")

        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        if port < 1 or port > 65535:
            raise ValueError(f"Target endpoint specifies invalid port: {port}")

        host = (parsed.hostname or "").lower()
        if not host:
            raise ValueError("Target endpoint missing hostname")

        if host in PROHIBITED_METADATA_HOSTS:
            raise ValueError(f"Prohibited cloud metadata destination: '{host}'")

        # Disallow loopback unless explicitly running in local simulation/lab mode
        is_loopback = host in ("127.0.0.1", "localhost", "::1") or host.startswith("127.")
        if is_loopback and not self.is_lab and not hasattr(self.transport_engine, "lab_port"):
            raise ValueError(f"Loopback destination '{host}' is prohibited outside deterministic simulation lab")

        # Production dispatch requires authoritative ScopeEngine
        if not self.is_lab and self.scope_engine is None:
            raise ValueError("ScopeEngine is mandatory for production dispatch; missing scope configuration")

        if self.scope_engine is not None and not self.is_lab:
            try:
                if hasattr(self.scope_engine, "is_in_scope"):
                    in_scope = self.scope_engine.is_in_scope(target_endpoint)
                elif hasattr(self.scope_engine, "check"):
                    dec = self.scope_engine.check(target_endpoint)
                    in_scope = (getattr(dec, "status", None) == "IN_SCOPE")
                else:
                    in_scope = False
                if not in_scope:
                    raise ValueError(f"Target endpoint '{target_endpoint}' is out of configured program scope")
            except ValueError:
                raise
            except Exception as e:
                raise ValueError(f"Scope verification failed for controlled mutation: {e}")

    def _atomically_consume_approval(
        self,
        action_id: str,
        action_dossier: Dict[str, Any],
        session_ctx: Dict[str, Any],
        dispatch_op_id: str,
    ) -> str:
        """
        Consumes the action approval single-use under durable CrossProcessFileLock.
        Rejects replay attempts immediately.
        """
        consumed_path = self._get_consumed_registry_path()
        lock_path = self._get_consumed_lock_path()
        consumption_token = secrets.token_hex(32)
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        with self._consumed_lock, CrossProcessFileLock(lock_path):
            reg: Dict[str, Any] = {"version": 1, "consumed": {}}
            if os.path.exists(consumed_path):
                try:
                    with open(consumed_path, "r", encoding="utf-8") as f:
                        reg = json.load(f)
                    if not isinstance(reg, dict) or "consumed" not in reg:
                        reg = {"version": 1, "consumed": {}}
                except Exception as e:
                    raise ValueError(f"Consumed approvals registry corrupted: {e}")

            if action_id in reg.get("consumed", {}):
                raise ValueError(f"Action approval '{action_id}' has already been consumed (replay rejected)")

            rec = {
                "action_dossier_digest": action_id[4:],
                "action_id": action_id,
                "action_type": action_dossier.get("action_type"),
                "approval_id": action_dossier.get("unique_approval_id"),
                "consumed_at": now_iso,
                "consumption_token": consumption_token,
                "dispatch_op_id": dispatch_op_id,
                "method": action_dossier.get("method"),
                "operator_signature": action_dossier.get("approval_signature"),
                "principal_id": session_ctx.get("principal_id"),
                "program_id": action_dossier.get("program_id") or self.program_id,
                "session_ref": session_ctx.get("session_ref"),
                "target_endpoint": action_dossier.get("target_endpoint"),
                "test_account": action_dossier.get("test_account"),
                "action_dossier": action_dossier,
            }
            if self.approval_key is not None:
                from framework.auth_correlation.ledger import sign_consumption_receipt
                rec["receipt_signature"] = sign_consumption_receipt(rec, self.approval_key)
            reg["consumed"][action_id] = rec

            tmp_path = f"{consumed_path}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
            flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            fd = os.open(tmp_path, flags, 0o600)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(reg, f, indent=2)
                if os.name == "nt":
                    _enforce_windows_file_dacl(tmp_path)
                os.replace(tmp_path, consumed_path)
            except Exception as e:
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass
                raise ValueError(f"Failed to record consumed approval: {e}")

        return consumption_token

    def _persist_evidence(
        self,
        prefix: str,
        request: ControlledRequest,
        response: ControlledResponse,
        dispatch_op_id: str,
        action_id: str,
        approval_id: str,
        session_ref: str,
        principal_id: str,
        program_id: str,
        is_verification: bool = False,
        verification_method: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Persists raw transport request and response capture directly to protected evidence store.
        Returns evidence descriptor with evidence_id, request_sha256, response_sha256, etc.
        """
        desc = self._evidence_store.save_transport_dispatch_capture(
            request=request,
            response=response,
            action_id=action_id,
            approval_id=approval_id,
            session_ref=session_ref,
            principal_id=principal_id,
            program_id=program_id,
            dispatch_op_id=dispatch_op_id,
            is_verification=is_verification,
            verification_method=verification_method,
            prefix=prefix,
            authority_token=self._authority_token,
        )
        desc["status_code"] = response.status_code
        desc["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return desc

    def _execute_mutation_and_probe(
        self,
        target_endpoint: str,
        method: str,
        action_id: str,
        session_ctx: Dict[str, Any],
        dispatch_op_id: str,
    ) -> Tuple[ControlledRequest, ControlledResponse, ControlledRequest, ControlledResponse, str]:
        """
        Executes HTTP mutation request and independent verification probe using dispatcher transport.
        """
        volatile_headers = session_ctx.get("volatile_headers", {})
        mut_headers = dict(volatile_headers)
        mut_headers["X-Correlation-Action"] = action_id
        mut_headers["X-Correlation-Session"] = session_ctx.get("session_ref", "")
        mut_headers["X-Correlation-Principal"] = session_ctx.get("principal_id", "")
        mut_headers["X-Correlation-Dispatch"] = dispatch_op_id

        mut_req = ControlledRequest(
            url=target_endpoint,
            method=method,
            headers=mut_headers,
        )

        if self.transport_engine is not None and hasattr(self.transport_engine, "send_request"):
            mut_resp = self.transport_engine.send_request(mut_req)
        elif self.is_lab:
            raise ValueError("Deterministic simulation lab requires a registered transport engine")
        else:
            # Production safe transport: enforces destination-IP pinning, redirect checks, and anti-SSRF
            from framework.common.transport import safe_fetch_url
            fetch_res = safe_fetch_url(
                url=target_endpoint,
                method=method,
                headers=mut_headers,
                timeout=10.0,
                scope_engine=self.scope_engine,
            )
            if fetch_res is None:
                raise ValueError("Safe transport dispatch failed: target rejected by scope, DNS pinning, or anti-SSRF validation")
            mut_resp = ControlledResponse(
                status_code=fetch_res["status_code"],
                headers=fetch_res["headers"],
                body_bytes=fetch_res.get("body_bytes", b""),
            )

        if mut_resp.status_code >= 400 or mut_resp.status_code < 200:
            raise ValueError(f"Mutation request failed with HTTP {mut_resp.status_code}")

        mut_body = (mut_resp.body_text or "").lower()
        if any(phrase in mut_body for phrase in NEGATIVE_REVOCATION_PHRASES):
            raise ValueError("Mutation response contains negative revocation language")

        # Independent Verification Probe
        probe_headers = dict(volatile_headers)
        probe_headers["X-Correlation-Action"] = action_id
        probe_headers["X-Correlation-Session"] = session_ctx.get("session_ref", "")
        probe_headers["X-Correlation-Principal"] = session_ctx.get("principal_id", "")
        probe_headers["X-Correlation-Dispatch"] = f"{dispatch_op_id}-VERIFY"

        probe_req = ControlledRequest(
            url=target_endpoint,
            method="GET",
            headers=probe_headers,
        )

        if self.transport_engine is not None and hasattr(self.transport_engine, "send_request"):
            probe_resp = self.transport_engine.send_request(probe_req)
        elif self.is_lab:
            raise ValueError("Deterministic simulation lab requires a registered transport engine")
        else:
            from framework.common.transport import safe_fetch_url
            fetch_res = safe_fetch_url(
                url=target_endpoint,
                method="GET",
                headers=probe_headers,
                timeout=10.0,
                scope_engine=self.scope_engine,
            )
            if fetch_res is None:
                raise ValueError("Safe transport verification probe failed: target rejected by scope, DNS pinning, or anti-SSRF validation")
            probe_resp = ControlledResponse(
                status_code=fetch_res["status_code"],
                headers=fetch_res["headers"],
                body_bytes=fetch_res.get("body_bytes", b""),
            )

        # Evaluate invalidation semantics
        probe_loc = (probe_resp.headers.get("location") or "").lower()
        is_login_redirect = probe_resp.status_code in (301, 302, 303, 307, 308) and any(
            t in probe_loc for t in ("/login", "/auth", "/signin", "/sso", "login.")
        )

        # Check structured mutation response
        mut_body = mut_resp.body_text or ""
        is_explicit_json_revoked = False
        if "{" in mut_body:
            try:
                parsed_json = json.loads(mut_body)
                if isinstance(parsed_json, dict):
                    status_val = str(parsed_json.get("status", "")).lower()
                    if (
                        status_val in ("revoked", "logged_out", "invalidated", "terminated", "session_revoked")
                        or parsed_json.get("revoked") is True
                        or parsed_json.get("logged_out") is True
                    ):
                        is_explicit_json_revoked = True
            except Exception:
                pass

        ver_method = ""
        if probe_resp.status_code in (401, 403):
            if is_explicit_json_revoked:
                ver_method = "ACTION_MUTATION_AND_PROBE_VERIFIED"
            else:
                ver_method = "POST_MUTATION_PROBE_CONFIRMED_401"
        elif is_login_redirect:
            ver_method = "POST_MUTATION_PROBE_CONFIRMED_REDIRECT_LOGIN"
        elif is_explicit_json_revoked:
            probe_body = (probe_resp.body_text or "").lower()
            if any(phrase in probe_body for phrase in NEGATIVE_REVOCATION_PHRASES):
                raise ValueError("Probe response contains negative revocation language")
            ver_method = "MUTATION_EXPLICIT_REVOCATION_VERIFIED"
        elif probe_resp.status_code == 200:
            raise ValueError("Session probe returned HTTP 200: session was not invalidated")
        else:
            raise ValueError(f"Ambiguous verification probe response HTTP {probe_resp.status_code}")

        return mut_req, mut_resp, probe_req, probe_resp, ver_method

    def handle_request(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches an incoming request frame and returns the corresponding response frame."""
        validate_request_frame(req)
        action = req["action"]
        req_id = req["request_id"]
        nonce = req["nonce"]
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        resp_nonce = f"NONCE-{secrets.token_hex(16).upper()}"

        if action == "PING":
            return {
                "version": PROTOCOL_VERSION,
                "request_id": req_id,
                "response_nonce": resp_nonce,
                "timestamp": now_iso,
                "status": "SUCCESS",
                "error_code": None,
                "error_message": None,
                "receipt": None,
            }

        if action == "STATUS":
            return {
                "version": PROTOCOL_VERSION,
                "request_id": req_id,
                "response_nonce": resp_nonce,
                "timestamp": now_iso,
                "status": "SUCCESS",
                "error_code": None,
                "error_message": None,
                "receipt": {
                    "dispatcher_id": self.dispatcher_id,
                    "dispatcher_key_id": self.dispatcher_key_id,
                    "endpoint_type": self.endpoint_type,
                    "endpoint_address": self.endpoint_address,
                    "evidence_dir": self.evidence_dir,
                    "is_lab": self.is_lab,
                    "has_approval_key": self.approval_key is not None,
                    "has_scope_engine": self.scope_engine is not None,
                    "production_isolation_supported": (os.name != "nt"),
                    "platform_limitation": None if os.name != "nt" else "Windows service isolation under dedicated service account is NOT IMPLEMENTED",
                },
            }

        if action == "DISPATCH_MUTATION":
            try:
                payload = req["payload"]
                prog_id = payload["program_id"]
                action_id = payload["action_id"]
                dossier = payload["action_dossier"]
                sess_ctx = payload["session_context"]

                # 1. Canonical dossier verification (Digest integrity)
                canonical_copy = {k: dossier[k] for k in CANONICAL_ACTION_FIELDS if k in dossier}
                canonical_str = json.dumps(canonical_copy, sort_keys=True)
                computed_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
                if computed_hash != action_id[4:]:
                    return {
                        "version": PROTOCOL_VERSION,
                        "request_id": req_id,
                        "response_nonce": resp_nonce,
                        "timestamp": now_iso,
                        "status": "REJECTED",
                        "error_code": "DOSSIER_DIGEST_MISMATCH",
                        "error_message": "Action dossier digest mismatch; tampering detected",
                        "receipt": None,
                    }

                # 2. Operator authorization key and signature check (MANDATORY)
                if not self.approval_key:
                    return {
                        "version": PROTOCOL_VERSION,
                        "request_id": req_id,
                        "response_nonce": resp_nonce,
                        "timestamp": now_iso,
                        "status": "REJECTED",
                        "error_code": "MISSING_APPROVAL_KEY",
                        "error_message": "Operator approval key is mandatory; missing approval key in dispatcher configuration",
                        "receipt": None,
                    }

                if len(self.approval_key) < 32:
                    return {
                        "version": PROTOCOL_VERSION,
                        "request_id": req_id,
                        "response_nonce": resp_nonce,
                        "timestamp": now_iso,
                        "status": "REJECTED",
                        "error_code": "MALFORMED_APPROVAL_KEY",
                        "error_message": "Operator approval key is malformed (must be at least 32 bytes)",
                        "receipt": None,
                    }

                sig = dossier.get("approval_signature", "")
                if not sig or not sig.startswith("SIG-"):
                    return {
                        "version": PROTOCOL_VERSION,
                        "request_id": req_id,
                        "response_nonce": resp_nonce,
                        "timestamp": now_iso,
                        "status": "REJECTED",
                        "error_code": "INVALID_OPERATOR_SIGNATURE",
                        "error_message": "Missing or malformed operator approval signature format",
                        "receipt": None,
                    }

                expected_sig = hmac.new(self.approval_key, canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(sig[4:], expected_sig):
                    return {
                        "version": PROTOCOL_VERSION,
                        "request_id": req_id,
                        "response_nonce": resp_nonce,
                        "timestamp": now_iso,
                        "status": "REJECTED",
                        "error_code": "INVALID_OPERATOR_SIGNATURE",
                        "error_message": "Operator authorization signature verification failed",
                        "receipt": None,
                    }

                # 3. Destination and Scope verification
                target_endpoint = dossier.get("target_endpoint", "")
                try:
                    self._validate_scope_and_destination(target_endpoint)
                except ValueError as e:
                    return {
                        "version": PROTOCOL_VERSION,
                        "request_id": req_id,
                        "response_nonce": resp_nonce,
                        "timestamp": now_iso,
                        "status": "REJECTED",
                        "error_code": "SCOPE_OR_DESTINATION_DENIED",
                        "error_message": str(e),
                        "receipt": None,
                    }

                # 4. Atomic single-use approval consumption
                dispatch_op_id = f"DISP-OP-{secrets.token_hex(32).upper()}"
                try:
                    c_token = self._atomically_consume_approval(action_id, dossier, sess_ctx, dispatch_op_id)
                except ValueError as e:
                    return {
                        "version": PROTOCOL_VERSION,
                        "request_id": req_id,
                        "response_nonce": resp_nonce,
                        "timestamp": now_iso,
                        "status": "REJECTED",
                        "error_code": "APPROVAL_CONSUMPTION_FAILED",
                        "error_message": str(e),
                        "receipt": None,
                    }

                # 5. Network transport execution
                try:
                    mut_req, mut_resp, probe_req, probe_resp, ver_method = self._execute_mutation_and_probe(
                        target_endpoint=target_endpoint,
                        method=dossier["method"],
                        action_id=action_id,
                        session_ctx=sess_ctx,
                        dispatch_op_id=dispatch_op_id,
                    )
                except Exception as e:
                    return {
                        "version": PROTOCOL_VERSION,
                        "request_id": req_id,
                        "response_nonce": resp_nonce,
                        "timestamp": now_iso,
                        "status": "ERROR",
                        "error_code": "TRANSPORT_EXECUTION_FAILED",
                        "error_message": f"Failed to execute controlled invalidation mutation: {e}",
                        "receipt": None,
                    }

                # 6. Evidence persistence
                appr_id = dossier.get("unique_approval_id")
                s_ref = sess_ctx.get("session_ref")
                p_id = sess_ctx.get("principal_id")
                try:
                    mut_desc = self._persist_evidence(
                        "mut", mut_req, mut_resp, dispatch_op_id, action_id,
                        approval_id=appr_id, session_ref=s_ref, principal_id=p_id, program_id=prog_id,
                        is_verification=False,
                    )
                    ver_desc = self._persist_evidence(
                        "ver", probe_req, probe_resp, dispatch_op_id, action_id,
                        approval_id=appr_id, session_ref=s_ref, principal_id=p_id, program_id=prog_id,
                        is_verification=True, verification_method=ver_method,
                    )
                except Exception as e:
                    return {
                        "version": PROTOCOL_VERSION,
                        "request_id": req_id,
                        "response_nonce": resp_nonce,
                        "timestamp": now_iso,
                        "status": "ERROR",
                        "error_code": "EVIDENCE_PERSISTENCE_FAILED",
                        "error_message": f"Evidence persistence failed: {e}",
                        "receipt": None,
                    }

                # 7. Generate Signed ExecutionReceipt
                rcpt_id = f"RCPT-{secrets.token_hex(16).upper()}"
                exec_id = f"EXEC-{secrets.token_hex(16).upper()}"
                receipt_dict: Dict[str, Any] = {
                    "version": PROTOCOL_VERSION,
                    "receipt_id": rcpt_id,
                    "dispatcher_id": self.dispatcher_id,
                    "dispatcher_key_id": self.dispatcher_key_id,
                    "dispatch_op_id": dispatch_op_id,
                    "action_id": action_id,
                    "action_dossier_digest": action_id[4:],
                    "approval_id": dossier.get("unique_approval_id"),
                    "request_nonce": nonce,
                    "execution_id": exec_id,
                    "program_id": prog_id,
                    "principal_id": sess_ctx.get("principal_id"),
                    "session_ref": sess_ctx.get("session_ref"),
                    "target_endpoint": target_endpoint,
                    "http_method": dossier.get("method"),
                    "action_type": dossier.get("action_type"),
                    "scope_decision": "ALLOWED",
                    "execution_outcome": "REVOCATION_VERIFIED",
                    "mutation_evidence": {
                        "evidence_id": mut_desc["evidence_id"],
                        "request_sha256": mut_desc["request_sha256"],
                        "response_sha256": mut_desc["response_sha256"],
                        "status_code": mut_desc["status_code"],
                        "timestamp": mut_desc["timestamp"],
                    },
                    "verification_evidence": {
                        "evidence_id": ver_desc["evidence_id"],
                        "invalidation_result": "REVOKED",
                        "request_sha256": ver_desc["request_sha256"],
                        "response_sha256": ver_desc["response_sha256"],
                        "status_code": ver_desc["status_code"],
                        "timestamp": ver_desc["timestamp"],
                        "verification_method": ver_method,
                    },
                    "consumption_token": c_token,
                    "issued_at": now_iso,
                }
                receipt_dict["signature"] = sign_execution_receipt(receipt_dict, self.signing_key)
                receipt_dict["receipt_signature"] = receipt_dict["signature"]

                return {
                    "version": PROTOCOL_VERSION,
                    "request_id": req_id,
                    "response_nonce": resp_nonce,
                    "timestamp": now_iso,
                    "status": "SUCCESS",
                    "error_code": None,
                    "error_message": None,
                    "receipt": receipt_dict,
                }

            except Exception as e:
                return {
                    "version": PROTOCOL_VERSION,
                    "request_id": req_id,
                    "response_nonce": resp_nonce,
                    "timestamp": now_iso,
                    "status": "ERROR",
                    "error_code": "INTERNAL_DISPATCHER_ERROR",
                    "error_message": str(e),
                    "receipt": None,
                }

        return {
            "version": PROTOCOL_VERSION,
            "request_id": req_id,
            "response_nonce": resp_nonce,
            "timestamp": now_iso,
            "status": "ERROR",
            "error_code": "UNSUPPORTED_ACTION",
            "error_message": f"Action '{action}' is not supported",
            "receipt": None,
        }

    def start(self) -> None:
        """Starts the dispatcher service listener in a background thread."""
        if self._running:
            return

        self._running = True
        if self.endpoint_type == "unix":
            parent_dir = os.path.dirname(os.path.abspath(self.endpoint_address))
            if not os.path.exists(parent_dir):
                raise FileNotFoundError(f"Socket parent directory '{parent_dir}' does not exist")
            p_stat = os.stat(parent_dir)
            if p_stat.st_mode & 0o002 != 0:
                raise PermissionError(f"Socket directory '{parent_dir}' is world-writable; insecure for IPC")
            if (p_stat.st_mode & 0o020 != 0) and (p_stat.st_mode & 0o1000 == 0):
                raise PermissionError(
                    f"Socket directory '{parent_dir}' is group-writable without sticky bit (01000); insecure for IPC"
                )

            if os.path.exists(self.endpoint_address) or os.path.islink(self.endpoint_address):
                st = os.lstat(self.endpoint_address)
                if stat.S_ISLNK(st.st_mode):
                    raise PermissionError(f"Socket path '{self.endpoint_address}' is a symbolic link; rejecting")
                try:
                    os.unlink(self.endpoint_address)
                except OSError as e:
                    raise PermissionError(f"Cannot unlink stale socket '{self.endpoint_address}': {e}")
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.bind(self.endpoint_address)
            except OSError as e:
                sock.close()
                raise PermissionError(f"Failed to bind Unix socket at '{self.endpoint_address}': {e}")
            try:
                os.chmod(self.endpoint_address, 0o660)
            except OSError as e:
                sock.close()
                raise PermissionError(f"Failed to set permissions (0660) on socket '{self.endpoint_address}': {e}")
            sock.listen(5)
            self._listener_obj = sock

            def _unix_worker():
                while self._running:
                    try:
                        sock.settimeout(1.0)
                        conn, _ = sock.accept()
                    except socket.timeout:
                        continue
                    except Exception:
                        break
                    t = threading.Thread(target=self._handle_unix_client, args=(conn,))
                    t.daemon = True
                    t.start()

            self._server_thread = threading.Thread(target=_unix_worker)
            self._server_thread.daemon = True
            self._server_thread.start()

        elif self.endpoint_type == "pipe":
            from multiprocessing.connection import Listener
            listener = Listener(self.endpoint_address, family="AF_PIPE")
            self._listener_obj = listener

            def _pipe_worker():
                while self._running:
                    try:
                        conn = listener.accept()
                    except Exception:
                        break
                    if not self._running:
                        try:
                            conn.close()
                        except Exception:
                            pass
                        break
                    t = threading.Thread(target=self._handle_pipe_client, args=(conn,))
                    t.daemon = True
                    t.start()

            self._server_thread = threading.Thread(target=_pipe_worker)
            self._server_thread.daemon = True
            self._server_thread.start()

    def _handle_unix_client(self, conn: socket.socket) -> None:
        try:
            req = read_framed_message(conn)
            resp = self.handle_request(req)
            raw_resp = pack_message(resp)
            conn.sendall(raw_resp)
        except Exception as e:
            try:
                err_resp = {
                    "version": PROTOCOL_VERSION,
                    "request_id": f"REQ-{secrets.token_hex(16).upper()}",
                    "response_nonce": f"NONCE-{secrets.token_hex(16).upper()}",
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "status": "ERROR",
                    "error_code": "MALFORMED_REQUEST",
                    "error_message": str(e),
                    "receipt": None,
                }
                conn.sendall(pack_message(err_resp))
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _handle_pipe_client(self, conn: Any) -> None:
        try:
            raw_req = conn.recv_bytes(MAX_MESSAGE_BYTES)
            if len(raw_req) < 4:
                raise IPCValidationError("Undersized frame received")
            req = json.loads(raw_req[4:].decode("utf-8"))
            resp = self.handle_request(req)
            raw_resp = pack_message(resp)
            conn.send_bytes(raw_resp)
        except Exception as e:
            try:
                err_resp = {
                    "version": PROTOCOL_VERSION,
                    "request_id": f"REQ-{secrets.token_hex(16).upper()}",
                    "response_nonce": f"NONCE-{secrets.token_hex(16).upper()}",
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "status": "ERROR",
                    "error_code": "MALFORMED_REQUEST",
                    "error_message": str(e),
                    "receipt": None,
                }
                conn.send_bytes(pack_message(err_resp))
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def stop(self) -> None:
        """Stops the dispatcher listener."""
        self._running = False
        if self.endpoint_type == "pipe" and self._listener_obj is not None:
            # Unblock accept() on Windows named pipe
            try:
                from multiprocessing.connection import Client
                c = Client(self.endpoint_address, family="AF_PIPE")
                c.close()
            except Exception:
                pass
        if self._listener_obj is not None:
            try:
                self._listener_obj.close()
            except Exception:
                pass
        if self.endpoint_type == "unix" and os.path.exists(self.endpoint_address):
            try:
                os.unlink(self.endpoint_address)
            except OSError:
                pass
        if self._server_thread is not None and self._server_thread.is_alive():
            self._server_thread.join(timeout=2.0)
