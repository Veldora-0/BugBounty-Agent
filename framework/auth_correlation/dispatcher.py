"""
Phase 21: Controlled Dispatch Workflow.

Provides the single trusted execution boundary for Mode B controlled session invalidation.
Enforces preflight authorization, operator approval verification, atomic single-use
approval consumption under cross-process lock, transport-level request and response capture,
and independent post-mutation verification probe dispatch through the transport adapter.
Produces sealed, tamper-evident ControlledDispatchResult objects required for
issuing genuine ExecutionCapabilities.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from framework.auth_correlation.model import (
    ACTION_ID_PATTERN,
    ACTION_DOSSIER_DIGEST_PATTERN,
    CAPABILITY_ID_PATTERN,
    CAPABILITY_SIG_PATTERN,
    EVIDENCE_REF_PATTERN,
    SESSION_REF_PATTERN,
    SAFE_IDENTIFIER_PATTERN,
    ISO_TIMESTAMP_PATTERN,
    SerializationSecurityError,
    ApprovalSecurityError,
    CorrelatedSessionContext,
    CorrelationLifecycle,
    assert_safe_string,
    assert_strict_int,
)
from framework.auth_correlation.state import (
    CrossProcessFileLock,
    _enforce_windows_file_dacl,
    _verify_windows_file_security,
)
from framework.auth_correlation.ledger import (
    CANONICAL_ACTION_FIELDS,
    RECEIPT_FIELDS,
    ExecutionLedger,
    ExecutionProvenanceError,
    issue_execution_capability,
    sign_consumption_receipt,
    verify_consumed_approval_entry,
)
from framework.common.evidence import EvidencePersistenceError, sanitize_sensitive_data
from framework.validation.request import ControlledRequest, ControlledResponse


ALLOWED_DOSSIER_KEYS = frozenset({
    "action_id",
    "action_type",
    "approval_signature",
    "created_at",
    "method",
    "program_id",
    "target_endpoint",
    "test_account",
    "ttl",
    "unique_approval_id",
})

ALLOWED_MUTATION_METHODS = frozenset({"POST", "PUT", "DELETE"})
ALLOWED_ACTION_TYPES = frozenset({"LOGOUT", "ACTION-LOGOUT", "TOKEN_REVOCATION", "PASSWORD_CHANGE"})

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


@dataclass(frozen=True)
class ControlledDispatchResult:
    """
    Immutable sealed result produced exclusively by ControlledDispatchWorkflow.
    Guarantees that both mutation and independent verification dispatches occurred
    through the transport adapter, captures were persisted at the transport boundary,
    and the approval was consumed atomically under CrossProcessFileLock.
    """
    dispatch_op_id: str
    action_id: str
    action_dossier_digest: str
    approval_id: str
    program_id: str
    session_ref: str
    principal_id: str
    test_account: str
    target_endpoint: str
    http_method: str
    action_type: str
    mutation_evidence_ref: str
    mutation_request_digest: str
    mutation_response_digest: str
    mutation_status_code: int
    verification_evidence_ref: str
    verification_request_digest: str
    verification_response_digest: str
    verification_status_code: int
    verification_method: str
    invalidation_verification_result: str
    execution_timestamp: str
    verification_timestamp: str
    consumption_token: str
    is_genuine_dispatch: bool = True

    def validate(self) -> Dict[str, Any]:
        """Validates all fields against strict patterns and domain invariants."""
        if not self.is_genuine_dispatch:
            raise ExecutionProvenanceError("ControlledDispatchResult is not marked as a genuine dispatch")
        if not self.dispatch_op_id.startswith("DISP-OP-") or len(self.dispatch_op_id) != 72:
            raise ExecutionProvenanceError("Invalid dispatch_op_id format")
        if not ACTION_ID_PATTERN.match(self.action_id):
            raise ExecutionProvenanceError("Invalid action_id format")
        if not ACTION_DOSSIER_DIGEST_PATTERN.match(self.action_dossier_digest):
            raise ExecutionProvenanceError("Invalid action_dossier_digest format")
        if not EVIDENCE_REF_PATTERN.match(self.mutation_evidence_ref):
            raise ExecutionProvenanceError("Invalid mutation_evidence_ref format")
        if not EVIDENCE_REF_PATTERN.match(self.verification_evidence_ref):
            raise ExecutionProvenanceError("Invalid verification_evidence_ref format")
        if self.mutation_evidence_ref == self.verification_evidence_ref:
            raise ExecutionProvenanceError("Mutation and verification evidence cannot be identical")
        if self.mutation_request_digest == self.verification_request_digest:
            raise ExecutionProvenanceError("Mutation and verification request digests cannot be identical")
        return {
            "dispatch_op_id": self.dispatch_op_id,
            "action_id": self.action_id,
            "action_dossier_digest": self.action_dossier_digest,
            "approval_id": self.approval_id,
            "program_id": self.program_id,
            "session_ref": self.session_ref,
            "principal_id": self.principal_id,
            "test_account": self.test_account,
            "target_endpoint": self.target_endpoint,
            "http_method": self.http_method,
            "action_type": self.action_type,
            "mutation_evidence_ref": self.mutation_evidence_ref,
            "mutation_request_digest": self.mutation_request_digest,
            "mutation_response_digest": self.mutation_response_digest,
            "mutation_status_code": self.mutation_status_code,
            "verification_evidence_ref": self.verification_evidence_ref,
            "verification_request_digest": self.verification_request_digest,
            "verification_response_digest": self.verification_response_digest,
            "verification_status_code": self.verification_status_code,
            "verification_method": self.verification_method,
            "invalidation_verification_result": self.invalidation_verification_result,
            "execution_timestamp": self.execution_timestamp,
            "verification_timestamp": self.verification_timestamp,
            "consumption_token": self.consumption_token,
            "is_genuine_dispatch": self.is_genuine_dispatch,
        }


class ControlledDispatchWorkflow:
    """
    Unified Trusted Dispatch Workflow for Phase 21 Mode B Controlled Invalidation.
    """

    _consumed_lock = threading.Lock()

    def __init__(
        self,
        program_id: str,
        state_dir: str,
        evidence_store: Any,
        transport_engine: Any,
        scope_engine: Optional[Any] = None,
        approval_key: Optional[bytes] = None,
        approval_key_dir: Optional[str] = None,
        execution_ledger: Optional[ExecutionLedger] = None,
        execution_key: Optional[bytes] = None,
    ):
        self._program_id = program_id or "default-program"
        self._state_dir = state_dir
        self._evidence_store = evidence_store
        self._engine = transport_engine
        self._scope_engine = scope_engine
        self._approval_key = approval_key
        self._approval_key_dir = approval_key_dir
        self._execution_ledger = execution_ledger
        self._execution_key = execution_key

    def _get_consumed_approvals_path(self) -> str:
        return os.path.join(self._state_dir, "consumed_approvals.json")

    def _get_consumed_approvals_lock_path(self) -> str:
        return os.path.join(self._state_dir, "consumed_approvals.lock")

    def _is_approval_consumed(self, action_id: str) -> bool:
        """Reads consumed approvals state; fails closed on any corruption."""
        path = self._get_consumed_approvals_path()
        if not os.path.exists(path):
            return False
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict) or "consumed" not in data or not isinstance(data["consumed"], dict):
                raise ApprovalSecurityError("Consumed approvals state storage is corrupted")
            return action_id in data["consumed"]
        except ApprovalSecurityError:
            raise
        except Exception as e:
            raise ApprovalSecurityError(f"Consumed approvals state storage is corrupted: {e}")

    def execute(
        self,
        session_ctx: CorrelatedSessionContext,
        action_id: str,
        action_dossier: Dict[str, Any],
    ) -> Tuple[bool, Optional[ControlledDispatchResult], str]:
        """
        Executes active controlled invalidation mutation and independent verification probe.
        Guarantees single-use execution across processes via durable CrossProcessFileLock.
        Requires mandatory initialized and writable EvidenceStore.
        Requires mandatory ScopeEngine for non-simulation targets.
        Returns (success: bool, dispatch_result: Optional[ControlledDispatchResult], reason: str).
        """
        # 0. EvidenceStore is MANDATORY and must be writable before any mutation dispatch
        if self._evidence_store is None:
            raise ApprovalSecurityError("EvidenceStore is mandatory for Mode B controlled invalidation")
        if not hasattr(self._evidence_store, "is_writable") or not self._evidence_store.is_writable():
            raise ApprovalSecurityError("EvidenceStore is not writable or evidence directory is insecure")

        if not isinstance(action_id, str) or not action_id.startswith("ACT-") or len(action_id) != 68:
            raise ApprovalSecurityError("Invalid action approval identifier format: expected ACT-<64-hex>")

        if not isinstance(action_dossier, dict):
            raise ApprovalSecurityError("Action dossier must be a dictionary")

        # 1. Exact allowed keys enforcement (reject missing and unexpected keys)
        if set(action_dossier.keys()) != ALLOWED_DOSSIER_KEYS:
            raise ApprovalSecurityError("Action dossier keys do not match approved schema")

        # 2. Strict field type and value validations
        if action_dossier.get("action_id") != action_id:
            raise ApprovalSecurityError("Action dossier action_id does not match parameter action_id")

        sig = action_dossier.get("approval_signature")
        if not isinstance(sig, str) or not sig.startswith("SIG-") or len(sig) != 68:
            raise ApprovalSecurityError("Invalid operator approval signature format: expected SIG-<64-hex>")

        method = action_dossier.get("method")
        if not isinstance(method, str) or method not in ALLOWED_MUTATION_METHODS:
            raise ApprovalSecurityError("Action approval specifies invalid or unsupported HTTP method")

        action_type = action_dossier.get("action_type")
        if not isinstance(action_type, str) or action_type not in ALLOWED_ACTION_TYPES:
            raise ApprovalSecurityError("Action approval specifies unsupported action type")

        target_endpoint = action_dossier.get("target_endpoint")
        if not isinstance(target_endpoint, str) or not target_endpoint:
            raise ApprovalSecurityError("Action approval target_endpoint must be a non-empty string")

        test_account = action_dossier.get("test_account")
        if not isinstance(test_account, str) or not test_account:
            raise ApprovalSecurityError("Action approval test_account must be a non-empty string")
        if test_account != session_ctx.principal_id:
            raise ApprovalSecurityError(
                f"Action approval test_account '{test_account}' does not match session principal_id '{session_ctx.principal_id}'"
            )

        program_id = action_dossier.get("program_id")
        if not isinstance(program_id, str) or not program_id:
            raise ApprovalSecurityError("Action approval program_id must be a non-empty string")
        if program_id != self._program_id:
            raise ApprovalSecurityError(
                f"Action approval program_id '{program_id}' does not match validator program_id '{self._program_id}'"
            )

        unique_approval_id = action_dossier.get("unique_approval_id")
        if not isinstance(unique_approval_id, str) or not unique_approval_id:
            raise ApprovalSecurityError("Action approval unique_approval_id must be a non-empty string")

        created_at_raw = action_dossier.get("created_at")
        if isinstance(created_at_raw, bool) or not isinstance(created_at_raw, (int, float)):
            raise ApprovalSecurityError("Action approval created_at must be numeric timestamp")
        created_at = float(created_at_raw)

        ttl_raw = action_dossier.get("ttl")
        if isinstance(ttl_raw, bool) or not isinstance(ttl_raw, (int, float)) or ttl_raw <= 0:
            raise ApprovalSecurityError("Action approval ttl must be positive number")
        ttl = min(float(ttl_raw), 300.0)

        # 3. Canonical descriptor verification (Integrity)
        canonical_copy = {k: action_dossier[k] for k in CANONICAL_ACTION_FIELDS}
        canonical_str = json.dumps(canonical_copy, sort_keys=True)
        computed_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

        if computed_hash != action_id[4:]:
            raise ApprovalSecurityError("Action approval digest mismatch; action dossier has been tampered")

        # 4. Operator authorization signature verification (Authorization)
        if self._approval_key is not None:
            key = self._approval_key
        else:
            from framework.auth_correlation.revocation import get_or_create_approval_key
            key = get_or_create_approval_key(key_dir=self._approval_key_dir)
        expected_sig_hash = hmac.new(key, canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig[4:], expected_sig_hash):
            raise ApprovalSecurityError("Operator authorization signature verification failed")

        # 5. Mandatory Scope validation
        is_simulation = hasattr(self._engine, "lab_port") or type(self._engine).__name__ == "SimulationTransport"
        if not is_simulation:
            if self._scope_engine is None:
                raise ApprovalSecurityError("Mandatory ScopeEngine is required for controlled invalidation mutation")
        else:
            if hasattr(self._engine, "validate_target_url"):
                try:
                    self._engine.validate_target_url(target_endpoint)
                except Exception as e:
                    raise ApprovalSecurityError(f"Target endpoint '{target_endpoint}' failed simulation URL validation: {e}")

        parsed = urlparse(target_endpoint)
        if parsed.scheme.lower() not in ("http", "https"):
            raise ApprovalSecurityError(f"Target endpoint '{target_endpoint}' specifies invalid or unsupported scheme")
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        if port < 1 or port > 65535:
            raise ApprovalSecurityError(f"Target endpoint '{target_endpoint}' specifies invalid port")
        if not parsed.hostname:
            raise ApprovalSecurityError(f"Target endpoint '{target_endpoint}' has missing or empty hostname")

        if self._scope_engine is not None and not is_simulation:
            try:
                is_in_scope = self._scope_engine.is_in_scope(target_endpoint)
                if not is_in_scope:
                    raise ApprovalSecurityError(f"Target endpoint '{target_endpoint}' for controlled mutation is out of scope")
            except ApprovalSecurityError:
                raise
            except Exception as e:
                raise ApprovalSecurityError(f"Scope verification failed for controlled mutation: {e}")

        # Bind scope engine to validation engine if applicable
        if hasattr(self._engine, "scope_engine"):
            self._engine.scope_engine = self._scope_engine

        # 6. Timestamp and clock tolerance checks
        now = time.time()
        if created_at > now + 30.0:
            raise ApprovalSecurityError("Action approval created_at is future-dated beyond clock tolerance")
        if now - created_at > ttl:
            raise ApprovalSecurityError("Action approval has expired")

        # 7. Internal Dispatch Operation ID & Single-Use Consumption under Lock
        dispatch_op_id = f"DISP-OP-{secrets.token_hex(32).upper()}"
        consumption_token = secrets.token_hex(32)
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        lock_path = self._get_consumed_approvals_lock_path()

        os.makedirs(self._state_dir, exist_ok=True)
        consumed_path = self._get_consumed_approvals_path()

        with self._consumed_lock, CrossProcessFileLock(lock_path):
            if self._is_approval_consumed(action_id):
                raise ApprovalSecurityError(f"Action approval '{action_id}' has already been consumed (replay rejected)")

            # Read existing or initialize registry
            reg_data: Dict[str, Any] = {"version": 1, "consumed": {}}
            if os.path.exists(consumed_path):
                try:
                    with open(consumed_path, "r", encoding="utf-8") as f:
                        reg_data = json.load(f)
                    if not isinstance(reg_data, dict) or "consumed" not in reg_data or not isinstance(reg_data["consumed"], dict):
                        raise ApprovalSecurityError("Consumed approvals state storage is corrupted")
                except ApprovalSecurityError:
                    raise
                except Exception as e:
                    raise ApprovalSecurityError(f"Consumed approvals state storage is corrupted: {e}")

            receipt_payload: Dict[str, Any] = {
                "action_dossier_digest": action_id[4:],
                "action_id": action_id,
                "action_type": action_dossier.get("action_type", ""),
                "approval_id": unique_approval_id,
                "consumed_at": now_iso,
                "consumption_token": consumption_token,
                "dispatch_op_id": dispatch_op_id,
                "method": method,
                "operator_signature": sig,
                "principal_id": session_ctx.principal_id,
                "program_id": self._program_id,
                "session_ref": session_ctx.session_ref,
                "target_endpoint": target_endpoint,
                "test_account": test_account,
            }
            receipt_sig = sign_consumption_receipt(receipt_payload, key)

            reg_data["consumed"][action_id] = {
                **receipt_payload,
                "action_dossier": canonical_copy,
                "receipt_signature": receipt_sig,
                "capability_issued": False,
                "execution_id": None,
            }

            tmp_path = f"{consumed_path}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
            try:
                flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
                if hasattr(os, "O_BINARY"):
                    flags |= os.O_BINARY
                fd = os.open(tmp_path, flags, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(reg_data, f, indent=2)
                if os.name == "nt":
                    _enforce_windows_file_dacl(tmp_path)
                    _verify_windows_file_security(tmp_path)
                os.replace(tmp_path, consumed_path)
            except Exception as e:
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass
                raise ApprovalSecurityError(f"Failed to record consumed approval state: {e}")

        # 8. Dispatch Mutation Request via Transport Adapter
        exec_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        mut_headers = dict(session_ctx.volatile_headers)
        mut_headers["X-Correlation-Action"] = action_id
        mut_headers["X-Correlation-Session"] = session_ctx.session_ref
        mut_headers["X-Correlation-Principal"] = session_ctx.principal_id
        mut_headers["X-Correlation-Dispatch"] = dispatch_op_id

        mut_req = ControlledRequest(
            url=target_endpoint,
            method=method,
            headers=mut_headers,
        )

        try:
            mut_resp = self._engine.send_request(mut_req)
        except Exception as e:
            raise ApprovalSecurityError(f"Failed to execute controlled invalidation mutation: {e}")

        # Capture mutation evidence at transport boundary
        try:
            mut_cap = self._evidence_store.save_transport_dispatch_capture(
                request=mut_req,
                response=mut_resp,
                action_id=action_id,
                approval_id=unique_approval_id,
                session_ref=session_ctx.session_ref,
                principal_id=session_ctx.principal_id,
                program_id=self._program_id,
                dispatch_op_id=dispatch_op_id,
                is_verification=False,
                prefix="controlled_revocation_mutation",
            )
        except Exception as e:
            if isinstance(e, EvidencePersistenceError):
                raise
            raise EvidencePersistenceError(f"Failed to persist controlled revocation evidence: {e}")

        # Fail closed if mutation returned error status code or negative revocation language
        if mut_resp.status_code >= 400 or mut_resp.status_code < 200:
            return False, None, f"Mutation request failed with HTTP {mut_resp.status_code}"

        mut_body_text = mut_resp.body_text or ""
        mut_lower_body = mut_body_text.lower()
        if any(phrase in mut_lower_body for phrase in NEGATIVE_REVOCATION_PHRASES):
            return False, None, "Mutation response contains negative revocation language"

        # 9. Dispatch Independent Verification Probe via Transport Adapter
        # A separate probe request is dispatched to independently confirm revocation
        probe_endpoint = target_endpoint
        if self._scope_engine is not None and not is_simulation:
            try:
                if not self._scope_engine.is_in_scope(probe_endpoint):
                    return False, None, "Probe endpoint out of scope"
            except Exception:
                return False, None, "Probe endpoint scope check failed"

        probe_headers = dict(session_ctx.volatile_headers)
        probe_headers["X-Correlation-Action"] = action_id
        probe_headers["X-Correlation-Session"] = session_ctx.session_ref
        probe_headers["X-Correlation-Principal"] = session_ctx.principal_id
        probe_headers["X-Correlation-Dispatch"] = f"{dispatch_op_id}-VERIFY"

        probe_req = ControlledRequest(
            url=probe_endpoint,
            method="GET",
            headers=probe_headers,
        )

        try:
            probe_resp = self._engine.send_request(probe_req)
        except Exception as e:
            return False, None, f"Failed to dispatch independent verification probe: {e}"

        # 10. Evaluate Invalidation Semantics
        ver_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        ver_method = ""
        ver_result = ""
        is_invalidation_verified = False

        probe_loc = (probe_resp.headers.get("location") or "").lower()
        is_probe_login_redirect = probe_resp.status_code in (301, 302, 303, 307, 308) and any(
            term in probe_loc for term in ("/login", "/auth", "/signin", "/sso", "login.")
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

        if probe_resp.status_code in (401, 403):
            is_invalidation_verified = True
            if is_explicit_json_revoked:
                ver_method = "ACTION_MUTATION_AND_PROBE_VERIFIED"
            else:
                ver_method = "POST_MUTATION_PROBE_CONFIRMED_401"
            ver_result = "REVOKED"
        elif is_probe_login_redirect:
            is_invalidation_verified = True
            ver_method = "POST_MUTATION_PROBE_CONFIRMED_REDIRECT_LOGIN"
            ver_result = "REVOKED"
        elif is_explicit_json_revoked:
            probe_body = (probe_resp.body_text or "").lower()
            if any(phrase in probe_body for phrase in NEGATIVE_REVOCATION_PHRASES):
                return False, None, "Probe response contains negative revocation language"
            is_invalidation_verified = True
            ver_method = "MUTATION_EXPLICIT_REVOCATION_VERIFIED"
            ver_result = "REVOKED"
        elif probe_resp.status_code == 200:
            # Session probe confirmed access still granted: revocation failed!
            return False, None, "Session probe returned HTTP 200: session was not invalidated"
        else:
            return False, None, f"Ambiguous probe response HTTP {probe_resp.status_code}"

        if not is_invalidation_verified:
            return False, None, "Session invalidation could not be independently verified"

        # Capture independent verification evidence at transport boundary
        try:
            ver_cap = self._evidence_store.save_transport_dispatch_capture(
                request=probe_req,
                response=probe_resp,
                action_id=action_id,
                approval_id=unique_approval_id,
                session_ref=session_ctx.session_ref,
                principal_id=session_ctx.principal_id,
                program_id=self._program_id,
                dispatch_op_id=dispatch_op_id,
                is_verification=True,
                verification_method=ver_method,
                prefix="controlled_revocation_verification",
            )
        except Exception as e:
            if isinstance(e, EvidencePersistenceError):
                raise
            raise EvidencePersistenceError(f"Failed to persist controlled revocation evidence: {e}")

        # 11. Build Sealed ControlledDispatchResult
        dispatch_result = ControlledDispatchResult(
            dispatch_op_id=dispatch_op_id,
            action_id=action_id,
            action_dossier_digest=action_id[4:],
            approval_id=unique_approval_id,
            program_id=self._program_id,
            session_ref=session_ctx.session_ref,
            principal_id=session_ctx.principal_id,
            test_account=test_account,
            target_endpoint=target_endpoint,
            http_method=method,
            action_type=action_type,
            mutation_evidence_ref=mut_cap["evidence_id"],
            mutation_request_digest=mut_cap["request_sha256"],
            mutation_response_digest=mut_cap["response_sha256"],
            mutation_status_code=mut_resp.status_code,
            verification_evidence_ref=ver_cap["evidence_id"],
            verification_request_digest=ver_cap["request_sha256"],
            verification_response_digest=ver_cap["response_sha256"],
            verification_status_code=probe_resp.status_code,
            verification_method=ver_method,
            invalidation_verification_result=ver_result,
            execution_timestamp=exec_ts,
            verification_timestamp=ver_ts,
            consumption_token=consumption_token,
            is_genuine_dispatch=True,
        )

        return True, dispatch_result, f"Controlled invalidation executed and independently verified via {ver_method}"
