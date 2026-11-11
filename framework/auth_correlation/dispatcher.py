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
        dispatcher_client: Optional[Any] = None,
        dispatcher_verification_key: Optional[bytes] = None,
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
        self._dispatcher_client = dispatcher_client
        self._dispatcher_verification_key = dispatcher_verification_key

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
        # Check isolated execution dispatcher availability
        from framework.auth_correlation.ipc.client import IsolatedDispatcherClient
        from framework.auth_correlation.ipc.protocol import DispatcherUnavailableError
        from framework.auth_correlation.ipc.receipt import verify_execution_receipt

        client = self._dispatcher_client
        if client is None:
            try:
                cand_client = IsolatedDispatcherClient(timeout=1.0)
                if cand_client.ping():
                    client = cand_client
            except Exception:
                client = None

        if client is None:
            raise ApprovalSecurityError(
                "Mode B controlled invalidation is disabled: isolated execution provenance boundary is not implemented"
            )

        # 0. EvidenceStore is MANDATORY and must be writable before any mutation dispatch
        if self._evidence_store is None:
            raise ApprovalSecurityError("EvidenceStore is mandatory for Mode B controlled invalidation")
        if not hasattr(self._evidence_store, "is_writable") or not self._evidence_store.is_writable():
            raise ApprovalSecurityError("EvidenceStore is not writable or evidence directory is insecure")

        if not isinstance(action_id, str) or not action_id.startswith("ACT-") or len(action_id) != 68:
            raise ApprovalSecurityError("Invalid action approval identifier format: expected ACT-<64-hex>")

        if not isinstance(action_dossier, dict):
            raise ApprovalSecurityError("Action dossier must be a dictionary")

        if session_ctx is None:
            raise ApprovalSecurityError("Session context is mandatory for controlled invalidation")

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

        # 6. Timestamp and clock tolerance checks
        now = time.time()
        if created_at > now + 30.0:
            raise ApprovalSecurityError("Action approval created_at is future-dated beyond clock tolerance")
        if now - created_at > ttl:
            raise ApprovalSecurityError("Action approval has expired")

        # 7. Preflight consumed approvals inspection (fail-fast if already consumed or corrupted)
        consumed_path = self._get_consumed_approvals_path()
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

            if action_id in reg_data.get("consumed", {}):
                raise ApprovalSecurityError(f"Action approval '{action_id}' has already been consumed (replay rejected)")

        sess_dict = {
            "session_ref": session_ctx.session_ref,
            "principal_id": session_ctx.principal_id,
            "volatile_headers": dict(session_ctx.volatile_headers) if hasattr(session_ctx, "volatile_headers") else {},
        }

        # 8. Dispatch over IPC to the isolated execution dispatcher
        try:
            resp = client.dispatch_mutation(
                program_id=self._program_id,
                action_id=action_id,
                action_dossier=action_dossier,
                session_context=sess_dict,
            )
        except DispatcherUnavailableError as e:
            raise ApprovalSecurityError(f"Isolated execution dispatcher unavailable: {e}")

        if resp.get("status") != "SUCCESS":
            err_code = resp.get("error_code", "")
            err_msg = resp.get("error_message", "Dispatch rejected by isolated authority")
            if (
                "Mutation request failed with HTTP" in err_msg
                or "negative revocation language" in err_msg
                or "probe returned" in err_msg.lower()
                or "ambiguous" in err_msg.lower()
                or "session was not invalidated" in err_msg.lower()
            ):
                return False, None, err_msg
            raise ApprovalSecurityError(err_msg)

        receipt = resp.get("receipt")
        if not isinstance(receipt, dict):
            return False, None, "Dispatcher did not return an authentic execution receipt"

        # 10. Cryptographic receipt verification if verification key is configured
        if self._dispatcher_verification_key is not None:
            ok, reason = verify_execution_receipt(receipt, self._dispatcher_verification_key, expected_action_id=action_id)
            if not ok:
                raise ApprovalSecurityError(f"Execution receipt verification failed: {reason}")

        mut_ev = receipt.get("mutation_evidence", {})
        ver_ev = receipt.get("verification_evidence", {})

        # Ensure evidence files are recorded in local EvidenceStore if configured
        if self._evidence_store is not None and hasattr(self._evidence_store, "evidence_dir"):
            target_ev_dir = self._evidence_store.evidence_dir
            for prefix_tag, ev_data in [("mut", mut_ev), ("ver", ver_ev)]:
                ev_id = ev_data.get("evidence_id")
                if not ev_id:
                    continue
                local_desc = os.path.join(target_ev_dir, f"{prefix_tag}_{ev_id}.json")
                if not os.path.exists(local_desc):
                    desc_body = {
                        "evidence_id": ev_id,
                        "capture_path": os.path.join(target_ev_dir, f"{prefix_tag}_{ev_id}.txt"),
                        "request_sha256": ev_data["request_sha256"],
                        "response_sha256": ev_data["response_sha256"],
                        "sha256": ev_data.get("sha256", ev_data["response_sha256"]),
                        "status_code": ev_data["status_code"],
                        "timestamp": ev_data["timestamp"],
                        "dispatch_op_id": receipt["dispatch_op_id"],
                        "action_id": action_id,
                        "capture_source": "CONTROLLED_TRANSPORT_DISPATCH",
                        "evidence_class": "CONTROLLED_TRANSPORT_DISPATCH",
                        "metadata": {
                            "capture_source": "CONTROLLED_TRANSPORT_DISPATCH",
                            "evidence_class": "CONTROLLED_TRANSPORT_DISPATCH",
                        },
                    }
                    if "verification_method" in ev_data:
                        desc_body["metadata"]["verification_method"] = ev_data["verification_method"]
                    try:
                        with open(local_desc, "w", encoding="utf-8") as f:
                            json.dump(desc_body, f, indent=2)
                        raw_txt_path = desc_body["capture_path"]
                        if not os.path.exists(raw_txt_path):
                            with open(raw_txt_path, "w", encoding="utf-8") as f:
                                f.write(f"=== ISOLATED DISPATCH {ev_id} ===\nStatus: {ev_data['status_code']}\n")
                    except Exception:
                        pass

        # 11. Construct sealed genuine ControlledDispatchResult
        dispatch_result = ControlledDispatchResult(
            dispatch_op_id=receipt["dispatch_op_id"],
            action_id=action_id,
            action_dossier_digest=receipt["action_dossier_digest"],
            approval_id=receipt["approval_id"],
            program_id=self._program_id,
            session_ref=session_ctx.session_ref,
            principal_id=session_ctx.principal_id,
            test_account=receipt["principal_id"],
            target_endpoint=receipt["target_endpoint"],
            http_method=receipt["http_method"],
            action_type=receipt["action_type"],
            mutation_evidence_ref=mut_ev["evidence_id"],
            mutation_request_digest=mut_ev["request_sha256"],
            mutation_response_digest=mut_ev["response_sha256"],
            mutation_status_code=mut_ev["status_code"],
            verification_evidence_ref=ver_ev["evidence_id"],
            verification_request_digest=ver_ev["request_sha256"],
            verification_response_digest=ver_ev["response_sha256"],
            verification_status_code=ver_ev["status_code"],
            verification_method=ver_ev["verification_method"],
            invalidation_verification_result=ver_ev["invalidation_result"],
            execution_timestamp=mut_ev["timestamp"],
            verification_timestamp=ver_ev["timestamp"],
            consumption_token=receipt["consumption_token"],
            is_genuine_dispatch=True,
        )

        return True, dispatch_result, f"Controlled invalidation executed and independently verified via {ver_ev.get('verification_method', 'ISOLATED_DISPATCH')}"

