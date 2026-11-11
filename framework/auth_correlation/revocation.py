"""
Phase 21: PostRevocationResourceValidator.

Verifies whether protected resource endpoints remain accessible after session
revocation, logout, or token expiration:
- Mode A (Default): Observe Existing Invalidation (Strictly observation-only; requires
  pre-captured baseline and invalidation evidence; returns INCONCLUSIVE if missing).
- Mode B: Controlled Invalidation (Active mutation requiring explicit single-use
  action-specific approval matching ACT-<SHA256> signed with trusted operator approval key).
Bound to ExecutionLedger for genuine execution provenance and EvidenceStore for cryptographic evidence integrity.
"""

from __future__ import annotations

import difflib
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

from framework.auth_correlation.cvss import (
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    CIAImpact,
    CVSS31Metrics,
    CVSS31Calculator,
)
from framework.auth_correlation.ledger import (
    ExecutionLedger,
    ExecutionRecord,
    ExecutionProvenanceError,
    ExecutionCapability,
    issue_execution_capability,
    get_or_create_execution_key,
    get_or_create_capability_key,
    EXECUTION_ID_PATTERN,
    EXECUTION_SIG_PATTERN,
    EXECUTION_DOMAIN,
    sign_consumption_receipt,
    verify_consumed_approval_entry,
)
from framework.auth_correlation.model import (
    CorrelatedSessionContext,
    ControlledExecutionResult,
    CorrelationFinding,
    CorrelationLifecycle,
    SerializationSecurityError,
    EvidencePersistenceError,
    AttestationSecurityError,
    ApprovalSecurityError,
    EVIDENCE_REF_PATTERN,
    ATTESTATION_REF_PATTERN,
    ATTESTATION_SIG_PATTERN,
    SESSION_REF_PATTERN,
    SAFE_IDENTIFIER_PATTERN,
    ACTION_ID_PATTERN,
    ACTION_DOSSIER_DIGEST_PATTERN,
    ISO_TIMESTAMP_PATTERN,
)
from framework.auth_correlation.state import (
    CrossProcessFileLock,
    _enforce_windows_directory_dacl,
    _enforce_windows_file_dacl,
    _verify_windows_directory_security,
    _verify_windows_file_security,
)
from framework.authentication.validators import AuthenticationFalsePositiveClassifier
from framework.authz.model import ResourceAccessTarget
from framework.common.evidence import sanitize_sensitive_data
from framework.validation.engine import SecurityValidationEngine
from framework.validation.request import ControlledRequest, ControlledResponse
from framework.auth_correlation.dispatcher import ControlledDispatchWorkflow, ControlledDispatchResult


ALLOWED_DOSSIER_KEYS: Set[str] = {
    "action_id", "target_endpoint", "method", "test_account", 
    "action_type", "program_id", "created_at", "ttl", "unique_approval_id",
    "approval_signature",
}

CANONICAL_ACTION_FIELDS: List[str] = [
    "action_type", "created_at", "method", "program_id",
    "target_endpoint", "test_account", "ttl", "unique_approval_id"
]

ALLOWED_MUTATION_METHODS: Set[str] = {"POST", "PUT", "DELETE"}
ALLOWED_ACTION_TYPES: Set[str] = {"LOGOUT", "ACTION-LOGOUT", "TOKEN_REVOCATION", "PASSWORD_CHANGE"}

GENUINE_INVALIDATION_EVENTS: Set[str] = {
    "SESSION_REVOCATION",
    "LOGOUT",
    "SESSION_INVALIDATION",
    "PASSWORD_CHANGE",
    "TOKEN_REVOCATION",
    "ADMIN_SESSION_TERMINATION",
}

NEGATIVE_REVOCATION_PHRASES: Tuple[str, ...] = (
    "not revoked",
    "was not revoked",
    "is not revoked",
    "has not been revoked",
    "never revoked",
    "failed to revoke",
    "could not revoke",
    "revocation failed",
    "revocation error",
    "unrevoked",
    "not logged out",
    "logout failed",
    "logout error",
    "session active",
    "session is active",
    "session still active",
    "token valid",
    "token is valid",
    "token still valid",
    "unauthorized access denied",
)


def get_or_create_approval_key(key_dir: Optional[str] = None) -> bytes:
    """
    Retrieves or generates the 32-byte secret HMAC key used for Mode B operator action authorization.
    Stored strictly outside the Git repository:
    - POSIX: ~/.config/opencode/auth_approval.key (or $XDG_CONFIG_HOME/opencode/auth_approval.key)
    - Windows: %LOCALAPPDATA%\\opencode\\auth_approval.key (fallback ~/.config/opencode/auth_approval.key)
    - Override: OPENCODE_APPROVAL_KEY_PATH environment variable
    """
    env_path = os.environ.get("OPENCODE_APPROVAL_KEY_PATH")
    if env_path:
        key_file = os.path.abspath(env_path)
        key_folder = os.path.dirname(key_file)
    elif key_dir:
        key_folder = os.path.abspath(key_dir)
        key_file = os.path.join(key_folder, "auth_approval.key")
    elif os.name == "nt":
        base_dir = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        key_folder = os.path.join(base_dir, "opencode")
        key_file = os.path.join(key_folder, "auth_approval.key")
    else:
        base_dir = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        key_folder = os.path.join(base_dir, "opencode")
        key_file = os.path.join(key_folder, "auth_approval.key")

    try:
        if not os.path.exists(key_folder):
            if os.name != "nt":
                os.makedirs(key_folder, mode=0o700, exist_ok=True)
            else:
                os.makedirs(key_folder, exist_ok=True)
                _enforce_windows_directory_dacl(key_folder)

        if os.name == "nt":
            _enforce_windows_directory_dacl(key_folder)
            _verify_windows_directory_security(key_folder)
        else:
            kdir_stat = os.lstat(key_folder)
            if stat.S_ISLNK(kdir_stat.st_mode):
                raise ApprovalSecurityError("Approval key directory is a symbolic link")
            if kdir_stat.st_uid != os.getuid():
                raise ApprovalSecurityError("Approval key directory ownership mismatch")
            if kdir_stat.st_mode & 0o077 != 0:
                try:
                    os.chmod(key_folder, 0o700)
                    kdir_stat = os.lstat(key_folder)
                except OSError:
                    pass
            if kdir_stat.st_mode & 0o077 != 0:
                raise ApprovalSecurityError("Approval key directory permissions are not private")

        if os.path.exists(key_file):
            k_stat = os.lstat(key_file)
            if stat.S_ISLNK(k_stat.st_mode):
                raise ApprovalSecurityError("Approval key file is a symbolic link")
            if os.name == "nt":
                try:
                    _enforce_windows_file_dacl(key_file)
                    _verify_windows_file_security(key_file)
                except SerializationSecurityError as err:
                    raise ApprovalSecurityError(str(err))
            else:
                if k_stat.st_uid != os.getuid():
                    raise ApprovalSecurityError("Approval key file ownership mismatch")
                if k_stat.st_mode & 0o077 != 0:
                    raise ApprovalSecurityError("Approval key file permissions are not private")
                if k_stat.st_nlink != 1:
                    raise ApprovalSecurityError("Approval key file has unexpected hardlinks")

            with open(key_file, "rb") as f:
                key = f.read(32)
            if len(key) != 32:
                raise ApprovalSecurityError("Invalid approval key file length")
            return key
        else:
            key = secrets.token_bytes(32)
            flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            fd = os.open(key_file, flags, 0o600)
            try:
                with os.fdopen(fd, "wb", closefd=True) as f:
                    f.write(key)
            except Exception as e:
                raise ApprovalSecurityError(f"Failed to write approval key file: {e}")

            if os.name == "nt":
                try:
                    _enforce_windows_file_dacl(key_file)
                    _verify_windows_file_security(key_file)
                except SerializationSecurityError as err:
                    raise ApprovalSecurityError(str(err))
            return key
    except Exception as e:
        if isinstance(e, ApprovalSecurityError):
            raise
        raise ApprovalSecurityError(f"Cannot secure external approval key: {e}")


def get_or_create_attestation_key(key_dir: Optional[str] = None) -> bytes:
    """
    Retrieves or generates the 32-byte secret HMAC key used for invalidation event attestation.
    Stored strictly outside the Git repository:
    - POSIX: ~/.config/opencode/invalidation_attestation.key (or $XDG_CONFIG_HOME/opencode/invalidation_attestation.key)
    - Windows: %LOCALAPPDATA%\\opencode\\invalidation_attestation.key (fallback ~/.config/opencode/invalidation_attestation.key)
    - Override: OPENCODE_ATTESTATION_KEY_PATH environment variable
    """
    env_path = os.environ.get("OPENCODE_ATTESTATION_KEY_PATH")
    if env_path:
        key_file = os.path.abspath(env_path)
        key_folder = os.path.dirname(key_file)
    elif key_dir:
        key_folder = os.path.abspath(key_dir)
        key_file = os.path.join(key_folder, "invalidation_attestation.key")
    elif os.name == "nt":
        base_dir = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        key_folder = os.path.join(base_dir, "opencode")
        key_file = os.path.join(key_folder, "invalidation_attestation.key")
    else:
        base_dir = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        key_folder = os.path.join(base_dir, "opencode")
        key_file = os.path.join(key_folder, "invalidation_attestation.key")

    try:
        if not os.path.exists(key_folder):
            if os.name != "nt":
                os.makedirs(key_folder, mode=0o700, exist_ok=True)
            else:
                os.makedirs(key_folder, exist_ok=True)
                _enforce_windows_directory_dacl(key_folder)

        if os.name == "nt":
            _enforce_windows_directory_dacl(key_folder)
            _verify_windows_directory_security(key_folder)
        else:
            kdir_stat = os.lstat(key_folder)
            if stat.S_ISLNK(kdir_stat.st_mode):
                raise AttestationSecurityError("Attestation key directory is a symbolic link")
            if kdir_stat.st_uid != os.getuid():
                raise AttestationSecurityError("Attestation key directory ownership mismatch")
            if kdir_stat.st_mode & 0o077 != 0:
                try:
                    os.chmod(key_folder, 0o700)
                    kdir_stat = os.lstat(key_folder)
                except OSError:
                    pass
            if kdir_stat.st_mode & 0o077 != 0:
                raise AttestationSecurityError("Attestation key directory permissions are not private")

        if os.path.exists(key_file):
            k_stat = os.lstat(key_file)
            if stat.S_ISLNK(k_stat.st_mode):
                raise AttestationSecurityError("Attestation key file is a symbolic link")
            if os.name == "nt":
                try:
                    _enforce_windows_file_dacl(key_file)
                    _verify_windows_file_security(key_file)
                except SerializationSecurityError as err:
                    raise AttestationSecurityError(str(err))
            else:
                if k_stat.st_uid != os.getuid():
                    raise AttestationSecurityError("Attestation key file ownership mismatch")
                if k_stat.st_mode & 0o077 != 0:
                    raise AttestationSecurityError("Attestation key file permissions are not private")
                if k_stat.st_nlink != 1:
                    raise AttestationSecurityError("Attestation key file has unexpected hardlinks")

            with open(key_file, "rb") as f:
                key = f.read(32)
            if len(key) != 32:
                raise AttestationSecurityError("Invalid attestation key file length")
            return key
        else:
            key = secrets.token_bytes(32)
            flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            fd = os.open(key_file, flags, 0o600)
            try:
                with os.fdopen(fd, "wb", closefd=True) as f:
                    f.write(key)
            except Exception as e:
                raise AttestationSecurityError(f"Failed to write attestation key file: {e}")

            if os.name == "nt":
                try:
                    _enforce_windows_file_dacl(key_file)
                    _verify_windows_file_security(key_file)
                except SerializationSecurityError as err:
                    raise AttestationSecurityError(str(err))
            return key
    except Exception as e:
        if isinstance(e, AttestationSecurityError):
            raise
        raise AttestationSecurityError(f"Cannot secure external attestation key: {e}")


CANONICAL_ATTESTATION_FIELDS = (
    "action_dossier_digest",
    "action_id",
    "created_at",
    "domain",
    "event_type",
    "execution_id",
    "execution_timestamp",
    "http_method",
    "invalidation_verification_result",
    "key_id",
    "mutation_evidence_ref",
    "operator_id",
    "original_evidence_ref",
    "principal_id",
    "program_id",
    "reason",
    "session_ref",
    "source",
    "target_endpoint",
    "verification_evidence_ref",
    "verification_method",
    "verification_timestamp",
)
ATTESTATION_DOMAIN = "BB_INVALIDATION_ATTESTATION_V1"
ALLOWED_ATTESTATION_SOURCES = frozenset({"CONTROLLED_WORKFLOW", "OPERATOR_ATTESTATION", "VERIFIED_EXTERNAL"})
ALLOWED_CONTROLLED_VERIFICATION_METHODS = frozenset({
    "ACTION_MUTATION_AND_PROBE_VERIFIED",
    "MUTATION_EXPLICIT_REVOCATION_VERIFIED",
    "MUTATION_STRUCTURED_REVOCATION_CONFIRMED",
    "MUTATION_LOGIN_REDIRECT_AND_COOKIE_CLEARED",
    "POST_MUTATION_PROBE_CONFIRMED_401",
    "POST_MUTATION_PROBE_CONFIRMED_REDIRECT_LOGIN",
})
ALLOWED_VERIFIED_RESULTS = frozenset({"VERIFIED", "REVOKED", "SESSION_REVOKED"})


def _sign_attestation_payload(
    canonical_payload: Dict[str, Any],
    attestation_key: Optional[bytes] = None,
    key_dir: Optional[str] = None,
) -> Tuple[str, str]:
    """Generates attestation_id and HMAC signature for canonical payload."""
    canonical_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    attestation_id = f"ATT-{hashlib.sha256(canonical_bytes).hexdigest().upper()}"
    key = attestation_key or get_or_create_attestation_key(key_dir=key_dir)
    sig_hash = hmac.new(key, canonical_bytes, hashlib.sha256).hexdigest().upper()
    signature = f"ATT-SIG-{sig_hash}"
    return attestation_id, signature


def _create_controlled_invalidation_attestation_from_record(
    execution_record: ExecutionRecord,
    execution_ledger: ExecutionLedger,
    evidence_store: Any,
    attestation_key: Optional[bytes] = None,
    key_dir: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Internal trusted factory: creates and persists an authenticated invalidation event
    attestation strictly from an authenticated, un-replayed ExecutionRecord in ExecutionLedger.
    """
    if not isinstance(execution_record, ExecutionRecord):
        raise AttestationSecurityError("Invalid execution record for controlled attestation")

    validated = execution_record.validate()

    if validated["verification_method"] not in ALLOWED_CONTROLLED_VERIFICATION_METHODS:
        raise AttestationSecurityError(
            f"Verification method '{validated['verification_method']}' is not authorized for controlled attestation"
        )

    if validated["invalidation_verification_result"] not in ALLOWED_VERIFIED_RESULTS:
        raise AttestationSecurityError(
            f"Invalidation verification result '{validated['invalidation_verification_result']}' does not satisfy verification criteria"
        )

    # Verify execution record existence and cryptographic signature in ExecutionLedger
    if execution_ledger is not None:
        rec_in_ledger = execution_ledger.get_execution(validated["execution_id"])
        if rec_in_ledger is None:
            raise AttestationSecurityError(f"Execution '{validated['execution_id']}' is not registered in ExecutionLedger")
        if getattr(rec_in_ledger, "is_testing_primitive", False):
            raise AttestationSecurityError("Execution record is a test primitive and not genuine execution provenance")
        if rec_in_ledger.attestation_created:
            raise AttestationSecurityError(
                f"Execution '{validated['execution_id']}' has already been claimed for attestation '{rec_in_ledger.attestation_id}' (replay rejected)"
            )

    # Verify mutation and verification captures exist in EvidenceStore
    if evidence_store is None or not hasattr(evidence_store, "get_evidence"):
        raise AttestationSecurityError("EvidenceStore is mandatory for controlled attestation creation")

    mut_ev = evidence_store.get_evidence(validated["mutation_evidence_ref"])
    if mut_ev is None:
        raise AttestationSecurityError(f"Mutation evidence '{validated['mutation_evidence_ref']}' missing from EvidenceStore")
    ver_ev = evidence_store.get_evidence(validated["verification_evidence_ref"])
    if ver_ev is None:
        raise AttestationSecurityError(f"Verification evidence '{validated['verification_evidence_ref']}' missing from EvidenceStore")

    from datetime import datetime, timezone
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    key_id = "KEY-LOCAL-ATTESTATION-1"

    canonical: Dict[str, Any] = {
        "action_dossier_digest": validated["action_dossier_digest"],
        "action_id": validated["action_id"],
        "created_at": created_at,
        "domain": ATTESTATION_DOMAIN,
        "event_type": "SESSION_REVOCATION",
        "execution_id": validated["execution_id"],
        "execution_timestamp": validated["execution_timestamp"],
        "http_method": validated["http_method"],
        "invalidation_verification_result": validated["invalidation_verification_result"],
        "key_id": key_id,
        "mutation_evidence_ref": validated["mutation_evidence_ref"].upper(),
        "operator_id": "N/A",
        "original_evidence_ref": validated["mutation_evidence_ref"].upper(),
        "principal_id": validated["principal_id"],
        "program_id": validated["program_id"],
        "reason": "N/A",
        "session_ref": validated["session_ref"],
        "source": "CONTROLLED_WORKFLOW",
        "target_endpoint": validated["target_endpoint"],
        "verification_evidence_ref": validated["verification_evidence_ref"].upper(),
        "verification_method": validated["verification_method"],
        "verification_timestamp": validated["verification_timestamp"],
    }
    att_id, sig = _sign_attestation_payload(canonical, attestation_key=attestation_key, key_dir=key_dir)

    # Atomically claim execution in ExecutionLedger under lock to prevent duplicate creation
    if execution_ledger is not None:
        execution_ledger.claim_for_attestation(validated["execution_id"], att_id)

    record = dict(canonical)
    record["attestation_id"] = att_id
    record["signature"] = sig
    record["trust_classification"] = "INDEPENDENTLY_VERIFIED_WORKFLOW"
    record["details"] = dict(details or {})
    record["details"]["action_id"] = validated["action_id"]
    record["details"]["action_type"] = validated["action_type"]
    record["details"]["execution_id"] = validated["execution_id"]

    if hasattr(evidence_store, "save_invalidation_attestation"):
        evidence_store.save_invalidation_attestation(record)
    return record


def _create_controlled_invalidation_attestation_from_result(
    execution_result: Any,
    evidence_store: Any,
    attestation_key: Optional[bytes] = None,
    key_dir: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    execution_ledger: Optional[Any] = None,
) -> Dict[str, Any]:
    """Adapter bridging legacy ControlledExecutionResult calls to ExecutionLedger verification."""
    if isinstance(execution_result, ExecutionRecord):
        if execution_ledger is None:
            raise AttestationSecurityError("ExecutionLedger is required to verify ExecutionRecord for attestation")
        return _create_controlled_invalidation_attestation_from_record(
            execution_record=execution_result,
            execution_ledger=execution_ledger,
            evidence_store=evidence_store,
            attestation_key=attestation_key,
            key_dir=key_dir,
            details=details,
        )

    if not isinstance(execution_result, ControlledExecutionResult):
        raise AttestationSecurityError("Invalid execution result for controlled attestation")

    validated = execution_result.validate()
    exec_id = validated.get("execution_id")
    if not exec_id or not EXECUTION_ID_PATTERN.match(exec_id):
        raise AttestationSecurityError(
            "Controlled attestation requires a genuine execution record registered in ExecutionLedger; "
            "unverified caller-instantiated results are rejected"
        )

    if execution_ledger is None:
        raise AttestationSecurityError("ExecutionLedger is required to verify execution provenance for attestation")

    rec = execution_ledger.get_execution(exec_id)
    if rec is None:
        raise AttestationSecurityError(f"Execution '{exec_id}' not found in ExecutionLedger")

    return _create_controlled_invalidation_attestation_from_record(
        execution_record=rec,
        execution_ledger=execution_ledger,
        evidence_store=evidence_store,
        attestation_key=attestation_key,
        key_dir=key_dir,
        details=details,
    )


def create_controlled_invalidation_attestation(
    evidence_store: Any,
    execution_result: Optional[Any] = None,
    execution_record: Optional[Any] = None,
    execution_ledger: Optional[Any] = None,
    *args: Any,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Entry point for creating a controlled invalidation event attestation.
    STRICTLY ENFORCES that attestations cannot be generated from caller assertions or
    arbitrary action IDs without a verified execution record registered in ExecutionLedger.
    """
    target = execution_record if execution_record is not None else execution_result
    if target is None:
        raise AttestationSecurityError(
            "Controlled attestation cannot be created from caller assertion; "
            "must provide a verified ExecutionRecord from ExecutionLedger"
        )

    ledger = execution_ledger or kwargs.get("ledger")
    if ledger is None and isinstance(kwargs.get("state_dir"), str):
        ledger = ExecutionLedger(kwargs["state_dir"], key_dir=kwargs.get("key_dir"))

    if isinstance(target, ExecutionRecord):
        if ledger is None:
            raise AttestationSecurityError("ExecutionLedger is required to verify ExecutionRecord")
        return _create_controlled_invalidation_attestation_from_record(
            execution_record=target,
            execution_ledger=ledger,
            evidence_store=evidence_store,
            attestation_key=kwargs.get("attestation_key"),
            key_dir=kwargs.get("key_dir"),
            details=kwargs.get("details"),
        )
    elif isinstance(target, ControlledExecutionResult):
        return _create_controlled_invalidation_attestation_from_result(
            execution_result=target,
            evidence_store=evidence_store,
            attestation_key=kwargs.get("attestation_key"),
            key_dir=kwargs.get("key_dir"),
            details=kwargs.get("details"),
            execution_ledger=ledger,
        )
    else:
        raise AttestationSecurityError("Invalid execution type for controlled attestation")


def create_operator_invalidation_attestation(
    evidence_store: Any,
    original_evidence_ref: str,
    session_ctx: CorrelatedSessionContext,
    program_id: str,
    event_type: str,
    operator_id: str,
    reason: str,
    attestation_key: Optional[bytes] = None,
    key_dir: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Creates and persists an explicit, auditable operator attestation of session invalidation.
    Explicitly categorized as OPERATOR_REPORTED trust classification.
    """
    if not isinstance(original_evidence_ref, str) or not EVIDENCE_REF_PATTERN.match(original_evidence_ref):
        raise AttestationSecurityError(f"Invalid original evidence reference '{original_evidence_ref}'")
    if not isinstance(session_ctx, CorrelatedSessionContext) or not session_ctx.session_ref:
        raise AttestationSecurityError("Invalid session context for attestation")
    if not isinstance(program_id, str) or not SAFE_IDENTIFIER_PATTERN.match(program_id):
        raise AttestationSecurityError(f"Invalid program identifier '{program_id}'")
    if event_type not in GENUINE_INVALIDATION_EVENTS:
        raise AttestationSecurityError(f"Event type '{event_type}' is not an authorized invalidation event")
    if not isinstance(operator_id, str) or not operator_id.strip():
        raise AttestationSecurityError("Operator ID is required for operator attestation")
    if not isinstance(reason, str) or not reason.strip():
        raise AttestationSecurityError("Attestation reason is required for operator attestation")

    if evidence_store is not None and hasattr(evidence_store, "get_evidence"):
        orig_ev = evidence_store.get_evidence(original_evidence_ref.upper())
        if orig_ev is None:
            raise AttestationSecurityError(f"Original evidence '{original_evidence_ref}' missing from EvidenceStore")

    from datetime import datetime, timezone
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    key_id = "KEY-LOCAL-ATTESTATION-1"

    canonical: Dict[str, Any] = {
        "action_dossier_digest": "N/A",
        "action_id": "N/A",
        "created_at": created_at,
        "domain": ATTESTATION_DOMAIN,
        "event_type": event_type,
        "execution_id": "N/A",
        "execution_timestamp": "N/A",
        "http_method": "N/A",
        "invalidation_verification_result": "OPERATOR_ASSERTED",
        "key_id": key_id,
        "mutation_evidence_ref": "N/A",
        "operator_id": operator_id.strip(),
        "original_evidence_ref": original_evidence_ref.upper(),
        "principal_id": session_ctx.principal_id,
        "program_id": program_id,
        "reason": reason.strip(),
        "session_ref": session_ctx.session_ref,
        "source": "OPERATOR_ATTESTATION",
        "target_endpoint": "N/A",
        "verification_evidence_ref": "N/A",
        "verification_method": "OPERATOR_ASSERTION",
        "verification_timestamp": "N/A",
    }
    att_id, sig = _sign_attestation_payload(canonical, attestation_key=attestation_key, key_dir=key_dir)

    record = dict(canonical)
    record["attestation_id"] = att_id
    record["signature"] = sig
    record["trust_classification"] = "OPERATOR_REPORTED"
    record["details"] = dict(details or {})
    record["details"]["operator_id"] = operator_id.strip()
    record["details"]["reason"] = reason.strip()

    if hasattr(evidence_store, "save_invalidation_attestation"):
        evidence_store.save_invalidation_attestation(record)
    return record


def sign_action_approval(
    action_dossier: Dict[str, Any],
    approval_key: Optional[bytes] = None,
    key_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generates action integrity hash (action_id) and operator authorization signature (approval_signature)
    for a controlled invalidation action descriptor using an external approval key.
    """
    if not isinstance(action_dossier, dict):
        raise ApprovalSecurityError("Action dossier must be a dictionary")

    for field in CANONICAL_ACTION_FIELDS:
        if field not in action_dossier:
            raise ApprovalSecurityError(f"Action dossier missing required field: '{field}'")

    method = action_dossier["method"]
    if not isinstance(method, str) or method not in ALLOWED_MUTATION_METHODS:
        raise ApprovalSecurityError("Action approval specifies invalid or unsupported HTTP method")

    action_type = action_dossier["action_type"]
    if not isinstance(action_type, str) or action_type not in ALLOWED_ACTION_TYPES:
        raise ApprovalSecurityError("Action approval specifies unsupported action type")

    target_endpoint = action_dossier["target_endpoint"]
    if not isinstance(target_endpoint, str) or not target_endpoint:
        raise ApprovalSecurityError("Action approval target_endpoint must be a non-empty string")

    test_account = action_dossier["test_account"]
    if not isinstance(test_account, str) or not test_account:
        raise ApprovalSecurityError("Action approval test_account must be a non-empty string")

    program_id = action_dossier["program_id"]
    if not isinstance(program_id, str) or not program_id:
        raise ApprovalSecurityError("Action approval program_id must be a non-empty string")

    unique_approval_id = action_dossier["unique_approval_id"]
    if not isinstance(unique_approval_id, str) or not unique_approval_id:
        raise ApprovalSecurityError("Action approval unique_approval_id must be a non-empty string")

    created_at_raw = action_dossier["created_at"]
    if isinstance(created_at_raw, bool) or not isinstance(created_at_raw, (int, float)):
        raise ApprovalSecurityError("Action approval created_at must be numeric timestamp")

    ttl_raw = action_dossier["ttl"]
    if isinstance(ttl_raw, bool) or not isinstance(ttl_raw, (int, float)) or ttl_raw <= 0:
        raise ApprovalSecurityError("Action approval ttl must be positive number")

    canonical_copy = {k: action_dossier[k] for k in CANONICAL_ACTION_FIELDS}
    canonical_str = json.dumps(canonical_copy, sort_keys=True)
    action_id = f"ACT-{hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()}"

    key = approval_key or get_or_create_approval_key(key_dir=key_dir)
    sig_hash = hmac.new(key, canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()
    approval_signature = f"SIG-{sig_hash}"

    result = dict(canonical_copy)
    result["action_id"] = action_id
    result["approval_signature"] = approval_signature
    return result


def classify_revocation_response(
    resp: Optional[ControlledResponse],
    baseline: Optional[ControlledResponse] = None,
) -> Tuple[str, Optional[str]]:
    """
    Conservatively classifies post-revocation probe responses according to security policy:
    Eliminates loose substring matching and rejects negative revocation statements.
    - 401 with structured expiration/revocation evidence: 'REVOKED' or 'EXPIRED'
    - Generic 401: 'AUTHENTICATION_FAILED' (does not prove revocation)
    - 403: 'AUTHORIZATION_DENIED' (does not prove revocation)
    - Recognized login redirect: 'REDIRECT_LOGIN'
    - WAF/challenge response: 'INCONCLUSIVE'
    - Generic 200 response (shell, landing, empty): 'INCONCLUSIVE'
    - 200 with structured revocation confirmation: 'REVOKED'
    - 200 with matching protected baseline content: 'SESSION_NOT_INVALIDATED' (retained access finding)
    - Ambiguous / unhandled: 'INCONCLUSIVE'
    """
    if resp is None:
        return "INCONCLUSIVE", "No response received"

    body_text = resp.body_text or ""
    lower_body = body_text.lower()
    has_negative_revocation = any(phrase in lower_body for phrase in NEGATIVE_REVOCATION_PHRASES)

    # 1. 401 Unauthorized -> check for explicit structured expiration or revocation evidence
    if resp.status_code == 401:
        if has_negative_revocation:
            return "INCONCLUSIVE", "Response contains negative revocation statements (revocation not proven)"

        revocation_indicators = (
            "token has been revoked", "session has been revoked",
            "token was revoked", "session was revoked",
            "token_revoked", "session_revoked", "session_invalidated",
            "logged_out", "logged out", "token revoked", "session revoked",
            "revoked",
        )
        expiration_indicators = (
            "token has expired", "session has expired",
            "token was expired", "token_expired", "session_expired",
            "token expired", "session expired", "expired",
        )

        # Try parsing structured JSON
        parsed_json: Optional[Dict[str, Any]] = None
        if body_text.strip().startswith("{"):
            try:
                parsed_json = json.loads(body_text)
            except Exception:
                parsed_json = None

        if isinstance(parsed_json, dict):
            status_val = str(parsed_json.get("status", "")).lower()
            if (
                any(ind in status_val for ind in revocation_indicators)
                or parsed_json.get("revoked") is True
                or parsed_json.get("logged_out") is True
            ):
                return "REVOKED", "Response explicitly reports token or session as revoked via structured JSON"
            if (
                any(ind in status_val for ind in expiration_indicators)
                or parsed_json.get("expired") is True
            ):
                return "EXPIRED", "Response explicitly reports token or session as expired via structured JSON"

            for field in ("error", "message", "detail", "error_description"):
                field_val = str(parsed_json.get(field, "")).lower()
                if field_val and any(ind in field_val for ind in revocation_indicators):
                    return "REVOKED", f"Response explicitly reports token or session as revoked via '{field}' field"
                if field_val and any(ind in field_val for ind in expiration_indicators):
                    return "EXPIRED", f"Response explicitly reports token or session as expired via '{field}' field"

        www_auth = (resp.headers.get("www-authenticate") or "").lower()
        if any(ind in www_auth for ind in revocation_indicators):
            return "REVOKED", "WWW-Authenticate header explicitly reports token as revoked"
        if any(ind in www_auth for ind in expiration_indicators):
            return "EXPIRED", "WWW-Authenticate header explicitly reports token as expired"

        if any(ind in lower_body for ind in revocation_indicators):
            return "REVOKED", "Response explicitly reports token or session as revoked"
        if any(ind in lower_body for ind in expiration_indicators):
            return "EXPIRED", "Response explicitly reports token or session as expired"

        return "AUTHENTICATION_FAILED", "Generic 401 unauthorized without explicit structured revocation evidence"

    # 3. 403 Forbidden -> AUTHORIZATION_DENIED (does not prove session invalidation)
    if resp.status_code == 403:
        return "AUTHORIZATION_DENIED", "HTTP 403 indicates authorization denial, not session invalidation"

    # 4. Recognized login redirect
    if resp.status_code in (301, 302, 303, 307, 308):
        loc = (resp.headers.get("location") or "").lower()
        if any(term in loc for term in ("/login", "/auth", "/signin", "/sso", "login.")):
            return "REDIRECT_LOGIN", f"Redirect to authentication interface ({loc})"
        return "INCONCLUSIVE", f"Redirect to non-login interface ({loc})"

    # 5. Check for inline login forms
    if AuthenticationFalsePositiveClassifier.is_login_page_false_positive(resp.status_code, body_text):
        return "REDIRECT_LOGIN", "Inline login challenge form returned"

    # 6. Generic 200/204 response
    if resp.status_code in (200, 204):
        if AuthenticationFalsePositiveClassifier.is_waf_or_challenge_page(resp.status_code, body_text):
            return "INCONCLUSIVE", "WAF or bot security challenge page"
        if AuthenticationFalsePositiveClassifier.is_public_landing_or_generic_shell(resp.status_code, body_text):
            return "INCONCLUSIVE", "Public landing page or generic SPA application shell"
        if AuthenticationFalsePositiveClassifier.is_generic_status_or_empty_response(resp.status_code, body_text):
            return "INCONCLUSIVE", "Generic status or empty response without protected data"

        # Check structured JSON for explicit revocation confirmation (e.g. from logout endpoint)
        if not has_negative_revocation and body_text:
            parsed_json = None
            if body_text.strip().startswith("{"):
                try:
                    parsed_json = json.loads(body_text)
                except Exception:
                    parsed_json = None
            if isinstance(parsed_json, dict):
                status_val = str(parsed_json.get("status", "")).lower()
                if (
                    status_val in ("revoked", "logged_out", "invalidated", "terminated", "session_revoked")
                    or parsed_json.get("revoked") is True
                    or parsed_json.get("logged_out") is True
                ):
                    return "REVOKED", "Structured response explicitly confirms session invalidation"
                if parsed_json.get("revoked") is False or status_val in ("active", "valid", "authenticated"):
                    return "SESSION_NOT_INVALIDATED", "Response explicitly reports session is still active"

        # 7. Verify matching protected baseline content
        if baseline is not None and baseline.status_code == 200:
            ratio = difflib.SequenceMatcher(None, body_text, baseline.body_text).ratio()
            if ratio >= 0.50:
                return "SESSION_NOT_INVALIDATED", f"Response matches protected baseline content (similarity: {ratio:.2f})"
            return "INCONCLUSIVE", f"Response similarity ({ratio:.2f}) below threshold for baseline match"

    return "INCONCLUSIVE", f"Ambiguous response (HTTP {resp.status_code})"


class PostRevocationResourceValidator:
    """Evaluates resource accessibility post-revocation across Mode A and Mode B."""

    _consumed_lock = threading.Lock()

    def __init__(
        self,
        validation_engine: Optional[Any] = None,
        program_dir: Optional[str] = None,
        state_dir: Optional[str] = None,
        scope_engine: Optional[Any] = None,
        approval_key: Optional[bytes] = None,
        approval_key_dir: Optional[str] = None,
        evidence_store: Optional[Any] = None,
        program_id: Optional[str] = None,
        attestation_key: Optional[bytes] = None,
        execution_ledger: Optional[Any] = None,
        execution_key: Optional[bytes] = None,
    ):
        self._engine = validation_engine
        self._program_dir = program_dir or "."
        if program_id:
            self._program_id = program_id
        elif program_dir and program_dir != ".":
            self._program_id = os.path.basename(program_dir.rstrip("/\\")) or "default-program"
        else:
            self._program_id = "default-program"
        if state_dir:
            self._state_dir = state_dir
        elif evidence_store and hasattr(evidence_store, "evidence_dir") and os.path.dirname(evidence_store.evidence_dir):
            self._state_dir = os.path.join(os.path.dirname(evidence_store.evidence_dir), "state")
        else:
            self._state_dir = os.path.join(self._program_dir, "state")
        self._scope_engine = scope_engine
        self._approval_key = approval_key
        self._attestation_key = attestation_key
        self._approval_key_dir = approval_key_dir
        self._evidence_store = evidence_store
        self._execution_ledger = execution_ledger
        self._execution_key = execution_key

    @property
    def engine(self) -> Any:
        if self._engine is None:
            self._engine = SecurityValidationEngine(program_dir=self._program_dir)
        return self._engine

    @property
    def ledger(self) -> ExecutionLedger:
        if self._execution_ledger is None:
            self._execution_ledger = ExecutionLedger(
                state_dir=self._state_dir,
                execution_key=self._execution_key,
                key_dir=self._approval_key_dir,
            )
        return self._execution_ledger

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

    def _mark_approval_consumed(
        self,
        action_id: str,
        dossier: Dict[str, Any],
        session_ctx: Optional[CorrelatedSessionContext] = None,
    ) -> str:
        """Atomically marks action approval as consumed; fails closed on corruption."""
        os.makedirs(self._state_dir, exist_ok=True)
        path = self._get_consumed_approvals_path()
        data: Dict[str, Any] = {"version": 1, "consumed": {}}
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if not isinstance(data, dict) or "consumed" not in data or not isinstance(data["consumed"], dict):
                    raise ApprovalSecurityError("Consumed approvals state storage is corrupted")
            except ApprovalSecurityError:
                raise
            except Exception as e:
                raise ApprovalSecurityError(f"Consumed approvals state storage is corrupted: {e}")

        if "version" not in data:
            data["version"] = 1

        from datetime import datetime, timezone
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        consumption_token = secrets.token_hex(32)
        sess_ref = getattr(session_ctx, "session_ref", "") if session_ctx else ""
        p_id = getattr(session_ctx, "principal_id", "") if session_ctx else (dossier.get("test_account") or "")
        key = self._approval_key or get_or_create_approval_key(key_dir=self._approval_key_dir)
        op_sig = dossier.get("approval_signature", "")

        receipt_payload: Dict[str, Any] = {
            "action_dossier_digest": action_id[4:],
            "action_id": action_id,
            "action_type": dossier.get("action_type", ""),
            "approval_id": dossier.get("unique_approval_id", ""),
            "consumed_at": now_iso,
            "consumption_token": consumption_token,
            "method": dossier.get("method", ""),
            "operator_signature": op_sig,
            "principal_id": p_id,
            "program_id": self._program_id,
            "session_ref": sess_ref,
            "target_endpoint": dossier.get("target_endpoint", ""),
            "test_account": dossier.get("test_account", ""),
        }
        receipt_sig = sign_consumption_receipt(receipt_payload, key)
        canonical_dossier_copy = {k: dossier[k] for k in CANONICAL_ACTION_FIELDS if k in dossier}

        data["consumed"][action_id] = {
            **receipt_payload,
            "action_dossier": canonical_dossier_copy,
            "receipt_signature": receipt_sig,
            "capability_issued": False,
            "execution_id": None,
        }

        tmp_path = f"{path}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
        try:
            flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            fd = os.open(tmp_path, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            if os.name == "nt":
                _enforce_windows_file_dacl(tmp_path)
                _verify_windows_file_security(tmp_path)
            os.replace(tmp_path, path)
        except Exception as e:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            raise ApprovalSecurityError(f"Failed to record consumed approval state: {e}")
        return consumption_token

    def verify_invalidation_provenance(
        self,
        invalidation_evidence_ref: Any,
        session_ctx: CorrelatedSessionContext,
        program_id: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Strictly verifies invalidation evidence provenance via authentic event attestation:
        1. Reference matches EVIDENCE_REF_PATTERN ('EVID-[0-9A-F]{12}') or ATTESTATION_REF_PATTERN ('ATT-[0-9A-F]{64}').
        2. Resolves against the configured EvidenceStore and retrieves authenticated invalidation attestation.
        3. Fails closed if evidence is an ordinary capture without an authenticated invalidation attestation.
        4. Validates attestation schema, domain tag (BB_INVALIDATION_ATTESTATION_V1), and event_type in GENUINE_INVALIDATION_EVENTS.
        5. Enforces exact attribution matching across session_ref, principal_id, and program_id.
        6. Cryptographically verifies HMAC-SHA256 signature using dedicated attestation key.
        7. Resolves original evidence capture in EvidenceStore, verifying descriptor structure, on-disk .txt existence, and SHA-256 content digest.
        8. For CONTROLLED_WORKFLOW: verifies execution_id in ExecutionLedger, verifies execution signature, and verifies mutation & verification captures.
        9. Rejects Mode A observation artifacts and self-referential evidence.
        10. Distinguishes independently verified events (CONTROLLED_WORKFLOW) from auditable operator attestations (OPERATOR_ATTESTATION).
        Returns (is_valid, reason, attestation_record).
        """
        if not invalidation_evidence_ref or not isinstance(invalidation_evidence_ref, str):
            return False, "Invalid or missing invalidation evidence reference format", None

        clean_ref = invalidation_evidence_ref.strip().upper()
        is_evid = bool(EVIDENCE_REF_PATTERN.match(clean_ref))
        is_att = bool(ATTESTATION_REF_PATTERN.match(clean_ref))
        if not is_evid and not is_att:
            return False, f"Evidence reference '{invalidation_evidence_ref}' does not match required EVID-... or ATT-... pattern", None

        if self._evidence_store is None:
            return False, "EvidenceStore is not configured; cannot establish invalidation provenance", None

        if not hasattr(self._evidence_store, "get_invalidation_attestation"):
            return False, "EvidenceStore does not support attestation retrieval; cannot establish invalidation provenance", None

        # 1. Attestation lookup
        try:
            att_record = self._evidence_store.get_invalidation_attestation(clean_ref)
        except Exception as e:
            return False, f"EvidenceStore attestation lookup failure for '{clean_ref}': {e}", None

        if att_record is None or not isinstance(att_record, dict):
            return False, f"Evidence '{clean_ref}' does not possess an authenticated invalidation event attestation", None

        # 2. Structural descriptor validation of attestation
        for req_f in CANONICAL_ATTESTATION_FIELDS:
            if req_f not in att_record or not isinstance(att_record[req_f], str):
                return False, f"Attestation record missing or malformed required field '{req_f}'", None

        for req_meta in ("attestation_id", "signature"):
            if req_meta not in att_record or not isinstance(att_record[req_meta], str):
                return False, f"Attestation record missing or malformed '{req_meta}'", None

        if att_record.get("domain") != ATTESTATION_DOMAIN:
            return False, f"Attestation domain '{att_record.get('domain')}' does not match expected '{ATTESTATION_DOMAIN}'", None

        event_type = att_record.get("event_type")
        if event_type not in GENUINE_INVALIDATION_EVENTS:
            return False, f"Attestation event_type '{event_type}' is not an authorized invalidation event", None

        source = att_record.get("source")
        if source not in ALLOWED_ATTESTATION_SOURCES:
            return False, f"Attestation source '{source}' is not recognized or authorized", None

        stored_key_id = att_record.get("key_id")
        if stored_key_id != "KEY-LOCAL-ATTESTATION-1":
            return False, f"Attestation key_id '{stored_key_id}' is unknown or unsupported", None

        # 3. Mandatory exact attribution: session_ref, principal_id, program_id
        stored_session = att_record.get("session_ref")
        if not stored_session or not SESSION_REF_PATTERN.match(stored_session):
            return False, "Attestation record missing valid 'session_ref' attribution", None
        if stored_session != session_ctx.session_ref:
            return False, f"Attestation attribution mismatch: session_ref '{stored_session}' does not match context session '{session_ctx.session_ref}'", None

        stored_principal = att_record.get("principal_id")
        if not stored_principal or not SAFE_IDENTIFIER_PATTERN.match(stored_principal):
            return False, "Attestation record missing valid 'principal_id' attribution", None
        if stored_principal != session_ctx.principal_id:
            return False, f"Attestation attribution mismatch: principal_id '{stored_principal}' does not match context principal '{session_ctx.principal_id}'", None

        stored_program = att_record.get("program_id")
        if not stored_program or not SAFE_IDENTIFIER_PATTERN.match(stored_program):
            return False, "Attestation record missing valid 'program_id' attribution", None
        target_prog = program_id or getattr(self, "_program_id", None) or "default-program"
        if stored_program != target_prog:
            return False, f"Attestation attribution mismatch: program_id '{stored_program}' does not match target program '{target_prog}'", None

        # 4. Cryptographic signature and ID integrity check
        sig = att_record.get("signature")
        if not ATTESTATION_SIG_PATTERN.match(sig):
            return False, "Attestation contains invalid signature format", None

        try:
            key = self._attestation_key or get_or_create_attestation_key(key_dir=self._approval_key_dir)
        except Exception as e:
            return False, f"Attestation key unavailable or insecure: {e}", None

        canonical_payload = {k: att_record[k] for k in CANONICAL_ATTESTATION_FIELDS}
        canonical_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected_att_id = f"ATT-{hashlib.sha256(canonical_bytes).hexdigest().upper()}"
        expected_sig = f"ATT-SIG-{hmac.new(key, canonical_bytes, hashlib.sha256).hexdigest().upper()}"

        if att_record.get("attestation_id", "").upper() != expected_att_id:
            return False, "Attestation identifier digest mismatch (attestation record has been tampered)", None

        if not hmac.compare_digest(sig.upper(), expected_sig):
            return False, "Attestation cryptographic signature verification failed", None

        # 5. Original Evidence Capture Verification
        orig_ref = att_record.get("original_evidence_ref")
        if not orig_ref or not EVIDENCE_REF_PATTERN.match(orig_ref):
            return False, f"Attestation references invalid original evidence reference format: '{orig_ref}'", None

        if not hasattr(self._evidence_store, "get_evidence"):
            return False, "EvidenceStore does not support get_evidence lookup", None

        try:
            orig_evidence = self._evidence_store.get_evidence(orig_ref)
        except Exception as e:
            return False, f"Failed to retrieve original evidence '{orig_ref}' from EvidenceStore: {e}", None

        if orig_evidence is None or not isinstance(orig_evidence, dict):
            return False, f"Original evidence capture '{orig_ref}' referenced by attestation is missing from EvidenceStore", None

        for req_field in ("evidence_id", "filename", "sha256", "metadata"):
            if req_field not in orig_evidence:
                return False, f"Original evidence descriptor is missing required structural field '{req_field}'", None

        if orig_evidence.get("evidence_id") != orig_ref:
            return False, f"Descriptor evidence_id '{orig_evidence.get('evidence_id')}' does not match reference '{orig_ref}'", None

        stored_sha256 = orig_evidence.get("sha256")
        if not isinstance(stored_sha256, str) or len(stored_sha256) != 64 or not all(c in "0123456789abcdefABCDEF" for c in stored_sha256):
            return False, "Original evidence descriptor contains invalid or malformed sha256 digest", None

        expected_id_from_hash = f"EVID-{stored_sha256[:12].upper()}"
        if expected_id_from_hash != orig_ref:
            return False, f"Original evidence identifier '{orig_ref}' does not match stored sha256 prefix '{expected_id_from_hash}'", None

        capture_path = orig_evidence.get("capture_path")
        if not capture_path or not os.path.isfile(capture_path) or os.path.islink(capture_path):
            return False, f"Associated capture file for '{orig_ref}' is missing or not a regular file", None

        try:
            with open(capture_path, "rb") as cf:
                capture_bytes = cf.read()
            actual_digest = hashlib.sha256(capture_bytes).hexdigest()
            if actual_digest.lower() != stored_sha256.lower():
                return False, f"Original evidence capture content has been altered or corrupted (digest mismatch: {actual_digest} != {stored_sha256})", None
        except Exception as e:
            return False, f"Failed to read and verify evidence capture file: {e}", None

        meta = orig_evidence.get("metadata")
        if not isinstance(meta, dict):
            return False, "Original evidence metadata is missing or malformed (must be a dictionary)", None

        # 6. Reject Mode A observation artifacts reused as invalidation evidence
        if (
            meta.get("mode") == "MODE_A"
            or meta.get("observation_mode") == "MODE_A"
            or meta.get("category") == "SESSION_NOT_INVALIDATED"
            or meta.get("finding_category") == "SESSION_NOT_INVALIDATED"
            or "invalidation_evidence_ref" in meta
        ):
            return False, f"Evidence '{orig_ref}' represents a Mode A observation artifact, not a genuine invalidation event", None

        # 7. Preserved auditability of source and strict provenance verification
        if source == "CONTROLLED_WORKFLOW":
            aid = att_record.get("action_id", "")
            if not aid or not ACTION_ID_PATTERN.match(aid):
                return False, f"Controlled attestation contains invalid action_id '{aid}'", None
            adig = att_record.get("action_dossier_digest", "")
            if not adig or not ACTION_DOSSIER_DIGEST_PATTERN.match(adig):
                return False, f"Controlled attestation contains invalid action_dossier_digest '{adig}'", None
            if aid[4:] != adig:
                return False, "Controlled attestation action_id does not match action_dossier_digest", None

            eid = att_record.get("execution_id", "")
            if not eid or not EXECUTION_ID_PATTERN.match(eid):
                return False, f"Controlled attestation contains invalid execution_id '{eid}'", None

            ver_res = att_record.get("invalidation_verification_result")
            if ver_res not in ALLOWED_VERIFIED_RESULTS:
                return False, f"Controlled attestation verification result '{ver_res}' is not valid", None

            ver_meth = att_record.get("verification_method")
            if ver_meth not in ALLOWED_CONTROLLED_VERIFICATION_METHODS:
                return False, f"Controlled attestation verification method '{ver_meth}' is not authorized", None

            mut_ref = att_record.get("mutation_evidence_ref")
            if not mut_ref or not EVIDENCE_REF_PATTERN.match(mut_ref):
                return False, f"Controlled attestation has invalid mutation_evidence_ref '{mut_ref}'", None

            mut_ev = self._evidence_store.get_evidence(mut_ref)
            if mut_ev is None:
                return False, f"Controlled attestation mutation evidence '{mut_ref}' missing from EvidenceStore", None
            mut_cap_path = mut_ev.get("capture_path")
            if not mut_cap_path or not os.path.isfile(mut_cap_path) or os.path.islink(mut_cap_path):
                return False, f"Controlled attestation mutation evidence file '{mut_ref}' missing or not a regular file", None

            ver_ref = att_record.get("verification_evidence_ref")
            if not ver_ref or not EVIDENCE_REF_PATTERN.match(ver_ref):
                return False, f"Controlled attestation has invalid verification_evidence_ref '{ver_ref}'", None

            if mut_ref == ver_ref:
                return False, "Mutation and verification evidence references must be distinct", None

            ver_ev = self._evidence_store.get_evidence(ver_ref)
            if ver_ev is None:
                return False, f"Controlled attestation verification evidence '{ver_ref}' missing from EvidenceStore", None
            ver_cap_path = ver_ev.get("capture_path")
            if not ver_cap_path or not os.path.isfile(ver_cap_path) or os.path.islink(ver_cap_path):
                return False, f"Controlled attestation verification evidence file '{ver_ref}' missing or not a regular file", None

            # Verify on-disk byte integrity of mutation and verification captures
            try:
                with open(mut_cap_path, "rb") as mf:
                    actual_mut_digest = hashlib.sha256(mf.read()).hexdigest()
                if actual_mut_digest.lower() != mut_ev.get("sha256", "").lower():
                    return False, "Controlled attestation mutation capture content corrupted", None

                with open(ver_cap_path, "rb") as vf:
                    actual_ver_digest = hashlib.sha256(vf.read()).hexdigest()
                if actual_ver_digest.lower() != ver_ev.get("sha256", "").lower():
                    return False, "Controlled attestation verification capture content corrupted", None
                if actual_mut_digest.lower() == actual_ver_digest.lower():
                    return False, "Mutation and verification captures must be distinct", None
            except Exception as e:
                return False, f"Failed to verify evidence capture bytes: {e}", None

            # Verify execution ledger record (mandatory for CONTROLLED_WORKFLOW)
            ledger = getattr(self, "_execution_ledger", None)
            if ledger is None and os.path.isdir(self._state_dir):
                try:
                    ledger = ExecutionLedger(self._state_dir, key_dir=self._approval_key_dir)
                except Exception:
                    ledger = None

            if ledger is None:
                return False, "ExecutionLedger is not available; cannot verify controlled execution provenance", None

            try:
                exec_rec = ledger.get_execution(eid)
                if exec_rec is None:
                    return False, f"Execution '{eid}' referenced by attestation is missing from ExecutionLedger", None
                if getattr(exec_rec, "is_testing_primitive", False):
                    return False, "Execution record is a test primitive and not genuine execution provenance", None
                if exec_rec.attestation_id and exec_rec.attestation_id != att_record.get("attestation_id"):
                    return False, "Execution record attestation_id mismatch in ledger", None
                if exec_rec.session_ref != session_ctx.session_ref:
                    return False, "Execution record session attribution mismatch in ledger", None
                if exec_rec.principal_id != session_ctx.principal_id:
                    return False, "Execution record principal attribution mismatch in ledger", None
                if exec_rec.program_id != target_prog:
                    return False, "Execution record program attribution mismatch in ledger", None
                if exec_rec.mutation_evidence_ref != mut_ref:
                    return False, "Execution record mutation evidence reference mismatch in ledger", None
                if exec_rec.verification_evidence_ref != ver_ref:
                    return False, "Execution record verification evidence reference mismatch in ledger", None
                if not getattr(exec_rec, "dispatch_op_id", ""):
                    return False, "Execution record missing dispatch_op_id in ledger", None
            except ExecutionProvenanceError as e:
                return False, f"Execution provenance verification failed: {e}", None

            # Verify consumed approval registry binding
            consumed_path = self._get_consumed_approvals_path()
            if not os.path.isfile(consumed_path):
                return False, "Consumed approvals registry is missing; cannot verify execution provenance", None
            try:
                with open(consumed_path, "r", encoding="utf-8") as cf:
                    c_data = json.load(cf)
                c_dict = c_data.get("consumed", {}) if isinstance(c_data, dict) else {}
                c_entry = c_dict.get(exec_rec.action_id)
                if not c_entry or not isinstance(c_entry, dict):
                    return False, f"Action receipt '{exec_rec.action_id}' missing in consumed approvals registry", None
                if c_entry.get("execution_id") != eid:
                    return False, f"Action receipt '{exec_rec.action_id}' execution_id mismatch in consumed approvals registry", None
                if c_entry.get("approval_id") != exec_rec.approval_id:
                    return False, "Action receipt approval_id mismatch in consumed approvals registry", None
                if c_entry.get("session_ref") != session_ctx.session_ref:
                    return False, "Action receipt session_ref mismatch in consumed approvals registry", None
                if c_entry.get("principal_id") != session_ctx.principal_id:
                    return False, "Action receipt principal_id mismatch in consumed approvals registry", None
                if c_entry.get("program_id") != target_prog:
                    return False, "Action receipt program_id mismatch in consumed approvals registry", None
                if c_entry.get("dispatch_op_id") != exec_rec.dispatch_op_id:
                    return False, "Action receipt dispatch_op_id mismatch in consumed approvals registry", None

                # Cryptographic verification of consumed approval receipt
                app_key = self._approval_key or get_or_create_approval_key(key_dir=self._approval_key_dir)
                if not verify_consumed_approval_entry(c_entry, app_key):
                    return False, "Action receipt signature verification failed in consumed approvals registry: receipt is forged or tampered", None
            except Exception as e:
                return False, f"Failed to verify consumed approval registry: {e}", None

            # Verify capture source tag on evidence metadata
            if mut_ev.get("metadata", {}).get("capture_source") != "CONTROLLED_TRANSPORT_DISPATCH" or mut_ev.get("metadata", {}).get("evidence_class") != "CONTROLLED_TRANSPORT_DISPATCH":
                return False, "Mutation evidence was not captured by controlled transport dispatch", None
            if ver_ev.get("metadata", {}).get("capture_source") != "CONTROLLED_TRANSPORT_DISPATCH" or ver_ev.get("metadata", {}).get("evidence_class") != "CONTROLLED_TRANSPORT_DISPATCH":
                return False, "Verification evidence was not captured by controlled transport dispatch", None
            if mut_ev.get("metadata", {}).get("dispatch_op_id") != exec_rec.dispatch_op_id:
                return False, "Mutation evidence dispatch_op_id mismatch", None
            if ver_ev.get("metadata", {}).get("dispatch_op_id") != exec_rec.dispatch_op_id:
                return False, "Verification evidence dispatch_op_id mismatch", None

            att_record["trust_classification"] = "INDEPENDENTLY_VERIFIED_WORKFLOW"
            reason = f"Invalidation event attestation verified (Source: {source}, Method: {ver_meth})"
        elif source == "OPERATOR_ATTESTATION":
            op_id = att_record.get("operator_id", "")
            reason_str = att_record.get("reason", "")
            if not op_id or op_id == "N/A":
                return False, "Operator attestation missing valid operator_id", None
            if not reason_str or reason_str == "N/A":
                return False, "Operator attestation missing valid reason", None
            att_record["trust_classification"] = "OPERATOR_REPORTED"
            reason = f"Operator attestation verified for {clean_ref} (Operator: {op_id})"
        else:
            att_record["trust_classification"] = "UNVERIFIED"
            reason = f"External attestation verified ({source})"

        return True, reason, att_record

    def evaluate_revoked_session(
        self,
        session_ctx: CorrelatedSessionContext,
        resource_target: ResourceAccessTarget,
        pre_revocation_baseline: Optional[ControlledResponse],
        invalidation_evidence_ref: Optional[str],
    ) -> Tuple[str, Optional[CorrelationFinding]]:
        """
        Mode A: Observes whether an already-invalidated session can access a protected resource.
        Mandatory Evidentiary Prerequisites:
        1. pre_revocation_baseline proving prior authorized access (HTTP 200).
        2. invalidation_evidence_ref verified for provenance against configured EvidenceStore.
        3. Strict read-only GET/HEAD dispatch with immediate ScopeEngine authorization check.
        If any prerequisite is missing or invalid, fails closed returning ('INCONCLUSIVE', None).
        """
        # 1. Require legitimate pre-revocation baseline (HTTP 200)
        if pre_revocation_baseline is None or pre_revocation_baseline.status_code != 200:
            return "INCONCLUSIVE", None

        # 2. Require verified invalidation evidence provenance
        prov_ok, prov_reason, ev_record = self.verify_invalidation_provenance(
            invalidation_evidence_ref, session_ctx, program_id=getattr(self, "_program_id", None)
        )
        if not prov_ok or ev_record is None:
            return "INCONCLUSIVE", None

        # Mode A vulnerability findings require independently verified invalidation provenance.
        # Operator attestations are human assertions and cannot generate confirmed findings.
        if (
            ev_record.get("source") != "CONTROLLED_WORKFLOW"
            or ev_record.get("trust_classification") != "INDEPENDENTLY_VERIFIED_WORKFLOW"
        ):
            return "INCONCLUSIVE", None

        # 3. Mode A: strictly read-only request (GET or HEAD)
        target_endpoint = getattr(resource_target, "endpoint", None) or getattr(resource_target, "url", "")
        if not target_endpoint:
            return "INCONCLUSIVE", None

        parsed = urlparse(target_endpoint)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            return "INCONCLUSIVE", None
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        if port < 1 or port > 65535:
            return "INCONCLUSIVE", None

        method_raw = (getattr(resource_target, "method", "GET") or "GET").upper()
        method = "HEAD" if method_raw == "HEAD" else "GET"

        # 4. Scope authorization check immediately before dispatch
        is_simulation = hasattr(self.engine, "lab_port") or type(self.engine).__name__ == "SimulationTransport"
        if not is_simulation:
            if self._scope_engine is None:
                return "INCONCLUSIVE", None
            try:
                if not self._scope_engine.is_in_scope(target_endpoint):
                    return "INCONCLUSIVE", None
            except Exception:
                return "INCONCLUSIVE", None
        else:
            try:
                self.engine.validate_target_url(target_endpoint)
            except Exception:
                return "INCONCLUSIVE", None

        # Bind scope engine to validation engine so redirect following cannot bypass scope checks
        if hasattr(self.engine, "scope_engine") and self._scope_engine is not None:
            self.engine.scope_engine = self._scope_engine

        req = ControlledRequest(
            url=target_endpoint,
            method=method,
            headers=dict(session_ctx.volatile_headers),
        )
        try:
            resp = self.engine.send_request(req)
        except Exception:
            return "INCONCLUSIVE", None

        classification, reason = classify_revocation_response(resp, pre_revocation_baseline)

        if classification == "SESSION_NOT_INVALIDATED":
            metrics = CVSS31Metrics(
                av=AttackVector.NETWORK,
                ac=AttackComplexity.LOW,
                pr=PrivilegesRequired.LOW,
                ui=UserInteraction.NONE,
                scope=Scope.UNCHANGED,
                c=CIAImpact.LOW,
                i=CIAImpact.LOW,
                a=CIAImpact.NONE,
            )
            score, sev, vector = CVSS31Calculator.calculate_base_score(metrics)

            clean_req = f"{method} {target_endpoint}\nHeaders: [REDACTED]"
            clean_res = f"HTTP {resp.status_code}\n{sanitize_sensitive_data(resp.body_text[:500])}"

            evidence_chain: List[str] = []
            if self._evidence_store is not None:
                try:
                    evid_meta = self._evidence_store.save_http_capture(
                        request_text=clean_req,
                        response_text=clean_res,
                        metadata={
                            "hypothesis_category": "REVOCATION_ENFORCEMENT",
                            "mode": "MODE_A",
                            "invalidation_evidence_ref": invalidation_evidence_ref,
                            "session_ref": session_ctx.session_ref,
                            "principal_id": session_ctx.principal_id,
                        },
                        prefix="revocation_mode_a",
                    )
                    if not isinstance(evid_meta, dict) or not evid_meta.get("evidence_id"):
                        raise EvidencePersistenceError("EvidenceStore failed to return valid persisted evidence ID")
                    evidence_chain = [evid_meta["evidence_id"]]
                except Exception as e:
                    if isinstance(e, EvidencePersistenceError):
                        raise
                    raise EvidencePersistenceError(f"Failed to persist Mode A revocation evidence: {e}")
            else:
                evidence_chain = []

            rev_hash = hashlib.sha256(f"{target_endpoint}_{time.time_ns()}".encode("utf-8")).hexdigest()[:10].upper()
            finding_id = f"FIND-REVOKE-{rev_hash}"
            endpoint_path = target_endpoint if target_endpoint.startswith("/") else "/" + target_endpoint.split("/", 3)[-1]
            desc_prefix = "" if self._evidence_store is not None else "[EVIDENCE_NOT_PERSISTED] "
            finding = CorrelationFinding(
                finding_id=finding_id,
                title="Session Retains Protected Resource Access After Invalidation",
                category="SESSION_NOT_INVALIDATED",
                severity=sev,
                cvss_score=score,
                cvss_vector=vector,
                confidence=0.90,
                endpoint=endpoint_path,
                description=f"{desc_prefix}Session token continues to access protected resource despite verified invalidation event. {reason}",
                evidence_chain=evidence_chain,
            )
            return "SESSION_NOT_INVALIDATED", finding

        return classification, None

    def verify_post_revocation_access(
        self,
        session_ctx: CorrelatedSessionContext,
        target_endpoint: str,
        probe_response: ControlledResponse,
        baseline_target: Optional[ControlledResponse] = None,
    ) -> Optional[CorrelationFinding]:
        """
        Verifies whether a session whose revocation mutation was executed remains capable
        of accessing protected resources. Returns CorrelationFinding if vulnerability is detected.
        """
        if probe_response is None:
            return None

        classification, reason = classify_revocation_response(probe_response, baseline_target)

        if classification == "SESSION_NOT_INVALIDATED":
            metrics = CVSS31Metrics(
                av=AttackVector.NETWORK,
                ac=AttackComplexity.LOW,
                pr=PrivilegesRequired.LOW,
                ui=UserInteraction.NONE,
                scope=Scope.UNCHANGED,
                c=CIAImpact.LOW,
                i=CIAImpact.LOW,
                a=CIAImpact.NONE,
            )
            score, sev, vector = CVSS31Calculator.calculate_base_score(metrics)
            clean_req = f"GET {target_endpoint}\nHeaders: [REDACTED]"
            clean_res = f"HTTP {probe_response.status_code}\n{sanitize_sensitive_data(probe_response.body_text[:500])}"

            evidence_chain: List[str] = []
            if self._evidence_store is not None:
                try:
                    evid_meta = self._evidence_store.save_http_capture(
                        request_text=clean_req,
                        response_text=clean_res,
                        metadata={
                            "hypothesis_category": "REVOCATION_ENFORCEMENT",
                            "mode": "MODE_B",
                            "session_ref": session_ctx.session_ref,
                        },
                        prefix="revocation_mode_b",
                    )
                    if not isinstance(evid_meta, dict) or not evid_meta.get("evidence_id"):
                        raise EvidencePersistenceError("EvidenceStore failed to return valid persisted evidence ID")
                    evidence_chain = [evid_meta["evidence_id"]]
                except Exception as e:
                    if isinstance(e, EvidencePersistenceError):
                        raise
                    raise EvidencePersistenceError(f"Failed to persist Mode B revocation evidence: {e}")

            rev_hash = hashlib.sha256(f"{target_endpoint}_{time.time_ns()}".encode("utf-8")).hexdigest()[:10].upper()
            finding_id = f"FIND-REVOKE-{rev_hash}"
            endpoint_path = target_endpoint if target_endpoint.startswith("/") else "/" + target_endpoint.split("/", 3)[-1]
            desc_prefix = "" if self._evidence_store is not None else "[EVIDENCE_NOT_PERSISTED] "
            return CorrelationFinding(
                finding_id=finding_id,
                title="Session Retains Protected Resource Access After Invalidation",
                category="SESSION_NOT_INVALIDATED",
                severity=sev,
                cvss_score=score,
                cvss_vector=vector,
                confidence=0.90,
                endpoint=endpoint_path,
                description=f"{desc_prefix}Session token continues to access protected resource despite verified invalidation event. {reason}",
                evidence_chain=evidence_chain,
            )

        if classification in ("REVOKED", "EXPIRED", "REDIRECT_LOGIN"):
            session_ctx.lifecycle = CorrelationLifecycle.REVOKED
            return None

        if classification == "AUTHORIZATION_DENIED":
            session_ctx.lifecycle = CorrelationLifecycle.AUTHORIZATION_DENIED
            return None

        if classification == "AUTHENTICATION_FAILED":
            session_ctx.lifecycle = CorrelationLifecycle.AUTHENTICATION_FAILED
            return None

        return None

    def execute_controlled_invalidation(
        self,
        session_ctx: CorrelatedSessionContext,
        action_id: str,
        action_dossier: Dict[str, Any],
    ) -> bool:
        """
        Mode B: Executes active mutation (logout / password change) on verified test accounts.
        Enforces strict action-specific single-use approval bound to ACT-<SHA256> with
        operator authorization signature SIG-<HMAC-SHA256>.
        Guarantees single-use execution across processes via durable CrossProcessFileLock.
        Requires mandatory initialized and writable EvidenceStore.
        Requires mandatory initialized ScopeEngine.
        Binds execution results into ExecutionLedger for genuine execution provenance.
        """
        # Enforce execution through the single trusted ControlledDispatchWorkflow boundary
        workflow = ControlledDispatchWorkflow(
            program_id=self._program_id,
            state_dir=self._state_dir,
            evidence_store=self._evidence_store,
            transport_engine=self.engine,
            scope_engine=self._scope_engine,
            approval_key=self._approval_key,
            approval_key_dir=self._approval_key_dir,
        )
        ok, dispatch_result, reason = workflow.execute(
            session_ctx=session_ctx,
            action_id=action_id,
            action_dossier=action_dossier,
        )
        if not ok or dispatch_result is None:
            return False

        try:
            # Issue verifiable ExecutionCapability from genuine ControlledDispatchResult
            capability = issue_execution_capability(
                dispatch_result=dispatch_result,
                approval_key=self._approval_key or get_or_create_approval_key(key_dir=self._approval_key_dir),
                evidence_store=self._evidence_store,
                consumed_approvals_path=self._get_consumed_approvals_path(),
                key_dir=self._approval_key_dir,
            )

            # Record in ExecutionLedger with capability and evidence_store
            exec_rec = self.ledger.record_execution(
                capability=capability,
                evidence_store=self._evidence_store,
                consumed_approvals_path=self._get_consumed_approvals_path(),
                approval_key=self._approval_key or get_or_create_approval_key(key_dir=self._approval_key_dir),
            )

            att = _create_controlled_invalidation_attestation_from_record(
                execution_record=exec_rec,
                execution_ledger=self.ledger,
                evidence_store=self._evidence_store,
                attestation_key=self._attestation_key,
                key_dir=self._approval_key_dir,
                details={
                    "target_endpoint": action_dossier.get("target_endpoint"),
                    "test_account": action_dossier.get("test_account"),
                },
            )
            session_ctx.invalidation_evidence_ref = att["attestation_id"]
            session_ctx.lifecycle = CorrelationLifecycle.REVOKED
        except Exception as e:
            if isinstance(e, (EvidencePersistenceError, AttestationSecurityError)):
                raise
            raise EvidencePersistenceError(f"Failed to record execution or issue attestation: {e}")

        return True
