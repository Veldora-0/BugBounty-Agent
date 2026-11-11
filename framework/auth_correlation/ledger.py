"""
Phase 21: ExecutionLedger & Provenance Tracking.

Provides a tamper-evident, cryptographically signed internal execution ledger
that guarantees genuine execution provenance for Mode B controlled invalidation mutations.
Requires a verifiable ExecutionCapability issued only upon successful completion of the
trusted Mode B execution workflow, bound to consumed approval receipts and persisted evidence bytes.
Enforces single-use attestation issuance, preventing replay, duplicate attestation creation,
and cross-session / cross-program execution record substitution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import time
from typing import Any, Dict, List, Optional, Set, Tuple

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
    assert_safe_string,
    assert_strict_int,
    _safe_repr,
)
from framework.auth_correlation.state import (
    _enforce_windows_directory_dacl,
    _enforce_windows_file_dacl,
    _verify_windows_directory_security,
    _verify_windows_file_security,
)


class ExecutionProvenanceError(Exception):
    """Raised when controlled execution record is missing, invalid, tampered, expired, or replayed."""
    pass


EXECUTION_ID_PATTERN = re.compile(r"^EXEC-[0-9A-F]{64}$")
EXECUTION_SIG_PATTERN = re.compile(r"^EXEC-SIG-[0-9A-F]{64}$")
EXECUTION_DOMAIN = "BB_CONTROLLED_EXECUTION_V1"

CAPABILITY_DOMAIN = "BB_EXECUTION_CAPABILITY_V1"

CANONICAL_CAPABILITY_FIELDS = (
    "action_dossier_digest",
    "action_id",
    "action_type",
    "approval_id",
    "capability_id",
    "consumption_token",
    "domain",
    "execution_timestamp",
    "http_method",
    "invalidation_verification_result",
    "key_id",
    "mutation_evidence_ref",
    "mutation_request_digest",
    "mutation_response_digest",
    "mutation_status_code",
    "principal_id",
    "program_id",
    "session_ref",
    "target_endpoint",
    "test_account",
    "verification_evidence_ref",
    "verification_method",
    "verification_request_digest",
    "verification_response_digest",
    "verification_status_code",
    "verification_timestamp",
)

CANONICAL_EXECUTION_FIELDS = (
    "action_dossier_digest",
    "action_id",
    "action_type",
    "approval_id",
    "domain",
    "execution_id",
    "execution_timestamp",
    "http_method",
    "invalidation_verification_result",
    "key_id",
    "mutation_evidence_ref",
    "mutation_request_digest",
    "mutation_response_digest",
    "mutation_status_code",
    "principal_id",
    "program_id",
    "session_ref",
    "target_endpoint",
    "test_account",
    "verification_evidence_ref",
    "verification_method",
    "verification_request_digest",
    "verification_response_digest",
    "verification_status_code",
    "verification_timestamp",
)


def get_or_create_capability_key(key_dir: Optional[str] = None) -> bytes:
    """
    Retrieves or generates the 32-byte secret HMAC key used for execution capability signing.
    Stored strictly outside the Git repository:
    - POSIX: ~/.config/opencode/execution_capability.key
    - Windows: %LOCALAPPDATA%\\opencode\\execution_capability.key
    - Override: OPENCODE_CAPABILITY_KEY_PATH environment variable
    """
    env_path = os.environ.get("OPENCODE_CAPABILITY_KEY_PATH")
    if env_path:
        key_file = os.path.abspath(env_path)
        key_folder = os.path.dirname(key_file)
    elif key_dir:
        key_folder = os.path.abspath(key_dir)
        key_file = os.path.join(key_folder, "execution_capability.key")
    elif os.name == "nt":
        base_dir = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        key_folder = os.path.join(base_dir, "opencode")
        key_file = os.path.join(key_folder, "execution_capability.key")
    else:
        base_dir = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        key_folder = os.path.join(base_dir, "opencode")
        key_file = os.path.join(key_folder, "execution_capability.key")

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
                raise ExecutionProvenanceError("Execution capability key directory is a symbolic link")
            if kdir_stat.st_uid != os.getuid():
                raise ExecutionProvenanceError("Execution capability key directory ownership mismatch")
            if kdir_stat.st_mode & 0o077 != 0:
                try:
                    os.chmod(key_folder, 0o700)
                    kdir_stat = os.lstat(key_folder)
                except OSError:
                    pass
            if kdir_stat.st_mode & 0o077 != 0:
                raise ExecutionProvenanceError("Execution capability key directory permissions are not private")

        if os.path.exists(key_file):
            k_stat = os.lstat(key_file)
            if stat.S_ISLNK(k_stat.st_mode):
                raise ExecutionProvenanceError("Execution capability key file is a symbolic link")
            if os.name == "nt":
                try:
                    _enforce_windows_file_dacl(key_file)
                    _verify_windows_file_security(key_file)
                except SerializationSecurityError as err:
                    raise ExecutionProvenanceError(str(err))
            else:
                if k_stat.st_uid != os.getuid():
                    raise ExecutionProvenanceError("Execution capability key file ownership mismatch")
                if k_stat.st_mode & 0o077 != 0:
                    raise ExecutionProvenanceError("Execution capability key file permissions are not private")
                if k_stat.st_nlink != 1:
                    raise ExecutionProvenanceError("Execution capability key file has unexpected hardlinks")

            with open(key_file, "rb") as f:
                key = f.read(32)
            if len(key) != 32:
                raise ExecutionProvenanceError("Invalid execution capability key file length")
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
                raise ExecutionProvenanceError(f"Failed to write execution capability key file: {e}")

            if os.name == "nt":
                try:
                    _enforce_windows_file_dacl(key_file)
                    _verify_windows_file_security(key_file)
                except SerializationSecurityError as err:
                    raise ExecutionProvenanceError(str(err))
            return key
    except Exception as e:
        if isinstance(e, ExecutionProvenanceError):
            raise
        raise ExecutionProvenanceError(f"Cannot secure external execution capability key: {e}")


def get_or_create_execution_key(key_dir: Optional[str] = None) -> bytes:
    """
    Retrieves or generates the 32-byte secret HMAC key used for internal execution ledger signing.
    Stored strictly outside the Git repository:
    - POSIX: ~/.config/opencode/execution_ledger.key (or $XDG_CONFIG_HOME/opencode/execution_ledger.key)
    - Windows: %LOCALAPPDATA%\\opencode\\execution_ledger.key (fallback ~/.config/opencode/execution_ledger.key)
    - Override: OPENCODE_EXECUTION_KEY_PATH environment variable
    """
    env_path = os.environ.get("OPENCODE_EXECUTION_KEY_PATH")
    if env_path:
        key_file = os.path.abspath(env_path)
        key_folder = os.path.dirname(key_file)
    elif key_dir:
        key_folder = os.path.abspath(key_dir)
        key_file = os.path.join(key_folder, "execution_ledger.key")
    elif os.name == "nt":
        base_dir = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        key_folder = os.path.join(base_dir, "opencode")
        key_file = os.path.join(key_folder, "execution_ledger.key")
    else:
        base_dir = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        key_folder = os.path.join(base_dir, "opencode")
        key_file = os.path.join(key_folder, "execution_ledger.key")

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
                raise ExecutionProvenanceError("Execution key directory is a symbolic link")
            if kdir_stat.st_uid != os.getuid():
                raise ExecutionProvenanceError("Execution key directory ownership mismatch")
            if kdir_stat.st_mode & 0o077 != 0:
                try:
                    os.chmod(key_folder, 0o700)
                    kdir_stat = os.lstat(key_folder)
                except OSError:
                    pass
            if kdir_stat.st_mode & 0o077 != 0:
                raise ExecutionProvenanceError("Execution key directory permissions are not private")

        if os.path.exists(key_file):
            k_stat = os.lstat(key_file)
            if stat.S_ISLNK(k_stat.st_mode):
                raise ExecutionProvenanceError("Execution key file is a symbolic link")
            if os.name == "nt":
                try:
                    _enforce_windows_file_dacl(key_file)
                    _verify_windows_file_security(key_file)
                except SerializationSecurityError as err:
                    raise ExecutionProvenanceError(str(err))
            else:
                if k_stat.st_uid != os.getuid():
                    raise ExecutionProvenanceError("Execution key file ownership mismatch")
                if k_stat.st_mode & 0o077 != 0:
                    raise ExecutionProvenanceError("Execution key file permissions are not private")
                if k_stat.st_nlink != 1:
                    raise ExecutionProvenanceError("Execution key file has unexpected hardlinks")

            with open(key_file, "rb") as f:
                key = f.read(32)
            if len(key) != 32:
                raise ExecutionProvenanceError("Invalid execution key file length")
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
                raise ExecutionProvenanceError(f"Failed to write execution key file: {e}")

            if os.name == "nt":
                try:
                    _enforce_windows_file_dacl(key_file)
                    _verify_windows_file_security(key_file)
                except SerializationSecurityError as err:
                    raise ExecutionProvenanceError(str(err))
            return key
    except Exception as e:
        if isinstance(e, ExecutionProvenanceError):
            raise
        raise ExecutionProvenanceError(f"Cannot secure external execution key: {e}")


@dataclass
class ExecutionCapability:
    """
    Verifiable execution capability issued strictly upon successful completion
    of the trusted Mode B execution workflow.
    Bound cryptographically under HMAC-SHA256 (CAP-SIG-...) using execution_capability.key.
    Binds the consumed approval ID, action ID, canonical dossier digest, program ID,
    session reference, principal, test account, target endpoint, method, action type,
    mutation and verification evidence references, recomputed request/response digests,
    status codes, timestamps, verification method, and single-use consumption token.
    """
    approval_id: str
    action_id: str
    action_dossier_digest: str
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
    capability_id: str = ""
    signature: str = ""
    key_id: str = "KEY-LOCAL-CAPABILITY-1"
    domain: str = CAPABILITY_DOMAIN

    def __repr__(self) -> str:
        cid = _safe_repr(self.capability_id, CAPABILITY_ID_PATTERN, "UNVALIDATED_CAP_ID")
        aid = _safe_repr(self.action_id, ACTION_ID_PATTERN, "UNVALIDATED_ACTION_ID")
        sref = _safe_repr(self.session_ref, SESSION_REF_PATTERN, "UNVALIDATED_SESSION_REF")
        return f"ExecutionCapability(capability_id={cid}, action_id={aid}, session_ref={sref})"

    def __str__(self) -> str:
        return self.__repr__()

    def to_dict(self) -> Dict[str, Any]:
        """Serializes capability into canonical dictionary representation."""
        return {
            "approval_id": self.approval_id,
            "action_id": self.action_id,
            "action_dossier_digest": self.action_dossier_digest,
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
            "capability_id": self.capability_id,
            "signature": self.signature,
            "key_id": self.key_id,
            "domain": self.domain,
        }

    def validate(self) -> Dict[str, Any]:
        """Performs fail-closed schema and integrity validation over all capability fields."""
        app_id = assert_safe_string(self.approval_id, "approval_id", SAFE_IDENTIFIER_PATTERN)
        aid = assert_safe_string(self.action_id, "action_id", ACTION_ID_PATTERN)
        add = assert_safe_string(self.action_dossier_digest, "action_dossier_digest", ACTION_DOSSIER_DIGEST_PATTERN)
        prog = assert_safe_string(self.program_id, "program_id", SAFE_IDENTIFIER_PATTERN)
        sref = assert_safe_string(self.session_ref, "session_ref", SESSION_REF_PATTERN)
        pid = assert_safe_string(self.principal_id, "principal_id", SAFE_IDENTIFIER_PATTERN)
        t_acct = assert_safe_string(self.test_account, "test_account", SAFE_IDENTIFIER_PATTERN)

        if not isinstance(self.target_endpoint, str) or not (
            self.target_endpoint.startswith("http://") or self.target_endpoint.startswith("https://")
        ):
            raise ExecutionProvenanceError("Target endpoint must be an http or https URL")

        method = assert_safe_string(self.http_method, "http_method")
        if method not in ("POST", "PUT", "DELETE"):
            raise ExecutionProvenanceError(f"HTTP method '{method}' is not an authorized mutation method")

        act_type = assert_safe_string(self.action_type, "action_type")
        if act_type not in ("LOGOUT", "ACTION-LOGOUT", "TOKEN_REVOCATION", "PASSWORD_CHANGE"):
            raise ExecutionProvenanceError(f"Action type '{act_type}' is not an authorized action type")

        mut_ref = assert_safe_string(self.mutation_evidence_ref, "mutation_evidence_ref", EVIDENCE_REF_PATTERN)
        ver_ref = assert_safe_string(self.verification_evidence_ref, "verification_evidence_ref", EVIDENCE_REF_PATTERN)

        sha_pattern = re.compile(r"^[0-9a-f]{64}$")
        mut_req_dig = assert_safe_string(self.mutation_request_digest, "mutation_request_digest", sha_pattern)
        mut_res_dig = assert_safe_string(self.mutation_response_digest, "mutation_response_digest", sha_pattern)
        ver_req_dig = assert_safe_string(self.verification_request_digest, "verification_request_digest", sha_pattern)
        ver_res_dig = assert_safe_string(self.verification_response_digest, "verification_response_digest", sha_pattern)

        mut_status = assert_strict_int(self.mutation_status_code, "mutation_status_code", 100, 599)
        ver_status = assert_strict_int(self.verification_status_code, "verification_status_code", 100, 599)

        exec_ts = assert_safe_string(self.execution_timestamp, "execution_timestamp", ISO_TIMESTAMP_PATTERN)
        ver_ts = assert_safe_string(self.verification_timestamp, "verification_timestamp", ISO_TIMESTAMP_PATTERN)

        ver_res = assert_safe_string(self.invalidation_verification_result, "invalidation_verification_result")
        if ver_res not in ("VERIFIED", "REVOKED", "SESSION_REVOKED"):
            raise ExecutionProvenanceError(f"Invalidation verification result '{ver_res}' does not satisfy verification criteria")

        ver_meth = assert_safe_string(self.verification_method, "verification_method")
        if ver_meth not in (
            "ACTION_MUTATION_AND_PROBE_VERIFIED",
            "MUTATION_EXPLICIT_REVOCATION_VERIFIED",
            "MUTATION_STRUCTURED_REVOCATION_CONFIRMED",
            "MUTATION_LOGIN_REDIRECT_AND_COOKIE_CLEARED",
            "POST_MUTATION_PROBE_CONFIRMED_401",
            "POST_MUTATION_PROBE_CONFIRMED_REDIRECT_LOGIN",
        ):
            raise ExecutionProvenanceError(f"Verification method '{ver_meth}' is not recognized")

        token_pat = re.compile(r"^[0-9a-fA-F]{64}$")
        token = assert_safe_string(self.consumption_token, "consumption_token", token_pat)

        cid = assert_safe_string(self.capability_id, "capability_id", CAPABILITY_ID_PATTERN)
        sig = assert_safe_string(self.signature, "signature", CAPABILITY_SIG_PATTERN)

        if self.domain != CAPABILITY_DOMAIN:
            raise ExecutionProvenanceError(f"Capability domain mismatch: expected '{CAPABILITY_DOMAIN}', got '{self.domain}'")

        if self.key_id != "KEY-LOCAL-CAPABILITY-1":
            raise ExecutionProvenanceError(f"Capability key_id '{self.key_id}' is unsupported")

        return self.to_dict()

    def verify_signature(self, capability_key: bytes) -> bool:
        """Cryptographically verifies HMAC-SHA256 signature and deterministic capability_id."""
        if not self.signature or not self.capability_id:
            return False

        # Verify hash computation of capability_id
        hash_payload = {k: getattr(self, k) for k in CANONICAL_CAPABILITY_FIELDS if k != "capability_id"}
        hash_bytes = json.dumps(hash_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected_cid = f"CAP-{hashlib.sha256(hash_bytes).hexdigest().upper()}"
        if self.capability_id != expected_cid:
            return False

        # Verify HMAC-SHA256 signature
        sign_payload = {k: getattr(self, k) for k in CANONICAL_CAPABILITY_FIELDS}
        sign_bytes = json.dumps(sign_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected_sig = f"CAP-SIG-{hmac.new(capability_key, sign_bytes, hashlib.sha256).hexdigest().upper()}"
        return hmac.compare_digest(self.signature, expected_sig)


def issue_execution_capability(
    action_id: str,
    action_dossier_digest: str,
    approval_id: str,
    program_id: str,
    session_ref: str,
    principal_id: str,
    test_account: str,
    target_endpoint: str,
    http_method: str,
    action_type: str,
    mutation_evidence_ref: str,
    mutation_request_digest: str,
    mutation_response_digest: str,
    mutation_status_code: int,
    verification_evidence_ref: str,
    verification_request_digest: str,
    verification_response_digest: str,
    verification_status_code: int,
    verification_method: str,
    invalidation_verification_result: str,
    execution_timestamp: str,
    verification_timestamp: str,
    consumption_token: str,
    capability_key: Optional[bytes] = None,
    key_dir: Optional[str] = None,
) -> ExecutionCapability:
    """
    Constructs, hashes, and cryptographically signs a genuine ExecutionCapability.
    Invoked strictly upon the successful execution and invalidation confirmation of Mode B mutations.
    """
    key = capability_key or get_or_create_capability_key(key_dir=key_dir)

    payload: Dict[str, Any] = {
        "action_dossier_digest": action_dossier_digest,
        "action_id": action_id,
        "action_type": action_type,
        "approval_id": approval_id,
        "capability_id": "",
        "consumption_token": consumption_token,
        "domain": CAPABILITY_DOMAIN,
        "execution_timestamp": execution_timestamp,
        "http_method": http_method,
        "invalidation_verification_result": invalidation_verification_result,
        "key_id": "KEY-LOCAL-CAPABILITY-1",
        "mutation_evidence_ref": mutation_evidence_ref,
        "mutation_request_digest": mutation_request_digest,
        "mutation_response_digest": mutation_response_digest,
        "mutation_status_code": mutation_status_code,
        "principal_id": principal_id,
        "program_id": program_id,
        "session_ref": session_ref,
        "target_endpoint": target_endpoint,
        "test_account": test_account,
        "verification_evidence_ref": verification_evidence_ref,
        "verification_method": verification_method,
        "verification_request_digest": verification_request_digest,
        "verification_response_digest": verification_response_digest,
        "verification_status_code": verification_status_code,
        "verification_timestamp": verification_timestamp,
    }

    # Deterministic capability identifier excludes capability_id itself
    hash_payload = {k: payload[k] for k in CANONICAL_CAPABILITY_FIELDS if k != "capability_id"}
    hash_bytes = json.dumps(hash_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    cid = f"CAP-{hashlib.sha256(hash_bytes).hexdigest().upper()}"
    payload["capability_id"] = cid

    # Signature signs entire canonical capability payload including capability_id
    sign_payload = {k: payload[k] for k in CANONICAL_CAPABILITY_FIELDS}
    sign_bytes = json.dumps(sign_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = f"CAP-SIG-{hmac.new(key, sign_bytes, hashlib.sha256).hexdigest().upper()}"

    cap = ExecutionCapability(
        approval_id=approval_id,
        action_id=action_id,
        action_dossier_digest=action_dossier_digest,
        program_id=program_id,
        session_ref=session_ref,
        principal_id=principal_id,
        test_account=test_account,
        target_endpoint=target_endpoint,
        http_method=http_method,
        action_type=action_type,
        mutation_evidence_ref=mutation_evidence_ref,
        mutation_request_digest=mutation_request_digest,
        mutation_response_digest=mutation_response_digest,
        mutation_status_code=mutation_status_code,
        verification_evidence_ref=verification_evidence_ref,
        verification_request_digest=verification_request_digest,
        verification_response_digest=verification_response_digest,
        verification_status_code=verification_status_code,
        verification_method=verification_method,
        invalidation_verification_result=invalidation_verification_result,
        execution_timestamp=execution_timestamp,
        verification_timestamp=verification_timestamp,
        consumption_token=consumption_token,
        capability_id=cid,
        signature=sig,
        key_id="KEY-LOCAL-CAPABILITY-1",
        domain=CAPABILITY_DOMAIN,
    )
    cap.validate()
    return cap


@dataclass
class ExecutionRecord:
    """
    Immutable representation of an authenticated, verified Mode B execution record.
    Carries cryptographic signatures binding execution parameters, evidence digests,
    and verification results.
    """
    execution_id: str
    approval_id: str
    action_id: str
    action_dossier_digest: str
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
    signature: str
    key_id: str = "KEY-LOCAL-EXECUTION-1"
    domain: str = EXECUTION_DOMAIN
    attestation_created: bool = False
    attestation_id: Optional[str] = None
    is_testing_primitive: bool = False

    def __repr__(self) -> str:
        eid = _safe_repr(self.execution_id, EXECUTION_ID_PATTERN, "UNVALIDATED_EXEC_ID")
        aid = _safe_repr(self.action_id, ACTION_ID_PATTERN, "UNVALIDATED_ACTION_ID")
        sref = _safe_repr(self.session_ref, SESSION_REF_PATTERN, "UNVALIDATED_SESSION_REF")
        return f"ExecutionRecord(execution_id={eid}, action_id={aid}, session_ref={sref}, claimed={self.attestation_created})"

    def __str__(self) -> str:
        return self.__repr__()

    def to_dict(self) -> Dict[str, Any]:
        """Serializes verified record into dictionary representation."""
        return {
            "execution_id": self.execution_id,
            "approval_id": self.approval_id,
            "action_id": self.action_id,
            "action_dossier_digest": self.action_dossier_digest,
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
            "signature": self.signature,
            "key_id": self.key_id,
            "domain": self.domain,
            "attestation_created": self.attestation_created,
            "attestation_id": self.attestation_id,
            "is_testing_primitive": self.is_testing_primitive,
        }

    def validate(self) -> Dict[str, Any]:
        """Performs fail-closed schema and integrity validation over all record fields."""
        eid = assert_safe_string(self.execution_id, "execution_id", EXECUTION_ID_PATTERN)
        app_id = assert_safe_string(self.approval_id, "approval_id", SAFE_IDENTIFIER_PATTERN)
        aid = assert_safe_string(self.action_id, "action_id", ACTION_ID_PATTERN)
        add = assert_safe_string(self.action_dossier_digest, "action_dossier_digest", ACTION_DOSSIER_DIGEST_PATTERN)
        prog = assert_safe_string(self.program_id, "program_id", SAFE_IDENTIFIER_PATTERN)
        sref = assert_safe_string(self.session_ref, "session_ref", SESSION_REF_PATTERN)
        pid = assert_safe_string(self.principal_id, "principal_id", SAFE_IDENTIFIER_PATTERN)
        t_acct = assert_safe_string(self.test_account, "test_account", SAFE_IDENTIFIER_PATTERN)

        if not isinstance(self.target_endpoint, str) or not (
            self.target_endpoint.startswith("http://") or self.target_endpoint.startswith("https://")
        ):
            raise ExecutionProvenanceError("Target endpoint must be an http or https URL")

        method = assert_safe_string(self.http_method, "http_method")
        if method not in ("POST", "PUT", "DELETE"):
            raise ExecutionProvenanceError(f"HTTP method '{method}' is not an authorized mutation method")

        act_type = assert_safe_string(self.action_type, "action_type")
        if act_type not in ("LOGOUT", "ACTION-LOGOUT", "TOKEN_REVOCATION", "PASSWORD_CHANGE"):
            raise ExecutionProvenanceError(f"Action type '{act_type}' is not an authorized action type")

        mut_ref = assert_safe_string(self.mutation_evidence_ref, "mutation_evidence_ref", EVIDENCE_REF_PATTERN)
        ver_ref = assert_safe_string(self.verification_evidence_ref, "verification_evidence_ref", EVIDENCE_REF_PATTERN)

        sha_pattern = re.compile(r"^[0-9a-f]{64}$")
        mut_req_dig = assert_safe_string(self.mutation_request_digest, "mutation_request_digest", sha_pattern)
        mut_res_dig = assert_safe_string(self.mutation_response_digest, "mutation_response_digest", sha_pattern)
        ver_req_dig = assert_safe_string(self.verification_request_digest, "verification_request_digest", sha_pattern)
        ver_res_dig = assert_safe_string(self.verification_response_digest, "verification_response_digest", sha_pattern)

        mut_status = assert_strict_int(self.mutation_status_code, "mutation_status_code", 100, 599)
        ver_status = assert_strict_int(self.verification_status_code, "verification_status_code", 100, 599)

        exec_ts = assert_safe_string(self.execution_timestamp, "execution_timestamp", ISO_TIMESTAMP_PATTERN)
        ver_ts = assert_safe_string(self.verification_timestamp, "verification_timestamp", ISO_TIMESTAMP_PATTERN)

        ver_res = assert_safe_string(self.invalidation_verification_result, "invalidation_verification_result")
        if ver_res not in ("VERIFIED", "REVOKED", "SESSION_REVOKED"):
            raise ExecutionProvenanceError(f"Invalidation verification result '{ver_res}' does not satisfy verification criteria")

        ver_meth = assert_safe_string(self.verification_method, "verification_method")
        if ver_meth not in (
            "ACTION_MUTATION_AND_PROBE_VERIFIED",
            "MUTATION_EXPLICIT_REVOCATION_VERIFIED",
            "MUTATION_STRUCTURED_REVOCATION_CONFIRMED",
            "MUTATION_LOGIN_REDIRECT_AND_COOKIE_CLEARED",
            "POST_MUTATION_PROBE_CONFIRMED_401",
            "POST_MUTATION_PROBE_CONFIRMED_REDIRECT_LOGIN",
        ):
            raise ExecutionProvenanceError(f"Verification method '{ver_meth}' is not recognized")

        sig = assert_safe_string(self.signature, "signature", EXECUTION_SIG_PATTERN)

        if self.domain != EXECUTION_DOMAIN:
            raise ExecutionProvenanceError(f"Execution domain mismatch: expected '{EXECUTION_DOMAIN}', got '{self.domain}'")

        if self.key_id != "KEY-LOCAL-EXECUTION-1":
            raise ExecutionProvenanceError(f"Execution key_id '{self.key_id}' is unsupported")

        return {
            "execution_id": eid,
            "approval_id": app_id,
            "action_id": aid,
            "action_dossier_digest": add,
            "program_id": prog,
            "session_ref": sref,
            "principal_id": pid,
            "test_account": t_acct,
            "target_endpoint": self.target_endpoint,
            "http_method": method,
            "action_type": act_type,
            "mutation_evidence_ref": mut_ref,
            "mutation_request_digest": mut_req_dig,
            "mutation_response_digest": mut_res_dig,
            "mutation_status_code": mut_status,
            "verification_evidence_ref": ver_ref,
            "verification_request_digest": ver_req_dig,
            "verification_response_digest": ver_res_dig,
            "verification_status_code": ver_status,
            "verification_method": ver_meth,
            "invalidation_verification_result": ver_res,
            "execution_timestamp": exec_ts,
            "verification_timestamp": ver_ts,
            "signature": sig,
            "key_id": self.key_id,
            "domain": self.domain,
            "attestation_created": bool(self.attestation_created),
            "attestation_id": self.attestation_id,
            "is_testing_primitive": bool(self.is_testing_primitive),
        }


class ExecutionLedger:
    """
    Cryptographically sealed execution ledger.
    Stores and tracks verified execution records in state/execution_ledger.json.
    Uses cross-process locking and atomic file replacement.
    Requires genuine ExecutionCapability issued through Mode B execution.
    """

    def __init__(
        self,
        state_dir: str,
        execution_key: Optional[bytes] = None,
        capability_key: Optional[bytes] = None,
        key_dir: Optional[str] = None,
    ):
        self.state_dir = os.path.abspath(state_dir)
        self.ledger_file = os.path.join(self.state_dir, "execution_ledger.json")
        self.lock_file = os.path.join(self.state_dir, "execution_ledger.lock")
        self._execution_key = execution_key
        self._capability_key = capability_key
        self._key_dir = key_dir

    @property
    def key_dir(self) -> Optional[str]:
        return self._key_dir

    def _get_key(self) -> bytes:
        if self._execution_key is not None:
            return self._execution_key
        return get_or_create_execution_key(key_dir=self._key_dir)

    def _get_capability_key(self) -> bytes:
        if self._capability_key is not None:
            return self._capability_key
        return get_or_create_capability_key(key_dir=self._key_dir)

    def _acquire_lock(self) -> Any:
        from framework.auth_correlation.revocation import CrossProcessFileLock
        return CrossProcessFileLock(self.lock_file)

    def _load_ledger_data(self) -> Dict[str, Any]:
        """Loads and parses raw ledger data; fails closed on corruption."""
        if not os.path.exists(self.ledger_file):
            return {"records": {}}
        try:
            with open(self.ledger_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict) or "records" not in data or not isinstance(data["records"], dict):
                raise ExecutionProvenanceError("Execution ledger storage is corrupted: invalid root structure")
            return data
        except ExecutionProvenanceError:
            raise
        except Exception as e:
            raise ExecutionProvenanceError(f"Execution ledger storage read error: {e}")

    def _save_ledger_data(self, data: Dict[str, Any]) -> None:
        """Atomically saves ledger data to disk."""
        os.makedirs(self.state_dir, exist_ok=True)
        tmp_path = f"{self.ledger_file}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
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
            os.replace(tmp_path, self.ledger_file)
        except Exception as e:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            if isinstance(e, ExecutionProvenanceError):
                raise
            raise ExecutionProvenanceError(f"Failed to persist execution ledger: {e}")

    def record_execution(
        self,
        capability: Any = None,
        evidence_store: Any = None,
        consumed_approvals_path: Optional[str] = None,
        **kwargs: Any,
    ) -> ExecutionRecord:
        """
        Validates capability and evidence binding, cryptographically signs, and records an authentic Mode B execution record.
        Strictly requires a verified ExecutionCapability and EvidenceStore.
        Direct caller invocation with loose fabricated arguments is strictly rejected.
        """
        if capability is None or not isinstance(capability, ExecutionCapability):
            raise ExecutionProvenanceError("Ordinary callers cannot create execution records without a verified ExecutionCapability")

        if evidence_store is None or not hasattr(evidence_store, "get_evidence"):
            raise ExecutionProvenanceError("EvidenceStore is mandatory for verifying execution evidence binding")

        # 1. Capability schema and pattern validation
        cap_dict = capability.validate()

        # 2. Cryptographic signature verification over capability
        cap_key = self._get_capability_key()
        if not capability.verify_signature(cap_key):
            raise ExecutionProvenanceError("Execution capability signature verification failed: capability is forged or tampered")

        # 3. Consumed approval verification (single-use approval and attribution binding)
        consumed_path = consumed_approvals_path or os.path.join(self.state_dir, "consumed_approvals.json")
        if os.path.exists(consumed_path):
            with self._acquire_lock():
                try:
                    with open(consumed_path, "r", encoding="utf-8") as f:
                        consumed_data = json.load(f)
                except Exception as e:
                    raise ExecutionProvenanceError(f"Failed to load consumed approvals registry: {e}")

                if not isinstance(consumed_data, dict):
                    raise ExecutionProvenanceError("Consumed approvals registry is corrupted")

                consumed_dict = consumed_data.get("consumed", consumed_data)
                if not isinstance(consumed_dict, dict):
                    raise ExecutionProvenanceError("Consumed approvals registry is corrupted")

                entry = consumed_dict.get(capability.action_id)
                if not entry or not isinstance(entry, dict):
                    raise ExecutionProvenanceError(f"Action '{capability.action_id}' has not been consumed in approval registry")

                if entry.get("approval_id") != capability.approval_id:
                    raise ExecutionProvenanceError("Approval ID mismatch with consumed approval record")

                if entry.get("consumption_token") != capability.consumption_token:
                    raise ExecutionProvenanceError("Consumption token mismatch with consumed approval record")

                if entry.get("program_id") != capability.program_id:
                    raise ExecutionProvenanceError("Program ID mismatch with consumed approval record")

                if entry.get("test_account") != capability.test_account:
                    raise ExecutionProvenanceError("Test account mismatch with consumed approval record")

                if entry.get("target_endpoint") != capability.target_endpoint:
                    raise ExecutionProvenanceError("Target endpoint mismatch with consumed approval record")

                if entry.get("method") != capability.http_method:
                    raise ExecutionProvenanceError("HTTP method mismatch with consumed approval record")

                if entry.get("action_type") != capability.action_type:
                    raise ExecutionProvenanceError("Action type mismatch with consumed approval record")

                if entry.get("execution_id") is not None:
                    raise ExecutionProvenanceError(
                        f"Action '{capability.action_id}' has already been executed under '{entry['execution_id']}' (duplicate execution rejected)"
                    )

        # 4. Exact evidence-to-ledger binding (Correction B)
        mut_ev = evidence_store.get_evidence(capability.mutation_evidence_ref)
        if mut_ev is None:
            raise ExecutionProvenanceError(f"Mutation evidence '{capability.mutation_evidence_ref}' not found or corrupted in EvidenceStore")

        ver_ev = evidence_store.get_evidence(capability.verification_evidence_ref)
        if ver_ev is None:
            raise ExecutionProvenanceError(f"Verification evidence '{capability.verification_evidence_ref}' not found or corrupted in EvidenceStore")

        if capability.mutation_evidence_ref == capability.verification_evidence_ref:
            raise ExecutionProvenanceError("Mutation and verification evidence references must be distinct")

        # Check cross-execution evidence reuse
        with self._acquire_lock():
            ledger_data = self._load_ledger_data()
            for rec in ledger_data.get("records", {}).values():
                existing_mut = rec.get("mutation_evidence_ref")
                existing_ver = rec.get("verification_evidence_ref")
                if capability.mutation_evidence_ref in (existing_mut, existing_ver):
                    raise ExecutionProvenanceError(
                        f"Mutation evidence '{capability.mutation_evidence_ref}' has already been bound to execution '{rec.get('execution_id')}' (cross-execution reuse rejected)"
                    )
                if capability.verification_evidence_ref in (existing_mut, existing_ver):
                    raise ExecutionProvenanceError(
                        f"Verification evidence '{capability.verification_evidence_ref}' has already been bound to execution '{rec.get('execution_id')}' (cross-execution reuse rejected)"
                    )

        # Verify mutation capture on disk
        mut_cap_path = mut_ev["capture_path"]
        if os.path.islink(mut_cap_path) or not os.path.isfile(mut_cap_path):
            raise ExecutionProvenanceError("Mutation capture path is invalid or symbolic link")
        if os.name == "nt":
            lst = os.lstat(mut_cap_path)
            if hasattr(lst, "st_file_attributes") and (lst.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
                raise ExecutionProvenanceError("Mutation capture path is an NTFS reparse point")

        with open(mut_cap_path, "rb") as mf:
            mut_bytes = mf.read()
        if hashlib.sha256(mut_bytes).hexdigest().lower() != mut_ev["sha256"].lower():
            raise ExecutionProvenanceError("Mutation capture file content has been modified or corrupted on disk")

        mut_parts = mut_bytes.decode("utf-8", errors="replace").split("\n\n--- RESPONSE ---\n", 1)
        if len(mut_parts) != 2 or not mut_parts[0].startswith("--- REQUEST ---\n"):
            raise ExecutionProvenanceError("Mutation capture format is invalid or corrupted")
        m_req = mut_parts[0][len("--- REQUEST ---\n"):]
        m_res = mut_parts[1][:-1] if mut_parts[1].endswith("\n") else mut_parts[1]
        if hashlib.sha256(m_req.encode("utf-8")).hexdigest().lower() != capability.mutation_request_digest.lower():
            raise ExecutionProvenanceError("Mutation request digest mismatch with actual capture content")
        if hashlib.sha256(m_res.encode("utf-8")).hexdigest().lower() != capability.mutation_response_digest.lower():
            raise ExecutionProvenanceError("Mutation response digest mismatch with actual capture content")

        # Verify verification capture on disk
        ver_cap_path = ver_ev["capture_path"]
        if os.path.islink(ver_cap_path) or not os.path.isfile(ver_cap_path):
            raise ExecutionProvenanceError("Verification capture path is invalid or symbolic link")
        if os.name == "nt":
            v_lst = os.lstat(ver_cap_path)
            if hasattr(v_lst, "st_file_attributes") and (v_lst.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
                raise ExecutionProvenanceError("Verification capture path is an NTFS reparse point")

        with open(ver_cap_path, "rb") as vf:
            ver_bytes = vf.read()
        if hashlib.sha256(ver_bytes).hexdigest().lower() != ver_ev["sha256"].lower():
            raise ExecutionProvenanceError("Verification capture file content has been modified or corrupted on disk")

        ver_parts = ver_bytes.decode("utf-8", errors="replace").split("\n\n--- RESPONSE ---\n", 1)
        if len(ver_parts) != 2 or not ver_parts[0].startswith("--- REQUEST ---\n"):
            raise ExecutionProvenanceError("Verification capture format is invalid or corrupted")
        v_req = ver_parts[0][len("--- REQUEST ---\n"):]
        v_res = ver_parts[1][:-1] if ver_parts[1].endswith("\n") else ver_parts[1]
        if hashlib.sha256(v_req.encode("utf-8")).hexdigest().lower() != capability.verification_request_digest.lower():
            raise ExecutionProvenanceError("Verification request digest mismatch with actual capture content")
        if hashlib.sha256(v_res.encode("utf-8")).hexdigest().lower() != capability.verification_response_digest.lower():
            raise ExecutionProvenanceError("Verification response digest mismatch with actual capture content")

        # Verify metadata on disk
        mut_meta = mut_ev.get("metadata", {})
        ver_meta = ver_ev.get("metadata", {})
        if mut_meta.get("action_id") and mut_meta.get("action_id") != capability.action_id:
            raise ExecutionProvenanceError("Mutation evidence metadata action_id mismatch")
        if mut_meta.get("session_ref") != capability.session_ref:
            raise ExecutionProvenanceError("Mutation evidence metadata session_ref mismatch")
        if mut_meta.get("principal_id") != capability.principal_id:
            raise ExecutionProvenanceError("Mutation evidence metadata principal_id mismatch")
        if mut_meta.get("program_id") != capability.program_id:
            raise ExecutionProvenanceError("Mutation evidence metadata program_id mismatch")
        if mut_meta.get("event_type") != "SESSION_REVOCATION":
            raise ExecutionProvenanceError("Mutation evidence metadata event_type mismatch")

        if ver_meta.get("action_id") and ver_meta.get("action_id") != capability.action_id:
            raise ExecutionProvenanceError("Verification evidence metadata action_id mismatch")
        if ver_meta.get("session_ref") != capability.session_ref:
            raise ExecutionProvenanceError("Verification evidence metadata session_ref mismatch")
        if ver_meta.get("principal_id") != capability.principal_id:
            raise ExecutionProvenanceError("Verification evidence metadata principal_id mismatch")
        if ver_meta.get("program_id") != capability.program_id:
            raise ExecutionProvenanceError("Verification evidence metadata program_id mismatch")
        if ver_meta.get("verification_method") != capability.verification_method:
            raise ExecutionProvenanceError("Verification evidence metadata verification_method mismatch")

        # 5. Build canonical execution payload and sign under execution key
        canonical_payload: Dict[str, Any] = {
            "action_dossier_digest": capability.action_dossier_digest,
            "action_id": capability.action_id,
            "action_type": capability.action_type,
            "approval_id": capability.approval_id,
            "domain": EXECUTION_DOMAIN,
            "execution_id": "",
            "execution_timestamp": capability.execution_timestamp,
            "http_method": capability.http_method,
            "invalidation_verification_result": capability.invalidation_verification_result,
            "key_id": "KEY-LOCAL-EXECUTION-1",
            "mutation_evidence_ref": capability.mutation_evidence_ref,
            "mutation_request_digest": capability.mutation_request_digest,
            "mutation_response_digest": capability.mutation_response_digest,
            "mutation_status_code": capability.mutation_status_code,
            "principal_id": capability.principal_id,
            "program_id": capability.program_id,
            "session_ref": capability.session_ref,
            "target_endpoint": capability.target_endpoint,
            "test_account": capability.test_account,
            "verification_evidence_ref": capability.verification_evidence_ref,
            "verification_method": capability.verification_method,
            "verification_request_digest": capability.verification_request_digest,
            "verification_response_digest": capability.verification_response_digest,
            "verification_status_code": capability.verification_status_code,
            "verification_timestamp": capability.verification_timestamp,
        }

        # Canonical execution hash excludes execution_id itself
        hash_payload = {k: canonical_payload[k] for k in CANONICAL_EXECUTION_FIELDS if k != "execution_id"}
        hash_bytes = json.dumps(hash_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        exec_id = f"EXEC-{hashlib.sha256(hash_bytes).hexdigest().upper()}"
        canonical_payload["execution_id"] = exec_id

        # Signature signs entire canonical payload including execution_id
        sign_payload = {k: canonical_payload[k] for k in CANONICAL_EXECUTION_FIELDS}
        sign_bytes = json.dumps(sign_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        key = self._get_key()
        sig = f"EXEC-SIG-{hmac.new(key, sign_bytes, hashlib.sha256).hexdigest().upper()}"

        record = ExecutionRecord(
            execution_id=exec_id,
            approval_id=capability.approval_id,
            action_id=capability.action_id,
            action_dossier_digest=capability.action_dossier_digest,
            program_id=capability.program_id,
            session_ref=capability.session_ref,
            principal_id=capability.principal_id,
            test_account=capability.test_account,
            target_endpoint=capability.target_endpoint,
            http_method=capability.http_method,
            action_type=capability.action_type,
            mutation_evidence_ref=capability.mutation_evidence_ref,
            mutation_request_digest=capability.mutation_request_digest,
            mutation_response_digest=capability.mutation_response_digest,
            mutation_status_code=capability.mutation_status_code,
            verification_evidence_ref=capability.verification_evidence_ref,
            verification_request_digest=capability.verification_request_digest,
            verification_response_digest=capability.verification_response_digest,
            verification_status_code=capability.verification_status_code,
            verification_method=capability.verification_method,
            invalidation_verification_result=capability.invalidation_verification_result,
            execution_timestamp=capability.execution_timestamp,
            verification_timestamp=capability.verification_timestamp,
            signature=sig,
            key_id="KEY-LOCAL-EXECUTION-1",
            domain=EXECUTION_DOMAIN,
            attestation_created=False,
            attestation_id=None,
            is_testing_primitive=False,
        )
        record.validate()

        with self._acquire_lock():
            ledger_data = self._load_ledger_data()
            if exec_id in ledger_data["records"]:
                raise ExecutionProvenanceError(f"Duplicate execution entry for '{exec_id}' detected")
            ledger_data["records"][exec_id] = record.to_dict()
            self._save_ledger_data(ledger_data)

            # Update consumed approval record with execution_id
            if os.path.exists(consumed_path):
                try:
                    with open(consumed_path, "r", encoding="utf-8") as f:
                        c_data = json.load(f)
                    if isinstance(c_data, dict):
                        c_dict = c_data.get("consumed", c_data)
                        if isinstance(c_dict, dict) and capability.action_id in c_dict:
                            c_dict[capability.action_id]["execution_id"] = exec_id
                            tmp_c = f"{consumed_path}.tmp.{os.getpid()}"
                            with open(tmp_c, "w", encoding="utf-8") as f:
                                json.dump(c_data, f, indent=2)
                            os.replace(tmp_c, consumed_path)
                except Exception:
                    pass

        return record

    def _record_raw_record_for_testing(
        self,
        action_id: str,
        action_dossier_digest: str,
        approval_id: str,
        program_id: str,
        session_ref: str,
        principal_id: str,
        test_account: str,
        target_endpoint: str,
        http_method: str,
        action_type: str,
        mutation_evidence_ref: str,
        mutation_request_digest: str,
        mutation_response_digest: str,
        mutation_status_code: int,
        verification_evidence_ref: str,
        verification_request_digest: str,
        verification_response_digest: str,
        verification_status_code: int,
        verification_method: str,
        invalidation_verification_result: str,
        execution_timestamp: str,
        verification_timestamp: str,
    ) -> ExecutionRecord:
        """
        Low-level internal primitive for unit testing signature math and storage corruption.
        Explicitly flagged as testing primitive (is_testing_primitive=True).
        Never accepted as genuine execution provenance in Mode A verification.
        """
        canonical_payload: Dict[str, Any] = {
            "action_dossier_digest": action_dossier_digest,
            "action_id": action_id,
            "action_type": action_type,
            "approval_id": approval_id,
            "domain": EXECUTION_DOMAIN,
            "execution_id": "",
            "execution_timestamp": execution_timestamp,
            "http_method": http_method,
            "invalidation_verification_result": invalidation_verification_result,
            "key_id": "KEY-LOCAL-EXECUTION-1",
            "mutation_evidence_ref": mutation_evidence_ref,
            "mutation_request_digest": mutation_request_digest,
            "mutation_response_digest": mutation_response_digest,
            "mutation_status_code": mutation_status_code,
            "principal_id": principal_id,
            "program_id": program_id,
            "session_ref": session_ref,
            "target_endpoint": target_endpoint,
            "test_account": test_account,
            "verification_evidence_ref": verification_evidence_ref,
            "verification_method": verification_method,
            "verification_request_digest": verification_request_digest,
            "verification_response_digest": verification_response_digest,
            "verification_status_code": verification_status_code,
            "verification_timestamp": verification_timestamp,
        }

        hash_payload = {k: canonical_payload[k] for k in CANONICAL_EXECUTION_FIELDS if k != "execution_id"}
        hash_bytes = json.dumps(hash_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        exec_id = f"EXEC-{hashlib.sha256(hash_bytes).hexdigest().upper()}"
        canonical_payload["execution_id"] = exec_id

        sign_payload = {k: canonical_payload[k] for k in CANONICAL_EXECUTION_FIELDS}
        sign_bytes = json.dumps(sign_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        key = self._get_key()
        sig = f"EXEC-SIG-{hmac.new(key, sign_bytes, hashlib.sha256).hexdigest().upper()}"

        record = ExecutionRecord(
            execution_id=exec_id,
            approval_id=approval_id,
            action_id=action_id,
            action_dossier_digest=action_dossier_digest,
            program_id=program_id,
            session_ref=session_ref,
            principal_id=principal_id,
            test_account=test_account,
            target_endpoint=target_endpoint,
            http_method=http_method,
            action_type=action_type,
            mutation_evidence_ref=mutation_evidence_ref,
            mutation_request_digest=mutation_request_digest,
            mutation_response_digest=mutation_response_digest,
            mutation_status_code=mutation_status_code,
            verification_evidence_ref=verification_evidence_ref,
            verification_request_digest=verification_request_digest,
            verification_response_digest=verification_response_digest,
            verification_status_code=verification_status_code,
            verification_method=verification_method,
            invalidation_verification_result=invalidation_verification_result,
            execution_timestamp=execution_timestamp,
            verification_timestamp=verification_timestamp,
            signature=sig,
            key_id="KEY-LOCAL-EXECUTION-1",
            domain=EXECUTION_DOMAIN,
            attestation_created=False,
            attestation_id=None,
            is_testing_primitive=True,
        )
        record.validate()

        with self._acquire_lock():
            ledger_data = self._load_ledger_data()
            if exec_id in ledger_data["records"]:
                raise ExecutionProvenanceError(f"Duplicate execution entry for '{exec_id}' detected")
            ledger_data["records"][exec_id] = record.to_dict()
            self._save_ledger_data(ledger_data)

        return record

    def _verify_record_dict_unlocked(self, clean_id: str, rec_dict: Dict[str, Any]) -> ExecutionRecord:
        """Verifies signature, fields, and digests of an execution record dict without acquiring lock."""
        for f in CANONICAL_EXECUTION_FIELDS:
            if f not in rec_dict:
                raise ExecutionProvenanceError(f"Execution record missing canonical field '{f}'")

        sign_payload = {k: rec_dict[k] for k in CANONICAL_EXECUTION_FIELDS}
        sign_bytes = json.dumps(sign_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        key = self._get_key()
        expected_sig = f"EXEC-SIG-{hmac.new(key, sign_bytes, hashlib.sha256).hexdigest().upper()}"

        stored_sig = rec_dict.get("signature", "")
        if not hmac.compare_digest(stored_sig, expected_sig):
            raise ExecutionProvenanceError("Execution record signature verification failed: record has been tampered")

        # Verify hash computation of execution_id
        hash_payload = {k: rec_dict[k] for k in CANONICAL_EXECUTION_FIELDS if k != "execution_id"}
        hash_bytes = json.dumps(hash_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected_id = f"EXEC-{hashlib.sha256(hash_bytes).hexdigest().upper()}"
        if clean_id != expected_id:
            raise ExecutionProvenanceError("Execution identifier digest mismatch")

        record = ExecutionRecord(
            execution_id=rec_dict["execution_id"],
            approval_id=rec_dict["approval_id"],
            action_id=rec_dict["action_id"],
            action_dossier_digest=rec_dict["action_dossier_digest"],
            program_id=rec_dict["program_id"],
            session_ref=rec_dict["session_ref"],
            principal_id=rec_dict["principal_id"],
            test_account=rec_dict["test_account"],
            target_endpoint=rec_dict["target_endpoint"],
            http_method=rec_dict["http_method"],
            action_type=rec_dict["action_type"],
            mutation_evidence_ref=rec_dict["mutation_evidence_ref"],
            mutation_request_digest=rec_dict["mutation_request_digest"],
            mutation_response_digest=rec_dict["mutation_response_digest"],
            mutation_status_code=rec_dict["mutation_status_code"],
            verification_evidence_ref=rec_dict["verification_evidence_ref"],
            verification_request_digest=rec_dict["verification_request_digest"],
            verification_response_digest=rec_dict["verification_response_digest"],
            verification_status_code=rec_dict["verification_status_code"],
            verification_method=rec_dict["verification_method"],
            invalidation_verification_result=rec_dict["invalidation_verification_result"],
            execution_timestamp=rec_dict["execution_timestamp"],
            verification_timestamp=rec_dict["verification_timestamp"],
            signature=stored_sig,
            key_id=rec_dict.get("key_id", "KEY-LOCAL-EXECUTION-1"),
            domain=rec_dict.get("domain", EXECUTION_DOMAIN),
            attestation_created=bool(rec_dict.get("attestation_created", False)),
            attestation_id=rec_dict.get("attestation_id"),
            is_testing_primitive=bool(rec_dict.get("is_testing_primitive", False)),
        )
        record.validate()
        return record

    def get_execution(self, execution_id: str) -> Optional[ExecutionRecord]:
        """
        Retrieves and cryptographically verifies an execution record by execution_id.
        Raises ExecutionProvenanceError if signature or integrity verification fails.
        """
        if not execution_id or not isinstance(execution_id, str):
            return None
        clean_id = execution_id.strip().upper()
        if not EXECUTION_ID_PATTERN.match(clean_id):
            return None

        with self._acquire_lock():
            ledger_data = self._load_ledger_data()
            rec_dict = ledger_data.get("records", {}).get(clean_id)
            if not rec_dict or not isinstance(rec_dict, dict):
                return None

        return self._verify_record_dict_unlocked(clean_id, rec_dict)

    def claim_for_attestation(self, execution_id: str, attestation_id: str) -> ExecutionRecord:
        """
        Atomically marks an execution record as claimed for attestation issuance under lock.
        Prevents replay and duplicate attestation creation.
        """
        if not execution_id or not isinstance(execution_id, str):
            raise ExecutionProvenanceError("Invalid execution_id for attestation claim")
        clean_id = execution_id.strip().upper()
        if not EXECUTION_ID_PATTERN.match(clean_id):
            raise ExecutionProvenanceError(f"Execution ID '{execution_id}' does not match required EXEC-... pattern")

        with self._acquire_lock():
            ledger_data = self._load_ledger_data()
            rec_dict = ledger_data.get("records", {}).get(clean_id)
            if not rec_dict or not isinstance(rec_dict, dict):
                raise ExecutionProvenanceError(f"Execution record '{clean_id}' not found in ledger")

            record = self._verify_record_dict_unlocked(clean_id, rec_dict)

            if record.attestation_created:
                raise ExecutionProvenanceError(
                    f"Execution '{clean_id}' has already been claimed for attestation '{record.attestation_id}' (replay rejected)"
                )

            ledger_data["records"][clean_id]["attestation_created"] = True
            ledger_data["records"][clean_id]["attestation_id"] = attestation_id
            self._save_ledger_data(ledger_data)

            record.attestation_created = True
            record.attestation_id = attestation_id
            return record
