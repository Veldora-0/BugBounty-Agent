"""
Phase 21: PostRevocationResourceValidator.

Verifies whether protected resource endpoints remain accessible after session
revocation, logout, or token expiration:
- Mode A (Default): Observe Existing Invalidation (Strictly observation-only; requires
  pre-captured baseline and invalidation evidence; returns INCONCLUSIVE if missing).
- Mode B: Controlled Invalidation (Active mutation requiring explicit single-use
  action-specific approval matching ACT-<SHA256> signed with trusted operator approval key).
"""

from __future__ import annotations

import difflib
import hashlib
import hmac
import json
import os
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
from framework.auth_correlation.model import (
    CorrelatedSessionContext,
    CorrelationFinding,
    CorrelationLifecycle,
    SerializationSecurityError,
)
from framework.auth_correlation.state import (
    _enforce_windows_directory_dacl,
    _enforce_windows_file_dacl,
    _verify_windows_directory_security,
    _verify_windows_file_security,
)
from framework.authentication.validators import AuthenticationFalsePositiveClassifier
from framework.authz.model import ResourceAccessTarget
from framework.validation.engine import SecurityValidationEngine
from framework.validation.request import ControlledRequest, ControlledResponse


class ApprovalSecurityError(Exception):
    """Raised when controlled invalidation action approval is missing, expired, replayed, or tampered."""
    pass


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


class CrossProcessFileLock:
    """
    Cross-process file lock supporting Windows (msvcrt) and POSIX (fcntl).
    Guarantees that single-use approval checks and marks are strictly atomic across processes.
    """

    def __init__(self, lock_path: str, timeout: float = 10.0, retry_interval: float = 0.05):
        self.lock_path = lock_path
        self.timeout = timeout
        self.retry_interval = retry_interval
        self._fd: Optional[int] = None

    def __enter__(self) -> CrossProcessFileLock:
        os.makedirs(os.path.dirname(os.path.abspath(self.lock_path)), exist_ok=True)
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        self._fd = os.open(self.lock_path, flags, 0o600)
        start = time.time()
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except (OSError, IOError):
                if time.time() - start >= self.timeout:
                    if self._fd is not None:
                        try:
                            os.close(self._fd)
                        except OSError:
                            pass
                        self._fd = None
                    raise ApprovalSecurityError(f"Timed out acquiring cross-process lock on '{self.lock_path}'")
                time.sleep(self.retry_interval)

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._fd is not None:
            try:
                if os.name == "nt":
                    import msvcrt
                    try:
                        msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
                    except (OSError, IOError):
                        pass
                else:
                    import fcntl
                    try:
                        fcntl.flock(self._fd, fcntl.LOCK_UN)
                    except (OSError, IOError):
                        pass
                os.close(self._fd)
            except OSError:
                pass
            finally:
                self._fd = None


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
    ):
        self._engine = validation_engine
        self._program_dir = program_dir or "."
        self._state_dir = state_dir or os.path.join(self._program_dir, "state")
        self._scope_engine = scope_engine
        self._approval_key = approval_key
        self._approval_key_dir = approval_key_dir

    @property
    def engine(self) -> Any:
        if self._engine is None:
            self._engine = SecurityValidationEngine(program_dir=self._program_dir)
        return self._engine

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

    def _mark_approval_consumed(self, action_id: str, dossier: Dict[str, Any]) -> None:
        """Atomically marks action approval as consumed; fails closed on corruption."""
        os.makedirs(self._state_dir, exist_ok=True)
        path = self._get_consumed_approvals_path()
        data: Dict[str, Any] = {"consumed": {}}
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

        data["consumed"][action_id] = {
            "consumed_at": time.time(),
            "target_endpoint": dossier.get("target_endpoint"),
            "action_type": dossier.get("action_type"),
            "test_account": dossier.get("test_account"),
        }

        tmp_path = f"{path}.tmp.{os.getpid()}"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, path)
        except Exception as e:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            raise ApprovalSecurityError(f"Failed to record consumed approval state: {e}")

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
        2. invalidation_evidence_ref providing defensible proof of the invalidation event.
        If either prerequisite is missing, fails closed returning ('INCONCLUSIVE', None).
        """
        if pre_revocation_baseline is None or pre_revocation_baseline.status_code != 200:
            return "INCONCLUSIVE", None

        if not invalidation_evidence_ref or not isinstance(invalidation_evidence_ref, str):
            return "INCONCLUSIVE", None

        # Mode A: strictly read-only request (GET or HEAD)
        target_endpoint = getattr(resource_target, "endpoint", None) or getattr(resource_target, "url", "")
        method_raw = getattr(resource_target, "method", "GET")
        method = "HEAD" if method_raw == "HEAD" else "GET"
        req = ControlledRequest(
            url=target_endpoint,
            method=method,
            headers=dict(session_ctx.volatile_headers),
        )
        try:
            resp = self.engine.send_request(req)
        except Exception:
            return "INCONCLUSIVE", None

        # Secure invalidation: 401, 403, or login redirect
        if resp.status_code in (401, 403):
            return "SECURE_INVALIDATION", None

        if resp.status_code in (301, 302, 303, 307, 308):
            loc = (resp.headers.get("location") or "").lower()
            if any(term in loc for term in ("/login", "/auth", "/signin", "/sso", "login.")):
                return "SECURE_INVALIDATION", None
            return "INCONCLUSIVE", None

        if AuthenticationFalsePositiveClassifier.is_login_page_false_positive(resp.status_code, resp.body_text):
            return "SECURE_INVALIDATION", None

        if AuthenticationFalsePositiveClassifier.is_waf_or_challenge_page(resp.status_code, resp.body_text):
            return "INCONCLUSIVE", None

        # If HTTP 200 OK: verify body data against pre-revocation baseline
        if resp.status_code == 200:
            # Must not be a generic shell or empty response
            if AuthenticationFalsePositiveClassifier.is_public_landing_or_generic_shell(resp.status_code, resp.body_text):
                return "INCONCLUSIVE", None
            if AuthenticationFalsePositiveClassifier.is_generic_status_or_empty_response(resp.status_code, resp.body_text):
                return "INCONCLUSIVE", None

            ratio = difflib.SequenceMatcher(None, resp.body_text, pre_revocation_baseline.body_text).ratio()
            if ratio >= 0.50:
                # Authentic CVSS 3.1 calculation for SESSION_NOT_INVALIDATED
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

                rev_hash = hashlib.sha256(f"{target_endpoint}_{time.time_ns()}".encode("utf-8")).hexdigest()[:10].upper()
                finding_id = f"FIND-REVOKE-{rev_hash}"
                endpoint_path = target_endpoint if target_endpoint.startswith("/") else "/" + target_endpoint.split("/", 3)[-1]
                finding = CorrelationFinding(
                    finding_id=finding_id,
                    title="Session Retains Protected Resource Access After Invalidation",
                    category="SESSION_NOT_INVALIDATED",
                    severity=sev,
                    cvss_score=score,
                    cvss_vector=vector,
                    confidence=0.90,
                    endpoint=endpoint_path,
                    description="Session token continues to access protected resource despite verified invalidation event.",
                    evidence_chain=[invalidation_evidence_ref],
                )
                return "SESSION_NOT_INVALIDATED", finding

        return "INCONCLUSIVE", None

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

        # Secure invalidation responses
        if probe_response.status_code in (401, 403):
            session_ctx.lifecycle = CorrelationLifecycle.REVOKED
            return None

        if probe_response.status_code in (301, 302, 303, 307, 308):
            loc = (probe_response.headers.get("location") or "").lower()
            if any(term in loc for term in ("/login", "/auth", "/signin", "/sso", "login.")):
                session_ctx.lifecycle = CorrelationLifecycle.REVOKED
                return None
            return None

        if AuthenticationFalsePositiveClassifier.is_login_page_false_positive(
            probe_response.status_code, probe_response.body_text
        ):
            session_ctx.lifecycle = CorrelationLifecycle.REVOKED
            return None

        if AuthenticationFalsePositiveClassifier.is_waf_or_challenge_page(
            probe_response.status_code, probe_response.body_text
        ):
            return None

        if probe_response.status_code == 200:
            if AuthenticationFalsePositiveClassifier.is_public_landing_or_generic_shell(
                probe_response.status_code, probe_response.body_text
            ):
                return None
            if AuthenticationFalsePositiveClassifier.is_generic_status_or_empty_response(
                probe_response.status_code, probe_response.body_text
            ):
                return None

            is_valid_leak = True
            if baseline_target is not None and baseline_target.status_code == 200:
                ratio = difflib.SequenceMatcher(None, probe_response.body_text, baseline_target.body_text).ratio()
                if ratio < 0.50:
                    is_valid_leak = False

            if is_valid_leak:
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
                ev_hash = hashlib.sha256((clean_req + clean_res).encode("utf-8")).hexdigest()[:12]
                evidence_ref = f"EVID-{ev_hash}"
                rev_hash = hashlib.sha256(f"{target_endpoint}_{time.time_ns()}".encode("utf-8")).hexdigest()[:10].upper()
                finding_id = f"FIND-REVOKE-{rev_hash}"
                endpoint_path = target_endpoint if target_endpoint.startswith("/") else "/" + target_endpoint.split("/", 3)[-1]
                return CorrelationFinding(
                    finding_id=finding_id,
                    title="Session Retains Protected Resource Access After Invalidation",
                    category="SESSION_NOT_INVALIDATED",
                    severity=sev,
                    cvss_score=score,
                    cvss_vector=vector,
                    confidence=0.90,
                    endpoint=endpoint_path,
                    description="Session token continues to access protected resource despite verified invalidation event.",
                    evidence_chain=[evidence_ref],
                )

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
        Requires mandatory initialized ScopeEngine.
        """
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

        program_id = action_dossier.get("program_id")
        if not isinstance(program_id, str) or not program_id:
            raise ApprovalSecurityError("Action approval program_id must be a non-empty string")

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
        key = self._approval_key or get_or_create_approval_key(key_dir=self._approval_key_dir)
        expected_sig_hash = hmac.new(key, canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig[4:], expected_sig_hash):
            raise ApprovalSecurityError("Operator authorization signature verification failed")

        # 5. Mandatory Scope validation
        if self._scope_engine is None:
            raise ApprovalSecurityError("Mandatory ScopeEngine is required for controlled invalidation mutation")

        parsed = urlparse(target_endpoint)
        if parsed.scheme.lower() not in ("http", "https"):
            raise ApprovalSecurityError(f"Target endpoint '{target_endpoint}' specifies invalid or unsupported scheme")
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        if port < 1 or port > 65535:
            raise ApprovalSecurityError(f"Target endpoint '{target_endpoint}' specifies invalid port")
        if not parsed.hostname:
            raise ApprovalSecurityError(f"Target endpoint '{target_endpoint}' has missing or empty hostname")

        try:
            is_in_scope = self._scope_engine.is_in_scope(target_endpoint)
            if not is_in_scope:
                raise ApprovalSecurityError(f"Target endpoint '{target_endpoint}' for controlled mutation is out of scope")
        except ApprovalSecurityError:
            raise
        except Exception as e:
            raise ApprovalSecurityError(f"Scope verification failed for controlled mutation: {e}")

        # Bind scope engine to validation engine to ensure redirects are validated
        if hasattr(self.engine, "scope_engine"):
            self.engine.scope_engine = self._scope_engine

        # 6. Timestamp and clock tolerance checks
        now = time.time()
        if created_at > now + 30.0:
            raise ApprovalSecurityError("Action approval created_at is future-dated beyond clock tolerance")
        if now - created_at > ttl:
            raise ApprovalSecurityError("Action approval has expired")

        # 7. Durable cross-process single-use execution enforcement
        lock_path = self._get_consumed_approvals_lock_path()
        with self._consumed_lock, CrossProcessFileLock(lock_path):
            if self._is_approval_consumed(action_id):
                raise ApprovalSecurityError(f"Action approval '{action_id}' has already been consumed (replay rejected)")
            # Mark consumed immediately BEFORE network mutation
            self._mark_approval_consumed(action_id, action_dossier)

        # 8. Execute the controlled invalidation mutation
        req = ControlledRequest(
            url=target_endpoint,
            method=method,
            headers=dict(session_ctx.volatile_headers),
        )
        try:
            resp = self.engine.send_request(req)
            session_ctx.lifecycle = CorrelationLifecycle.REVOKED
            return resp.status_code in (200, 204, 302, 303)
        except Exception as e:
            raise ApprovalSecurityError(f"Failed to execute controlled invalidation mutation: {e}")
