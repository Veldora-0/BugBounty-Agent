"""
Phase 21: PostRevocationResourceValidator.

Verifies whether protected resource endpoints remain accessible after session
revocation, logout, or token expiration:
- Mode A (Default): Observe Existing Invalidation (Strictly observation-only; requires
  pre-captured baseline and invalidation evidence; returns INCONCLUSIVE if missing).
- Mode B: Controlled Invalidation (Active mutation requiring explicit single-use
  action-specific approval matching ACT-<SHA256>).
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

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
from framework.authentication.validators import AuthenticationFalsePositiveClassifier
from framework.authz.model import ResourceAccessTarget
from framework.validation.engine import SecurityValidationEngine
from framework.validation.request import ControlledRequest, ControlledResponse


class ApprovalSecurityError(Exception):
    """Raised when controlled invalidation action approval is missing, expired, replayed, or tampered."""
    pass


ALLOWED_DOSSIER_KEYS: Set[str] = {
    "action_id", "target_endpoint", "method", "test_account", 
    "action_type", "program_id", "created_at", "ttl", "unique_approval_id"
}

ALLOWED_MUTATION_METHODS: Set[str] = {"POST", "PUT", "DELETE"}
ALLOWED_ACTION_TYPES: Set[str] = {"LOGOUT", "ACTION-LOGOUT", "TOKEN_REVOCATION", "PASSWORD_CHANGE"}


class PostRevocationResourceValidator:
    """Evaluates resource accessibility post-revocation across Mode A and Mode B."""

    _consumed_lock = threading.Lock()

    def __init__(
        self,
        validation_engine: Optional[Any] = None,
        program_dir: Optional[str] = None,
        state_dir: Optional[str] = None,
        scope_engine: Optional[Any] = None,
    ):
        self._engine = validation_engine
        self._program_dir = program_dir or "."
        self._state_dir = state_dir or os.path.join(self._program_dir, "state")
        self._scope_engine = scope_engine

    @property
    def engine(self) -> Any:
        if self._engine is None:
            self._engine = SecurityValidationEngine(program_dir=self._program_dir)
        return self._engine

    def _get_consumed_approvals_path(self) -> str:
        return os.path.join(self._state_dir, "consumed_approvals.json")

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

                finding_id = f"FIND-REVOKE-{int(time.time())}"[:20]
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

    def execute_controlled_invalidation(
        self,
        session_ctx: CorrelatedSessionContext,
        action_id: str,
        action_dossier: Dict[str, Any],
    ) -> bool:
        """
        Mode B: Executes active mutation (logout / password change) on verified test accounts.
        Enforces strict action-specific single-use approval bound to ACT-<SHA256>.
        Guarantees single-use execution through persistent consumed approval tracking.
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

        # 3. Scope validation if ScopeEngine is bound
        if self._scope_engine is not None:
            try:
                is_in_scope = self._scope_engine.is_in_scope(target_endpoint)
                if not is_in_scope:
                    raise ApprovalSecurityError("Target endpoint for controlled mutation is out of scope")
            except ApprovalSecurityError:
                raise
            except Exception as e:
                raise ApprovalSecurityError(f"Scope verification failed for controlled mutation: {e}")

        # 4. Canonical digest verification
        expected_hash = action_id[4:]
        dossier_copy = {k: action_dossier[k] for k in sorted(action_dossier.keys()) if k != "action_id"}
        canonical_str = json.dumps(dossier_copy, sort_keys=True)
        computed_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

        if computed_hash != expected_hash:
            raise ApprovalSecurityError("Action approval digest mismatch; action dossier has been tampered")

        # 5. Timestamp and clock tolerance checks
        now = time.time()
        if created_at > now + 30.0:
            raise ApprovalSecurityError("Action approval created_at is future-dated beyond clock tolerance")
        if now - created_at > ttl:
            raise ApprovalSecurityError("Action approval has expired")

        # 6. Single-use execution enforcement (persistent and thread-safe)
        with self._consumed_lock:
            if self._is_approval_consumed(action_id):
                raise ApprovalSecurityError(f"Action approval '{action_id}' has already been consumed (replay rejected)")
            # Mark consumed immediately before network mutation to prevent concurrent/interrupted replays
            self._mark_approval_consumed(action_id, action_dossier)

        # 7. Execute the controlled invalidation mutation
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
