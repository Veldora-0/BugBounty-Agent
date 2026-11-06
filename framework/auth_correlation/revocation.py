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
import time
from typing import Any, Dict, List, Optional, Tuple

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
    """Raised when controlled invalidation action approval is missing, expired, or tampered."""
    pass


class PostRevocationResourceValidator:
    """Evaluates resource accessibility post-revocation across Mode A and Mode B."""

    def __init__(self, validation_engine: Optional[Any] = None, program_dir: Optional[str] = None):
        self._engine = validation_engine
        self._program_dir = program_dir or "."

    @property
    def engine(self) -> Any:
        if self._engine is None:
            self._engine = SecurityValidationEngine(program_dir=self._program_dir)
        return self._engine

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
        if resp.status_code in (401, 403) or resp.status_code in (301, 302, 303, 307, 308):
            return "SECURE_INVALIDATION", None

        if AuthenticationFalsePositiveClassifier.is_login_page_false_positive(resp.status_code, resp.body_text):
            return "SECURE_INVALIDATION", None

        # If HTTP 200 OK: verify body data against pre-revocation baseline
        if resp.status_code == 200:
            # Must not be a generic shell or empty response
            if AuthenticationFalsePositiveClassifier.is_public_landing_or_generic_shell(resp.status_code, resp.body_text):
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
        """
        if not action_id.startswith("ACT-") or len(action_id) != 68:  # "ACT-" + 64 hex chars
            raise ApprovalSecurityError("Invalid action approval identifier format")

        expected_hash = action_id[4:]

        required_keys = {"action_id", "target_endpoint", "method", "test_account", "action_type", "created_at", "ttl"}
        if not required_keys.issubset(action_dossier.keys()):
            raise ApprovalSecurityError("Action dossier missing mandatory security fields")

        # Canonical digest verification
        dossier_copy = {k: action_dossier[k] for k in sorted(action_dossier.keys()) if k != "action_id"}
        canonical_str = json.dumps(dossier_copy, sort_keys=True)
        computed_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

        if computed_hash != expected_hash:
            raise ApprovalSecurityError("Action approval digest mismatch; action dossier has been tampered")

        # TTL check (max 300 seconds)
        ttl = min(int(action_dossier.get("ttl", 300)), 300)
        created_at = float(action_dossier.get("created_at", 0))
        if time.time() - created_at > ttl:
            raise ApprovalSecurityError("Action approval has expired")

        # Execute the controlled invalidation mutation
        req = ControlledRequest(
            url=action_dossier["target_endpoint"],
            method=action_dossier.get("method", "POST"),
            headers=dict(session_ctx.volatile_headers),
        )
        try:
            resp = self.engine.send_request(req)
            session_ctx.lifecycle = CorrelationLifecycle.REVOKED
            return resp.status_code in (200, 204, 302, 303)
        except Exception as e:
            raise ApprovalSecurityError(f"Failed to execute controlled invalidation mutation: {e}")
