"""
Phase 21: PreMfaPrivilegeValidator.

Audits whether authorization endpoints expose sensitive user or tenant data to
partially authenticated sessions that have completed password verification but have
not satisfied Multi-Factor Authentication (MFA) or step-up requirements.
"""

from __future__ import annotations

import difflib
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
)
from framework.authentication.validators import AuthenticationFalsePositiveClassifier
from framework.authz.model import ResourceAccessTarget
from framework.validation.engine import SecurityValidationEngine
from framework.validation.request import ControlledRequest, ControlledResponse


class PreMfaPrivilegeValidator:
    """Evaluates privilege leakage across pre-MFA and step-up authentication boundaries."""

    def __init__(self, validation_engine: Optional[Any] = None, program_dir: Optional[str] = None):
        self._engine = validation_engine
        self._program_dir = program_dir or "."

    @property
    def engine(self) -> Any:
        if self._engine is None:
            self._engine = SecurityValidationEngine(program_dir=self._program_dir)
        return self._engine

    def is_mfa_challenge_form(self, response: ControlledResponse) -> bool:
        """Detects if response is an MFA challenge form, OTP prompt, or intermediate challenge JSON."""
        if response.status_code != 200:
            return False

        lower_body = response.body_text.lower()
        challenge_indicators = [
            "otp", "authenticator", "mfa_token", "mfa_required", "totp",
            "verify your identity", "sms code", "two-factor", "security code",
            "challenge_token", "enter the 6-digit code", "mfa challenge",
            "type=\"password\"", "name=\"otp\"", "name=\"code\"",
        ]
        return any(ind in lower_body for ind in challenge_indicators)

    def evaluate_pre_mfa_boundary(
        self,
        session_ctx: CorrelatedSessionContext,
        resource_target: ResourceAccessTarget,
        fully_authenticated_response: ControlledResponse,
    ) -> Optional[CorrelationFinding]:
        """
        Tests whether an intermediate pre-MFA session can access a protected resource.
        Dispatches probe and compares response with fully authenticated baseline.
        Actively eliminates 200 OK login/MFA challenge forms and public landing shells.
        """
        target_endpoint = getattr(resource_target, "endpoint", None) or getattr(resource_target, "url", "")
        method = getattr(resource_target, "method", "GET")

        req = ControlledRequest(
            url=target_endpoint,
            method=method,
            headers=dict(session_ctx.volatile_headers),
        )
        try:
            resp = self.engine.send_request(req)
        except Exception:
            return None

        # Safe denial: 401, 403, 302 redirect, or challenge form
        if resp.status_code in (401, 403) or resp.status_code in (301, 302, 303, 307, 308):
            return None

        if self.is_mfa_challenge_form(resp) or AuthenticationFalsePositiveClassifier.is_login_page_false_positive(resp.status_code, resp.body_text):
            return None

        if AuthenticationFalsePositiveClassifier.is_waf_or_challenge_page(resp.status_code, resp.body_text):
            return None

        # If HTTP 200 OK: verify if protected data matching baseline is returned
        if resp.status_code == 200:
            if AuthenticationFalsePositiveClassifier.is_public_landing_or_generic_shell(resp.status_code, resp.body_text):
                return None
            if AuthenticationFalsePositiveClassifier.is_generic_status_or_empty_response(resp.status_code, resp.body_text):
                return None

            # Check similarity against fully authenticated baseline
            ratio = difflib.SequenceMatcher(None, resp.body_text, fully_authenticated_response.body_text).ratio()
            if ratio >= 0.50:
                # Authentic CVSS 3.1 calculation for PRE_MFA_PRIVILEGE_LEAK (REF-03 profile)
                metrics = CVSS31Metrics(
                    av=AttackVector.NETWORK,
                    ac=AttackComplexity.LOW,
                    pr=PrivilegesRequired.NONE,
                    ui=UserInteraction.NONE,
                    scope=Scope.UNCHANGED,
                    c=CIAImpact.HIGH,
                    i=CIAImpact.NONE,
                    a=CIAImpact.NONE,
                )
                score, sev, vector = CVSS31Calculator.calculate_base_score(metrics)

                finding_id = f"FIND-MFA-{int(time.time())}"[:20]
                endpoint_path = target_endpoint if target_endpoint.startswith("/") else "/" + target_endpoint.split("/", 3)[-1]
                return CorrelationFinding(
                    finding_id=finding_id,
                    title="Pre-MFA Session Exposes Protected Authorization Endpoint Data",
                    category="PRE_MFA_PRIVILEGE_LEAK",
                    severity=sev,
                    cvss_score=score,
                    cvss_vector=vector,
                    confidence=0.90,
                    endpoint=endpoint_path,
                    description="Intermediate session in pre-MFA state accessed sensitive resource without completing MFA challenge.",
                    evidence_chain=[],
                )

        return None

    def evaluate_step_up_boundary(
        self,
        session_ctx: CorrelatedSessionContext,
        resource_target: ResourceAccessTarget,
        step_up_response: ControlledResponse,
    ) -> Optional[CorrelationFinding]:
        """
        Audits whether high-privilege endpoints enforce step-up authentication.
        """
        target_endpoint = getattr(resource_target, "endpoint", None) or getattr(resource_target, "url", "")
        method = getattr(resource_target, "method", "GET")

        req = ControlledRequest(
            url=target_endpoint,
            method=method,
            headers=dict(session_ctx.volatile_headers),
        )
        try:
            resp = self.engine.send_request(req)
        except Exception:
            return None

        # Safe denial or step-up challenge prompt
        if resp.status_code in (401, 403) or self.is_mfa_challenge_form(resp):
            return None

        if resp.status_code == 200:
            if AuthenticationFalsePositiveClassifier.is_public_landing_or_generic_shell(resp.status_code, resp.body_text):
                return None
            if AuthenticationFalsePositiveClassifier.is_generic_status_or_empty_response(resp.status_code, resp.body_text):
                return None

            ratio = difflib.SequenceMatcher(None, resp.body_text, step_up_response.body_text).ratio()
            if ratio >= 0.50:
                metrics = CVSS31Metrics(
                    av=AttackVector.NETWORK,
                    ac=AttackComplexity.LOW,
                    pr=PrivilegesRequired.LOW,
                    ui=UserInteraction.NONE,
                    scope=Scope.UNCHANGED,
                    c=CIAImpact.HIGH,
                    i=CIAImpact.NONE,
                    a=CIAImpact.NONE,
                )
                score, sev, vector = CVSS31Calculator.calculate_base_score(metrics)

                finding_id = f"FIND-STEPUP-{int(time.time())}"[:20]
                endpoint_path = target_endpoint if target_endpoint.startswith("/") else "/" + target_endpoint.split("/", 3)[-1]
                return CorrelationFinding(
                    finding_id=finding_id,
                    title="Sensitive Action Endpoint Lacks Required Step-Up Authentication",
                    category="PRE_MFA_PRIVILEGE_LEAK",
                    severity=sev,
                    cvss_score=score,
                    cvss_vector=vector,
                    confidence=0.85,
                    endpoint=endpoint_path,
                    description="Session performed step-up action without supplying elevated step-up credential.",
                    evidence_chain=[],
                )

        return None
