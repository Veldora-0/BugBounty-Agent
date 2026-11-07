"""
Phase 21: DualControlPreflightValidator.

Executes sequential 6-point preflight session health verification protocol:
1. Probe 1 (Principal A headers)
2. Probe 2 (Principal B headers)
3. Probe 3 (Anonymous control)
4. Differential validation
5. Cache state assessment
6. Fail-closed gating on any failure or ambiguity.
"""

from __future__ import annotations

import difflib
import time
from typing import Any, Dict, List, Optional, Tuple

from framework.auth_correlation.model import (
    CorrelatedPrincipalContext,
    CorrelatedSessionContext,
    CorrelationLifecycle,
    ProbeStatus,
)
from framework.authentication.validators import AuthenticationFalsePositiveClassifier
from framework.validation.engine import SecurityValidationEngine
from framework.validation.request import ControlledRequest, ControlledResponse


class DualControlPreflightValidator:
    """Validates session health and active authentication state before comparative testing."""

    def __init__(self, validation_engine: Optional[Any] = None, program_dir: Optional[str] = None):
        self._engine = validation_engine
        self._program_dir = program_dir or "."

    @property
    def engine(self) -> Any:
        if self._engine is None:
            self._engine = SecurityValidationEngine(program_dir=self._program_dir)
        return self._engine

    def probe_anonymous_control(self, preflight_url: str) -> ControlledResponse:
        """Dispatches an anonymous control probe without authentication headers."""
        req = ControlledRequest(
            url=preflight_url,
            method="GET",
            headers={"Accept": "application/json, text/html, */*"},
        )
        return self.engine.send_request(req)

    def _assess_cache_headers(self, response: ControlledResponse) -> str:
        """Evaluates whether response indicates reverse-proxy caching."""
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        age = headers.get("age")
        cf_cache = headers.get("cf-cache-status", "")
        x_cache = headers.get("x-cache", "")

        if cf_cache == "hit" or "hit" in x_cache:
            return "CACHE_CONFIRMED"
        if age and age.isdigit() and int(age) > 0:
            return "CACHE_CONFIRMED"
        return "CACHE_NOT_INDICATED"

    @classmethod
    def classify_probe_response(
        cls,
        resp: ControlledResponse,
        anon_resp: Optional[ControlledResponse] = None,
    ) -> CorrelationLifecycle:
        """
        Classifies probe response into explicit lifecycle states:
        - VERIFIED: legitimate protected resource access distinct from anonymous control.
        - EXPIRED: response explicitly indicates token/session expiration.
        - AUTHENTICATION_FAILED: 401 Unauthorized or redirect to login.
        - AUTHORIZATION_DENIED: 403 Forbidden (session authenticated but lacks access).
        - UNKNOWN: ambiguous response, public landing page, or SPA shell matching anonymous control.
        - FAILED: 5xx server error, unexpected transport fault, or unclassifiable failure.
        """
        # 1. 401 Unauthorized -> check for explicit expiration cues
        if resp.status_code == 401:
            lower_body = (resp.body_text or "").lower()
            if any(term in lower_body for term in ("expired", "token_expired", "session_expired")):
                return CorrelationLifecycle.EXPIRED
            return CorrelationLifecycle.AUTHENTICATION_FAILED

        # 2. 403 Forbidden -> explicitly AUTHORIZATION_DENIED
        if resp.status_code == 403:
            return CorrelationLifecycle.AUTHORIZATION_DENIED

        # 3. Redirects -> Check if login redirect vs normal redirect
        if resp.status_code in (301, 302, 303, 307, 308):
            loc = (resp.headers.get("location") or "").lower()
            if any(term in loc for term in ("/login", "/auth", "/signin", "/sso", "login.")):
                return CorrelationLifecycle.AUTHENTICATION_FAILED
            return CorrelationLifecycle.UNKNOWN

        # 4. Check for inline login forms or WAF challenges on 200 OK
        if AuthenticationFalsePositiveClassifier.is_login_page_false_positive(resp.status_code, resp.body_text):
            return CorrelationLifecycle.AUTHENTICATION_FAILED

        if AuthenticationFalsePositiveClassifier.is_waf_or_challenge_page(resp.status_code, resp.body_text):
            return CorrelationLifecycle.UNKNOWN

        # Check for public landing, generic shell, or empty status responses
        if AuthenticationFalsePositiveClassifier.is_public_landing_or_generic_shell(resp.status_code, resp.body_text):
            return CorrelationLifecycle.UNKNOWN
        if AuthenticationFalsePositiveClassifier.is_generic_status_or_empty_response(resp.status_code, resp.body_text):
            return CorrelationLifecycle.UNKNOWN

        # Empty body rejection
        if not resp.body_text or not resp.body_text.strip() or resp.body_text.strip() in ("{}", "[]", '""', "null"):
            return CorrelationLifecycle.UNKNOWN

        # 5. Anonymous differential comparison / public landing shell verification
        if anon_resp is not None:
            # A failed anonymous control must not silently be interpreted as a successful control
            if anon_resp.status_code >= 500:
                return CorrelationLifecycle.FAILED

            if anon_resp.status_code == 200:
                if AuthenticationFalsePositiveClassifier.is_public_landing_or_generic_shell(anon_resp.status_code, anon_resp.body_text):
                    return CorrelationLifecycle.UNKNOWN
                if resp.body_text.strip() == anon_resp.body_text.strip():
                    return CorrelationLifecycle.UNKNOWN
                ratio = difflib.SequenceMatcher(None, anon_resp.body_text, resp.body_text).ratio()
                if ratio > 0.70:
                    return CorrelationLifecycle.UNKNOWN

        # 6. 200 OK with authentic protected data
        if resp.status_code == 200:
            return CorrelationLifecycle.VERIFIED

        if resp.status_code >= 500:
            return CorrelationLifecycle.FAILED

        return CorrelationLifecycle.UNKNOWN

    def validate_session_pair(
        self,
        context_a: CorrelatedSessionContext,
        context_b: CorrelatedSessionContext,
        preflight_url: str,
        principal_a: Optional[CorrelatedPrincipalContext] = None,
        principal_b: Optional[CorrelatedPrincipalContext] = None,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Executes deterministic sequential preflight protocol across session pair:
        1. Probe 1 (Principal A authenticated request)
        2. Probe 2 (Principal B authenticated request)
        3. Probe 3 (Anonymous control request)
        4. Differential classification with anonymous control input.
        Short-circuits immediately if Probe 1 or Probe 2 fails with authentication/authorization failure.
        """
        details: Dict[str, Any] = {}

        # ----------------------------------------------------------------------
        # Probe 1: Principal A
        # ----------------------------------------------------------------------
        req_a = ControlledRequest(
            url=preflight_url,
            method="GET",
            headers=dict(context_a.volatile_headers),
        )
        try:
            resp_a = self.engine.send_request(req_a)
        except Exception as e:
            context_a.lifecycle = CorrelationLifecycle.FAILED
            context_b.lifecycle = CorrelationLifecycle.FAILED
            return False, "FAILED", {"probe": "probe_1", "error": str(e)}

        details["probe_1"] = resp_a

        # Sequential short-circuit check: Probe 1 must not be expired, unauthenticated, or forbidden
        initial_lc_a = self.classify_probe_response(resp_a)
        if initial_lc_a in (
            CorrelationLifecycle.EXPIRED,
            CorrelationLifecycle.AUTHENTICATION_FAILED,
            CorrelationLifecycle.AUTHORIZATION_DENIED,
            CorrelationLifecycle.FAILED,
        ):
            context_a.lifecycle = initial_lc_a
            context_b.lifecycle = CorrelationLifecycle.FAILED
            return False, "SESSION_HEALTH_FAILED", {
                "failed_probe": "probe_1",
                "status_code": resp_a.status_code,
                "lifecycle": initial_lc_a.value,
            }

        # ----------------------------------------------------------------------
        # Probe 2: Principal B
        # ----------------------------------------------------------------------
        req_b = ControlledRequest(
            url=preflight_url,
            method="GET",
            headers=dict(context_b.volatile_headers),
        )
        try:
            resp_b = self.engine.send_request(req_b)
        except Exception as e:
            context_b.lifecycle = CorrelationLifecycle.FAILED
            return False, "SESSION_HEALTH_FAILED", {"probe": "probe_2", "error": str(e)}

        details["probe_2"] = resp_b

        # Sequential short-circuit check: Probe 2 must not be expired, unauthenticated, or forbidden
        initial_lc_b = self.classify_probe_response(resp_b)
        if initial_lc_b in (
            CorrelationLifecycle.EXPIRED,
            CorrelationLifecycle.AUTHENTICATION_FAILED,
            CorrelationLifecycle.AUTHORIZATION_DENIED,
            CorrelationLifecycle.FAILED,
        ):
            context_b.lifecycle = initial_lc_b
            return False, "SESSION_HEALTH_FAILED", {
                "failed_probe": "probe_2",
                "status_code": resp_b.status_code,
                "lifecycle": initial_lc_b.value,
            }

        # ----------------------------------------------------------------------
        # Probe 3: Anonymous Control
        # ----------------------------------------------------------------------
        try:
            resp_anon = self.probe_anonymous_control(preflight_url)
        except Exception as e:
            context_a.lifecycle = CorrelationLifecycle.FAILED
            context_b.lifecycle = CorrelationLifecycle.FAILED
            return False, "SESSION_HEALTH_FAILED", {"failed_probe": "probe_3", "error": str(e), "lifecycle": "FAILED"}

        details["probe_3"] = resp_anon

        # A failed anonymous control must not silently be interpreted as a successful control
        if resp_anon.status_code >= 500:
            context_a.lifecycle = CorrelationLifecycle.FAILED
            context_b.lifecycle = CorrelationLifecycle.FAILED
            return False, "SESSION_HEALTH_FAILED", {
                "failed_probe": "probe_3",
                "status_code": resp_anon.status_code,
                "reason": "Anonymous control probe failed with server error",
                "lifecycle": "FAILED",
            }

        # ----------------------------------------------------------------------
        # Differential Classification using Anonymous Control Input
        # ----------------------------------------------------------------------
        lc_a = self.classify_probe_response(resp_a, anon_resp=resp_anon)
        if lc_a != CorrelationLifecycle.VERIFIED:
            context_a.lifecycle = lc_a
            context_b.lifecycle = CorrelationLifecycle.UNKNOWN if lc_a == CorrelationLifecycle.UNKNOWN else CorrelationLifecycle.FAILED
            return False, "SESSION_HEALTH_FAILED", {
                "failed_probe": "probe_1",
                "status_code": resp_a.status_code,
                "lifecycle": lc_a.value,
                "reason": "Authenticated response A failed differential or verification criteria",
            }

        lc_b = self.classify_probe_response(resp_b, anon_resp=resp_anon)
        if lc_b != CorrelationLifecycle.VERIFIED:
            context_b.lifecycle = lc_b
            return False, "SESSION_HEALTH_FAILED", {
                "failed_probe": "probe_2",
                "status_code": resp_b.status_code,
                "lifecycle": lc_b.value,
                "reason": "Authenticated response B failed differential or verification criteria",
            }

        # Additional Differential Cross-Check against Anonymous Response
        if resp_anon.status_code == 200:
            if resp_a.body_text.strip() == resp_anon.body_text.strip() or resp_b.body_text.strip() == resp_anon.body_text.strip():
                context_a.lifecycle = CorrelationLifecycle.UNKNOWN
                context_b.lifecycle = CorrelationLifecycle.UNKNOWN
                return False, "SESSION_HEALTH_FAILED", {
                    "failed_probe": "probe_3",
                    "lifecycle": "UNKNOWN",
                    "reason": "Authenticated response identical to anonymous control",
                }

            ratio_a = difflib.SequenceMatcher(None, resp_anon.body_text, resp_a.body_text).ratio()
            ratio_b = difflib.SequenceMatcher(None, resp_anon.body_text, resp_b.body_text).ratio()
            is_shell_a = AuthenticationFalsePositiveClassifier.is_public_landing_or_generic_shell(resp_a.status_code, resp_a.body_text)
            is_shell_b = AuthenticationFalsePositiveClassifier.is_public_landing_or_generic_shell(resp_b.status_code, resp_b.body_text)
            if ratio_a > 0.70 or ratio_b > 0.70 or is_shell_a or is_shell_b:
                context_a.lifecycle = CorrelationLifecycle.UNKNOWN
                context_b.lifecycle = CorrelationLifecycle.UNKNOWN
                return False, "SESSION_HEALTH_FAILED", {
                    "failed_probe": "probe_3",
                    "lifecycle": "UNKNOWN",
                    "reason": "Anonymous response matches authenticated profile (public endpoint / SPA shell)",
                }

        # Check for caching artifacts
        cache_a = self._assess_cache_headers(resp_a)
        cache_b = self._assess_cache_headers(resp_b)
        if cache_a == "CACHE_CONFIRMED" or cache_b == "CACHE_CONFIRMED":
            details["cache_warning"] = "CACHE_CONFIRMED"

        # Verification successful: update lifecycles
        context_a.lifecycle = CorrelationLifecycle.VERIFIED
        context_b.lifecycle = CorrelationLifecycle.VERIFIED
        context_a.verified_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        context_b.verified_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        return True, "VERIFIED", details

    def validate_single_session(
        self,
        session_ctx: CorrelatedSessionContext,
        preflight_url: str,
        principal_ctx: Optional[CorrelatedPrincipalContext] = None,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Validates health and distinct authenticated behavior for a single session."""
        req = ControlledRequest(
            url=preflight_url,
            method="GET",
            headers=dict(session_ctx.volatile_headers),
        )
        try:
            resp = self.engine.send_request(req)
        except Exception as e:
            session_ctx.lifecycle = CorrelationLifecycle.FAILED
            return False, "FAILED", {"error": str(e)}

        initial_lc = self.classify_probe_response(resp)
        if initial_lc in (
            CorrelationLifecycle.EXPIRED,
            CorrelationLifecycle.AUTHENTICATION_FAILED,
            CorrelationLifecycle.AUTHORIZATION_DENIED,
            CorrelationLifecycle.FAILED,
        ):
            session_ctx.lifecycle = initial_lc
            return False, "SESSION_HEALTH_FAILED", {"status_code": resp.status_code, "lifecycle": initial_lc.value}

        try:
            resp_anon = self.probe_anonymous_control(preflight_url)
        except Exception as e:
            session_ctx.lifecycle = CorrelationLifecycle.FAILED
            return False, "SESSION_HEALTH_FAILED", {"error": str(e), "lifecycle": "FAILED"}

        if resp_anon.status_code >= 500:
            session_ctx.lifecycle = CorrelationLifecycle.FAILED
            return False, "SESSION_HEALTH_FAILED", {
                "status_code": resp_anon.status_code,
                "reason": "Anonymous probe failed with server error",
                "lifecycle": "FAILED",
            }

        lc = self.classify_probe_response(resp, anon_resp=resp_anon)
        if lc != CorrelationLifecycle.VERIFIED:
            session_ctx.lifecycle = lc
            return False, "SESSION_HEALTH_FAILED", {"status_code": resp.status_code, "lifecycle": lc.value}

        if resp_anon.status_code == 200:
            if resp.body_text.strip() == resp_anon.body_text.strip():
                session_ctx.lifecycle = CorrelationLifecycle.UNKNOWN
                return False, "SESSION_HEALTH_FAILED", {"reason": "Public endpoint / SPA shell", "lifecycle": "UNKNOWN"}
            ratio = difflib.SequenceMatcher(None, resp_anon.body_text, resp.body_text).ratio()
            if ratio > 0.70:
                session_ctx.lifecycle = CorrelationLifecycle.UNKNOWN
                return False, "SESSION_HEALTH_FAILED", {"reason": "Public endpoint / SPA shell", "lifecycle": "UNKNOWN"}

        session_ctx.lifecycle = CorrelationLifecycle.VERIFIED
        session_ctx.verified_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return True, "VERIFIED", {"response": resp}
