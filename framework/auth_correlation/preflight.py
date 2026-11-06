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

    def validate_session_pair(
        self,
        context_a: CorrelatedSessionContext,
        context_b: CorrelatedSessionContext,
        preflight_url: str,
        principal_a: Optional[CorrelatedPrincipalContext] = None,
        principal_b: Optional[CorrelatedPrincipalContext] = None,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Executes deterministic sequential preflight protocol across session pair.
        Short-circuits immediately if Probe 1 or Probe 2 fails.
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
            return False, "SESSION_HEALTH_FAILED", {"probe": "probe_1", "error": str(e)}

        details["probe_1"] = resp_a
        if resp_a.status_code != 200 or AuthenticationFalsePositiveClassifier.is_login_page_false_positive(resp_a.status_code, resp_a.body_text):
            context_a.lifecycle = CorrelationLifecycle.EXPIRED if resp_a.status_code in (401, 403) else CorrelationLifecycle.FAILED
            context_b.lifecycle = CorrelationLifecycle.FAILED
            return False, "SESSION_HEALTH_FAILED", {"failed_probe": "probe_1", "status_code": resp_a.status_code}

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
        if resp_b.status_code != 200 or AuthenticationFalsePositiveClassifier.is_login_page_false_positive(resp_b.status_code, resp_b.body_text):
            context_b.lifecycle = CorrelationLifecycle.EXPIRED if resp_b.status_code in (401, 403) else CorrelationLifecycle.FAILED
            return False, "SESSION_HEALTH_FAILED", {"failed_probe": "probe_2", "status_code": resp_b.status_code}

        # ----------------------------------------------------------------------
        # Probe 3: Anonymous Control
        # ----------------------------------------------------------------------
        try:
            resp_anon = self.probe_anonymous_control(preflight_url)
        except Exception as e:
            return False, "SESSION_HEALTH_FAILED", {"probe": "probe_3", "error": str(e)}

        details["probe_3"] = resp_anon

        # ----------------------------------------------------------------------
        # Differential Validation
        # ----------------------------------------------------------------------
        # Anonymous response must not yield 200 OK with identical authenticated content
        if resp_anon.status_code == 200:
            if not AuthenticationFalsePositiveClassifier.is_login_page_false_positive(resp_anon.status_code, resp_anon.body_text):
                ratio_a = difflib.SequenceMatcher(None, resp_anon.body_text, resp_a.body_text).ratio()
                ratio_b = difflib.SequenceMatcher(None, resp_anon.body_text, resp_b.body_text).ratio()
                if ratio_a > 0.70 or ratio_b > 0.70:
                    context_a.lifecycle = CorrelationLifecycle.UNKNOWN
                    context_b.lifecycle = CorrelationLifecycle.UNKNOWN
                    return False, "SESSION_HEALTH_FAILED", {
                        "failed_probe": "probe_3",
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
            return False, "SESSION_HEALTH_FAILED", {"error": str(e)}

        if resp.status_code != 200 or AuthenticationFalsePositiveClassifier.is_login_page_false_positive(resp.status_code, resp.body_text):
            session_ctx.lifecycle = CorrelationLifecycle.EXPIRED if resp.status_code in (401, 403) else CorrelationLifecycle.FAILED
            return False, "SESSION_HEALTH_FAILED", {"status_code": resp.status_code}

        resp_anon = self.probe_anonymous_control(preflight_url)
        if resp_anon.status_code == 200:
            ratio = difflib.SequenceMatcher(None, resp_anon.body_text, resp.body_text).ratio()
            if ratio > 0.70:
                session_ctx.lifecycle = CorrelationLifecycle.UNKNOWN
                return False, "SESSION_HEALTH_FAILED", {"reason": "Public endpoint / SPA shell"}

        session_ctx.lifecycle = CorrelationLifecycle.VERIFIED
        session_ctx.verified_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return True, "VERIFIED", {"response": resp}
