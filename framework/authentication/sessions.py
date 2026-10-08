"""
Session Lifecycle & Security Intelligence Engine (Phase 14).

Analyzes session identifiers, token rotation, session fixation, logout invalidation,
password-change invalidation, and cookie security flags.
Never stores raw cookie secrets or credentials; hashes or masks session tokens for safe tracking.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple

from framework.authentication.models import (
    AuthenticationFindingFamily,
    AuthenticationState,
    SessionLifecycle,
    SessionProfile,
)


class SessionAnalyzer:
    """Performs structural and lifecycle security analysis on session identifiers."""

    @staticmethod
    def mask_or_hash_session(raw_token: str) -> str:
        """
        Creates a deterministic redacted fingerprint for a session token.
        Never persists raw tokens.
        """
        if not raw_token:
            return "sess_empty"
        digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()[:12]
        return f"sess_sha256_{digest}"

    @staticmethod
    def parse_cookie_attributes(cookie_header: str) -> Dict[str, Any]:
        """
        Parses Set-Cookie header strings into cookie name and security attributes.
        Returns cookie name and boolean attributes: secure, httponly, samesite.
        """
        attrs: Dict[str, Any] = {
            "name": "",
            "is_secure": False,
            "is_httponly": False,
            "samesite": "None",
            "path": "/",
            "domain": "",
        }
        if not cookie_header:
            return attrs

        parts = [p.strip() for p in cookie_header.split(";")]
        if parts:
            first_part = parts[0]
            if "=" in first_part:
                attrs["name"] = first_part.split("=")[0].strip()

        for part in parts[1:]:
            lower_part = part.lower()
            if lower_part == "secure":
                attrs["is_secure"] = True
            elif lower_part == "httponly":
                attrs["is_httponly"] = True
            elif lower_part.startswith("samesite"):
                if "=" in part:
                    attrs["samesite"] = part.split("=")[1].strip()
                else:
                    attrs["samesite"] = "Lax"
            elif lower_part.startswith("path="):
                attrs["path"] = part[5:].strip()
            elif lower_part.startswith("domain="):
                attrs["domain"] = part[7:].strip()

        return attrs

    @classmethod
    def evaluate_session_fixation(
        cls,
        session_id_pre: str,
        session_id_post: str,
        state_after_login: AuthenticationState,
    ) -> Tuple[bool, str]:
        """
        Evaluates potential session fixation.
        Returns (is_vulnerable, rationale).
        Condition: same session identifier survives across authentication boundary AND grants authenticated state.
        """
        if not session_id_pre or not session_id_post:
            return False, "Missing pre or post session identifier for fixation evaluation"

        if session_id_pre == session_id_post:
            if state_after_login in (AuthenticationState.AUTHENTICATED, AuthenticationState.MFA_VERIFIED):
                return (
                    True,
                    f"Session identifier '{session_id_pre}' survived authentication transition from anonymous to {state_after_login.value} without rotation, demonstrating session fixation.",
                )
            return (
                False,
                "Session identifier unchanged, but target did not reach authenticated state.",
            )
        return False, "Session identifier correctly rotated upon authentication."

    @classmethod
    def evaluate_session_invalidation(
        cls,
        session_id: str,
        status_code: int,
        response_body: str,
        action_name: str = "logout",
    ) -> Tuple[bool, str]:
        """
        Evaluates whether a session remains active after an invalidating event (logout, password change, reset).
        Returns (is_vulnerable, rationale).
        """
        # If response indicates continued authenticated access (HTTP 200 with user profile/data)
        # rather than 401 Unauthorized or 403 Forbidden or redirect to login
        is_success = status_code in (200, 201)
        lower_body = response_body.lower()

        # Check if body contains indicators of authentication failure or redirection
        login_prompt = any(term in lower_body for term in ["login", "sign in", "unauthorized", "expired", "invalid session"])

        if is_success and not login_prompt:
            return (
                True,
                f"Session '{session_id}' remained active with HTTP {status_code} after {action_name}. The server failed to invalidate the server-side session.",
            )

        return (
            False,
            f"Session correctly invalidated or rejected (HTTP {status_code}) after {action_name}.",
        )

    @classmethod
    def evaluate_session_rotation(
        cls,
        session_id_before: str,
        session_id_after: str,
        transition_name: str = "privilege elevation",
    ) -> Tuple[bool, str]:
        """
        Inspects session identifier rotation across a privilege boundary.
        """
        if not session_id_before or not session_id_after:
            return False, "Insufficient session identifiers to evaluate rotation"

        if session_id_before == session_id_after:
            return (
                True,
                f"Session identifier was not rotated across {transition_name}.",
            )
        return False, f"Session identifier rotated successfully across {transition_name}."
