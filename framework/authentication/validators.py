"""
Safe Validation & False Positive Reduction Engine (Phase 14).

Performs controlled differential analysis between anonymous and authenticated requests,
evaluates session lifecycles, and actively eliminates non-vulnerabilities.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from framework.authentication.models import (
    AccountEnumerationSignal,
    AuthenticationFindingFamily,
    AuthenticationState,
    HypothesisValidationStatus,
    MFAState,
)
from framework.authentication.mfa import MFAAnalyzer
from framework.authentication.password_reset import PasswordResetAnalyzer
from framework.authentication.sessions import SessionAnalyzer
from framework.authentication.tokens import TokenAnalyzer


class AuthenticationFalsePositiveClassifier:
    """Actively eliminates false positives and normal application behaviors."""

    @staticmethod
    def is_login_page_false_positive(status_code: int, response_body: str) -> bool:
        """
        Detects if an HTTP 200 response on an authentication endpoint is merely
        a public login page, registration form, or documentation rather than a bypass.
        """
        if status_code != 200:
            return False

        lower_body = response_body.lower()
        form_indicators = [
            "<form", "type=\"password\"", "name=\"password\"", "login to your account",
            "sign in to continue", "please log in", "enter credentials", "oauth/authorize"
        ]
        return any(ind in lower_body for ind in form_indicators)

    @staticmethod
    def is_normal_access_control(
        anon_status: int,
        auth_status: int,
    ) -> bool:
        """
        Detects expected normal access control (Anonymous 401/403 -> Authenticated 200).
        This is proper security, NEVER a vulnerability.
        """
        return anon_status in (401, 403) and auth_status in (200, 201)

    @staticmethod
    def is_cookie_flag_false_positive(cookie_attrs: Dict[str, Any], is_sensitive: bool = False) -> bool:
        """
        Cookie flag absence alone (Secure/HttpOnly/SameSite) is NOT automatically a vulnerability.
        Especially on non-sensitive cookies (e.g. tracking, theme, language).
        """
        return not is_sensitive


class SafeAuthenticationValidator:
    """Executes safe differential validation and verifies authentication hypotheses."""

    @classmethod
    def validate_authentication_bypass(
        cls,
        endpoint: str,
        anon_status: int,
        anon_body: str,
        auth_status: int,
        auth_body: str,
    ) -> Tuple[HypothesisValidationStatus, str]:
        """
        Validates whether a protected endpoint is accessible unauthenticated.
        Enforces false positive filtering: HTTP 200 login forms or public assets are rejected.
        """
        # If anonymous response is 401/403 and auth is 200, this is normal access control
        if AuthenticationFalsePositiveClassifier.is_normal_access_control(anon_status, auth_status):
            return (
                HypothesisValidationStatus.REJECTED,
                f"Endpoint '{endpoint}' correctly enforces authentication (Anonymous HTTP {anon_status} vs Authenticated HTTP {auth_status}).",
            )

        # If anonymous response is 200, check if it's merely a public login page or docs
        if AuthenticationFalsePositiveClassifier.is_login_page_false_positive(anon_status, anon_body):
            return (
                HypothesisValidationStatus.REJECTED,
                f"Endpoint '{endpoint}' returned HTTP 200 containing a public login/sign-in interface, not a protected resource bypass.",
            )

        # If anonymous response returns HTTP 200 with substantial protected data matching authenticated response
        if anon_status in (200, 201) and len(anon_body) > 30:
            # Check for sensitive account/user indicators
            lower_body = anon_body.lower()
            sensitive_indicators = ["email", "user_id", "account", "profile", "admin", "tenant", "roles", "balance"]
            if any(ind in lower_body for ind in sensitive_indicators):
                return (
                    HypothesisValidationStatus.VALIDATED,
                    f"Protected endpoint '{endpoint}' returned HTTP {anon_status} with sensitive user/account content without authentication challenge.",
                )

        return (
            HypothesisValidationStatus.REJECTED,
            f"Endpoint '{endpoint}' did not expose protected data without authentication.",
        )

    @classmethod
    def validate_pre_mfa_exposure(
        cls,
        endpoint: str,
        mfa_status: int,
        mfa_body: str,
        verified_status: int,
        verified_body: str,
    ) -> Tuple[HypothesisValidationStatus, str]:
        """Validates pre-MFA privilege exposure on sensitive endpoints."""
        is_vuln, reason = MFAAnalyzer.evaluate_pre_mfa_exposure(
            endpoint=endpoint,
            session_mfa_state=MFAState.REQUIRED,
            status_code=mfa_status,
            response_body=mfa_body,
        )
        if is_vuln:
            return HypothesisValidationStatus.VALIDATED, reason
        return HypothesisValidationStatus.REJECTED, reason

    @classmethod
    def validate_session_invalidation(
        cls,
        endpoint: str,
        session_id: str,
        post_logout_status: int,
        post_logout_body: str,
        action_name: str = "logout",
    ) -> Tuple[HypothesisValidationStatus, str]:
        """Validates whether a session was properly invalidated post-logout or post-password change."""
        is_vuln, reason = SessionAnalyzer.evaluate_session_invalidation(
            session_id=session_id,
            status_code=post_logout_status,
            response_body=post_logout_body,
            action_name=action_name,
        )
        if is_vuln:
            return HypothesisValidationStatus.VALIDATED, reason
        return HypothesisValidationStatus.REJECTED, reason

    @classmethod
    def validate_session_fixation(
        cls,
        session_pre: str,
        session_post: str,
        state_post: AuthenticationState,
    ) -> Tuple[HypothesisValidationStatus, str]:
        """Validates session fixation across authentication boundaries."""
        is_vuln, reason = SessionAnalyzer.evaluate_session_fixation(
            session_id_pre=session_pre,
            session_id_post=session_post,
            state_after_login=state_post,
        )
        if is_vuln:
            return HypothesisValidationStatus.VALIDATED, reason
        return HypothesisValidationStatus.REJECTED, reason

    @classmethod
    def validate_reset_token_reuse(
        cls,
        first_status: int,
        first_body: str,
        second_status: int,
        second_body: str,
    ) -> Tuple[HypothesisValidationStatus, str]:
        """Validates password reset token one-time use."""
        is_vuln, reason = PasswordResetAnalyzer.evaluate_token_reuse(
            first_status=first_status,
            first_body=first_body,
            second_status=second_status,
            second_body=second_body,
        )
        if is_vuln:
            return HypothesisValidationStatus.VALIDATED, reason
        return HypothesisValidationStatus.REJECTED, reason

    @classmethod
    def validate_refresh_token_reuse(
        cls,
        first_status: int,
        second_status: int,
        second_body: str,
    ) -> Tuple[HypothesisValidationStatus, str]:
        """Validates refresh token rotation and reuse prevention."""
        is_vuln, reason = TokenAnalyzer.evaluate_refresh_token_reuse(
            status_first_use=first_status,
            status_second_use=second_status,
            response_second_use=second_body,
        )
        if is_vuln:
            return HypothesisValidationStatus.VALIDATED, reason
        return HypothesisValidationStatus.REJECTED, reason

    @classmethod
    def validate_account_enumeration(
        cls,
        valid_status: int,
        valid_body: str,
        invalid_status: int,
        invalid_body: str,
        valid_redirect: Optional[str] = None,
        invalid_redirect: Optional[str] = None,
    ) -> Tuple[HypothesisValidationStatus, str]:
        """Validates account enumeration differential signals."""
        signal, reason = PasswordResetAnalyzer.analyze_account_enumeration(
            valid_user_status=valid_status,
            valid_user_body=valid_body,
            invalid_user_status=invalid_status,
            invalid_user_body=invalid_body,
            valid_user_redirect=valid_redirect,
            invalid_user_redirect=invalid_redirect,
        )
        if signal == AccountEnumerationSignal.STRONG_ENUMERATION_SIGNAL:
            return HypothesisValidationStatus.VALIDATED, reason
        elif signal == AccountEnumerationSignal.WEAK_ENUMERATION_SIGNAL:
            return HypothesisValidationStatus.INFORMATIONAL, reason
        return HypothesisValidationStatus.REJECTED, reason
