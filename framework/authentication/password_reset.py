"""
Password Reset & Account Enumeration Intelligence Engine (Phase 14).

Models password-reset lifecycles, reset-token reuse, reset-token expiration,
and differential account enumeration signals.
Strictly non-destructive: zero credential stuffing, zero token brute-forcing,
and zero email flooding to unauthorized third-party addresses.
"""

from __future__ import annotations

import difflib
from typing import Any, Dict, List, Optional, Tuple

from framework.authentication.models import (
    AccountEnumerationSignal,
    PasswordResetFlow,
)


class PasswordResetAnalyzer:
    """Analyzes password reset token lifecycles and differential enumeration signals."""

    @classmethod
    def evaluate_token_reuse(
        cls,
        first_status: int,
        first_body: str,
        second_status: int,
        second_body: str,
    ) -> Tuple[bool, str]:
        """
        Evaluates whether a password reset token can be consumed more than once.
        Returns (is_vulnerable, rationale).
        """
        # If second reset attempt also succeeded (e.g., 200 OK or 302 redirect without error)
        is_first_success = first_status in (200, 201, 302)
        is_second_success = second_status in (200, 201, 302)
        second_error = any(e in second_body.lower() for e in ["expired", "invalid", "already used", "token error", "unauthorized"])

        if is_first_success and is_second_success and not second_error:
            return (
                True,
                f"Password reset token was accepted for multiple password updates (HTTP {second_status}), demonstrating token reuse vulnerability.",
            )

        return (
            False,
            f"Reset token reuse correctly rejected on second attempt (HTTP {second_status}).",
        )

    @classmethod
    def evaluate_token_expiration(
        cls,
        expired_status: int,
        expired_body: str,
    ) -> Tuple[bool, str]:
        """
        Evaluates whether an intentionally expired reset token is properly rejected.
        """
        is_success = expired_status in (200, 201, 302)
        has_error = any(e in expired_body.lower() for e in ["expired", "invalid", "token error", "unauthorized"])

        if is_success and not has_error:
            return (
                True,
                f"Expired password reset token was accepted by endpoint (HTTP {expired_status}). Server fails to enforce token expiration bounds.",
            )

        return (
            False,
            f"Expired reset token was correctly rejected (HTTP {expired_status}).",
        )

    @classmethod
    def analyze_account_enumeration(
        cls,
        valid_user_status: int,
        valid_user_body: str,
        invalid_user_status: int,
        invalid_user_body: str,
        valid_user_redirect: Optional[str] = None,
        invalid_user_redirect: Optional[str] = None,
    ) -> Tuple[AccountEnumerationSignal, str]:
        """
        Performs controlled differential comparison between responses for existing
        vs non-existent accounts on password-reset / login endpoints.
        """
        status_diff = valid_user_status != invalid_user_status
        redirect_diff = (valid_user_redirect or "") != (invalid_user_redirect or "")
        len_diff = abs(len(valid_user_body) - len(invalid_user_body))

        # Check explicit text indicators
        lower_valid = valid_user_body.lower()
        lower_invalid = invalid_user_body.lower()

        explicit_found = any(s in lower_valid for s in ["email sent", "instructions sent", "check your inbox", "reset link sent"])
        explicit_not_found = any(s in lower_invalid for s in ["user not found", "no account exists", "invalid user", "unknown account", "does not exist"])

        if status_diff or (explicit_found and explicit_not_found) or redirect_diff:
            return (
                AccountEnumerationSignal.STRONG_ENUMERATION_SIGNAL,
                f"Definitive differential response observed: Status ({valid_user_status} vs {invalid_user_status}), "
                f"Redirect ('{valid_user_redirect}' vs '{invalid_user_redirect}'), or distinct error messages exposing account existence.",
            )

        if len_diff > 100:
            return (
                AccountEnumerationSignal.WEAK_ENUMERATION_SIGNAL,
                f"Noticeable response length divergence ({len(valid_user_body)} bytes vs {len(invalid_user_body)} bytes) without explicit textual leak.",
            )

        return (
            AccountEnumerationSignal.NO_ENUMERATION_SIGNAL,
            "Uniform response returned for both valid and invalid accounts; no enumeration signal observed.",
        )
