"""
Multi-Factor Authentication (MFA) Intelligence Engine (Phase 14).

Models MFA state machines, pre-MFA authorization boundaries, factor verification,
and recovery flow interactions.
Enforces strict safety: zero OTP brute forcing, zero OTP flooding, and zero automated CAPTCHA bypasses.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from framework.authentication.models import (
    AuthenticationFindingFamily,
    AuthenticationState,
    MFAState,
)


class MFAAnalyzer:
    """Evaluates MFA state transitions and pre-MFA authorization enforcement."""

    @classmethod
    def evaluate_pre_mfa_exposure(
        cls,
        endpoint: str,
        session_mfa_state: MFAState,
        status_code: int,
        response_body: str,
    ) -> Tuple[bool, str]:
        """
        Evaluates whether a sensitive resource is accessible prior to MFA completion.
        Returns (is_vulnerable, rationale).
        """
        # If session has MFA REQUIRED or CHALLENGE_ACTIVE (pre-MFA), but protected endpoint returns 200 with sensitive content
        if session_mfa_state in (MFAState.REQUIRED, MFAState.CHALLENGE_ACTIVE):
            is_success = status_code in (200, 201)
            lower_body = response_body.lower()
            mfa_challenge_prompt = any(t in lower_body for t in ["enter code", "otp", "two-factor", "2fa", "verify identity", "challenge"])

            if is_success and not mfa_challenge_prompt:
                # Sensitive account response received prior to completing MFA
                return (
                    True,
                    f"Sensitive endpoint '{endpoint}' returned HTTP {status_code} with account data while session was in pre-MFA state ({session_mfa_state.value}). MFA enforcement is bypassed at the API layer.",
                )

        return (
            False,
            f"Pre-MFA access correctly blocked or prompted for MFA verification (HTTP {status_code}).",
        )

    @classmethod
    def evaluate_mfa_factor_verification(
        cls,
        status_code: int,
        response_body: str,
        submitted_valid_code: bool,
    ) -> Tuple[bool, str]:
        """
        Evaluates whether an MFA verification endpoint properly validates the provided challenge.
        """
        is_success = status_code in (200, 201, 302)
        lower_body = response_body.lower()
        error_indicated = any(e in lower_body for e in ["invalid", "incorrect", "expired", "failed", "unauthorized"])

        if not submitted_valid_code and is_success and not error_indicated:
            return (
                True,
                f"MFA challenge endpoint accepted invalid verification token (HTTP {status_code}), demonstrating MFA verification bypass.",
            )

        return (
            False,
            "MFA verification behaved as expected for the submitted factor.",
        )
