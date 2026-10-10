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
            "<form", "type=\"password\"", "type='password'", "name=\"password\"", "name='password'",
            "login to your account", "sign in to continue", "please log in", "enter credentials",
            "oauth/authorize", "user-login", "auth-form", "signin",
        ]
        return any(ind in lower_body for ind in form_indicators)

    @staticmethod
    def is_waf_or_challenge_page(status_code: int, response_body: str) -> bool:
        """Detects if response is a WAF challenge, Cloudflare block, or bot detection page."""
        lower_body = response_body.lower()
        waf_indicators = [
            "cf-ray", "cloudflare", "access denied", "attention required",
            "recaptcha", "hcaptcha", "ddos protection", "incident id",
            "request blocked", "security challenge", "bot detection",
        ]
        return any(ind in lower_body for ind in waf_indicators)

    @staticmethod
    def is_public_landing_or_generic_shell(status_code: int, response_body: str) -> bool:
        """
        Detects if response is a generic public SPA application shell, landing page,
        or documentation page without user-specific protected data.
        """
        if status_code != 200:
            return False
        lower_body = response_body.lower().strip()
        shell_indicators = [
            '<div id="root"></div>', '<div id="app"></div>', '<div id="__next"></div>',
            "<!doctype html>", "<html",
        ]
        is_html = any(ind in lower_body for ind in shell_indicators)
        if not is_html:
            return False

        # If it's HTML, check if it's merely a shell without authenticated user payload
        has_user_payload = any(k in lower_body for k in [
            '"user_id"', '"account_id"', '"email"', 'user-profile', 'dashboard-content',
            'account balance', 'user details',
        ])
        return not has_user_payload

    @staticmethod
    def is_generic_status_or_empty_response(status_code: int, response_body: str) -> bool:
        """
        Detects generic JSON or text status responses (e.g., {"status": "ok"}, health checks)
        that do not contain protected user/account data.
        """
        cleaned = response_body.strip()
        if not cleaned or len(cleaned) < 5:
            return True

        lower_body = cleaned.lower()
        generic_literals = [
            '{"status":"ok"}', '{"status": "ok"}', '{"status":"success"}', '{"status": "success"}',
            '{"success":true}', '{"success": true}', '{"healthy":true}', '{"healthy": true}',
            '{"message":"pong"}', '{"message": "pong"}', 'ok', 'pong',
        ]
        if lower_body in generic_literals:
            return True

        try:
            import json
            obj = json.loads(cleaned)
            if isinstance(obj, dict):
                keys = set(str(k).lower() for k in obj.keys())
                user_keys = {"user_id", "id", "email", "username", "account", "profile", "admin", "tenant", "roles", "balance"}
                if not (keys & user_keys) and keys.issubset({"status", "success", "version", "message", "timestamp", "code", "alive"}):
                    return True
        except Exception:
            pass

        return False

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
        Validates whether a protected endpoint is genuinely accessible unauthenticated.
        Requires authenticated baseline context; compares protected response content,
        authorization state, and security invariants.
        Actively eliminates login pages, generic HTML shells, and status false positives.
        """
        # 1. Normal access control check
        if AuthenticationFalsePositiveClassifier.is_normal_access_control(anon_status, auth_status):
            return (
                HypothesisValidationStatus.REJECTED,
                f"Endpoint '{endpoint}' correctly enforces access control (Anonymous HTTP {anon_status} vs Authenticated HTTP {auth_status}).",
            )

        # 2. Both unauthenticated or error
        if anon_status not in (200, 201) and auth_status not in (200, 201):
            return (
                HypothesisValidationStatus.REJECTED,
                f"Endpoint '{endpoint}' did not grant access (Anonymous HTTP {anon_status}, Authenticated HTTP {auth_status}).",
            )

        # 3. Reject negative controls: login pages, WAF challenges, shells, and generic status responses
        if AuthenticationFalsePositiveClassifier.is_login_page_false_positive(anon_status, anon_body):
            return (
                HypothesisValidationStatus.REJECTED,
                f"Endpoint '{endpoint}' returned HTTP {anon_status} displaying a public login/sign-in interface, not a protected resource bypass.",
            )

        if AuthenticationFalsePositiveClassifier.is_waf_or_challenge_page(anon_status, anon_body):
            return (
                HypothesisValidationStatus.REJECTED,
                f"Endpoint '{endpoint}' returned WAF challenge or block page.",
            )

        if AuthenticationFalsePositiveClassifier.is_public_landing_or_generic_shell(anon_status, anon_body):
            return (
                HypothesisValidationStatus.REJECTED,
                f"Endpoint '{endpoint}' returned public static shell or landing page without user-specific protected data.",
            )

        if AuthenticationFalsePositiveClassifier.is_generic_status_or_empty_response(anon_status, anon_body):
            return (
                HypothesisValidationStatus.REJECTED,
                f"Endpoint '{endpoint}' returned generic status or empty response without protected user content.",
            )

        # 4. Check whether authenticated baseline is present and valid
        if auth_status not in (200, 201) or not auth_body.strip():
            # Missing or invalid authenticated context CANNOT produce VALIDATED
            sensitive_indicators = ["email", "user_id", "account", "profile", "admin", "tenant", "roles", "balance"]
            lower_body = anon_body.lower()
            if anon_status in (200, 201) and any(ind in lower_body for ind in sensitive_indicators):
                return (
                    HypothesisValidationStatus.CANDIDATE,
                    f"Endpoint '{endpoint}' returned HTTP {anon_status} with sensitive user markers, but lacks valid authenticated baseline context to confirm differential access control bypass.",
                )
            return (
                HypothesisValidationStatus.REJECTED,
                f"Endpoint '{endpoint}' lacks valid authenticated baseline and did not expose protected user data.",
            )

        # 5. Meaningful response body comparison between authenticated and anonymous observations
        import json
        is_both_json = False
        anon_json = None
        auth_json = None
        try:
            anon_json = json.loads(anon_body)
            auth_json = json.loads(auth_body)
            is_both_json = True
        except Exception:
            is_both_json = False

        sensitive_fields = {"user_id", "id", "email", "username", "account", "profile", "admin", "tenant", "roles", "balance", "billing"}

        if is_both_json and isinstance(anon_json, dict) and isinstance(auth_json, dict):
            # Check if anonymous response matches authenticated protected keys and values
            matching_sensitive_keys = [k for k in auth_json.keys() if str(k).lower() in sensitive_fields and k in anon_json]
            
            # If both objects are identical and have protected indicators (e.g. lab scenario)
            if anon_json == auth_json and (matching_sensitive_keys or any(str(k).lower() in sensitive_fields for k in auth_json.keys())):
                return (
                    HypothesisValidationStatus.VALIDATED,
                    f"Protected endpoint '{endpoint}' returned identical protected resource content to anonymous requests as authenticated context (matching keys: {', '.join(matching_sensitive_keys or auth_json.keys())}).",
                )

            # If matching protected user attributes are returned anonymously with equal values
            matching_vals = [k for k in matching_sensitive_keys if anon_json[k] == auth_json[k]]
            if matching_vals:
                return (
                    HypothesisValidationStatus.VALIDATED,
                    f"Protected endpoint '{endpoint}' returned authenticated user data anonymously matching protected baseline (fields: {', '.join(matching_vals)}).",
                )

            # Anonymous returned JSON, but does not expose authenticated protected payload
            return (
                HypothesisValidationStatus.REJECTED,
                f"Anonymous JSON response from '{endpoint}' does not expose authenticated protected user payload.",
            )

        # Non-JSON content comparison: require substantive overlap of protected content
        lower_anon = anon_body.lower()
        lower_auth = auth_body.lower()
        sensitive_found = [s for s in sensitive_fields if s in lower_auth and s in lower_anon]
        if sensitive_found and len(anon_body) > 30 and abs(len(anon_body) - len(auth_body)) < max(len(auth_body) * 0.5, 200):
            return (
                HypothesisValidationStatus.VALIDATED,
                f"Protected endpoint '{endpoint}' returned HTTP {anon_status} with protected content matching authenticated baseline (indicators: {', '.join(sensitive_found)}).",
            )

        return (
            HypothesisValidationStatus.REJECTED,
            f"Endpoint '{endpoint}' did not expose authenticated protected resource content without authentication.",
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
        timing_delta_ms: float = 0.0,
        trial_count: int = 3,
        trial_consistency: bool = True,
    ) -> Tuple[HypothesisValidationStatus, str]:
        """
        Validates account enumeration differential signals.
        Timing differences and text variations are treated as signals, not standalone proof.
        Requires at least 3 controlled trials with confirmed consistency before assigning VALIDATED.
        Incomplete trial sets (< 3 trials) report INFORMATIONAL / CANDIDATE.
        """
        if not trial_consistency:
            return (
                HypothesisValidationStatus.REJECTED,
                "Differential response was inconsistent across controlled trials; rejected as timing/noise artifact.",
            )

        signal, reason = PasswordResetAnalyzer.analyze_account_enumeration(
            valid_user_status=valid_status,
            valid_user_body=valid_body,
            invalid_user_status=invalid_status,
            invalid_user_body=invalid_body,
            valid_user_redirect=valid_redirect,
            invalid_user_redirect=invalid_redirect,
        )
        if signal == AccountEnumerationSignal.STRONG_ENUMERATION_SIGNAL:
            if trial_count >= 3:
                return HypothesisValidationStatus.VALIDATED, f"Confirmed repeatable differential across {trial_count} controlled trials: {reason}"
            return (
                HypothesisValidationStatus.INFORMATIONAL,
                f"Differential signal observed ({reason}), but requires at least 3 controlled trials to validate repeatability (completed {trial_count}/3).",
            )
        elif signal == AccountEnumerationSignal.WEAK_ENUMERATION_SIGNAL:
            return HypothesisValidationStatus.INFORMATIONAL, f"Weak differential signal observed across {trial_count} trials ({reason}); not sufficiently repeatable for validation."
        return HypothesisValidationStatus.REJECTED, reason

    @classmethod
    def validate_password_reset_state_confusion(
        cls,
        endpoint: str,
        step_status: int,
        step_body: str,
        is_prerequisite_satisfied: bool = False,
    ) -> Tuple[HypothesisValidationStatus, str]:
        """
        Validates whether a password reset state machine permits completing a later step
        (e.g., password change confirmation) without the prerequisite verification token or step.
        """
        if is_prerequisite_satisfied:
            return HypothesisValidationStatus.REJECTED, "Normal workflow execution: prerequisite step was satisfied."

        is_success = step_status in (200, 201, 204, 302)
        lower_b = step_body.lower()
        error_markers = ["invalid", "expired", "missing", "token required", "unauthorized", "error", "forbidden", "fail", "bad request"]
        has_error = any(err in lower_b for err in error_markers)
        success_markers = ["password updated", "password changed", "success", "reset complete", "updated successfully"]
        has_success = any(sm in lower_b for sm in success_markers)

        if is_success and not has_error and (has_success or step_status in (200, 204)):
            return (
                HypothesisValidationStatus.VALIDATED,
                f"Password reset state confusion confirmed on '{endpoint}': final state transition accepted (HTTP {step_status}) without verified prerequisite token/step.",
            )

        return (
            HypothesisValidationStatus.REJECTED,
            f"Password reset workflow correctly rejected state transition when prerequisite was unsatisfied (HTTP {step_status}).",
        )

    @classmethod
    def validate_mfa_bypass(
        cls,
        endpoint: str,
        status_code: int,
        response_body: str,
        submitted_valid_code: bool = False,
    ) -> Tuple[HypothesisValidationStatus, str]:
        """
        Validates whether an MFA verification challenge can be bypassed with invalid/empty factor.
        """
        if submitted_valid_code:
            return HypothesisValidationStatus.REJECTED, "Valid MFA factor submitted; normal verification behavior."

        is_vuln, reason = MFAAnalyzer.evaluate_mfa_factor_verification(
            status_code=status_code,
            response_body=response_body,
            submitted_valid_code=False,
        )
        if is_vuln:
            return (
                HypothesisValidationStatus.VALIDATED,
                f"MFA bypass confirmed on '{endpoint}': challenge endpoint accepted invalid or missing verification factor (HTTP {status_code}).",
            )
        return (
            HypothesisValidationStatus.REJECTED,
            f"MFA verification challenge correctly enforced on '{endpoint}' (HTTP {status_code}).",
        )

    @classmethod
    def validate_mfa_state_confusion(
        cls,
        endpoint: str,
        target_status: int,
        target_body: str,
        cross_session_elevated: bool = False,
    ) -> Tuple[HypothesisValidationStatus, str]:
        """
        Validates whether completing MFA for one session/factor confuses the state of another unverified session.
        """
        is_success = target_status in (200, 201)
        lower_b = target_body.lower()
        mfa_prompt = any(p in lower_b for p in ["enter code", "otp", "two-factor", "2fa", "verify identity", "challenge"])

        if cross_session_elevated or (is_success and not mfa_prompt and len(target_body) > 10):
            return (
                HypothesisValidationStatus.VALIDATED,
                f"MFA state confusion confirmed on '{endpoint}': unverified session gained elevated authenticated access following external factor completion (HTTP {target_status}).",
            )
        return (
            HypothesisValidationStatus.REJECTED,
            f"MFA state isolation maintained on '{endpoint}': unverified session correctly challenged (HTTP {target_status}).",
        )

    @classmethod
    def validate_authentication_state_inconsistency(
        cls,
        endpoint: str,
        auth_status_code: int,
        auth_status_body: str,
        resource_status_code: int,
        resource_body: str,
    ) -> Tuple[HypothesisValidationStatus, str]:
        """
        Validates whether conflicting authentication states exist across system boundaries
        (e.g., auth check endpoint reports unauthenticated while resource endpoint grants access).
        """
        # Component 1 (auth check) reports unauthenticated / logged out
        c1_unauth = auth_status_code in (401, 403) or any(s in auth_status_body.lower() for s in ["\"authenticated\": false", "\"logged_in\": false", "unauthenticated", "logged out"])
        
        # Component 2 (resource) permits access to protected user data
        c2_auth = resource_status_code in (200, 201) and any(s in resource_body.lower() for s in ["user_id", "email", "account", "profile", "admin", "tenant"])

        if c1_unauth and c2_auth:
            return (
                HypothesisValidationStatus.VALIDATED,
                f"Authentication state inconsistency confirmed: auth boundary reports unauthenticated (HTTP {auth_status_code}) while protected resource '{endpoint}' returns active user session data (HTTP {resource_status_code}).",
            )
        return (
            HypothesisValidationStatus.REJECTED,
            f"Authentication state is consistent across system boundaries (HTTP {auth_status_code} / HTTP {resource_status_code}).",
        )
