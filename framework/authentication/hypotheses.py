"""
Authentication Hypothesis Generation Engine (Phase 14.1 / 14.2).

Formulates structured, testable hypotheses regarding authentication boundaries,
session lifecycles, MFA enforcement, and token security based on discovered attack surfaces.
Strictly maps hypotheses to the 14 declared families in AuthenticationFindingFamily.
Uses deterministic SHA-256 fingerprinting for robust deduplication and cross-run resume.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from framework.authentication.models import (
    AuthenticationFindingFamily,
    AuthenticationHypothesis,
    AuthenticationState,
    AuthenticationStep,
    HypothesisValidationStatus,
    IdentityProfile,
    SessionProfile,
)


def generate_hypothesis_id(
    family: AuthenticationFindingFamily | str,
    endpoint: str,
    principal: str,
    required_state: AuthenticationState | str,
) -> str:
    """
    Generates a deterministic hypothesis ID based on canonical SHA-256 hash.
    Ensures context-awareness: distinct endpoints, families, principals, or required states
    produce distinct IDs, enabling legitimate re-testing while preventing redundant probes.
    """
    fam_str = family.value if hasattr(family, "value") else str(family)
    req_str = required_state.value if hasattr(required_state, "value") else str(required_state)
    raw = f"{fam_str.upper()}|{endpoint.strip()}|{principal.strip()}|{req_str.upper()}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]
    fam_clean = fam_str.replace("_", "-")[:8]
    return f"HYP-{fam_clean}-{digest}"


class AuthenticationHypothesisEngine:
    """Generates structured hypotheses from discovered authentication surfaces and identities."""

    generate_hypothesis_id = staticmethod(generate_hypothesis_id)

    @classmethod
    def generate_hypotheses_for_endpoint(
        cls,
        endpoint: str,
        step: Optional[AuthenticationStep] = None,
        identity: Optional[IdentityProfile] = None,
    ) -> List[AuthenticationHypothesis]:
        """Formulates potential security hypotheses for a specific authentication endpoint."""
        hypotheses: List[AuthenticationHypothesis] = []
        principal_id = identity.identity_id if identity else "ANONYMOUS"
        ep_lower = endpoint.lower()

        # 1. AUTHENTICATION_BYPASS (Operational)
        if any(p in ep_lower for p in ["/admin", "/api/user", "/profile", "/dashboard", "/account", "/settings"]):
            hypotheses.append(
                AuthenticationHypothesis(
                    hypothesis_id=cls.generate_hypothesis_id(
                        AuthenticationFindingFamily.AUTHENTICATION_BYPASS,
                        endpoint,
                        principal_id,
                        AuthenticationState.AUTHENTICATED,
                    ),
                    family=AuthenticationFindingFamily.AUTHENTICATION_BYPASS,
                    endpoint=endpoint,
                    principal=principal_id,
                    required_state=AuthenticationState.AUTHENTICATED,
                    observed_state=AuthenticationState.ANONYMOUS,
                    expected_behavior="Endpoint rejects unauthenticated requests with HTTP 401 or 403.",
                    observed_behavior="To be verified via differential comparison against anonymous baseline.",
                    confidence=0.6,
                    impact_hint="HIGH",
                    rationale=f"Endpoint '{endpoint}' manages protected user/administrative state. Verify if authentication challenge is enforced.",
                )
            )

        # 2. PRE_AUTH_PRIVILEGE_EXPOSURE (Operational)
        if any(p in ep_lower for p in ["/api/account", "/profile", "/settings", "/billing", "/api/v1/user"]):
            hypotheses.append(
                AuthenticationHypothesis(
                    hypothesis_id=cls.generate_hypothesis_id(
                        AuthenticationFindingFamily.PRE_AUTH_PRIVILEGE_EXPOSURE,
                        endpoint,
                        principal_id,
                        AuthenticationState.MFA_VERIFIED,
                    ),
                    family=AuthenticationFindingFamily.PRE_AUTH_PRIVILEGE_EXPOSURE,
                    endpoint=endpoint,
                    principal=principal_id,
                    required_state=AuthenticationState.MFA_VERIFIED,
                    observed_state=AuthenticationState.MFA_REQUIRED,
                    expected_behavior="Endpoint requires completed MFA verification before returning sensitive account details.",
                    observed_behavior="To be verified via pre-MFA token probe.",
                    confidence=0.5,
                    impact_hint="HIGH",
                    rationale=f"Endpoint '{endpoint}' may expose sensitive account data prior to completing secondary authentication factors.",
                )
            )

        # 3. SESSION_FIXATION (Operational) & 5. SESSION_NOT_ROTATED (Observation-Only)
        if any(p in ep_lower for p in ["/login", "/signin", "/auth/login", "/session"]):
            hypotheses.append(
                AuthenticationHypothesis(
                    hypothesis_id=cls.generate_hypothesis_id(
                        AuthenticationFindingFamily.SESSION_FIXATION,
                        endpoint,
                        principal_id,
                        AuthenticationState.AUTHENTICATED,
                    ),
                    family=AuthenticationFindingFamily.SESSION_FIXATION,
                    endpoint=endpoint,
                    principal=principal_id,
                    required_state=AuthenticationState.AUTHENTICATED,
                    observed_state=AuthenticationState.ANONYMOUS,
                    expected_behavior="Server issues new session identifier upon authentication.",
                    observed_behavior="To be verified by replaying pre-login session identifier.",
                    confidence=0.6,
                    impact_hint="MEDIUM",
                    rationale="Server must rotate session identifier across login boundary to prevent session fixation.",
                )
            )
            hypotheses.append(
                AuthenticationHypothesis(
                    hypothesis_id=cls.generate_hypothesis_id(
                        AuthenticationFindingFamily.SESSION_NOT_ROTATED,
                        endpoint,
                        principal_id,
                        AuthenticationState.AUTHENTICATED,
                    ),
                    family=AuthenticationFindingFamily.SESSION_NOT_ROTATED,
                    endpoint=endpoint,
                    principal=principal_id,
                    required_state=AuthenticationState.AUTHENTICATED,
                    observed_state=AuthenticationState.AUTHENTICATED,
                    expected_behavior="Session token rotated after privilege elevation.",
                    observed_behavior="Observation: check if session cookie remains unchanged across login.",
                    confidence=0.4,
                    impact_hint="LOW",
                    rationale="Failure to rotate session ID is an informational hardening concern.",
                )
            )

        # 4. SESSION_NOT_INVALIDATED (Operational)
        if any(p in ep_lower for p in ["/logout", "/signout", "/api/logout", "/auth/logout"]):
            hypotheses.append(
                AuthenticationHypothesis(
                    hypothesis_id=cls.generate_hypothesis_id(
                        AuthenticationFindingFamily.SESSION_NOT_INVALIDATED,
                        endpoint,
                        principal_id,
                        AuthenticationState.AUTHENTICATED,
                    ),
                    family=AuthenticationFindingFamily.SESSION_NOT_INVALIDATED,
                    endpoint=endpoint,
                    principal=principal_id,
                    required_state=AuthenticationState.AUTHENTICATED,
                    observed_state=AuthenticationState.LOGGED_OUT,
                    expected_behavior="Session identifier is invalidated on backend and subsequent requests return HTTP 401.",
                    observed_behavior="To be verified via post-logout session replay.",
                    confidence=0.7,
                    impact_hint="MEDIUM",
                    rationale="Logout action must revoke server-side session authorization.",
                )
            )

        # 6. PASSWORD_RESET_TOKEN_REUSE & 7. PASSWORD_RESET_STATE_CONFUSION & 8. ACCOUNT_ENUMERATION
        if any(p in ep_lower for p in ["/password/reset", "/reset-password", "/forgot-password", "/account/recovery"]):
            hypotheses.append(
                AuthenticationHypothesis(
                    hypothesis_id=cls.generate_hypothesis_id(
                        AuthenticationFindingFamily.PASSWORD_RESET_TOKEN_REUSE,
                        endpoint,
                        principal_id,
                        AuthenticationState.RECOVERY,
                    ),
                    family=AuthenticationFindingFamily.PASSWORD_RESET_TOKEN_REUSE,
                    endpoint=endpoint,
                    principal=principal_id,
                    required_state=AuthenticationState.RECOVERY,
                    observed_state=AuthenticationState.AUTHENTICATED,
                    expected_behavior="Password reset token is strictly one-time use and invalidated upon first password change.",
                    observed_behavior="To be verified via secondary reset token submission.",
                    confidence=0.6,
                    impact_hint="HIGH",
                    rationale="Password reset token must be consumed atomically and revoked permanently.",
                )
            )
            hypotheses.append(
                AuthenticationHypothesis(
                    hypothesis_id=cls.generate_hypothesis_id(
                        AuthenticationFindingFamily.PASSWORD_RESET_STATE_CONFUSION,
                        endpoint,
                        principal_id,
                        AuthenticationState.RECOVERY,
                    ),
                    family=AuthenticationFindingFamily.PASSWORD_RESET_STATE_CONFUSION,
                    endpoint=endpoint,
                    principal=principal_id,
                    required_state=AuthenticationState.RECOVERY,
                    observed_state=AuthenticationState.RECOVERY,
                    expected_behavior="Password reset requires step-order compliance and valid identity binding.",
                    observed_behavior="To be verified via parameter manipulation on test account.",
                    confidence=0.5,
                    impact_hint="HIGH",
                    rationale="State confusion during password reset can permit account takeover on researcher test accounts.",
                )
            )
            hypotheses.append(
                AuthenticationHypothesis(
                    hypothesis_id=cls.generate_hypothesis_id(
                        AuthenticationFindingFamily.ACCOUNT_ENUMERATION,
                        endpoint,
                        principal_id,
                        AuthenticationState.ANONYMOUS,
                    ),
                    family=AuthenticationFindingFamily.ACCOUNT_ENUMERATION,
                    endpoint=endpoint,
                    principal=principal_id,
                    required_state=AuthenticationState.ANONYMOUS,
                    observed_state=AuthenticationState.ANONYMOUS,
                    expected_behavior="Endpoint returns uniform response regardless of account existence.",
                    observed_behavior="To be evaluated via controlled differential probe over multiple trials.",
                    confidence=0.5,
                    impact_hint="LOW",
                    rationale="Password reset initiation should not leak user registration status via differential errors.",
                )
            )

        # 9. MFA_BYPASS & 10. MFA_STATE_CONFUSION
        if any(p in ep_lower for p in ["/mfa", "/2fa", "/otp", "/verify-mfa", "/two-factor"]):
            hypotheses.append(
                AuthenticationHypothesis(
                    hypothesis_id=cls.generate_hypothesis_id(
                        AuthenticationFindingFamily.MFA_BYPASS,
                        endpoint,
                        principal_id,
                        AuthenticationState.MFA_VERIFIED,
                    ),
                    family=AuthenticationFindingFamily.MFA_BYPASS,
                    endpoint=endpoint,
                    principal=principal_id,
                    required_state=AuthenticationState.MFA_VERIFIED,
                    observed_state=AuthenticationState.MFA_REQUIRED,
                    expected_behavior="Access to post-MFA functionality strictly requires successful second factor validation.",
                    observed_behavior="To be verified by testing post-MFA routes with primary credentials only.",
                    confidence=0.6,
                    impact_hint="HIGH",
                    rationale="MFA verification step must not be skippable via direct endpoint access.",
                )
            )
            hypotheses.append(
                AuthenticationHypothesis(
                    hypothesis_id=cls.generate_hypothesis_id(
                        AuthenticationFindingFamily.MFA_STATE_CONFUSION,
                        endpoint,
                        principal_id,
                        AuthenticationState.MFA_REQUIRED,
                    ),
                    family=AuthenticationFindingFamily.MFA_STATE_CONFUSION,
                    endpoint=endpoint,
                    principal=principal_id,
                    required_state=AuthenticationState.MFA_REQUIRED,
                    observed_state=AuthenticationState.MFA_REQUIRED,
                    expected_behavior="MFA state transitions must be serialized and bound to specific session.",
                    observed_behavior="To be verified via out-of-order state parameter submission.",
                    confidence=0.5,
                    impact_hint="HIGH",
                    rationale="Intermediate MFA states must not be reused across sessions.",
                )
            )

        # 11. REFRESH_TOKEN_REUSE
        if any(p in ep_lower for p in ["/token/refresh", "/auth/refresh", "/refresh-token"]):
            hypotheses.append(
                AuthenticationHypothesis(
                    hypothesis_id=cls.generate_hypothesis_id(
                        AuthenticationFindingFamily.REFRESH_TOKEN_REUSE,
                        endpoint,
                        principal_id,
                        AuthenticationState.AUTHENTICATED,
                    ),
                    family=AuthenticationFindingFamily.REFRESH_TOKEN_REUSE,
                    endpoint=endpoint,
                    principal=principal_id,
                    required_state=AuthenticationState.AUTHENTICATED,
                    observed_state=AuthenticationState.AUTHENTICATED,
                    expected_behavior="Refresh token is rotated and revoked on first usage.",
                    observed_behavior="To be verified via refresh token replay.",
                    confidence=0.6,
                    impact_hint="MEDIUM",
                    rationale="Refresh token reuse allows extended unauthorized session persistence.",
                )
            )

        # 12. TOKEN_TRANSPORT_EXPOSURE (Observation-Only)
        if any(p in ep_lower for p in ["token=", "access_token=", "bearer=", "auth="]):
            hypotheses.append(
                AuthenticationHypothesis(
                    hypothesis_id=cls.generate_hypothesis_id(
                        AuthenticationFindingFamily.TOKEN_TRANSPORT_EXPOSURE,
                        endpoint,
                        principal_id,
                        AuthenticationState.AUTHENTICATED,
                    ),
                    family=AuthenticationFindingFamily.TOKEN_TRANSPORT_EXPOSURE,
                    endpoint=endpoint,
                    principal=principal_id,
                    required_state=AuthenticationState.AUTHENTICATED,
                    observed_state=AuthenticationState.AUTHENTICATED,
                    expected_behavior="Sensitive tokens conveyed in secure headers or request bodies, not URL query strings.",
                    observed_behavior="Observation: token detected in URL or transport parameter.",
                    confidence=0.7,
                    impact_hint="LOW",
                    rationale="Token transport exposure may leak credentials to web server logs or Referer headers.",
                )
            )

        # 13. AUTHENTICATION_STATE_INCONSISTENCY
        if any(p in ep_lower for p in ["/api/v", "/internal/auth", "/gateway"]):
            hypotheses.append(
                AuthenticationHypothesis(
                    hypothesis_id=cls.generate_hypothesis_id(
                        AuthenticationFindingFamily.AUTHENTICATION_STATE_INCONSISTENCY,
                        endpoint,
                        principal_id,
                        AuthenticationState.AUTHENTICATED,
                    ),
                    family=AuthenticationFindingFamily.AUTHENTICATION_STATE_INCONSISTENCY,
                    endpoint=endpoint,
                    principal=principal_id,
                    required_state=AuthenticationState.AUTHENTICATED,
                    observed_state=AuthenticationState.AUTHENTICATED,
                    expected_behavior="All backend services uniformly enforce current authentication and revocation state.",
                    observed_behavior="To be verified via cross-component credential probes.",
                    confidence=0.4,
                    impact_hint="MEDIUM",
                    rationale="Microservice or gateway discrepancies may allow revoked credentials on downstream services.",
                )
            )

        # 14. AUTHENTICATION_CONFIGURATION_WEAKNESS (Observation-Only)
        if any(p in ep_lower for p in ["/login", "/auth", "/session", "/api/auth"]):
            hypotheses.append(
                AuthenticationHypothesis(
                    hypothesis_id=cls.generate_hypothesis_id(
                        AuthenticationFindingFamily.AUTHENTICATION_CONFIGURATION_WEAKNESS,
                        endpoint,
                        principal_id,
                        AuthenticationState.AUTHENTICATED,
                    ),
                    family=AuthenticationFindingFamily.AUTHENTICATION_CONFIGURATION_WEAKNESS,
                    endpoint=endpoint,
                    principal=principal_id,
                    required_state=AuthenticationState.AUTHENTICATED,
                    observed_state=AuthenticationState.AUTHENTICATED,
                    expected_behavior="Session cookies configure Secure, HttpOnly, and SameSite; JWTs use strong signing.",
                    observed_behavior="Observation: check configuration attributes on session cookies and tokens.",
                    confidence=0.5,
                    impact_hint="LOW",
                    rationale="Configuration weaknesses represent defense-in-depth observations unless actively exploitable.",
                )
            )

        return hypotheses

    @classmethod
    def generate_all(
        cls,
        surfaces: List[AuthenticationStep],
        identity: Optional[IdentityProfile] = None,
    ) -> List[AuthenticationHypothesis]:
        """Generates hypotheses for all provided surfaces."""
        all_hyps: List[AuthenticationHypothesis] = []
        seen_ids = set()
        for s in surfaces:
            for h in cls.generate_hypotheses_for_endpoint(s.endpoint, step=s, identity=identity):
                if h.hypothesis_id not in seen_ids:
                    seen_ids.add(h.hypothesis_id)
                    all_hyps.append(h)
        return all_hyps
