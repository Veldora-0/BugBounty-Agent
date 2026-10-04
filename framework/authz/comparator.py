"""
Access-Control Response Analysis & False-Positive Elimination Engine (Phase 8).

Implements rigorous 3-point comparative baseline analysis:
- Baseline A: Authorized owner accessing target resource
- Baseline B: Testing principal accessing nonexistent/invalid resource
- Test: Testing principal accessing target resource

Eliminates false positives by actively detecting:
- Generic 200 error/denial pages
- Login form redirects / prompts
- Soft-404 pages
- Identical placeholder/empty responses
"""

from __future__ import annotations

import difflib
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from framework.authz.model import (
    AccessDecisionInferred,
    AuthzComparisonResult,
    ExpectedAccessDecision,
    ExpectedAccessPolicy,
    ResourceAccessTarget,
)
from framework.validation.request import ControlledResponse


# Generic denial and error signatures
DENIAL_KEYWORDS = [
    re.compile(r"\b(?:access denied|unauthorized|forbidden|permission denied)\b", re.IGNORECASE),
    re.compile(r"\b(?:you do not have permission|not allowed to view|requires elevated privileges)\b", re.IGNORECASE),
    re.compile(r"\b(?:please log in|sign in to continue|session expired|login required)\b", re.IGNORECASE),
    re.compile(r"\b(?:authentication required|auth required)\b", re.IGNORECASE),
]

# Soft-404 and missing entity signatures
SOFT_404_KEYWORDS = [
    re.compile(r"\b(?:page not found|not found|item not found|resource not found)\b", re.IGNORECASE),
    re.compile(r"\b(?:does not exist|could not be found|record not found|no such)\b", re.IGNORECASE),
]

# Login form HTML signatures
LOGIN_FORM_PATTERNS = [
    re.compile(r'<input[^>]+type=["\']password["\']', re.IGNORECASE),
    re.compile(r'action=["\'][^"\']*(?:login|signin|auth)[^"\']*["\']', re.IGNORECASE),
]


class AccessControlComparator:
    """
    Performs comparative baseline analysis to determine if unauthorized access occurred.
    """

    @classmethod
    def compare(
        cls,
        test_response: ControlledResponse,
        expected_policy: ExpectedAccessPolicy,
        resource: ResourceAccessTarget,
        baseline_owner_response: Optional[ControlledResponse] = None,
        baseline_invalid_response: Optional[ControlledResponse] = None,
    ) -> AuthzComparisonResult:
        """
        Evaluates test_response against expected policy and baseline observations.
        """
        code = test_response.status_code
        body = test_response.body
        signals: List[str] = []
        semantic_matches: List[str] = []

        # 1. Server errors
        if code >= 500:
            return AuthzComparisonResult(
                decision_inferred=AccessDecisionInferred.ERROR,
                status_code=code,
                body_similarity=0.0,
                is_vulnerable=False,
                signals=["SERVER_ERROR_5XX"],
                evidence_summary=f"Endpoint returned HTTP {code} server error.",
            )

        # 2. Explicit HTTP access control rejections
        if code in (401, 403):
            signals.append(f"HTTP_{code}_DENIED")
            return AuthzComparisonResult(
                decision_inferred=AccessDecisionInferred.DENY,
                status_code=code,
                body_similarity=0.0,
                is_vulnerable=False,
                signals=signals,
                evidence_summary=f"Access properly rejected with HTTP {code}.",
            )

        # 3. HTTP 404 Not Found
        if code == 404:
            signals.append("HTTP_404_NOT_FOUND")
            return AuthzComparisonResult(
                decision_inferred=AccessDecisionInferred.DENY,
                status_code=code,
                body_similarity=0.0,
                is_vulnerable=False,
                signals=signals,
                evidence_summary="Resource returned HTTP 404 Not Found.",
            )

        # 4. Login redirects (302/301/307 to login or auth routes)
        if code in (301, 302, 303, 307, 308):
            loc = (test_response.location_header or "").lower()
            if any(k in loc for k in ("login", "signin", "auth", "oauth", "sso")):
                signals.append(f"LOGIN_REDIRECT_{code}")
                return AuthzComparisonResult(
                    decision_inferred=AccessDecisionInferred.DENY,
                    status_code=code,
                    body_similarity=0.0,
                    is_vulnerable=False,
                    signals=signals,
                    evidence_summary=f"Request redirected to authentication route ({loc}).",
                )

        # 5. Check login form in body (200 OK login page)
        for pat in LOGIN_FORM_PATTERNS:
            if pat.search(body):
                signals.append("LOGIN_FORM_IN_BODY")
                return AuthzComparisonResult(
                    decision_inferred=AccessDecisionInferred.DENY,
                    status_code=code,
                    body_similarity=0.0,
                    is_vulnerable=False,
                    signals=signals,
                    evidence_summary="HTTP 200 response contains login form authentication prompt.",
                )

        # 6. Check generic denial keywords in HTTP 200
        for pat in DENIAL_KEYWORDS:
            match = pat.search(body)
            if match:
                signals.append(f"DENIAL_KEYWORD_{match.group(0)[:30]}")
                return AuthzComparisonResult(
                    decision_inferred=AccessDecisionInferred.DENY,
                    status_code=code,
                    body_similarity=0.0,
                    is_vulnerable=False,
                    generic_error_page=True,
                    signals=signals,
                    evidence_summary=f"HTTP 200 response contains denial message: '{match.group(0)}'.",
                )

        # 7. Check soft-404 keywords
        for pat in SOFT_404_KEYWORDS:
            match = pat.search(body)
            if match:
                signals.append(f"SOFT_404_KEYWORD_{match.group(0)[:30]}")
                return AuthzComparisonResult(
                    decision_inferred=AccessDecisionInferred.DENY,
                    status_code=code,
                    body_similarity=0.0,
                    is_vulnerable=False,
                    soft_404=True,
                    signals=signals,
                    evidence_summary=f"HTTP 200 response contains soft-404 message: '{match.group(0)}'.",
                )

        # 8. Baseline B comparison: compare with invalid resource response
        if baseline_invalid_response and baseline_invalid_response.body:
            inv_sim = difflib.SequenceMatcher(None, body[:2000], baseline_invalid_response.body[:2000]).ratio()
            if inv_sim > 0.90:
                signals.append(f"IDENTICAL_TO_INVALID_RESOURCE_{round(inv_sim, 2)}")
                return AuthzComparisonResult(
                    decision_inferred=AccessDecisionInferred.DENY,
                    status_code=code,
                    body_similarity=inv_sim,
                    is_vulnerable=False,
                    soft_404=True,
                    signals=signals,
                    evidence_summary=f"Response is {round(inv_sim*100, 1)}% identical to nonexistent resource response (soft-404).",
                )

        # 9. Baseline A comparison: compare with authorized owner response
        owner_sim = 0.0
        ownership_found = False

        if baseline_owner_response and baseline_owner_response.body:
            owner_sim = difflib.SequenceMatcher(None, body[:2000], baseline_owner_response.body[:2000]).ratio()

            # Check if resource identifier appears in response body
            if resource.resource_id in body:
                ownership_found = True
                semantic_matches.append(f"resource_id:{resource.resource_id}")

            # Check if owner principal ID appears in response body
            if resource.owner_principal_id and resource.owner_principal_id in body:
                ownership_found = True
                semantic_matches.append(f"owner_id:{resource.owner_principal_id}")

            # Check if tenant ID appears in response body
            if resource.tenant_id and resource.tenant_id in body:
                semantic_matches.append(f"tenant_id:{resource.tenant_id}")

            # Check for JSON object structure similarity
            try:
                owner_json = json.loads(baseline_owner_response.body)
                test_json = json.loads(body)
                if isinstance(owner_json, dict) and isinstance(test_json, dict):
                    shared_keys = set(owner_json.keys()) & set(test_json.keys())
                    if len(shared_keys) >= 2:
                        semantic_matches.append(f"shared_json_keys:{len(shared_keys)}")
            except Exception:
                pass

        # 10. Synthesize final inferred decision
        decision = AccessDecisionInferred.ALLOW if code == 200 else AccessDecisionInferred.UNKNOWN

        # Determine vulnerability state against expected policy
        is_vuln = False
        if expected_policy.expected_decision == ExpectedAccessDecision.DENY and decision == AccessDecisionInferred.ALLOW:
            # We have an authorization bypass if response is ALLOW and not generic denial
            is_vuln = True
            signals.append("UNAUTHORIZED_ACCESS_ALLOWED")

        summary = (
            f"Observed decision: {decision.value} (HTTP {code}, similarity: {round(owner_sim, 2)}). "
            f"Expected decision was: {expected_policy.expected_decision.value}."
        )

        return AuthzComparisonResult(
            decision_inferred=decision,
            status_code=code,
            body_similarity=owner_sim,
            is_vulnerable=is_vuln,
            semantic_matches=semantic_matches,
            ownership_identifier_found=ownership_found,
            signals=signals,
            evidence_summary=summary,
        )
