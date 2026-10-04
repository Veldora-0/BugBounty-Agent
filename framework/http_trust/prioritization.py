"""
Prioritization and Semantic Evaluation Engine for HTTP Header Trust (Phase 11).

Evaluates endpoint semantics, candidate header types, workflow sensitivity,
and context to assign a 0-100 priority score with explicit reasoning.
Strictly separates Priority (0-100) from Confidence (CANDIDATE->VALIDATED) and Severity.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from framework.http_trust.model import HttpTrustCategory


class HttpTrustPrioritizer:
    """
    Ranks HTTP trust candidates based on endpoint sensitivity,
    header role, and potential security impact.
    """

    # Workflows where Host/Proxy poisoning leads to critical account takeover / credential compromise
    CRITICAL_WORKFLOW_PATTERNS = [
        re.compile(r"(password[-_]?reset|forgot[-_]?password|reset[-_]?password)", re.IGNORECASE),
        re.compile(r"(invite|invitation|enroll|enrollment|onboard|onboarding)", re.IGNORECASE),
        re.compile(r"(verify|verification|activate|activation|confirm[-_]?email)", re.IGNORECASE),
        re.compile(r"(magic[-_]?link|passwordless|login[-_]?token)", re.IGNORECASE),
    ]

    AUTH_SESSION_PATTERNS = [
        re.compile(r"(auth|login|signin|oauth|sso|callback|token|session|logout)", re.IGNORECASE),
        re.compile(r"(account|profile|settings|user|admin|dashboard)", re.IGNORECASE),
    ]

    REDIRECT_PATTERNS = [
        re.compile(r"(redirect|return|next|goto|target|url|dest|forward)", re.IGNORECASE),
    ]

    STATIC_RESOURCE_PATTERNS = [
        re.compile(r"\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$", re.IGNORECASE),
        re.compile(r"/(static|assets|public|media|images|dist)/", re.IGNORECASE),
    ]

    @classmethod
    def evaluate(
        cls,
        header_name: str,
        endpoint: str,
        category: HttpTrustCategory | str = HttpTrustCategory.HOST_INJECTION,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, List[str], str, str]:
        """
        Evaluates an endpoint and header for testing priority.
        Returns:
            (priority_score 0-100, reasons, inferred_severity, workflow_type)
        """
        cat = (
            category
            if isinstance(category, HttpTrustCategory)
            else HttpTrustCategory.from_string(category)
        )
        parsed = urlparse(endpoint)
        path = parsed.path.lower()
        query = parsed.query.lower()
        hdr_lower = header_name.lower().strip()

        score = 25  # baseline
        reasons: List[str] = []
        workflow_type = "GENERAL"
        severity = "LOW"

        # 1. Critical Account Workflows (Password Reset, Invitations, Magic links)
        for pattern in cls.CRITICAL_WORKFLOW_PATTERNS:
            if pattern.search(path) or pattern.search(query):
                score += 45
                reasons.append("critical account workflow (password-reset/invitation/activation host-poisoning candidate)")
                workflow_type = "ACCOUNT_TAKEOVER_CANDIDATE"
                severity = "HIGH"
                break

        # 2. Authentication & Profile Endpoints
        if workflow_type == "GENERAL":
            for pattern in cls.AUTH_SESSION_PATTERNS:
                if pattern.search(path) or pattern.search(query):
                    score += 25
                    reasons.append("authenticated or profile workflow (session/origin-trust candidate)")
                    workflow_type = "AUTH_SESSION"
                    severity = "MEDIUM"
                    break

        # 3. Redirect endpoints
        for pattern in cls.REDIRECT_PATTERNS:
            if pattern.search(path) or pattern.search(query):
                score += 20
                reasons.append("potential redirect handler (redirect host-poisoning candidate)")
                if severity == "LOW":
                    severity = "MEDIUM"
                break

        # 4. Header-specific analysis
        if hdr_lower in ("host", "x-forwarded-host", "forwarded", "x-original-host"):
            if workflow_type == "ACCOUNT_TAKEOVER_CANDIDATE":
                score += 15
                reasons.append(f"{header_name} can poison server-generated action links")
            else:
                score += 10
                reasons.append(f"primary routing/domain header ({header_name})")
        elif hdr_lower in ("origin", "access-control-request-headers"):
            if workflow_type in ("AUTH_SESSION", "ACCOUNT_TAKEOVER_CANDIDATE"):
                score += 20
                reasons.append("cross-origin trust boundary on sensitive endpoint (CORS candidate)")
                if severity == "LOW":
                    severity = "MEDIUM"
            else:
                score += 5
                reasons.append("cross-origin boundary probe")
        elif hdr_lower in ("x-forwarded-proto", "x-forwarded-port"):
            score += 10
            reasons.append(f"scheme/port trust analysis ({header_name})")
        elif hdr_lower in ("cache-control", "x-cache"):
            score += 15
            reasons.append("cache behavior header candidate")

        # 5. HPP parameter evaluation
        if cat == HttpTrustCategory.HPP:
            if any(term in query for term in ("id", "user", "admin", "role", "auth", "token")):
                score += 20
                reasons.append("sensitive query parameters subject to duplicate pollution (HPP)")
            else:
                score += 10
                reasons.append("query parameter pollution candidate")

        # 6. Demotions for static/low-impact resources
        for static_pat in cls.STATIC_RESOURCE_PATTERNS:
            if static_pat.search(path):
                score = max(5, score - 40)
                reasons.append("static/cosmetic asset (demoted priority)")
                severity = "INFO"
                break

        # Clamp score between 0 and 100
        score = max(0, min(100, score))
        if score >= 80:
            severity = "HIGH"
        elif score >= 50 and severity == "LOW":
            severity = "MEDIUM"

        return score, reasons, severity, workflow_type
