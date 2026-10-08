"""
Authentication Finding Prioritization & Severity Scoring Engine (Phase 14).

Separates severity, confidence, exploitability, and evidence quality.
Calculates realistic CVSS base scores and sorts findings by actionable triage priority.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from framework.authentication.models import (
    AuthenticationFindingCandidate,
    AuthenticationFindingFamily,
    AuthenticationHypothesis,
    HypothesisValidationStatus,
)


class AuthenticationPrioritizer:
    """Prioritizes authentication findings based on risk, exploitability, and evidence certainty."""

    # Base severity mappings
    SEVERITY_TIERS = {
        AuthenticationFindingFamily.AUTHENTICATION_BYPASS: ("CRITICAL", 9.1),
        AuthenticationFindingFamily.PRE_AUTH_PRIVILEGE_EXPOSURE: ("HIGH", 8.2),
        AuthenticationFindingFamily.MFA_BYPASS: ("HIGH", 8.1),
        AuthenticationFindingFamily.PASSWORD_RESET_TOKEN_REUSE: ("HIGH", 7.5),
        AuthenticationFindingFamily.SESSION_NOT_INVALIDATED: ("MEDIUM", 6.5),
        AuthenticationFindingFamily.SESSION_FIXATION: ("MEDIUM", 6.1),
        AuthenticationFindingFamily.REFRESH_TOKEN_REUSE: ("MEDIUM", 5.8),
        AuthenticationFindingFamily.ACCOUNT_ENUMERATION: ("LOW", 5.3),
        AuthenticationFindingFamily.TOKEN_TRANSPORT_EXPOSURE: ("LOW", 4.3),
        AuthenticationFindingFamily.SESSION_NOT_ROTATED: ("LOW", 3.7),
        AuthenticationFindingFamily.AUTHENTICATION_CONFIGURATION_WEAKNESS: ("INFORMATIONAL", 2.0),
    }

    @classmethod
    def score_finding(
        cls,
        family: str,
        confidence_factor: float = 1.0,
    ) -> Tuple[str, float]:
        """Returns (severity_string, cvss_base_score)."""
        base_sev, base_score = cls.SEVERITY_TIERS.get(family, ("MEDIUM", 5.0))
        final_score = round(min(10.0, max(0.0, base_score * min(1.0, confidence_factor))), 1)
        return base_sev, final_score

    @classmethod
    def prioritize_findings(
        cls,
        findings: List[AuthenticationFindingCandidate],
    ) -> List[AuthenticationFindingCandidate]:
        """Sorts findings by severity rank, then CVSS score descending."""
        rank_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
        return sorted(
            findings,
            key=lambda f: (rank_order.get(f.severity, 5), -f.cvss_score),
        )

    @classmethod
    def prioritize_hypotheses(
        cls,
        hypotheses: List[AuthenticationHypothesis],
    ) -> List[AuthenticationHypothesis]:
        """Orders hypotheses for testing: High impact first, untested before completed."""
        status_rank = {
            HypothesisValidationStatus.UNTESTED: 0,
            HypothesisValidationStatus.PLANNED: 1,
            HypothesisValidationStatus.TESTING: 2,
            HypothesisValidationStatus.VALIDATED: 3,
            HypothesisValidationStatus.NEEDS_MANUAL_REVIEW: 4,
            HypothesisValidationStatus.INFORMATIONAL: 5,
            HypothesisValidationStatus.REJECTED: 6,
            HypothesisValidationStatus.DUPLICATE: 7,
        }
        return sorted(
            hypotheses,
            key=lambda h: (status_rank.get(h.validation_status, 9), -h.confidence),
        )
