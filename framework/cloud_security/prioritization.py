"""
Exposure Scoring and Prioritization Engine (Phase 13).

Scores and prioritizes cloud security hypotheses using:
1. unauthorized sensitive-data access
2. public object listing
3. public write capability suspicion
4. authentication bypass
5. cloud takeover suspicion
6. exposed administrative functionality
7. credential/secret exposure
8. configuration weaknesses
9. informational provider fingerprints

Ensures high confidence + low impact is distinguished from medium confidence + critical impact.
Low-value fingerprint findings are kept at the bottom of the execution queue.
"""

from __future__ import annotations

from typing import List, Tuple

from framework.cloud_security.models import (
    CloudExposureHypothesis,
    CloudHypothesisType,
    CloudServiceType,
)


# Priority rank for hypothesis types (lower number = higher priority)
HYPOTHESIS_PRIORITY_RANK = {
    CloudHypothesisType.WRITE_CAPABILITY_SUSPECTED: 1,
    CloudHypothesisType.PUBLIC_OBJECT_LISTING: 2,
    CloudHypothesisType.POTENTIAL_CLOUD_TAKEOVER: 3,
    CloudHypothesisType.HIGH_CONFIDENCE_CREDENTIAL: 4,
    CloudHypothesisType.UNAUTHENTICATED_ADMIN_ACCESS: 5,
    CloudHypothesisType.PUBLIC_OBJECT_READ: 6,
    CloudHypothesisType.SECRET_REFERENCE_FOUND: 7,
    CloudHypothesisType.PUBLIC_INTERFACE: 8,
    CloudHypothesisType.INFORMATIONAL_FINGERPRINT: 9,
}

SEVERITY_WEIGHTS = {
    "CRITICAL": 100.0,
    "HIGH": 80.0,
    "MEDIUM": 50.0,
    "LOW": 20.0,
    "INFO": 5.0,
}


class CloudExposureScorer:
    """Calculates multidimensional risk score, priority rank, and impact weight."""

    @classmethod
    def calculate_score(cls, hypothesis: CloudExposureHypothesis) -> float:
        """
        Calculates composite score (0 - 100) combining severity weight,
        hypothesis type rank, and calibrated confidence.
        """
        sev_weight = SEVERITY_WEIGHTS.get(hypothesis.severity_hint.upper(), 10.0)
        conf = hypothesis.confidence
        rank = HYPOTHESIS_PRIORITY_RANK.get(hypothesis.hypothesis_type, 9)

        # Base calculation: severity weight * confidence
        base = sev_weight * conf

        # Rank bonus (up to 20 points for top ranks)
        rank_bonus = max(0, 20 - (rank * 2))

        # Sensitive service modifier (e.g. storage or admin interfaces get slight boost)
        service_boost = 5.0 if hypothesis.service in (CloudServiceType.OBJECT_STORAGE, CloudServiceType.ADMIN_INTERFACE) else 0.0

        composite = min(100.0, base + rank_bonus + service_boost)
        return round(composite, 1)


class CloudPrioritizationEngine:
    """Sorts hypotheses by priority rank, composite score, and impact weight."""

    @classmethod
    def prioritize(cls, hypotheses: List[CloudExposureHypothesis]) -> List[CloudExposureHypothesis]:
        """
        Sorts hypotheses so critical security-impacting exposures appear first
        and informational fingerprints appear last.
        """
        def sort_key(h: CloudExposureHypothesis) -> Tuple[int, float]:
            rank = HYPOTHESIS_PRIORITY_RANK.get(h.hypothesis_type, 9)
            score = CloudExposureScorer.calculate_score(h)
            # Ascending rank (1 first), descending score (-score)
            return (rank, -score)

        return sorted(hypotheses, key=sort_key)
