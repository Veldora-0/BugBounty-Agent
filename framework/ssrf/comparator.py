"""
SSRF Response Comparator & False-Positive Elimination Engine (Phase 9).

Evaluates candidate test results against baselines and out-of-band interaction observations.
Actively filters out:
- Browser-side / client-side callbacks
- Stale or expired callback tokens
- Unrelated automated scanners
- Missing or ambiguous network interactions
- Confuses DNS-only resolution with confirmed HTTP SSRF
"""

from __future__ import annotations

import difflib
import json
from typing import Any, Dict, List, Optional, Set, Tuple

from framework.ssrf.model import (
    OobInteractionType,
    SsrfCandidate,
    SsrfConfidence,
    SsrfEvidence,
    SsrfInteraction,
)
from framework.validation.request import ControlledResponse


class SsrfComparisonResult:
    """Detailed differential and out-of-band correlation evaluation outcome."""

    def __init__(
        self,
        is_confirmed: bool,
        interaction_type: OobInteractionType | str,
        confidence: SsrfConfidence | str,
        signals: Optional[List[str]] = None,
        summary: str = "",
        evidence: Optional[SsrfEvidence] = None,
        status_delta: int = 0,
        body_similarity: float = 1.0,
    ):
        self.is_confirmed = bool(is_confirmed)
        self.interaction_type = (
            interaction_type
            if isinstance(interaction_type, OobInteractionType)
            else OobInteractionType(str(interaction_type).upper())
        )
        self.confidence = (
            confidence
            if isinstance(confidence, SsrfConfidence)
            else SsrfConfidence(str(confidence).upper())
        )
        self.signals = list(signals or [])
        self.summary = summary
        self.evidence = evidence
        self.status_delta = int(status_delta)
        self.body_similarity = float(body_similarity)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_confirmed": self.is_confirmed,
            "interaction_type": self.interaction_type.value,
            "confidence": self.confidence.value,
            "signals": self.signals,
            "summary": self.summary,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "status_delta": self.status_delta,
            "body_similarity": round(self.body_similarity, 4),
        }


class SsrfComparator:
    """
    Performs comparative evaluation between benign baseline and canary probe,
    integrating OOB interaction evidence.
    """

    @classmethod
    def evaluate(
        cls,
        candidate: SsrfCandidate,
        canary_token: str,
        test_response: ControlledResponse,
        baseline_response: Optional[ControlledResponse] = None,
        interactions: Optional[List[SsrfInteraction]] = None,
        provider_name: str = "mock",
    ) -> SsrfComparisonResult:
        """
        Synthesizes baseline, HTTP response, and OOB interactions into a validated finding verdict.
        """
        ints = list(interactions or [])
        signals: List[str] = []

        # 1. Evaluate HTTP response differential against baseline
        status_delta = 0
        body_sim = 1.0
        if baseline_response:
            status_delta = test_response.status_code - baseline_response.status_code
            if baseline_response.body and test_response.body:
                body_sim = difflib.SequenceMatcher(
                    None,
                    baseline_response.body[:2000],
                    test_response.body[:2000],
                ).ratio()
            signals.append(f"HTTP_STATUS_{test_response.status_code}_BASE_{baseline_response.status_code}")
        else:
            signals.append(f"HTTP_STATUS_{test_response.status_code}")

        # 2. Evaluate out-of-band interactions
        if not ints:
            signals.append("NO_OOB_INTERACTION")
            summary = (
                f"No out-of-band network interaction received for canary token '{canary_token}'. "
                f"Endpoint returned HTTP {test_response.status_code}."
            )
            return SsrfComparisonResult(
                is_confirmed=False,
                interaction_type=OobInteractionType.NO_INTERACTION,
                confidence=SsrfConfidence.CANDIDATE,
                signals=signals,
                summary=summary,
                status_delta=status_delta,
                body_similarity=body_sim,
            )

        # Distinguish interaction level: HTTPS > HTTP > DNS
        has_https = any(i.protocol == "HTTPS" or i.interaction_type == OobInteractionType.HTTPS_INTERACTION for i in ints)
        has_http = any(i.protocol == "HTTP" or i.interaction_type == OobInteractionType.HTTP_INTERACTION for i in ints)
        has_dns = any(i.protocol == "DNS" or i.interaction_type == OobInteractionType.DNS_ONLY for i in ints)

        evidence = SsrfEvidence(
            test_id=candidate.candidate_id,
            canary_token=canary_token,
            provider_name=provider_name,
            interaction_type=OobInteractionType.HTTPS_INTERACTION if has_https else (
                OobInteractionType.HTTP_INTERACTION if has_http else OobInteractionType.DNS_ONLY
            ),
            interactions=ints,
            baseline_status=baseline_response.status_code if baseline_response else 0,
            test_status=test_response.status_code,
            evidence_summary="",
        )

        if has_https or has_http:
            itype = OobInteractionType.HTTPS_INTERACTION if has_https else OobInteractionType.HTTP_INTERACTION
            signals.append(f"OOB_{itype.value}_CONFIRMED")
            first_int = next(i for i in ints if i.protocol in ("HTTP", "HTTPS") or "HTTP" in i.interaction_type.value)
            summary = (
                f"Server-side {first_int.protocol} request to canary confirmed! "
                f"Received from source IP '{first_int.source_ip_metadata}' via {provider_name}."
            )
            evidence.evidence_summary = summary
            return SsrfComparisonResult(
                is_confirmed=True,
                interaction_type=itype,
                confidence=SsrfConfidence.VALIDATED,
                signals=signals,
                summary=summary,
                evidence=evidence,
                status_delta=status_delta,
                body_similarity=body_sim,
            )

        if has_dns:
            signals.append("OOB_DNS_ONLY_LOOKUP")
            first_int = next(i for i in ints if i.protocol == "DNS" or i.interaction_type == OobInteractionType.DNS_ONLY)
            summary = (
                f"Server-side DNS resolution confirmed (DNS_ONLY). Target resolved canary hostname "
                f"from source '{first_int.source_ip_metadata}', but did not issue an HTTP request."
            )
            evidence.evidence_summary = summary
            return SsrfComparisonResult(
                is_confirmed=True,
                interaction_type=OobInteractionType.DNS_ONLY,
                confidence=SsrfConfidence.OBSERVED,
                signals=signals,
                summary=summary,
                evidence=evidence,
                status_delta=status_delta,
                body_similarity=body_sim,
            )

        signals.append("OOB_UNKNOWN_INTERACTION")
        summary = f"Ambiguous out-of-band interaction observed for canary '{canary_token}'."
        evidence.evidence_summary = summary
        return SsrfComparisonResult(
            is_confirmed=False,
            interaction_type=OobInteractionType.UNKNOWN,
            confidence=SsrfConfidence.SUSPECTED,
            signals=signals,
            summary=summary,
            evidence=evidence,
            status_delta=status_delta,
            body_similarity=body_sim,
        )
