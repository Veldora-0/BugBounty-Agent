"""
Human Approval Gate for HTTP Header Trust Testing (Phase 11).

Renders audit dossiers and enforces human authorization before active probes
are dispatched against target endpoints.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set

from framework.http_trust.model import HeaderTrustCandidate, HttpTrustCategory


class HumanApprovalGate:
    """Manages human review and approval for HTTP header trust candidate validation."""

    def __init__(self, auto_approve: bool = False):
        self.auto_approve = auto_approve
        self._approved_ids: Set[str] = set()

    def approve_candidate(self, candidate_id: str) -> None:
        self._approved_ids.add(candidate_id.strip())

    def is_candidate_approved(self, candidate: HeaderTrustCandidate) -> bool:
        if self.auto_approve:
            return True
        return candidate.candidate_id in self._approved_ids

    def generate_dossier(self, candidate: HeaderTrustCandidate) -> str:
        """Formats human-readable pre-test audit dossier."""
        dossier = f"""==============================================================================
                 HTTP TRUST VALIDATION HUMAN APPROVAL DOSSIER                 
==============================================================================
Candidate ID:      {candidate.candidate_id}
Category:          {candidate.category.value.upper()}
Header Name:       {candidate.header_name}
Endpoint:          {candidate.method} {candidate.endpoint}
Application:       {candidate.application}
Priority Score:    {candidate.priority} / 100
Confidence:        {candidate.confidence.value}
Lifecycle State:   {candidate.lifecycle.value}

Observed Behavior: {candidate.observed_behavior or 'Unprobed candidate'}
Trust Classification: {candidate.trust_classification.value}
Trust Source:      {candidate.trust_source.value}

Security Safeguards:
  - Canary domain strictly bounded: bb11-<program>-<id>.researcher-controlled.example.
  - Safe methods only by default (GET, HEAD, OPTIONS).
  - Anti-SSRF & private-IP egress controls enforced.
  - No automated stateful account mutations (password reset emails not submitted).
  - No shared production cache poisoning.
==============================================================================
"""
        return dossier
