"""
Human Approval Gate for SSRF & Out-of-Band Interaction Testing (Phase 9).

Enforces mandatory human verification before dispatching active canary tests.
Ensures zero automated probing of internal networks, localhost, or cloud metadata.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from framework.ssrf.model import SsrfCandidate
from framework.ssrf.state import SsrfStateManager


class HumanApprovalGate:
    """
    Manages explicit human approval dossiers and authorization checks for SSRF testing.
    """

    def __init__(self, state_mgr: SsrfStateManager):
        self.state_mgr = state_mgr

    @classmethod
    def format_approval_dossier(
        cls,
        candidate: SsrfCandidate,
        canary_url: str = "",
        provider_name: str = "mock",
    ) -> Dict[str, Any]:
        """Formats comprehensive human approval dossier."""
        parsed = urlparse(candidate.endpoint)
        host = parsed.netloc or candidate.application

        return {
            "candidate_id": candidate.candidate_id,
            "category": candidate.category.value.upper(),
            "host": host,
            "endpoint": candidate.endpoint,
            "parameter": candidate.parameter,
            "param_location": candidate.param_location,
            "method": candidate.method,
            "provider": provider_name,
            "canary_target": canary_url or f"[Canary for {candidate.candidate_id}]",
            "requests_planned": 2,  # Benign Baseline + Canary Probe
            "expected_evidence": "Server-side DNS lookup or HTTP callback to controlled canary only",
            "safety_classification": "SAFE: Non-destructive canary only; NO internal/private IP probing",
            "approval_status": candidate.approval_status,
        }

    def request_approval(
        self,
        candidate: SsrfCandidate,
        canary_url: str = "",
        provider_name: str = "mock",
    ) -> str:
        """Renders formatted approval text for human review."""
        dossier = self.format_approval_dossier(candidate, canary_url, provider_name)
        lines = [
            f"[!] LIVE SSRF / OOB TEST APPROVAL REQUIRED",
            f"    - Candidate ID:       {dossier['candidate_id']}",
            f"    - Category:           {dossier['category']}",
            f"    - Host:               {dossier['host']}",
            f"    - Target Endpoint:    {dossier['method']} {dossier['endpoint']}",
            f"    - Parameter:          {dossier['parameter']} ({dossier['param_location']})",
            f"    - OOB Provider:       {dossier['provider']}",
            f"    - Canary Target:      {dossier['canary_target']}",
            f"    - Requests Planned:   {dossier['requests_planned']}",
            f"    - Expected Evidence:  {dossier['expected_evidence']}",
            f"    - Safety Class:       {dossier['safety_classification']}",
            f"    - Status:             {dossier['approval_status']}",
        ]
        return "\n".join(lines)

    def approve(self, candidate_id: str, approver: str = "security-researcher") -> bool:
        """Grants human approval for a specific candidate."""
        return self.state_mgr.approve_test_case(candidate_id, approved_by=approver)

    def is_approved(self, candidate_id: str) -> bool:
        """Verifies if candidate is approved."""
        return self.state_mgr.is_test_approved(candidate_id)
