"""
Human Approval Gate for Injection Testing (Phase 10).

Renders audit dossiers and enforces human authorization before active probes
are dispatched against target endpoints.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set

from framework.injection.model import InjectionCandidate, InjectionType
from framework.injection.payloads import InjectionPayloadRegistry


class HumanApprovalGate:
    """Manages human review and approval for injection candidate validation."""

    def __init__(self, auto_approve: bool = False):
        self.auto_approve = auto_approve
        self._approved_ids: Set[str] = set()

    def approve_candidate(self, candidate_id: str) -> None:
        self._approved_ids.add(candidate_id.strip())

    def is_candidate_approved(self, candidate: InjectionCandidate) -> bool:
        if self.auto_approve:
            return True
        return candidate.candidate_id in self._approved_ids

    def generate_dossier(self, candidate: InjectionCandidate) -> str:
        """Formats human-readable pre-test audit dossier."""
        payloads = InjectionPayloadRegistry.get_payloads_for_type(candidate.family)
        p_lines = "\n".join(
            f"      - [{p.payload_id}] {p.purpose} (Risk: {p.risk_level.value}, Template: '{p.raw_template}')"
            for p in payloads[:4]
        )

        reasons = "\n".join(f"      - {r}" for r in candidate.priority_reasons)

        dossier = f"""==============================================================================
                 INJECTION VALIDATION HUMAN APPROVAL DOSSIER                 
==============================================================================
Candidate ID:      {candidate.candidate_id}
Family:            {candidate.family.value.upper()}
Endpoint:          {candidate.method} {candidate.endpoint}
Parameter:         {candidate.parameter} (Location: {candidate.parameter_location})
Backend Context:   {candidate.backend_context.value}
Inferred Type:     {candidate.inferred_input_type}
Priority Score:    {candidate.priority_score} / 100
Confidence:        {candidate.confidence.value}
Lifecycle State:   {candidate.lifecycle.value}

Priority Justifications:
{reasons if reasons else '      - Standard parameter heuristic'}

Planned Non-Destructive Probes:
{p_lines if p_lines else '      - No active payloads registered'}

Security Safeguards:
  - Destructive statements (DROP, DELETE, UPDATE, INSERT, ALTER) strictly blocked.
  - OS command execution (curl, wget, bash, sh, rm) strictly prohibited.
  - Max payload length capped to 128 bytes.
  - Rate-limited, bounded differential baseline controls.
==============================================================================
"""
        return dossier
