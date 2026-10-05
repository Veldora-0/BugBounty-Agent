"""
Human Approval Gate for Business Logic & Workflow Testing (Phase 12).

Renders audit dossiers and enforces operator review before active state transitions,
replays, or external engine jobs are executed.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from framework.business_logic.model import WorkflowHypothesis


class WorkflowApprovalGate:
    """Manages human operator authorization for business logic tests and external engine runs."""

    def __init__(self, auto_approve: bool = False):
        self.auto_approve = auto_approve
        self._approved_ids: Set[str] = set()

    def approve_hypothesis(self, hypothesis_id: str) -> None:
        self._approved_ids.add(hypothesis_id.strip())

    def is_hypothesis_approved(self, hypothesis: WorkflowHypothesis) -> bool:
        if self.auto_approve:
            return True
        return hypothesis.hypothesis_id in self._approved_ids

    def generate_dossier(self, hypothesis: WorkflowHypothesis, details: Optional[Dict[str, Any]] = None) -> str:
        """Formats human-readable pre-test audit dossier."""
        dt = dict(details or {})
        dossier = f"""==============================================================================
               BUSINESS LOGIC & WORKFLOW HUMAN APPROVAL DOSSIER
==============================================================================
Hypothesis ID:     {hypothesis.hypothesis_id}
Workflow ID:       {hypothesis.workflow_id}
Category:          {hypothesis.category.value.upper()}
Title:             {hypothesis.title}
Target Step:       {hypothesis.target_step_id}
Target Actor:      {hypothesis.target_actor}
Priority Score:    {hypothesis.priority} / 100
Confidence:        {hypothesis.confidence.value}
Lifecycle State:   {hypothesis.lifecycle.value}

Description:
  {hypothesis.description}

Test Strategy:
  {hypothesis.test_strategy}

Safeguards:
  - Financial, payment, and real purchasing requests strictly blocked.
  - Zero automated production user deletions or email dispatch.
  - Rate-limited bounded replay (maximum 5 requests per test case).
  - Anti-SSRF and ScopeEngine enforcement active.
==============================================================================
"""
        return dossier
