"""
Human Approval Gate for Authorization Testing (Phase 8).

Enforces strict human verification before live authorization tests can be executed.
Ensures zero accidental cross-principal probes or tenant isolation checks.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from framework.authz.model import AuthorizationTestCase
from framework.authz.state import AuthorizationStateManager


class HumanApprovalGate:
    """
    Manages explicit human approval for high-impact authorization tests.
    """

    def __init__(self, state_mgr: AuthorizationStateManager):
        self.state_mgr = state_mgr

    @classmethod
    def format_approval_dossier(cls, test_case: AuthorizationTestCase) -> Dict[str, Any]:
        """Formats comprehensive human approval dossier."""
        parsed = urlparse(test_case.endpoint)
        host = parsed.netloc or "target.local"
        owner_name = test_case.source_principal.principal_id if test_case.source_principal else "unassigned"

        return {
            "test_id": test_case.test_id,
            "category": test_case.category.value.upper(),
            "host": host,
            "endpoint": test_case.endpoint,
            "method": test_case.method,
            "owner_principal": owner_name,
            "testing_principal": test_case.testing_principal.principal_id,
            "target_resource_id": test_case.resource.resource_id,
            "substituted_identifier": test_case.substitute_identifier,
            "expected_decision": test_case.expected_decision.value,
            "requests_planned": 3,  # Baseline Owner + Baseline Nonexistent + Testing probe
            "approval_status": test_case.approval_status,
        }

    def request_approval(self, test_case: AuthorizationTestCase) -> str:
        """Renders formatted approval text for human review."""
        dossier = self.format_approval_dossier(test_case)
        lines = [
            f"[!] LIVE AUTHORIZATION TEST APPROVAL REQUIRED",
            f"    - Test ID:            {dossier['test_id']}",
            f"    - Category:           {dossier['category']}",
            f"    - Target Endpoint:    {dossier['method']} {dossier['endpoint']}",
            f"    - Owner Principal:    {dossier['owner_principal']}",
            f"    - Testing Principal:  {dossier['testing_principal']}",
            f"    - Resource ID:        {dossier['target_resource_id']}",
            f"    - Substituted ID:     {dossier['substituted_identifier']}",
            f"    - Expected Decision:  {dossier['expected_decision']}",
            f"    - Requests Planned:   {dossier['requests_planned']}",
            f"    - Status:             {dossier['approval_status']}",
        ]
        return "\n".join(lines)

    def approve(self, test_id: str, approver: str = "security-researcher") -> bool:
        """Grants approval for a specific test case."""
        return self.state_mgr.approve_test_case(test_id, approved_by=approver)

    def is_approved(self, test_id: str) -> bool:
        """Verifies if test case is approved."""
        return self.state_mgr.is_test_approved(test_id)
