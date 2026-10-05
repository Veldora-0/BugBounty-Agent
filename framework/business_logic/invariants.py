"""
Business Logic Invariant Engine (Phase 12).

Defines formal invariants across application workflows:
- User cannot mutate another user's resource
- Unverified user cannot perform verified-only transitions
- Deleted resource cannot be modified
- Completed workflow cannot be replayed
- Lower privilege cannot execute admin actions
- Tenant A cannot mutate Tenant B
- Quantity cannot become negative/zero
- Price cannot be client-authoritative
- Approval must precede privileged actions
- One-time tokens must be invalidated after first use
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from framework.business_logic.model import (
    BusinessLogicCategory,
    InvariantStatus,
    WorkflowInvariant,
    WorkflowState,
)
from framework.validation.request import ControlledResponse


class BusinessLogicInvariantEngine:
    """Evaluates business rules against baseline and mutated workflow responses."""

    @classmethod
    def evaluate_invariant(
        cls,
        category: BusinessLogicCategory,
        rule_name: str,
        baseline_resp: ControlledResponse,
        test_resp: ControlledResponse,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[InvariantStatus, str, List[str]]:
        """
        Evaluates whether a specific business logic invariant was upheld or violated.
        Returns:
            (status: InvariantStatus, violation_details: str, signals: List[str])
        """
        ctx = dict(context or {})
        signals: List[str] = []

        # Helper: check HTTP success (200-299)
        test_success = 200 <= test_resp.status_code < 300
        baseline_success = 200 <= baseline_resp.status_code < 300

        # Category 1: Step Skipping / Missing Prerequisite
        if category in (BusinessLogicCategory.STEP_SKIPPING, BusinessLogicCategory.MISSING_PREREQUISITE):
            # Precondition was skipped, but test request succeeded identically or returned active data
            if test_success:
                signals.append("STEP_SKIPPING_PERMITTED")
                details = f"Uncompleted prerequisite step allowed execution of terminal step with HTTP {test_resp.status_code}."
                return InvariantStatus.INVARIANT_VIOLATED, details, signals
            signals.append("PREREQUISITE_ENFORCED")
            return InvariantStatus.INVARIANT_OBSERVED, "Prerequisite requirement enforced by server.", signals

        # Category 2: Step Reordering
        elif category == BusinessLogicCategory.STEP_REORDERING:
            if test_success:
                signals.append("UNORDERED_STEP_ACCEPTED")
                details = f"Workflow step submitted out of required state sequence succeeded with HTTP {test_resp.status_code}."
                return InvariantStatus.INVARIANT_VIOLATED, details, signals
            signals.append("ORDERING_ENFORCED")
            return InvariantStatus.INVARIANT_OBSERVED, "Workflow step sequence verified by server.", signals

        # Category 3: Replay Action / Replay Token / One-time Token
        elif category in (BusinessLogicCategory.REPLAY_ACTION, BusinessLogicCategory.REPLAY_TOKEN):
            # Replaying action or token after completion should return 400/409/410/403
            if test_success:
                signals.append("ACTION_REPLAY_SUCCESSFUL")
                details = f"Completed action or one-time token accepted multiple times with HTTP {test_resp.status_code}."
                return InvariantStatus.INVARIANT_VIOLATED, details, signals
            signals.append("REPLAY_PREVENTED")
            return InvariantStatus.INVARIANT_OBSERVED, "One-time token or completed step invalidated upon use.", signals

        # Category 4: Duplicate Action Submission
        elif category == BusinessLogicCategory.DUPLICATE_ACTION:
            if test_success and test_resp.body_text == baseline_resp.body_text:
                signals.append("DUPLICATE_ACTION_PROCESSED")
                details = "Identical action processed twice without idempotency protection."
                return InvariantStatus.INVARIANT_VIOLATED, details, signals
            return InvariantStatus.INVARIANT_OBSERVED, "Idempotency or duplicate check enforced.", signals

        # Category 5: Ownership Mismatch (BOLA/IDOR in workflow)
        elif category == BusinessLogicCategory.OWNERSHIP_MISMATCH:
            if test_success and "unauthorized" not in test_resp.body_text.lower():
                signals.append("CROSS_USER_RESOURCE_MUTATED")
                details = "Actor successfully accessed or altered another principal's resource."
                return InvariantStatus.INVARIANT_VIOLATED, details, signals
            return InvariantStatus.INVARIANT_OBSERVED, "Resource ownership barrier enforced.", signals

        # Category 6: Role Transition / Privilege Abuse
        elif category == BusinessLogicCategory.ROLE_TRANSITION_ABUSE:
            if test_success and ("admin" in test_resp.body_text.lower() or "role" in test_resp.body_text.lower()):
                signals.append("UNAUTHORIZED_ROLE_TRANSITION")
                details = "Lower-privileged actor successfully transitioned to higher privilege role."
                return InvariantStatus.INVARIANT_VIOLATED, details, signals
            return InvariantStatus.INVARIANT_OBSERVED, "Role hierarchy enforced.", signals

        # Category 7: Tenant Boundary Violation
        elif category == BusinessLogicCategory.TENANT_BOUNDARY_VIOLATION:
            if test_success:
                signals.append("CROSS_TENANT_LEAKAGE")
                details = "Tenant boundary violated; foreign tenant resource accessible."
                return InvariantStatus.INVARIANT_VIOLATED, details, signals
            return InvariantStatus.INVARIANT_OBSERVED, "Tenant isolation barrier upheld.", signals

        # Category 8: Quantity / Price / Negative Quantity
        elif category in (
            BusinessLogicCategory.QUANTITY_MANIPULATION,
            BusinessLogicCategory.PRICE_MANIPULATION,
            BusinessLogicCategory.NEGATIVE_QUANTITY,
            BusinessLogicCategory.BOUNDARY_VALUE_ABUSE,
        ):
            if test_success and ("error" not in test_resp.body_text.lower() and "invalid" not in test_resp.body_text.lower()):
                signals.append("ARITHMETIC_MANIPULATION_ACCEPTED")
                details = f"Tampered quantity/price value ({ctx.get('tampered_param', 'value')}) accepted by checkout/processing endpoint."
                return InvariantStatus.INVARIANT_VIOLATED, details, signals
            signals.append("ARITHMETIC_VALIDATION_ENFORCED")
            return InvariantStatus.INVARIANT_OBSERVED, "Negative or client-authoritative values rejected.", signals

        # Category 9: Approval Bypass
        elif category == BusinessLogicCategory.APPROVAL_BYPASS:
            if test_success:
                signals.append("APPROVAL_GATE_BYPASSED")
                details = "Privileged action executed directly without required approval step."
                return InvariantStatus.INVARIANT_VIOLATED, details, signals
            return InvariantStatus.INVARIANT_OBSERVED, "Approval requirement enforced.", signals

        # Category 10: Resource Lifecycle Abuse (e.g. modifying deleted resource)
        elif category == BusinessLogicCategory.RESOURCE_LIFECYCLE_ABUSE:
            if test_success:
                signals.append("TERMINATED_RESOURCE_MUTATED")
                details = "Deleted or locked resource accepted modification requests."
                return InvariantStatus.INVARIANT_VIOLATED, details, signals
            return InvariantStatus.INVARIANT_OBSERVED, "Resource terminal state honored.", signals

        # Category 11: Race Condition (Double-Spend / Concurrent actions)
        elif category == BusinessLogicCategory.RACE_CONDITION:
            # Context holds concurrent success count
            success_count = int(ctx.get("concurrent_successes", 1))
            limit = int(ctx.get("allowed_limit", 1))
            if success_count > limit:
                signals.append("CONCURRENT_LIMIT_EXCEEDED")
                details = f"Race window exploited: {success_count} concurrent requests succeeded when limit is {limit}."
                return InvariantStatus.INVARIANT_VIOLATED, details, signals
            signals.append("CONCURRENCY_CONTROLLED")
            return InvariantStatus.INVARIANT_OBSERVED, "Concurrency control enforced.", signals

        # Fallback / General State Tampering
        if test_success and test_resp.status_code != baseline_resp.status_code:
            signals.append("STATE_TRANSITION_ANOMALY")
            return InvariantStatus.INVARIANT_OBSERVED, "Observable differential in state transition.", signals

        return InvariantStatus.INVARIANT_EXPECTED, "Baseline state behavior preserved.", signals
