"""
Invariant Evaluation Engine for Concurrency & Distributed Workflows.

Differentiates between confirmed race-condition vulnerabilities (CONFIRMED),
proper server-side concurrency serialization/locks (CONCURRENCY_CONTROLLED),
and ambiguous timing/network jitter (INCONCLUSIVE).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from framework.concurrency.model import (
    RaceCategory,
    RaceConfidence,
    SingleProbeExecution,
)
from framework.findings.lifecycle import FindingLifecycle
from framework.validation.request import ControlledResponse


class ConcurrencyInvariantEngine:
    """Evaluates business rules and invariants against concurrent burst responses."""

    @classmethod
    def evaluate_burst_results(
        cls,
        category: RaceCategory,
        allowed_limit: int,
        executions: List[SingleProbeExecution],
        responses: List[Optional[ControlledResponse]],
        post_state_data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, RaceConfidence, FindingLifecycle, str, List[str], Dict[str, Any]]:
        """
        Evaluates concurrent burst outcomes against formal safety invariants.

        Returns:
            (is_vulnerable, confidence, lifecycle_state, severity, reasons, evidence)
        """
        reasons: List[str] = []
        evidence: Dict[str, Any] = {
            "category": category.value,
            "allowed_limit": allowed_limit,
            "total_probes": len(executions),
            "status_codes": [e.status_code for e in executions],
        }

        # Analyze status codes and response bodies
        success_execs = [e for e in executions if 200 <= e.status_code < 300]
        conflict_execs = [e for e in executions if e.status_code in (409, 429, 423)] # 409 Conflict, 429 RateLimit, 423 Locked
        error_execs = [e for e in executions if e.status_code >= 500 or e.status_code == 0]
        bad_req_execs = [e for e in executions if e.status_code in (400, 403, 404)]

        success_count = len(success_execs)
        evidence["success_count"] = success_count
        evidence["conflict_count"] = len(conflict_execs)
        evidence["error_count"] = len(error_execs)

        # 1. Check for timeout or transport failure leading to inconclusive outcome
        if len(error_execs) == len(executions):
            reasons.append("All concurrent probes encountered transport errors or timeouts; outcome inconclusive.")
            return (
                False,
                RaceConfidence.INCONCLUSIVE,
                FindingLifecycle.OBSERVED,
                "INFORMATIONAL",
                reasons,
                evidence,
            )

        # 2. Case: Limit Overrun or Double Spend
        if category in (RaceCategory.LIMIT_OVERRUN, RaceCategory.DOUBLE_SPEND, RaceCategory.TOCTOU):
            # Check post-condition verification if provided
            verified_overrun = False
            actual_count = success_count

            if post_state_data:
                # E.g. post_state_data contains actual server-side counter or balance
                actual_counter = post_state_data.get("redemptions") or post_state_data.get("count") or post_state_data.get("total_votes")
                if actual_counter is not None and int(actual_counter) > allowed_limit:
                    verified_overrun = True
                    actual_count = int(actual_counter)
                    evidence["verified_server_counter"] = actual_count

                # Balance check for TOCTOU overdraw
                balance = post_state_data.get("balance")
                if balance is not None and float(balance) < 0:
                    verified_overrun = True
                    evidence["negative_balance_detected"] = float(balance)

            # Invariant breached if verified overrun OR multiple independent 200 successes exceeded limit
            if verified_overrun or success_count > allowed_limit:
                reasons.append(
                    f"Invariant violated: {actual_count} actions succeeded concurrently, "
                    f"exceeding authorized limit of {allowed_limit}."
                )
                severity = "HIGH" if category == RaceCategory.DOUBLE_SPEND else "MEDIUM"
                return (
                    True,
                    RaceConfidence.CONFIRMED,
                    FindingLifecycle.VALIDATED,
                    severity,
                    reasons,
                    evidence,
                )

            # Properly serialized / controlled concurrency
            if success_count <= allowed_limit and (conflict_execs or bad_req_execs):
                reasons.append(
                    f"Concurrency controlled: {success_count} action succeeded and subsequent requests were "
                    f"serialized or rejected ({len(conflict_execs)} conflict/locked, {len(bad_req_execs)} rejected)."
                )
                return (
                    False,
                    RaceConfidence.CONCURRENCY_CONTROLLED,
                    FindingLifecycle.OBSERVED,
                    "INFORMATIONAL",
                    reasons,
                    evidence,
                )

        # 3. Case: Idempotency Bypass
        elif category == RaceCategory.IDEMPOTENCY_BYPASS:
            # Check if identical payload or duplicate submission resulted in multiple processed records
            if success_count > allowed_limit:
                reasons.append(
                    f"Idempotency invariant breached: {success_count} duplicate concurrent requests processed "
                    f"without atomic deduplication."
                )
                return (
                    True,
                    RaceConfidence.CONFIRMED,
                    FindingLifecycle.VALIDATED,
                    "MEDIUM",
                    reasons,
                    evidence,
                )
            reasons.append("Duplicate submission prevented: duplicate requests safely deduplicated or rejected.")
            return (
                False,
                RaceConfidence.CONCURRENCY_CONTROLLED,
                FindingLifecycle.OBSERVED,
                "INFORMATIONAL",
                reasons,
                evidence,
            )

        # 4. Case: Distributed Partial Rollback / Desynchronization
        elif category == RaceCategory.PARTIAL_EXECUTION_DESYNC:
            if post_state_data and post_state_data.get("inconsistent_state"):
                reasons.append(
                    f"Distributed workflow desynchronization: partial step failure left state inconsistent: "
                    f"{post_state_data.get('details', 'rollback failure')}."
                )
                return (
                    True,
                    RaceConfidence.CONFIRMED,
                    FindingLifecycle.VALIDATED,
                    "HIGH",
                    reasons,
                    evidence,
                )
            if success_count > allowed_limit:
                reasons.append("Workflow state machine permitted conflicting multi-step state transitions.")
                return (
                    True,
                    RaceConfidence.CONFIRMED,
                    FindingLifecycle.VALIDATED,
                    "MEDIUM",
                    reasons,
                    evidence,
                )
            reasons.append("Distributed transaction maintained consistency or rolled back cleanly.")
            return (
                False,
                RaceConfidence.CONCURRENCY_CONTROLLED,
                FindingLifecycle.OBSERVED,
                "INFORMATIONAL",
                reasons,
                evidence,
            )

        # Fallback: Inconclusive
        reasons.append("Ambiguous response distribution under concurrent probe burst; invariant violation not proven.")
        return (
            False,
            RaceConfidence.INCONCLUSIVE,
            FindingLifecycle.OBSERVED,
            "INFORMATIONAL",
            reasons,
            evidence,
        )
