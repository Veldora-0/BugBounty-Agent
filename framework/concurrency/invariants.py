"""
Invariant Evaluation Engine for Concurrency & Distributed Workflows.

Differentiates between confirmed race-condition vulnerabilities (CONFIRMED),
proper server-side concurrency serialization/locks (CONCURRENCY_CONTROLLED),
and ambiguous timing/network jitter (INCONCLUSIVE).

Strictly enforces reliable proof of business-state mutation (distinct committed
resource IDs, server post-state counter > limit, negative balance) or verified
distributed workflow desynchronization before classifying as CONFIRMED.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

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
    def _extract_response_data(
        cls,
        executions: List[SingleProbeExecution],
        responses: List[Optional[ControlledResponse]],
    ) -> Tuple[List[str], Set[str], bool]:
        """
        Extracts response body representations, distinct resource IDs, and idempotency markers.
        """
        bodies: List[str] = []
        distinct_ids: Set[str] = set()
        is_idempotent = False

        id_keys = {
            "order_id",
            "redemption_id",
            "vote_id",
            "transaction_id",
            "tx_id",
            "id",
            "uuid",
            "resource_id",
            "coupon_id",
            "transfer_id",
            "record_id",
        }

        # Inspect responses
        for idx, exec_info in enumerate(executions):
            if not (200 <= exec_info.status_code < 300):
                continue

            resp_obj = responses[idx] if idx < len(responses) else None
            body_text = ""
            if resp_obj and (resp_obj.body_text or resp_obj.body):
                body_text = resp_obj.body_text or resp_obj.body or ""
            elif exec_info.body_snippet:
                body_text = exec_info.body_snippet

            if body_text:
                bodies.append(body_text.strip())

            # Attempt JSON parsing
            try:
                data = json.loads(body_text)
                if isinstance(data, dict):
                    # Check idempotency markers
                    if data.get("idempotent") is True:
                        is_idempotent = True
                    status_str = str(data.get("status", "")).upper()
                    if status_str in ("DUPLICATE_ORDER_IGNORED", "IDEMPOTENT_REPLAY", "CACHED", "ALREADY_PROCESSED"):
                        is_idempotent = True

                    # Look for distinct identifiers
                    for k in id_keys:
                        if k in data and data[k] is not None:
                            val_str = str(data[k]).strip()
                            if val_str:
                                distinct_ids.add(f"{k}:{val_str}")

                    # Look for counter progression if distinct
                    for c_key in ("total_votes", "redemptions", "counter", "order_count"):
                        if c_key in data and data[c_key] is not None:
                            distinct_ids.add(f"{c_key}:{data[c_key]}")

            except Exception:
                # Text or regex fallback for resource IDs
                for m in re.finditer(r'"(?:order_id|redemption_id|vote_id|tx_id|id)"\s*:\s*"([^"]+)"', body_text):
                    distinct_ids.add(m.group(1))

        return bodies, distinct_ids, is_idempotent

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

        # Analyze status codes
        success_execs = [e for e in executions if 200 <= e.status_code < 300]
        conflict_execs = [e for e in executions if e.status_code in (409, 429, 423)]
        error_execs = [e for e in executions if e.status_code >= 500 or e.status_code == 0]
        bad_req_execs = [e for e in executions if e.status_code in (400, 403, 404)]

        success_count = len(success_execs)
        evidence["success_count"] = success_count
        evidence["conflict_count"] = len(conflict_execs)
        evidence["error_count"] = len(error_execs)

        # 1. Check for worker timeouts or barrier synchronization errors
        timeout_execs = [e for e in executions if e.error and "timed out" in e.error.lower()]
        barrier_err_execs = [e for e in executions if e.error and "barrier synchronization" in e.error.lower()]
        if timeout_execs or barrier_err_execs:
            reasons.append(
                "Worker timeout or barrier synchronization failure: completion of all concurrent probes "
                "could not be established; outcome inconclusive."
            )
            return (
                False,
                RaceConfidence.INCONCLUSIVE,
                FindingLifecycle.OBSERVED,
                "INFORMATIONAL",
                reasons,
                evidence,
            )

        # 2. Extract response bodies, distinct IDs, and idempotency signals
        bodies, distinct_ids, is_idempotent = cls._extract_response_data(executions, responses)
        bodies_are_identical = (len(set(bodies)) == 1) if bodies else False

        # 3. Analyze authoritative post-state data if available
        post_state_overrun = False
        post_state_controlled = False
        post_state_inconsistent = False
        actual_server_count: Optional[int] = None

        if isinstance(post_state_data, dict) and post_state_data:
            # Check counter metrics safely
            counter_keys = (
                "redemptions",
                "count",
                "total_votes",
                "counter",
                "order_count",
                "coupon_redemptions",
                "voting_count",
                "transfers",
            )
            for ck in counter_keys:
                if ck in post_state_data and post_state_data[ck] is not None:
                    try:
                        c_val = int(post_state_data[ck])
                        actual_server_count = c_val
                        evidence["verified_server_counter"] = c_val
                        if c_val > allowed_limit:
                            post_state_overrun = True
                        else:
                            post_state_controlled = True
                        break
                    except (ValueError, TypeError):
                        pass

            # Check balance metrics safely
            balance_keys = ("balance", "account_balance", "remaining_balance")
            for bk in balance_keys:
                if bk in post_state_data and post_state_data[bk] is not None:
                    try:
                        b_val = float(post_state_data[bk])
                        if b_val < 0:
                            post_state_overrun = True
                            evidence["negative_balance_detected"] = b_val
                        break
                    except (ValueError, TypeError):
                        pass

            if post_state_data.get("overrun_verified") is True:
                post_state_overrun = True
            if post_state_data.get("inconsistent_state") is True:
                post_state_inconsistent = True

        # 4. Check for pure transport failures
        if len(error_execs) == len(executions) and category != RaceCategory.PARTIAL_EXECUTION_DESYNC:
            reasons.append("All concurrent probes encountered transport errors or timeouts; outcome inconclusive.")
            return (
                False,
                RaceConfidence.INCONCLUSIVE,
                FindingLifecycle.OBSERVED,
                "INFORMATIONAL",
                reasons,
                evidence,
            )

        # 5. Case: Limit Overrun, Double Spend, TOCTOU, Concurrent State Mutation
        if category in (
            RaceCategory.LIMIT_OVERRUN,
            RaceCategory.DOUBLE_SPEND,
            RaceCategory.TOCTOU,
            RaceCategory.CONCURRENT_STATE_MUTATION,
        ):
            # A. Authoritative post-state proves overrun
            if post_state_overrun:
                count_desc = f"{actual_server_count} mutations" if actual_server_count is not None else "overrun"
                reasons.append(
                    f"Invariant violated: verified server-side state mutation ({count_desc}) "
                    f"exceeded authorized limit of {allowed_limit}."
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

            # B. Authoritative post-state proves only allowed operations were committed
            if post_state_controlled:
                reasons.append(
                    f"Concurrency controlled: server-side state verified bounded within "
                    f"authorized limit of {allowed_limit}."
                )
                return (
                    False,
                    RaceConfidence.CONCURRENCY_CONTROLLED,
                    FindingLifecycle.OBSERVED,
                    "INFORMATIONAL",
                    reasons,
                    evidence,
                )

            # C. Distinct committed resource IDs returned across concurrent responses
            if len(distinct_ids) > allowed_limit:
                evidence["distinct_resource_ids"] = sorted(list(distinct_ids))
                reasons.append(
                    f"Invariant violated: {len(distinct_ids)} distinct committed resource identifiers "
                    f"({', '.join(sorted(list(distinct_ids))[:3])}) returned, exceeding authorized limit of {allowed_limit}."
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

            # D. Multiple 200 OK responses, but identical bodies / no verified mutation proof
            if success_count > allowed_limit:
                if is_idempotent:
                    reasons.append(
                        "Concurrency controlled: duplicate requests safely deduplicated or returned "
                        "idempotent cached representations."
                    )
                    return (
                        False,
                        RaceConfidence.CONCURRENCY_CONTROLLED,
                        FindingLifecycle.OBSERVED,
                        "INFORMATIONAL",
                        reasons,
                        evidence,
                    )
                if bodies_are_identical:
                    reasons.append(
                        f"Ambiguous outcome: {success_count} identical HTTP 200 OK responses returned "
                        f"without verified business-state mutation proof or distinct resource identifiers; outcome inconclusive."
                    )
                    return (
                        False,
                        RaceConfidence.INCONCLUSIVE,
                        FindingLifecycle.OBSERVED,
                        "INFORMATIONAL",
                        reasons,
                        evidence,
                    )
                reasons.append(
                    f"Ambiguous outcome: {success_count} successful responses returned but lacked "
                    f"distinct committed resource identifiers or post-state mutation proof; outcome inconclusive."
                )
                return (
                    False,
                    RaceConfidence.INCONCLUSIVE,
                    FindingLifecycle.OBSERVED,
                    "INFORMATIONAL",
                    reasons,
                    evidence,
                )

            # E. Properly serialized / rate limited / controlled concurrency
            if success_count <= allowed_limit and (conflict_execs or bad_req_execs or success_count == allowed_limit):
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

        # 6. Case: Idempotency Bypass
        elif category == RaceCategory.IDEMPOTENCY_BYPASS:
            if post_state_overrun or len(distinct_ids) > allowed_limit:
                evidence["distinct_resource_ids"] = sorted(list(distinct_ids))
                reasons.append(
                    f"Idempotency invariant breached: {len(distinct_ids) or success_count} distinct duplicate operations "
                    f"processed without atomic deduplication."
                )
                return (
                    True,
                    RaceConfidence.CONFIRMED,
                    FindingLifecycle.VALIDATED,
                    "MEDIUM",
                    reasons,
                    evidence,
                )
            if is_idempotent or (bodies_are_identical and len(distinct_ids) <= allowed_limit) or post_state_controlled:
                reasons.append(
                    "Duplicate submission prevented: duplicate requests safely deduplicated or "
                    "returned idempotent cached response."
                )
                return (
                    False,
                    RaceConfidence.CONCURRENCY_CONTROLLED,
                    FindingLifecycle.OBSERVED,
                    "INFORMATIONAL",
                    reasons,
                    evidence,
                )
            if success_count > allowed_limit:
                reasons.append(
                    "Multiple responses received without verified proof of duplicate processing or "
                    "distinct resource creation; outcome inconclusive."
                )
                return (
                    False,
                    RaceConfidence.INCONCLUSIVE,
                    FindingLifecycle.OBSERVED,
                    "INFORMATIONAL",
                    reasons,
                    evidence,
                )
            reasons.append("Duplicate submission prevented: concurrent requests safely serialized or rejected.")
            return (
                False,
                RaceConfidence.CONCURRENCY_CONTROLLED,
                FindingLifecycle.OBSERVED,
                "INFORMATIONAL",
                reasons,
                evidence,
            )

        # 7. Case: Distributed Workflow Partial Desynchronization
        elif category == RaceCategory.PARTIAL_EXECUTION_DESYNC:
            has_inconsistent_proof = False
            details = ""

            if post_state_inconsistent:
                has_inconsistent_proof = True
                details = str(post_state_data.get("details", "post-state verified rollback failure"))
            else:
                for resp in responses:
                    if resp:
                        b_text = (resp.body_text or resp.body or "").lower()
                        if '"inconsistent_state": true' in b_text or '"inconsistent_state":true' in b_text:
                            has_inconsistent_proof = True
                            try:
                                j_obj = json.loads(resp.body_text or resp.body or "")
                                details = j_obj.get("details", "response body verified rollback failure")
                            except Exception:
                                details = "response body indicated inconsistent state"
                            break

                if not has_inconsistent_proof:
                    for ex in executions:
                        snippet = ex.body_snippet.lower()
                        if '"inconsistent_state": true' in snippet or '"inconsistent_state":true' in snippet:
                            has_inconsistent_proof = True
                            details = "telemetry snippet indicated inconsistent state"
                            break

            if has_inconsistent_proof:
                evidence["inconsistent_state_details"] = details
                reasons.append(
                    f"Distributed workflow desynchronization: partial step failure left state inconsistent: {details}."
                )
                return (
                    True,
                    RaceConfidence.CONFIRMED,
                    FindingLifecycle.VALIDATED,
                    "HIGH",
                    reasons,
                    evidence,
                )

            # Partial failure or 500 error where consistency could NOT be established
            reasons.append(
                "Distributed workflow failure encountered but transactional state consistency or "
                "rollback failure could not be established; outcome inconclusive."
            )
            return (
                False,
                RaceConfidence.INCONCLUSIVE,
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
