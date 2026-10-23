"""
Invariant Evaluation Engine for Concurrency & Distributed Workflows.

Differentiates between confirmed race-condition vulnerabilities (CONFIRMED),
proper server-side concurrency serialization/locks (CONCURRENCY_CONTROLLED),
and ambiguous timing/network jitter (INCONCLUSIVE).

Strictly enforces:
1. Genuinely distinct resource entity identity (preventing field-alias inflation).
2. Distinction between entity identities, counters, response counts, and HTTP status codes.
3. Provenance validation for post-state evidence (untrusted caller claims rejected).
4. Unresolved in-flight worker timeouts fail closed to INCONCLUSIVE.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from framework.concurrency.model import (
    EvidenceSource,
    PostStateEvidence,
    RaceCategory,
    RaceConfidence,
    SingleProbeExecution,
    WorkerLifecycleState,
)
from framework.findings.lifecycle import FindingLifecycle
from framework.validation.request import ControlledResponse


class ResourceIdentityTracker:
    """
    Extracts and validates genuinely distinct business resource identities from responses.
    Prevents field-alias inflation (e.g. order_id: ORD-1 and id: ORD-1 refer to the same resource).
    Ensures counters, status codes, and response counts are not mixed into identity sets.
    """

    # Category-specific primary identifier keys in precedence order
    CATEGORY_PRIMARY_KEYS: Dict[RaceCategory, List[str]] = {
        RaceCategory.IDEMPOTENCY_BYPASS: ["order_id", "order", "id", "uuid", "resource_id", "record_id"],
        RaceCategory.DOUBLE_SPEND: ["redemption_id", "claim_id", "coupon_id", "tx_id", "transaction_id", "id", "uuid"],
        RaceCategory.TOCTOU: ["transaction_id", "tx_id", "transfer_id", "id", "uuid"],
        RaceCategory.LIMIT_OVERRUN: ["vote_id", "quota_id", "allocation_id", "id", "uuid"],
        RaceCategory.CONCURRENT_STATE_MUTATION: ["mutation_id", "record_id", "id", "uuid"],
        RaceCategory.PARTIAL_EXECUTION_DESYNC: ["workflow_id", "step_id", "id", "uuid"],
    }

    TRIVIAL_NON_IDENTIFIERS: Set[str] = {
        "", "none", "null", "true", "false", "ok", "success", "applied",
        "accepted", "default", "0", "-1", "undefined", "error", "failed",
    }

    @classmethod
    def extract_primary_resource_id(
        cls,
        category: RaceCategory,
        body_text: str,
    ) -> Optional[str]:
        """
        Extracts the single primary resource entity identifier from a response body.
        Resolves field aliases: multiple fields containing the same value (e.g. order_id and id)
        yield exactly one resource identifier.
        """
        if not body_text:
            return None

        # 1. Attempt JSON parsing
        try:
            data = json.loads(body_text)
            if isinstance(data, dict):
                primary_keys = cls.CATEGORY_PRIMARY_KEYS.get(
                    category, ["id", "uuid", "resource_id", "record_id"]
                )

                # Find candidate values in priority order
                for pk in primary_keys:
                    if pk in data and data[pk] is not None:
                        val = str(data[pk]).strip()
                        if val.lower() not in cls.TRIVIAL_NON_IDENTIFIERS:
                            return val

                # If no category key matched, check generic id / uuid
                for gk in ("id", "uuid"):
                    if gk in data and data[gk] is not None:
                        val = str(data[gk]).strip()
                        if val.lower() not in cls.TRIVIAL_NON_IDENTIFIERS:
                            return val

        except (json.JSONDecodeError, ValueError):
            pass

        # 2. Regex fallback for prefixed identifiers (e.g. "ORD-1", "TX-123", "RDM-1")
        regex_patterns = [
            r'"(?:order_id|redemption_id|vote_id|tx_id|transaction_id)"\s*:\s*"([^"]+)"',
            r'\b(?:order_id|redemption_id|vote_id|tx_id|transaction_id)\s*[:=]\s*([A-Za-z0-9_-]+)',
        ]
        for pat in regex_patterns:
            m = re.search(pat, body_text, re.IGNORECASE)
            if m:
                val = m.group(1).strip()
                if val.lower() not in cls.TRIVIAL_NON_IDENTIFIERS:
                    return val

        return None


class ConcurrencyInvariantEngine:
    """Evaluates business rules and invariants against concurrent burst responses."""

    @classmethod
    def _extract_response_data(
        cls,
        category: RaceCategory,
        executions: List[SingleProbeExecution],
        responses: List[Optional[ControlledResponse]],
    ) -> Tuple[List[str], Set[str], bool, Dict[str, List[int]]]:
        """
        Extracts response bodies, genuinely distinct resource IDs, idempotency signals,
        and observed counters (kept strictly separate from entity identities).
        """
        bodies: List[str] = []
        distinct_resource_ids: Set[str] = set()
        is_idempotent = False
        observed_counters: Dict[str, List[int]] = {}

        counter_keys = ("total_votes", "redemptions", "counter", "order_count", "voting_count")

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

            # Extract single primary resource identity for this response
            res_id = ResourceIdentityTracker.extract_primary_resource_id(category, body_text)
            if res_id:
                distinct_resource_ids.add(res_id)

            # Check idempotency markers and separate counter observations
            try:
                data = json.loads(body_text)
                if isinstance(data, dict):
                    if data.get("idempotent") is True:
                        is_idempotent = True
                    status_str = str(data.get("status", "")).upper()
                    if status_str in ("DUPLICATE_ORDER_IGNORED", "IDEMPOTENT_REPLAY", "CACHED", "ALREADY_PROCESSED"):
                        is_idempotent = True

                    # Track counters separately - never mix with resource identities!
                    for ck in counter_keys:
                        if ck in data and data[ck] is not None:
                            try:
                                c_val = int(data[ck])
                                observed_counters.setdefault(ck, []).append(c_val)
                            except (ValueError, TypeError):
                                pass
            except Exception:
                pass

        return bodies, distinct_resource_ids, is_idempotent, observed_counters

    @classmethod
    def evaluate_burst_results(
        cls,
        category: RaceCategory,
        allowed_limit: int,
        executions: List[SingleProbeExecution],
        responses: List[Optional[ControlledResponse]],
        post_state_data: Optional[Union[PostStateEvidence, Dict[str, Any]]] = None,
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

        # 1. Check for unresolved in-flight worker timeouts or barrier errors
        unresolved_workers = [
            e for e in executions
            if e.worker_state == WorkerLifecycleState.TIMED_OUT_UNRESOLVED
            or (e.error and "timed out" in e.error.lower())
        ]
        barrier_err_execs = [e for e in executions if e.error and "barrier synchronization" in e.error.lower()]

        if unresolved_workers or barrier_err_execs:
            evidence["unresolved_workers_count"] = len(unresolved_workers)
            reasons.append(
                "Worker timeout or unresolved in-flight probes: one or more worker threads timed out while HTTP dispatch was in flight; "
                "server-side state mutation outcome cannot be established safely. Outcome is inconclusive."
            )
            return (
                False,
                RaceConfidence.INCONCLUSIVE,
                FindingLifecycle.OBSERVED,
                "INFORMATIONAL",
                reasons,
                evidence,
            )

        # 2. Extract response representations, genuinely distinct resource IDs, and separate counters
        bodies, distinct_resource_ids, is_idempotent, observed_counters = cls._extract_response_data(
            category, executions, responses
        )
        bodies_are_identical = (len(set(bodies)) == 1) if bodies else False
        evidence["distinct_resource_ids"] = sorted(list(distinct_resource_ids))
        evidence["distinct_resources_count"] = len(distinct_resource_ids)
        if observed_counters:
            evidence["observed_response_counters"] = observed_counters

        # 3. Provenance and Trust Boundary Validation for Post-State Evidence
        post_state_evidence: Optional[PostStateEvidence] = None
        if isinstance(post_state_data, PostStateEvidence):
            post_state_evidence = post_state_data
        elif isinstance(post_state_data, dict):
            post_state_evidence = PostStateEvidence.from_dict(post_state_data)

        post_state_overrun = False
        post_state_controlled = False
        post_state_inconsistent = False
        authoritative_counter_value: Optional[int] = None

        if post_state_evidence:
            evidence["post_state_provenance"] = post_state_evidence.to_dict()

            # Separate untrusted caller claims from verified evidence
            if not post_state_evidence.is_authoritative():
                reasons.append(
                    "Caller-supplied post-state evidence lacks authoritative provenance "
                    f"({post_state_evidence.source.value}); cannot independently confirm state mutation."
                )
            else:
                # Authoritative source: validate internal consistency
                is_consistent, consistency_err = post_state_evidence.validate_consistency()
                if not is_consistent:
                    reasons.append(f"Post-state verification failed consistency check: {consistency_err}")
                    return (
                        False,
                        RaceConfidence.INCONCLUSIVE,
                        FindingLifecycle.OBSERVED,
                        "INFORMATIONAL",
                        reasons,
                        evidence,
                    )

                # Evaluate authoritative post-state metrics
                ps = post_state_evidence.post_state or {}
                pre = post_state_evidence.pre_state or {}

                # Check balance metrics for overdraw (especially for TOCTOU / balance transfer scenarios)
                for bk in ("balance", "account_balance", "remaining_balance"):
                    if bk in ps and ps[bk] is not None:
                        try:
                            b_val = float(ps[bk])
                            if b_val < 0:
                                post_state_overrun = True
                                evidence["negative_balance_detected"] = b_val
                            break
                        except (ValueError, TypeError):
                            pass

                # Category-specific counter metrics mapping
                category_counter_map: Dict[RaceCategory, Tuple[str, ...]] = {
                    RaceCategory.DOUBLE_SPEND: ("coupon_redemptions", "redemptions", "claims", "count"),
                    RaceCategory.LIMIT_OVERRUN: ("voting_count", "total_votes", "rate_limit_hits", "counter", "hits", "count"),
                    RaceCategory.IDEMPOTENCY_BYPASS: ("order_count", "orders", "tx_count", "count"),
                    RaceCategory.TOCTOU: ("transfers", "count"),
                    RaceCategory.CONCURRENT_STATE_MUTATION: ("safe_mutex_counter", "counter", "mutations", "count"),
                    RaceCategory.PARTIAL_EXECUTION_DESYNC: (),
                }
                counter_keys = category_counter_map.get(
                    category,
                    ("count", "counter", "redemptions", "total_votes", "order_count", "coupon_redemptions", "voting_count")
                )
                for ck in counter_keys:
                    if ck in ps and ps[ck] is not None:
                        try:
                            c_val = int(ps[ck])
                            authoritative_counter_value = c_val
                            evidence["verified_server_counter"] = c_val

                            # If pre-state is available, calculate delta
                            if ck in pre and pre[ck] is not None:
                                pre_val = int(pre[ck])
                                delta = c_val - pre_val
                                evidence["verified_counter_delta"] = delta
                                if delta > allowed_limit:
                                    post_state_overrun = True
                                elif not post_state_overrun:
                                    post_state_controlled = True
                            else:
                                if c_val > allowed_limit:
                                    post_state_overrun = True
                                elif not post_state_overrun:
                                    post_state_controlled = True
                            break
                        except (ValueError, TypeError):
                            pass

                # Check distributed inconsistent state
                if ps.get("inconsistent_state") is True:
                    post_state_inconsistent = True
                elif ps.get("distributed_step1_committed") is True and not ps.get("distributed_step2_committed"):
                    post_state_inconsistent = True

        # 4. Check for pure transport failure
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

        # 5. Invariant Evaluation: Limit Overrun, Double Spend, TOCTOU, Concurrent State Mutation
        if category in (
            RaceCategory.LIMIT_OVERRUN,
            RaceCategory.DOUBLE_SPEND,
            RaceCategory.TOCTOU,
            RaceCategory.CONCURRENT_STATE_MUTATION,
        ):
            # Authoritative post-state proves overrun
            if post_state_overrun:
                count_str = f"{authoritative_counter_value} mutations" if authoritative_counter_value is not None else "overrun"
                reasons.append(
                    f"Invariant violated: verified server-side state mutation ({count_str}) "
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

            # Authoritative post-state proves operations bounded within limit
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

            # Distinct provisional identifiers returned across responses without authoritative state proof
            if len(distinct_resource_ids) > allowed_limit:
                reasons.append(
                    f"Observed {len(distinct_resource_ids)} distinct provisional response identifiers "
                    f"({', '.join(sorted(list(distinct_resource_ids))[:3])}) across concurrent responses, "
                    f"but lacking authoritative server-side state verification; outcome is suspected, not confirmed."
                )
                evidence["observed_distinct_response_identifiers"] = sorted(list(distinct_resource_ids))
                return (
                    False,
                    RaceConfidence.SUSPECTED,
                    FindingLifecycle.OBSERVED,
                    "INFORMATIONAL",
                    reasons,
                    evidence,
                )

            # Multiple 200 OK responses, but no distinct resource IDs and no authoritative post-state proof
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
                    f"authoritative server-side state mutation proof; outcome inconclusive."
                )
                return (
                    False,
                    RaceConfidence.INCONCLUSIVE,
                    FindingLifecycle.OBSERVED,
                    "INFORMATIONAL",
                    reasons,
                    evidence,
                )

            # Normal concurrency controls (409 Conflict, 429 RateLimit, or serialized success)
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

        # 6. Invariant Evaluation: Idempotency Bypass
        elif category == RaceCategory.IDEMPOTENCY_BYPASS:
            if post_state_overrun:
                reasons.append(
                    f"Idempotency invariant breached: authoritative server-side state verification confirmed "
                    f"duplicate records created without atomic deduplication."
                )
                return (
                    True,
                    RaceConfidence.CONFIRMED,
                    FindingLifecycle.VALIDATED,
                    "MEDIUM",
                    reasons,
                    evidence,
                )
            if is_idempotent or (bodies_are_identical and len(distinct_resource_ids) <= allowed_limit) or post_state_controlled:
                reasons.append(
                    "Duplicate submission prevented: duplicate requests safely deduplicated or "
                    "returned idempotent cached representation."
                )
                return (
                    False,
                    RaceConfidence.CONCURRENCY_CONTROLLED,
                    FindingLifecycle.OBSERVED,
                    "INFORMATIONAL",
                    reasons,
                    evidence,
                )
            if len(distinct_resource_ids) > allowed_limit:
                reasons.append(
                    f"Observed {len(distinct_resource_ids)} distinct provisional response identifiers "
                    f"({', '.join(sorted(list(distinct_resource_ids))[:3])}) across duplicate submissions, "
                    f"but lacking authoritative server-side state verification; outcome is suspected, not confirmed."
                )
                evidence["observed_distinct_response_identifiers"] = sorted(list(distinct_resource_ids))
                return (
                    False,
                    RaceConfidence.SUSPECTED,
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

        # 7. Invariant Evaluation: Distributed Partial Rollback / Desynchronization
        elif category == RaceCategory.PARTIAL_EXECUTION_DESYNC:
            if post_state_inconsistent:
                ps = post_state_evidence.post_state if post_state_evidence else {}
                details = str(ps.get("details", "authoritative post-state verified rollback failure"))
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

            reasons.append(
                "No authoritative server-side post-state evidence of inconsistent distributed state "
                "or uncompensated rollback; outcome inconclusive."
            )
            return (
                False,
                RaceConfidence.INCONCLUSIVE,
                FindingLifecycle.OBSERVED,
                "INFORMATIONAL",
                reasons,
                evidence,
            )

        # Fallback
        reasons.append("Ambiguous response distribution under concurrent probe burst; invariant violation not proven.")
        return (
            False,
            RaceConfidence.INCONCLUSIVE,
            FindingLifecycle.OBSERVED,
            "INFORMATIONAL",
            reasons,
            evidence,
        )
