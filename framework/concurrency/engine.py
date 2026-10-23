"""
Race Conditions & Distributed Workflows Intelligence Engine (Phase 20).

Primary orchestrator coordinating concurrency hypothesis formulation,
scope/approval gating, precision barrier burst dispatching, formal invariant
evaluation, deduplication, and structured finding generation.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import re
import socket
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import uuid

from framework.common.config import get_program_dir
from framework.common.evidence import sanitize_sensitive_data
from framework.concurrency.invariants import ConcurrencyInvariantEngine
from framework.concurrency.model import (
    ConcurrencyProbePlan,
    RaceCategory,
    RaceConfidence,
    RaceConditionHypothesis,
    RaceConditionTestResult,
    SingleProbeExecution,
)
from framework.concurrency.policy import ConcurrencySafetyPolicy
from framework.concurrency.state import ConcurrencyStateManager
from framework.concurrency.synchronization import BarrierSynchronizer
from framework.findings.lifecycle import FindingLifecycle
from framework.findings.schema import Finding
from framework.scope.engine import ScopeEngine, ScopeStatus
from framework.state.manager import StateManager
from framework.validation.engine import ScopeViolationError, SecurityValidationEngine
from framework.validation.model import VulnerabilityFamily
from framework.validation.policy import PolicyViolationError, SecurityTestPolicy
from framework.validation.request import ControlledRequest, ControlledResponse


def _classify_request_exception(exc: Exception) -> str:
    """
    Returns a safe, high-level diagnostic string for a request exception.
    Strictly avoids exposing raw str(exc), URLs, query strings, headers, credentials,
    or response content.
    """
    exc_type = type(exc).__name__
    exc_module = getattr(type(exc), "__module__", "")

    if "Scope" in exc_type or "scope" in exc_module.lower():
        return "scope authorization failure"
    if "Policy" in exc_type or "policy" in exc_module.lower():
        return "security policy violation"

    if isinstance(exc, (TimeoutError, socket.timeout)) or "Timeout" in exc_type:
        return "connection or read timeout"
    if "SSL" in exc_type or "Certificate" in exc_type or "TLS" in exc_type:
        return "TLS/SSL handshake or certificate error"
    if isinstance(exc, ConnectionError) or any(k in exc_type for k in ("Connection", "Unreachable", "GaiError", "Resolve")):
        return "network connection failure"
    if "HTTP" in exc_type:
        return "HTTP protocol error"

    safe_name = re.sub(r"[^A-Za-z0-9_]", "", exc_type) or "ExecutionError"
    return f"network transport error ({safe_name})"


class RaceIntelligenceEngine:
    """Subsystem engine for concurrent state-machine and distributed workflow intelligence."""

    def __init__(
        self,
        program_dir: str,
        scope_engine: Optional[ScopeEngine] = None,
        policy: Optional[ConcurrencySafetyPolicy] = None,
        validation_engine: Optional[SecurityValidationEngine] = None,
        dispatch_fn: Optional[Callable[[ControlledRequest], ControlledResponse]] = None,
        require_approval: bool = True,
        lab_mode: bool = False,
    ):
        self.program_dir = os.path.abspath(program_dir)
        self.program_name = os.path.basename(self.program_dir)
        self.scope_engine = scope_engine
        self.policy = policy or ConcurrencySafetyPolicy(require_approval=require_approval, lab_mode=lab_mode)
        self.require_approval = require_approval
        self.lab_mode = lab_mode

        # Persistence managers
        self.state_mgr = ConcurrencyStateManager(self.program_dir)
        self.main_state_mgr: Optional[StateManager] = None
        try:
            self.main_state_mgr = StateManager(self.program_dir)
        except Exception:
            pass

        # Dispatch mechanism
        if dispatch_fn:
            self._dispatch_fn = dispatch_fn
        elif validation_engine:
            self._validation_engine = validation_engine
            self._dispatch_fn = validation_engine.send_request
        else:
            val_policy = SecurityTestPolicy(
                allowed_methods={"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"},
                max_requests_per_test=self.policy.max_requests_per_test,
                timeout=self.policy.timeout,
                block_destructive_actions=False,
            )
            self._validation_engine = SecurityValidationEngine(
                program_dir=self.program_dir,
                scope_engine=self.scope_engine,
                policy=val_policy,
            )
            self._dispatch_fn = self._validation_engine.send_request

        self.synchronizer = BarrierSynchronizer(self._send_request_safe, timeout=self.policy.timeout)
        self._request_budget_lock = threading.Lock()
        self._current_test_requests = 0

    def allow_fixture_port(self, port: int) -> None:
        """Whitelists an ephemeral local test fixture port."""
        self.policy.allow_fixture_port(port)
        if hasattr(self, "_validation_engine") and self._validation_engine:
            self._validation_engine.allow_fixture_port(port)

    def _send_request_safe(self, req: ControlledRequest) -> ControlledResponse:
        """
        Enforces fail-closed scope gating, anti-SSRF policy, and request budget limits
        immediately before each probe is dispatched.
        """
        # 1. Fail-closed scope enforcement
        if not self.lab_mode:
            if self.scope_engine is None:
                raise ScopeViolationError("ScopeEngine is required in production mode; refusing to dispatch unvetted requests.")
            decision = self.scope_engine.check(req.url)
            if decision.status != ScopeStatus.IN_SCOPE:
                raise ScopeViolationError(f"Scope authorization failure for {req.url}: {decision.reason}")
        elif self.scope_engine:
            decision = self.scope_engine.check(req.url)
            if decision.status != ScopeStatus.IN_SCOPE:
                raise ScopeViolationError(f"Scope authorization failure for {req.url}: {decision.reason}")

        # 2. Concurrency Safety Policy validation (methods, SSRF, fixture ports)
        self.policy.validate_request_safety(req.method, req.url)

        # 3. Enforce actual request budget per test
        with self._request_budget_lock:
            if self._current_test_requests >= self.policy.max_requests_per_test:
                raise PolicyViolationError(
                    f"Request budget exceeded: maximum {self.policy.max_requests_per_test} requests per test."
                )
            self._current_test_requests += 1

        return self._dispatch_fn(req)

    def add_hypothesis(
        self,
        endpoint: str,
        category: RaceCategory,
        method: str = "POST",
        allowed_limit: int = 1,
        burst_size: int = 4,
        description: str = "",
    ) -> RaceConditionHypothesis:
        """Registers a new race condition hypothesis."""
        hyp = RaceConditionHypothesis(
            hypothesis_id=f"hyp-race-{uuid.uuid4().hex[:8]}",
            program=self.program_name,
            category=category,
            endpoint=endpoint,
            method=method.upper(),
            description=description or f"Concurrent invariant testing for {category.value} on {endpoint}",
            allowed_limit=allowed_limit,
            burst_size=self.policy.validate_burst_size(burst_size),
            approval_status="APPROVED" if not self.require_approval else "PENDING",
        )
        self.state_mgr.save_hypothesis(hyp)
        return hyp

    def discover_hypotheses_from_state(self) -> List[RaceConditionHypothesis]:
        """Infers candidate state transitions from existing program intelligence files."""
        hypotheses: List[RaceConditionHypothesis] = []
        state_dir = os.path.join(self.program_dir, "state")
        endpoints: List[Dict[str, str]] = []

        # Inspect api.json and webapps.json
        for fname in ("api.json", "webapps.json", "endpoints.json"):
            fpath = os.path.join(state_dir, fname)
            if os.path.isfile(fpath):
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    items = data.get("endpoints") or data.get("routes") or []
                    for it in items:
                        if isinstance(it, dict):
                            url = it.get("url") or it.get("path")
                            meth = it.get("method", "POST")
                            if url:
                                endpoints.append({"url": url, "method": meth})
                except Exception:
                    pass

        # Keywords indicating check-then-act, coupons, limits, transfers
        keywords = {
            "coupon": RaceCategory.DOUBLE_SPEND,
            "voucher": RaceCategory.DOUBLE_SPEND,
            "promo": RaceCategory.DOUBLE_SPEND,
            "redeem": RaceCategory.DOUBLE_SPEND,
            "transfer": RaceCategory.TOCTOU,
            "withdraw": RaceCategory.TOCTOU,
            "vote": RaceCategory.LIMIT_OVERRUN,
            "checkout": RaceCategory.IDEMPOTENCY_BYPASS,
            "order": RaceCategory.IDEMPOTENCY_BYPASS,
            "claim": RaceCategory.LIMIT_OVERRUN,
        }

        for ep in endpoints:
            url = ep["url"]
            method = ep["method"].upper()
            url_low = url.lower()
            for kw, cat in keywords.items():
                if kw in url_low:
                    h = self.add_hypothesis(
                        endpoint=url,
                        category=cat,
                        method=method,
                        allowed_limit=1,
                        burst_size=4,
                        description=f"Automated pattern detection matched '{kw}' keyword for {cat.value}.",
                    )
                    hypotheses.append(h)
                    break

        return hypotheses

    def execute_hypothesis(
        self,
        hypothesis: RaceConditionHypothesis,
        auto_approve: bool = False,
        request_body: str = "",
        headers: Optional[Dict[str, str]] = None,
        post_state_data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[RaceConditionTestResult, Optional[Finding]]:
        """
        Executes bounded, barrier-synchronized concurrency probe burst against target endpoint.
        """
        # Reset per-test request counter
        with self._request_budget_lock:
            self._current_test_requests = 0

        # Scope fail-closed check
        if not self.lab_mode and self.scope_engine is None:
            hypothesis.lifecycle_state = FindingLifecycle.REJECTED
            hypothesis.notes = "Scope policy violation: ScopeEngine required in production mode"
            self.state_mgr.save_hypothesis(hypothesis)
            res = RaceConditionTestResult(
                hypothesis_id=hypothesis.hypothesis_id,
                category=hypothesis.category,
                confidence=RaceConfidence.INCONCLUSIVE,
                lifecycle_state=FindingLifecycle.REJECTED,
                severity="INFORMATIONAL",
                is_vulnerable=False,
                burst_size=0,
                success_count=0,
                failure_count=0,
                reasons=["Scope policy violation: ScopeEngine required in production mode"],
            )
            return res, None

        if self.scope_engine:
            try:
                decision = self.scope_engine.check(hypothesis.endpoint)
                if decision.status != ScopeStatus.IN_SCOPE:
                    hypothesis.lifecycle_state = FindingLifecycle.REJECTED
                    hypothesis.notes = f"Rejected: out of scope ({decision.reason})"
                    self.state_mgr.save_hypothesis(hypothesis)
                    res = RaceConditionTestResult(
                        hypothesis_id=hypothesis.hypothesis_id,
                        category=hypothesis.category,
                        confidence=RaceConfidence.INCONCLUSIVE,
                        lifecycle_state=FindingLifecycle.REJECTED,
                        severity="INFORMATIONAL",
                        is_vulnerable=False,
                        burst_size=0,
                        success_count=0,
                        failure_count=0,
                        reasons=[f"Scope policy violation: {hypothesis.endpoint} is {decision.status.value}"],
                    )
                    return res, None
            except Exception as exc:
                hypothesis.lifecycle_state = FindingLifecycle.REJECTED
                hypothesis.notes = f"Rejected: scope evaluation error ({_classify_request_exception(exc)})"
                self.state_mgr.save_hypothesis(hypothesis)
                res = RaceConditionTestResult(
                    hypothesis_id=hypothesis.hypothesis_id,
                    category=hypothesis.category,
                    confidence=RaceConfidence.INCONCLUSIVE,
                    lifecycle_state=FindingLifecycle.REJECTED,
                    severity="INFORMATIONAL",
                    is_vulnerable=False,
                    burst_size=0,
                    success_count=0,
                    failure_count=0,
                    reasons=[f"Scope authorization failure: {_classify_request_exception(exc)}"],
                )
                return res, None

        # Approval gate
        if self.require_approval and not auto_approve and hypothesis.approval_status != "APPROVED":
            hypothesis.lifecycle_state = FindingLifecycle.HYPOTHESIS
            hypothesis.notes = "Awaiting operator approval before concurrent burst dispatch"
            self.state_mgr.save_hypothesis(hypothesis)
            res = RaceConditionTestResult(
                hypothesis_id=hypothesis.hypothesis_id,
                category=hypothesis.category,
                confidence=RaceConfidence.INCONCLUSIVE,
                lifecycle_state=FindingLifecycle.HYPOTHESIS,
                severity="INFORMATIONAL",
                is_vulnerable=False,
                burst_size=0,
                success_count=0,
                failure_count=0,
                reasons=["Operator approval required before concurrent state mutation"],
            )
            return res, None

        # Deduplication check
        test_fp = hypothesis.compute_fingerprint()
        if self.state_mgr.is_fingerprint_tested(test_fp):
            hypothesis.notes = "Skipped: test fingerprint already evaluated"
            self.state_mgr.save_hypothesis(hypothesis)
            res = RaceConditionTestResult(
                hypothesis_id=hypothesis.hypothesis_id,
                category=hypothesis.category,
                confidence=RaceConfidence.INCONCLUSIVE,
                lifecycle_state=FindingLifecycle.DUPLICATE,
                severity="INFORMATIONAL",
                is_vulnerable=False,
                burst_size=0,
                success_count=0,
                failure_count=0,
                reasons=["Duplicate test fingerprint"],
            )
            return res, None

        # Prepare base probe request
        burst_size = min(self.policy.validate_burst_size(hypothesis.burst_size), self.policy.max_requests_per_test)
        req_headers = {
            "User-Agent": "BugBounty-Agent/Concurrency-Intelligence (Safe Burst)",
            "Content-Type": "application/json",
            "Accept": "application/json, */*",
        }
        if headers:
            req_headers.update(headers)

        base_req = ControlledRequest(
            method=hypothesis.method,
            url=hypothesis.endpoint,
            headers=req_headers,
            body=request_body,
        )

        # Dispatch synchronized burst
        raw_results = self.synchronizer.dispatch_burst(base_req, burst_size=burst_size)
        executions = [r[0] for r in raw_results]
        responses = [r[1] for r in raw_results]

        # Evaluate invariants
        (
            is_vuln,
            confidence,
            lifecycle,
            severity,
            reasons,
            evidence_dict,
        ) = ConcurrencyInvariantEngine.evaluate_burst_results(
            category=hypothesis.category,
            allowed_limit=hypothesis.allowed_limit,
            executions=executions,
            responses=responses,
            post_state_data=post_state_data,
        )

        success_count = sum(1 for e in executions if 200 <= e.status_code < 300)
        failure_count = len(executions) - success_count

        excerpt = "; ".join(f"[req-{e.request_index}]: {e.status_code} ({e.body_snippet[:64]})" for e in executions)
        sanitized_excerpt = sanitize_sensitive_data(excerpt)
        evidence_fp = hashlib.sha256(sanitized_excerpt.encode("utf-8")).hexdigest()

        test_result = RaceConditionTestResult(
            hypothesis_id=hypothesis.hypothesis_id,
            category=hypothesis.category,
            confidence=confidence,
            lifecycle_state=lifecycle,
            severity=severity,
            is_vulnerable=is_vuln,
            burst_size=burst_size,
            success_count=success_count,
            failure_count=failure_count,
            reasons=reasons,
            evidence=evidence_dict,
            executions=executions,
            sanitized_excerpt=sanitized_excerpt,
            evidence_fingerprint=evidence_fp,
        )

        # Update hypothesis state
        hypothesis.lifecycle_state = lifecycle
        hypothesis.notes = "; ".join(reasons)
        self.state_mgr.save_hypothesis(hypothesis)
        self.state_mgr.record_test_result(test_result)
        self.state_mgr.record_tested_fingerprint(test_fp)

        # Generate Finding if invariant violated
        finding: Optional[Finding] = None
        if is_vuln and confidence == RaceConfidence.CONFIRMED:
            finding_lifecycle = FindingLifecycle.SIMULATED if self.lab_mode else FindingLifecycle.VALIDATED
            finding_conf = "CONFIRMED"
            finding_id = f"FND-RACE-{hypothesis.hypothesis_id}"

            evidence_item = {
                "type": "concurrent_burst_telemetry",
                "content": sanitized_excerpt,
                "metadata": {
                    "burst_size": burst_size,
                    "success_count": success_count,
                    "allowed_limit": hypothesis.allowed_limit,
                    "category": hypothesis.category.value,
                    "sha256": evidence_fp,
                    "executions": [e.to_dict() for e in executions],
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            finding = Finding(
                title=f"Race Condition ({hypothesis.category.value}): {hypothesis.endpoint}",
                summary=(
                    f"Synchronized micro-burst ({burst_size} concurrent probes) confirmed invariant breach: "
                    f"{'; '.join(reasons)}"
                ),
                affected_asset=urlparse(hypothesis.endpoint).netloc or "target",
                affected_endpoint=hypothesis.endpoint,
                vulnerability_type=VulnerabilityFamily.BUSINESS_LOGIC.value,
                severity=severity,
                description=(
                    f"Target endpoint failed to serialize concurrent state transitions or enforce database locks. "
                    f"Multiple requests executed within the race window, bypassing limits."
                ),
                root_cause="Missing atomic transaction isolation, check-then-act gap, or un-synchronized distributed state.",
                prerequisites="Network access to target endpoint; concurrent request capability.",
                reproduction_steps=[
                    f"Prepare {burst_size} parallel HTTP {hypothesis.method} requests to '{hypothesis.endpoint}'.",
                    f"Synchronize transmission using a barrier to fire simultaneously.",
                    f"Observe multiple successful executions exceeding limit ({success_count} > {hypothesis.allowed_limit}).",
                ],
                expected_result=f"Server should serialize transactions or reject concurrent duplicates with HTTP 409/429.",
                observed_result=f"Server permitted {success_count} concurrent state mutations violating business limit.",
                security_impact=f"Exploitation allows multi-redemption, account balance overdraw, or quota bypass without authorization.",
                remediation="Implement atomic database transactions with row-level locks (SELECT ... FOR UPDATE), distributed Redis locks, or idempotency keys.",
                scope_reference="ScopeEngine authorized target.",
                confidence=finding_conf,
                finding_id=finding_id,
                lifecycle_state=finding_lifecycle,
                evidence=[evidence_item],
                validation_notes=f"Deterministic barrier synchronized burst verified {success_count} concurrent successes.",
                provenance={
                    "engine": "RaceIntelligenceEngine",
                    "category": hypothesis.category.value,
                    "evidence_fingerprint": evidence_fp,
                },
            )

            self.state_mgr.record_finding(finding.to_dict())
            if self.main_state_mgr and hasattr(self.main_state_mgr, "save_finding"):
                try:
                    self.main_state_mgr.save_finding(finding)
                except Exception:
                    pass

        return test_result, finding

    def run_all(self, auto_approve: bool = False) -> Dict[str, Any]:
        """Executes testing across all registered or discovered hypotheses."""
        state = self.state_mgr.load_state()
        raw_hyps = state.get("hypotheses", [])
        if not raw_hyps:
            self.discover_hypotheses_from_state()
            state = self.state_mgr.load_state()
            raw_hyps = state.get("hypotheses", [])

        hypotheses = [RaceConditionHypothesis.from_dict(h) for h in raw_hyps]
        results = []
        findings = []

        for h in hypotheses:
            res, fnd = self.execute_hypothesis(h, auto_approve=auto_approve)
            results.append(res)
            if fnd:
                findings.append(fnd)

        summary = self.state_mgr.get_summary()
        return {
            "total_tested": len(results),
            "findings_count": len(findings),
            "summary": summary,
        }
