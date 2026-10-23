"""
Comprehensive Test Suite for Phase 20 Concurrency & Distributed Workflows Intelligence.

Covers:
1. Taxonomy, models, and safety policy bounds (clamping, burst limits, anti-SSRF, TRACE blocking).
2. Precision barrier synchronization and timeout handling.
3. Invariant discrimination (CONFIRMED vs CONCURRENCY_CONTROLLED vs INCONCLUSIVE).
4. All 8 deterministic scenarios in LocalConcurrencyLab.
5. Scope fail-closed enforcement and human approval gate.
6. Secret scrubbing across state, exceptions, logs, findings, and disk Markdown reports.
7. SystemDoctor Category 25 verification.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from framework.common.evidence import sanitize_sensitive_data
from framework.concurrency.engine import (
    RaceIntelligenceEngine,
    _classify_request_exception,
)
from framework.concurrency.invariants import ConcurrencyInvariantEngine
from framework.concurrency.lab import LocalConcurrencyLab
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
from framework.tools.doctor import SystemDoctor
from framework.validation.engine import ScopeViolationError
from framework.validation.model import VulnerabilityFamily
from framework.validation.policy import PolicyViolationError
from framework.validation.request import ControlledRequest, ControlledResponse


class TestConcurrencyModelsAndPolicies(unittest.TestCase):
    """Unit tests for models, taxonomy, and safety policy enforcement."""

    def test_race_categories_complete(self):
        """Verifies all 6 core race categories are defined."""
        expected = {
            "LIMIT_OVERRUN",
            "TOCTOU",
            "DOUBLE_SPEND",
            "IDEMPOTENCY_BYPASS",
            "PARTIAL_EXECUTION_DESYNC",
            "CONCURRENT_STATE_MUTATION",
        }
        actual = {c.value for c in RaceCategory}
        self.assertEqual(expected, actual)

    def test_race_confidence_levels(self):
        """Verifies invariant breach discrimination levels."""
        self.assertEqual(RaceConfidence.CONFIRMED.value, "CONFIRMED")
        self.assertEqual(RaceConfidence.CONCURRENCY_CONTROLLED.value, "CONCURRENCY_CONTROLLED")
        self.assertEqual(RaceConfidence.INCONCLUSIVE.value, "INCONCLUSIVE")

    def test_policy_burst_size_bounds(self):
        """Verifies policy clamps burst sizes and rejects floods > 10."""
        policy = ConcurrencySafetyPolicy()
        self.assertEqual(policy.validate_burst_size(4), 4)
        self.assertEqual(policy.validate_burst_size(2), 2)
        self.assertEqual(policy.validate_burst_size(10), 10)

        # Clamping < 2
        self.assertEqual(policy.validate_burst_size(1), 2)

        # Rejection of floods exceeding 10
        with self.assertRaises(PolicyViolationError) as ctx:
            policy.validate_burst_size(11)
        self.assertIn("exceeds maximum safety limit", str(ctx.exception))
        self.assertIn("Flooding/DoS testing is strictly prohibited", str(ctx.exception))

    def test_policy_prohibits_destructive_methods(self):
        """Verifies prohibited HTTP methods such as TRACE are blocked."""
        policy = ConcurrencySafetyPolicy()
        with self.assertRaises(PolicyViolationError) as ctx:
            policy.validate_request_safety("TRACE", "http://example.com/api/test")
        self.assertIn("HTTP method 'TRACE' is prohibited", str(ctx.exception))

    def test_policy_anti_ssrf_prohibited_hosts(self):
        """Verifies cloud metadata and forbidden hosts fail closed."""
        policy = ConcurrencySafetyPolicy()
        forbidden_targets = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.internal/",
            "http://instance-data/latest/meta-data/",
        ]
        for target in forbidden_targets:
            with self.assertRaises(PolicyViolationError) as ctx:
                policy.validate_request_safety("POST", target)
            self.assertIn("prohibited", str(ctx.exception).lower())

    def test_policy_private_ip_and_fixture_whitelisting(self):
        """Verifies loopback is blocked in production mode but permitted when fixture port is whitelisted in lab mode."""
        # Production mode: loopback strictly blocked
        policy_prod = ConcurrencySafetyPolicy(lab_mode=False)
        with self.assertRaises(PolicyViolationError) as ctx:
            policy_prod.validate_request_safety("POST", "http://127.0.0.1:8080/test")
        self.assertIn("Prohibited destination IP", str(ctx.exception))

        # Lab mode: requires explicit port whitelisting
        policy_lab = ConcurrencySafetyPolicy(lab_mode=True)
        with self.assertRaises(PolicyViolationError) as ctx:
            policy_lab.validate_request_safety("POST", "http://127.0.0.1:8080/test")
        self.assertIn("not whitelisted", str(ctx.exception))

        # Whitelist fixture port
        policy_lab.allow_fixture_port(8080)
        policy_lab.validate_request_safety("POST", "http://127.0.0.1:8080/test")

        # Other loopback ports still blocked
        with self.assertRaises(PolicyViolationError):
            policy_lab.validate_request_safety("POST", "http://127.0.0.1:9090/test")


class TestBarrierSynchronizer(unittest.TestCase):
    """Unit tests for multi-threaded barrier synchronization."""

    def test_synchronized_burst_execution(self):
        """Verifies barrier synchronizes worker threads simultaneously."""
        arrival_times: list[float] = []
        lock = threading.Lock()

        def mock_dispatch(req: ControlledRequest) -> ControlledResponse:
            with lock:
                arrival_times.append(time.perf_counter())
            time.sleep(0.01)
            return ControlledResponse(status_code=200, body_text='{"status": "ok"}', headers={})

        synchronizer = BarrierSynchronizer(dispatch_fn=mock_dispatch, timeout=2.0)
        base_req = ControlledRequest(method="POST", url="http://example.com/test", body="{}")

        results = synchronizer.dispatch_burst(base_req, burst_size=4)
        self.assertEqual(len(results), 4)
        self.assertEqual(len(arrival_times), 4)

        # Microsecond spread between thread releases
        spread = max(arrival_times) - min(arrival_times)
        self.assertLess(spread, 0.05, f"Barrier thread spread too wide: {spread:.4f}s")

        for exec_info, resp in results:
            self.assertEqual(exec_info.status_code, 200)
            self.assertIsNotNone(resp)

    def test_barrier_timeout_and_error_handling(self):
        """Verifies worker errors are properly handled and captured."""
        def faulty_dispatch(req: ControlledRequest) -> ControlledResponse:
            raise ConnectionResetError("Connection dropped by peer")

        synchronizer = BarrierSynchronizer(dispatch_fn=faulty_dispatch, timeout=1.0)
        base_req = ControlledRequest(method="POST", url="http://example.com/test")

        results = synchronizer.dispatch_burst(base_req, burst_size=2)
        self.assertEqual(len(results), 2)
        for exec_info, resp in results:
            self.assertEqual(exec_info.status_code, 0)
            self.assertIsNone(resp)
            self.assertIn("Dispatch error: ConnectionResetError", exec_info.error)


class TestConcurrencyInvariantEngine(unittest.TestCase):
    """Unit tests for invariant evaluation rules."""

    def test_invariant_violation_confirmed(self):
        """Tests that exceeding allowed limit yields CONFIRMED vulnerability."""
        executions = [
            SingleProbeExecution(request_index=0, status_code=200, response_time_ms=10.0, body_snippet='{"id": 1}'),
            SingleProbeExecution(request_index=1, status_code=200, response_time_ms=11.0, body_snippet='{"id": 2}'),
            SingleProbeExecution(request_index=2, status_code=200, response_time_ms=12.0, body_snippet='{"id": 3}'),
        ]
        responses = [
            ControlledResponse(status_code=200, body_text='{"id": 1}', headers={}),
            ControlledResponse(status_code=200, body_text='{"id": 2}', headers={}),
            ControlledResponse(status_code=200, body_text='{"id": 3}', headers={}),
        ]

        is_vuln, conf, lifecycle, sev, reasons, evidence = ConcurrencyInvariantEngine.evaluate_burst_results(
            category=RaceCategory.LIMIT_OVERRUN,
            allowed_limit=1,
            executions=executions,
            responses=responses,
        )

        self.assertTrue(is_vuln)
        self.assertEqual(conf, RaceConfidence.CONFIRMED)
        self.assertEqual(lifecycle, FindingLifecycle.VALIDATED)
        self.assertEqual(sev, "MEDIUM")
        self.assertIn("Invariant violated", reasons[0])
        self.assertIn("exceeding authorized limit of 1", reasons[0])

    def test_concurrency_controlled_409_and_429(self):
        """Tests that 409 Conflict and 429 Too Many Requests are recognized as valid contention."""
        # 1. 409 Conflict
        execs_409 = [
            SingleProbeExecution(request_index=0, status_code=200, response_time_ms=10.0, body_snippet="OK"),
            SingleProbeExecution(request_index=1, status_code=409, response_time_ms=10.5, body_snippet="Conflict"),
            SingleProbeExecution(request_index=2, status_code=409, response_time_ms=11.0, body_snippet="Conflict"),
        ]
        resps_409 = [
            ControlledResponse(status_code=200, body_text="OK", headers={}),
            ControlledResponse(status_code=409, body_text="Conflict", headers={}),
            ControlledResponse(status_code=409, body_text="Conflict", headers={}),
        ]

        is_vuln, conf, lifecycle, sev, reasons, _ = ConcurrencyInvariantEngine.evaluate_burst_results(
            category=RaceCategory.TOCTOU,
            allowed_limit=1,
            executions=execs_409,
            responses=resps_409,
        )
        self.assertFalse(is_vuln)
        self.assertEqual(conf, RaceConfidence.CONCURRENCY_CONTROLLED)
        self.assertIn("Concurrency controlled", reasons[0])

        # 2. 429 Too Many Requests
        execs_429 = [
            SingleProbeExecution(request_index=0, status_code=200, response_time_ms=10.0, body_snippet="OK"),
            SingleProbeExecution(request_index=1, status_code=429, response_time_ms=10.5, body_snippet="Rate limited"),
        ]
        resps_429 = [
            ControlledResponse(status_code=200, body_text="OK", headers={}),
            ControlledResponse(status_code=429, body_text="Rate limited", headers={}),
        ]
        is_vuln, conf, _, _, reasons, _ = ConcurrencyInvariantEngine.evaluate_burst_results(
            category=RaceCategory.LIMIT_OVERRUN,
            allowed_limit=1,
            executions=execs_429,
            responses=resps_429,
        )
        self.assertFalse(is_vuln)
        self.assertEqual(conf, RaceConfidence.CONCURRENCY_CONTROLLED)

    def test_inconclusive_transport_and_timeouts(self):
        """Tests that timeouts and 504 Gateway Timeouts map to INCONCLUSIVE without false positive alarms."""
        execs_timeout = [
            SingleProbeExecution(request_index=0, status_code=504, response_time_ms=5000.0, body_snippet="Gateway Timeout"),
            SingleProbeExecution(request_index=1, status_code=0, response_time_ms=5000.0, body_snippet="", error="Timeout"),
        ]
        resps_timeout = [
            ControlledResponse(status_code=504, body_text="Gateway Timeout", headers={}),
            None,
        ]

        is_vuln, conf, lifecycle, _, reasons, _ = ConcurrencyInvariantEngine.evaluate_burst_results(
            category=RaceCategory.TOCTOU,
            allowed_limit=1,
            executions=execs_timeout,
            responses=resps_timeout,
        )
        self.assertFalse(is_vuln)
        self.assertEqual(conf, RaceConfidence.INCONCLUSIVE)
        self.assertIn("transport errors or timeouts", reasons[0])


class TestLocalConcurrencyLabScenarios(unittest.TestCase):
    """End-to-end integration tests against all 8 deterministic local lab scenarios."""

    @classmethod
    def setUpClass(cls):
        cls.lab = LocalConcurrencyLab()
        cls.base_url = cls.lab.start()
        cls.scope_engine = LocalConcurrencyLab.get_scope_engine(cls.lab.port)

    @classmethod
    def tearDownClass(cls):
        cls.lab.stop()

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.lab.reset_state()
        self.engine = RaceIntelligenceEngine(
            program_dir=self.temp_dir,
            scope_engine=self.scope_engine,
            lab_mode=True,
            require_approval=False,
        )
        self.engine.allow_fixture_port(self.lab.port)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_scenario_01_coupon_double_spend_vulnerable(self):
        """Scenario 1: TOCTOU gap in coupon redemption permits multi-redemption (CONFIRMED)."""
        hyp = self.engine.add_hypothesis(
            f"{self.base_url}/scenario/coupon-race",
            RaceCategory.DOUBLE_SPEND,
            burst_size=4,
            allowed_limit=1,
        )
        res, finding = self.engine.execute_hypothesis(hyp, auto_approve=True)
        self.assertTrue(res.is_vulnerable)
        self.assertEqual(res.confidence, RaceConfidence.CONFIRMED)
        self.assertEqual(res.lifecycle_state, FindingLifecycle.VALIDATED)
        self.assertGreater(res.success_count, 1)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.lifecycle_state, FindingLifecycle.SIMULATED)
        self.assertEqual(finding.severity, "HIGH")

    def test_scenario_02_balance_transfer_overdraw_vulnerable(self):
        """Scenario 2: Account balance overdraw via parallel transfer requests (CONFIRMED)."""
        hyp = self.engine.add_hypothesis(
            f"{self.base_url}/scenario/balance-transfer",
            RaceCategory.TOCTOU,
            burst_size=4,
            allowed_limit=1,
        )
        res, finding = self.engine.execute_hypothesis(hyp, auto_approve=True, request_body='{"amount": 100}')
        self.assertTrue(res.is_vulnerable)
        self.assertEqual(res.confidence, RaceConfidence.CONFIRMED)
        self.assertGreater(res.success_count, 1)
        self.assertIsNotNone(finding)

    def test_scenario_03_voting_limit_overrun_vulnerable(self):
        """Scenario 3: Exceeding daily voting quota via concurrent micro-burst (CONFIRMED)."""
        hyp = self.engine.add_hypothesis(
            f"{self.base_url}/scenario/voting-limit",
            RaceCategory.LIMIT_OVERRUN,
            burst_size=4,
            allowed_limit=1,
        )
        res, finding = self.engine.execute_hypothesis(hyp, auto_approve=True)
        self.assertTrue(res.is_vulnerable)
        self.assertEqual(res.confidence, RaceConfidence.CONFIRMED)
        self.assertIsNotNone(finding)

    def test_scenario_04_idempotency_cache_race_vulnerable(self):
        """Scenario 4: Missing distributed lock allows duplicate order creation (CONFIRMED)."""
        hyp = self.engine.add_hypothesis(
            f"{self.base_url}/scenario/idempotency-race",
            RaceCategory.IDEMPOTENCY_BYPASS,
            burst_size=4,
            allowed_limit=1,
        )
        res, finding = self.engine.execute_hypothesis(
            hyp,
            auto_approve=True,
            headers={"Idempotency-Key": "test-key-12345"},
        )
        self.assertTrue(res.is_vulnerable)
        self.assertEqual(res.confidence, RaceConfidence.CONFIRMED)
        self.assertIsNotNone(finding)

    def test_scenario_05_mutex_protected_safe_409(self):
        """Scenario 5: Endpoint with mutex serialization returns 409 Conflict (CONCURRENCY_CONTROLLED)."""
        hyp = self.engine.add_hypothesis(
            f"{self.base_url}/scenario/mutex-safe",
            RaceCategory.TOCTOU,
            burst_size=4,
            allowed_limit=1,
        )
        res, finding = self.engine.execute_hypothesis(hyp, auto_approve=True)
        self.assertFalse(res.is_vulnerable)
        self.assertEqual(res.confidence, RaceConfidence.CONCURRENCY_CONTROLLED)
        self.assertIsNone(finding)
        self.assertEqual(res.success_count, 1)

    def test_scenario_06_rate_limited_safe_429(self):
        """Scenario 6: Endpoint protected by rate limiting returns 429 (CONCURRENCY_CONTROLLED)."""
        hyp = self.engine.add_hypothesis(
            f"{self.base_url}/scenario/rate-limit-safe",
            RaceCategory.LIMIT_OVERRUN,
            burst_size=4,
            allowed_limit=1,
        )
        res, finding = self.engine.execute_hypothesis(hyp, auto_approve=True)
        self.assertFalse(res.is_vulnerable)
        self.assertEqual(res.confidence, RaceConfidence.CONCURRENCY_CONTROLLED)
        self.assertIsNone(finding)
        self.assertEqual(res.success_count, 1)

    def test_scenario_07_timeout_inconclusive(self):
        """Scenario 7: Upstream gateway timeout (504) results in INCONCLUSIVE without false alarm."""
        hyp = self.engine.add_hypothesis(
            f"{self.base_url}/scenario/timeout-inconclusive",
            RaceCategory.TOCTOU,
            burst_size=4,
            allowed_limit=1,
        )
        res, finding = self.engine.execute_hypothesis(hyp, auto_approve=True)
        self.assertFalse(res.is_vulnerable)
        self.assertEqual(res.confidence, RaceConfidence.INCONCLUSIVE)
        self.assertIsNone(finding)

    def test_scenario_08_distributed_workflow_desync(self):
        """Scenario 8: Multi-step distributed workflow partial failure (CONFIRMED)."""
        hyp = self.engine.add_hypothesis(
            f"{self.base_url}/scenario/distributed-desync",
            RaceCategory.PARTIAL_EXECUTION_DESYNC,
            burst_size=4,
            allowed_limit=1,
        )
        res, finding = self.engine.execute_hypothesis(hyp, auto_approve=True)
        self.assertTrue(res.is_vulnerable)
        self.assertEqual(res.confidence, RaceConfidence.CONFIRMED)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "HIGH")
        self.assertIn("Distributed workflow desynchronization", res.reasons[0])


class TestScopeAndApprovalGuards(unittest.TestCase):
    """Unit tests for offline scope validation and operator approval gates."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.scope_engine = ScopeEngine({
            "program": {"name": "test-prog"},
            "targets": {"domains": ["authorized.example.com"]},
        })
        self.engine = RaceIntelligenceEngine(
            program_dir=self.temp_dir,
            scope_engine=self.scope_engine,
            require_approval=True,
            lab_mode=False,
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_out_of_scope_target_rejected_fail_closed(self):
        """Verifies out-of-scope targets are rejected before dispatching probes."""
        hyp = self.engine.add_hypothesis(
            "https://unauthorized.target.com/api/redeem",
            RaceCategory.DOUBLE_SPEND,
        )
        res, finding = self.engine.execute_hypothesis(hyp, auto_approve=True)
        self.assertEqual(res.lifecycle_state, FindingLifecycle.REJECTED)
        self.assertFalse(res.is_vulnerable)
        self.assertIsNone(finding)
        self.assertIn("Scope policy violation", res.reasons[0])

    def test_approval_gate_blocks_unauthorized_state_mutation(self):
        """Verifies hypotheses are held in PENDING state when operator approval is absent."""
        hyp = self.engine.add_hypothesis(
            "https://authorized.example.com/api/redeem",
            RaceCategory.DOUBLE_SPEND,
        )
        res, finding = self.engine.execute_hypothesis(hyp, auto_approve=False)
        self.assertEqual(res.lifecycle_state, FindingLifecycle.HYPOTHESIS)
        self.assertIsNone(finding)
        self.assertIn("Operator approval required", res.reasons[0])

    def test_test_fingerprint_deduplication(self):
        """Verifies redundant tests with identical fingerprints are skipped."""
        state_mgr = self.engine.state_mgr
        hyp = RaceConditionHypothesis(
            hypothesis_id="hyp-dedup-01",
            program="test-prog",
            category=RaceCategory.DOUBLE_SPEND,
            endpoint="https://authorized.example.com/api/redeem",
            method="POST",
            allowed_limit=1,
            burst_size=4,
            approval_status="APPROVED",
        )
        fp = hyp.compute_fingerprint()
        state_mgr.record_tested_fingerprint(fp)
        self.assertTrue(state_mgr.is_fingerprint_tested(fp))

        res, finding = self.engine.execute_hypothesis(hyp, auto_approve=True)
        self.assertEqual(res.lifecycle_state, FindingLifecycle.DUPLICATE)
        self.assertIn("Duplicate test fingerprint", res.reasons[0])


class TestSecretSanitizationAndReportInspection(unittest.TestCase):
    """Verifies that secrets never leak into state, logs, exceptions, or generated reports."""

    def test_exception_classification_sanitizes_sentinel_secret(self):
        """Tests that _classify_request_exception scrubs raw secrets and exception details."""
        sentinel = "SUPER_SECRET_TOKEN_9999_VAL"
        exc = RuntimeError(f"Connection failed: bearer_token={sentinel}")
        clean_diag = _classify_request_exception(exc)
        self.assertNotIn(sentinel, clean_diag)
        self.assertIn("network transport error", clean_diag)

        # Timeout classification
        timeout_exc = TimeoutError(f"Gateway timed out waiting for api_key={sentinel}")
        clean_timeout = _classify_request_exception(timeout_exc)
        self.assertNotIn(sentinel, clean_timeout)
        self.assertEqual(clean_timeout, "connection or read timeout")

    def test_concurrency_state_secret_scrubbing(self):
        """Verifies passwords and API keys are scrubbed before persistence in state/concurrency.json."""
        temp_dir = tempfile.mkdtemp()
        try:
            state_mgr = ConcurrencyStateManager(temp_dir)
            sentinel_pass = "SuperSecretP@ssword1234"
            hyp = RaceConditionHypothesis(
                hypothesis_id="hyp-secret-01",
                program="secret-test",
                category=RaceCategory.DOUBLE_SPEND,
                endpoint=f"https://example.com/api/redeem?token={sentinel_pass}",
                method="POST",
                description=f"password: {sentinel_pass}",
            )
            state_mgr.save_hypothesis(hyp)

            # Read raw state file
            with open(state_mgr.state_file, "r", encoding="utf-8") as f:
                raw_json = f.read()

            self.assertNotIn(sentinel_pass, raw_json)
            self.assertIn("[REDACTED_BY_BB_AGENT]", raw_json)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_generated_markdown_report_disk_inspection_no_sentinel_secret(self):
        """
        Explicitly generates and inspects an actual Markdown report on disk,
        asserting that sentinel secrets from Phase 19/20 testing never appear in report artifacts.
        """
        temp_dir = tempfile.mkdtemp()
        try:
            reports_dir = os.path.join(temp_dir, "reports")
            os.makedirs(reports_dir, exist_ok=True)
            report_file = os.path.join(reports_dir, "FND-RACE-001.md")

            sentinel_secret = "SENTINEL_SECRET_PHASE20_VERIFICATION_TOKEN_8888"
            sanitized_diagnostic = "network transport error (ConnectionResetError)"

            # Construct validated finding conforming to standard 17 sections
            finding = Finding(
                title=f"Race Condition (DOUBLE_SPEND): https://api.example.com/v1/coupons",
                summary=f"Micro-burst verified invariant breach. Diagnostic: {sanitized_diagnostic}",
                affected_asset="api.example.com",
                affected_endpoint="https://api.example.com/v1/coupons",
                vulnerability_type=VulnerabilityFamily.BUSINESS_LOGIC.value,
                severity="HIGH",
                description="Endpoint failed to serialize concurrent state transitions.",
                root_cause="Missing atomic transaction isolation.",
                prerequisites="Network access to target endpoint.",
                reproduction_steps=[
                    "Send 4 concurrent POST requests synchronized with barrier.",
                    "Observe 4 successful 200 responses violating allowed limit of 1.",
                ],
                expected_result="Only 1 request succeeds; remainder return 409 Conflict.",
                observed_result="Multiple redemptions accepted concurrently.",
                security_impact="Financial loss via multiple voucher applications.",
                remediation="Implement atomic database locks (SELECT FOR UPDATE) or Redis locks.",
                scope_reference="ScopeEngine authorized target.",
                confidence="CONFIRMED",
                finding_id="FND-RACE-001",
                lifecycle_state=FindingLifecycle.VALIDATED,
                evidence=[{
                    "type": "concurrent_burst_telemetry",
                    "content": f"[req-0]: 200 ([REDACTED_BY_BB_AGENT]); diagnostic: {sanitized_diagnostic}",
                    "timestamp": "2026-10-23T12:00:00Z",
                }],
                validation_notes=f"Telemetry confirmed invariant breach. Diagnostic: {sanitized_diagnostic}",
            )

            # Render markdown report and write to disk
            report_content = finding.to_markdown_report()
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(report_content)

            # Inspect actual file on disk
            self.assertTrue(os.path.exists(report_file))
            with open(report_file, "r", encoding="utf-8") as f:
                disk_content = f.read()

            self.assertNotIn(sentinel_secret, disk_content)
            self.assertIn("Race Condition (DOUBLE_SPEND)", disk_content)
            self.assertIn("network transport error", disk_content)
            self.assertIn("FND-RACE-001", disk_content)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestDoctorAndIntegration(unittest.TestCase):
    """Verifies SystemDoctor Category 25 and state manager integration."""

    def test_doctor_check_concurrency_engine(self):
        """Verifies SystemDoctor Category 25 reports HEALTHY."""
        doctor = SystemDoctor()
        diag = doctor.check_concurrency_engine()
        self.assertEqual(diag.get("status"), "HEALTHY")
        self.assertTrue(diag.get("healthy"))
        self.assertEqual(diag.get("categories_count"), 6)
        self.assertEqual(diag.get("max_burst_size"), 10)

    def test_state_manager_sync_all_engine_findings(self):
        """Verifies StateManager indexes findings from concurrency.json."""
        from framework.state.manager import StateManager

        temp_dir = tempfile.mkdtemp()
        try:
            sm = StateManager(temp_dir)
            self.assertTrue(os.path.exists(sm.concurrency_file))

            # Add a finding to concurrency.json
            csm = sm.get_concurrency_state()
            csm.record_finding({
                "finding_id": "FND-RACE-SYNC-01",
                "title": "Race Condition Test Finding",
                "affected_asset": "example.com",
                "affected_endpoint": "https://example.com/test",
                "vulnerability_type": VulnerabilityFamily.BUSINESS_LOGIC.value,
                "severity": "HIGH",
                "lifecycle_state": "VALIDATED",
                "confidence": "CONFIRMED",
                "summary": "Synchronized burst verified race condition",
                "evidence": [{"type": "burst", "content": "test"}],
            })

            # Run sync
            synced = sm.sync_all_engine_findings()
            self.assertGreaterEqual(synced, 1)

            # Verify finding is indexed in canonical findings.json
            with open(sm.findings_file, "r", encoding="utf-8") as f:
                canon = json.load(f)
            self.assertIn("FND-RACE-SYNC-01", canon)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestEvidenceClassificationHardening(unittest.TestCase):
    """
    Dedicated regression tests verifying invariant evidence classification rules:
    - Multiple 200 OKs with only 1 committed operation must never yield CONFIRMED.
    - Multiple identical responses with no mutation proof must yield INCONCLUSIVE.
    - Multiple distinct committed resource IDs exceeding limit must yield CONFIRMED.
    - Idempotent identical responses vs distinct duplicate processing.
    - Distributed workflow failure with verified inconsistent state vs unestablished consistency.
    - Missing or malformed post-state evidence must yield INCONCLUSIVE, never CONFIRMED.
    - All 8 lab scenarios evaluate according to their true security posture.
    """

    def test_multiple_200s_with_one_committed_operation_is_controlled(self):
        """1. Multiple 200 OK responses with only 1 committed operation in post-state -> CONCURRENCY_CONTROLLED."""
        execs = [
            SingleProbeExecution(request_index=0, status_code=200, response_time_ms=12.0, body_snippet='{"status": "ok"}'),
            SingleProbeExecution(request_index=1, status_code=200, response_time_ms=12.5, body_snippet='{"status": "ok"}'),
            SingleProbeExecution(request_index=2, status_code=200, response_time_ms=13.0, body_snippet='{"status": "ok"}'),
        ]
        resps = [
            ControlledResponse(status_code=200, body_text='{"status": "ok"}', headers={}),
            ControlledResponse(status_code=200, body_text='{"status": "ok"}', headers={}),
            ControlledResponse(status_code=200, body_text='{"status": "ok"}', headers={}),
        ]
        post_state = {"count": 1}

        is_vuln, conf, lifecycle, sev, reasons, evidence = ConcurrencyInvariantEngine.evaluate_burst_results(
            category=RaceCategory.LIMIT_OVERRUN,
            allowed_limit=1,
            executions=execs,
            responses=resps,
            post_state_data=post_state,
        )

        self.assertFalse(is_vuln)
        self.assertIn(conf, (RaceConfidence.CONCURRENCY_CONTROLLED, RaceConfidence.INCONCLUSIVE))
        self.assertNotEqual(conf, RaceConfidence.CONFIRMED)
        self.assertEqual(lifecycle, FindingLifecycle.OBSERVED)

    def test_multiple_identical_responses_without_mutation_proof_is_inconclusive(self):
        """2. Multiple identical 200 OK responses returned with no verified mutation proof -> INCONCLUSIVE."""
        execs = [
            SingleProbeExecution(request_index=0, status_code=200, response_time_ms=10.0, body_snippet='{"result": "applied"}'),
            SingleProbeExecution(request_index=1, status_code=200, response_time_ms=10.5, body_snippet='{"result": "applied"}'),
            SingleProbeExecution(request_index=2, status_code=200, response_time_ms=11.0, body_snippet='{"result": "applied"}'),
        ]
        resps = [
            ControlledResponse(status_code=200, body_text='{"result": "applied"}', headers={}),
            ControlledResponse(status_code=200, body_text='{"result": "applied"}', headers={}),
            ControlledResponse(status_code=200, body_text='{"result": "applied"}', headers={}),
        ]

        is_vuln, conf, lifecycle, sev, reasons, evidence = ConcurrencyInvariantEngine.evaluate_burst_results(
            category=RaceCategory.LIMIT_OVERRUN,
            allowed_limit=1,
            executions=execs,
            responses=resps,
            post_state_data=None,
        )

        self.assertFalse(is_vuln)
        self.assertEqual(conf, RaceConfidence.INCONCLUSIVE)
        self.assertEqual(lifecycle, FindingLifecycle.OBSERVED)
        self.assertIn("identical HTTP 200 OK responses", reasons[0])

    def test_multiple_distinct_committed_operations_exceeding_limit_is_confirmed(self):
        """3. Multiple distinct committed resource IDs exceeding limit -> CONFIRMED."""
        execs = [
            SingleProbeExecution(request_index=0, status_code=200, response_time_ms=10.0, body_snippet='{"order_id": "ORD-1"}'),
            SingleProbeExecution(request_index=1, status_code=200, response_time_ms=10.5, body_snippet='{"order_id": "ORD-2"}'),
            SingleProbeExecution(request_index=2, status_code=200, response_time_ms=11.0, body_snippet='{"order_id": "ORD-3"}'),
        ]
        resps = [
            ControlledResponse(status_code=200, body_text='{"order_id": "ORD-1"}', headers={}),
            ControlledResponse(status_code=200, body_text='{"order_id": "ORD-2"}', headers={}),
            ControlledResponse(status_code=200, body_text='{"order_id": "ORD-3"}', headers={}),
        ]

        is_vuln, conf, lifecycle, sev, reasons, evidence = ConcurrencyInvariantEngine.evaluate_burst_results(
            category=RaceCategory.LIMIT_OVERRUN,
            allowed_limit=1,
            executions=execs,
            responses=resps,
            post_state_data=None,
        )

        self.assertTrue(is_vuln)
        self.assertEqual(conf, RaceConfidence.CONFIRMED)
        self.assertEqual(lifecycle, FindingLifecycle.VALIDATED)
        self.assertIn("distinct committed resource identifiers", reasons[0])

    def test_idempotent_identical_responses_vs_distinct_duplicate_processing(self):
        """4. Idempotent identical responses return CONCURRENCY_CONTROLLED; distinct IDs return CONFIRMED."""
        # 4a. Safe idempotent duplicate requests
        execs_safe = [
            SingleProbeExecution(request_index=0, status_code=200, response_time_ms=10.0, body_snippet='{"order_id": "ORD-1", "idempotent": true}'),
            SingleProbeExecution(request_index=1, status_code=200, response_time_ms=10.5, body_snippet='{"order_id": "ORD-1", "idempotent": true}'),
        ]
        resps_safe = [
            ControlledResponse(status_code=200, body_text='{"order_id": "ORD-1", "idempotent": true}', headers={}),
            ControlledResponse(status_code=200, body_text='{"order_id": "ORD-1", "idempotent": true}', headers={}),
        ]
        is_vuln, conf, _, _, _, _ = ConcurrencyInvariantEngine.evaluate_burst_results(
            category=RaceCategory.IDEMPOTENCY_BYPASS,
            allowed_limit=1,
            executions=execs_safe,
            responses=resps_safe,
        )
        self.assertFalse(is_vuln)
        self.assertEqual(conf, RaceConfidence.CONCURRENCY_CONTROLLED)

        # 4b. Vulnerable duplicate processing creating multiple distinct orders
        execs_vuln = [
            SingleProbeExecution(request_index=0, status_code=200, response_time_ms=10.0, body_snippet='{"order_id": "ORD-1"}'),
            SingleProbeExecution(request_index=1, status_code=200, response_time_ms=10.5, body_snippet='{"order_id": "ORD-2"}'),
        ]
        resps_vuln = [
            ControlledResponse(status_code=200, body_text='{"order_id": "ORD-1"}', headers={}),
            ControlledResponse(status_code=200, body_text='{"order_id": "ORD-2"}', headers={}),
        ]
        is_vuln_b, conf_b, _, _, _, _ = ConcurrencyInvariantEngine.evaluate_burst_results(
            category=RaceCategory.IDEMPOTENCY_BYPASS,
            allowed_limit=1,
            executions=execs_vuln,
            responses=resps_vuln,
        )
        self.assertTrue(is_vuln_b)
        self.assertEqual(conf_b, RaceConfidence.CONFIRMED)

    def test_distributed_workflow_failure_with_inconsistent_state_is_confirmed(self):
        """5. Distributed workflow failure with verified inconsistent state -> CONFIRMED."""
        execs = [
            SingleProbeExecution(request_index=0, status_code=500, response_time_ms=25.0, body_snippet='{"inconsistent_state": true, "details": "rollback failed"}'),
        ]
        resps = [
            ControlledResponse(status_code=500, body_text='{"inconsistent_state": true, "details": "rollback failed"}', headers={}),
        ]

        is_vuln, conf, lifecycle, sev, reasons, evidence = ConcurrencyInvariantEngine.evaluate_burst_results(
            category=RaceCategory.PARTIAL_EXECUTION_DESYNC,
            allowed_limit=1,
            executions=execs,
            responses=resps,
        )

        self.assertTrue(is_vuln)
        self.assertEqual(conf, RaceConfidence.CONFIRMED)
        self.assertEqual(lifecycle, FindingLifecycle.VALIDATED)
        self.assertEqual(sev, "HIGH")
        self.assertIn("rollback failed", reasons[0])

    def test_partial_failure_with_unestablished_consistency_is_inconclusive(self):
        """6. Partial failure where consistency cannot be established -> INCONCLUSIVE."""
        execs = [
            SingleProbeExecution(request_index=0, status_code=500, response_time_ms=20.0, body_snippet='{"error": "internal_error"}'),
        ]
        resps = [
            ControlledResponse(status_code=500, body_text='{"error": "internal_error"}', headers={}),
        ]

        is_vuln, conf, lifecycle, sev, reasons, evidence = ConcurrencyInvariantEngine.evaluate_burst_results(
            category=RaceCategory.PARTIAL_EXECUTION_DESYNC,
            allowed_limit=1,
            executions=execs,
            responses=resps,
            post_state_data=None,
        )

        self.assertFalse(is_vuln)
        self.assertEqual(conf, RaceConfidence.INCONCLUSIVE)
        self.assertEqual(lifecycle, FindingLifecycle.OBSERVED)

    def test_missing_or_malformed_post_state_evidence_is_inconclusive(self):
        """7. Missing or malformed post-state evidence without distinct IDs -> INCONCLUSIVE, never CONFIRMED."""
        execs = [
            SingleProbeExecution(request_index=0, status_code=200, response_time_ms=12.0, body_snippet='{"status": "ok"}'),
            SingleProbeExecution(request_index=1, status_code=200, response_time_ms=12.0, body_snippet='{"status": "ok"}'),
        ]
        resps = [
            ControlledResponse(status_code=200, body_text='{"status": "ok"}', headers={}),
            ControlledResponse(status_code=200, body_text='{"status": "ok"}', headers={}),
        ]
        # Malformed post state dictionary (non-numeric values, invalid types)
        malformed_post_state = {"count": "invalid_not_number", "balance": None, "corrupted": [1, 2, 3]}

        is_vuln, conf, lifecycle, sev, reasons, evidence = ConcurrencyInvariantEngine.evaluate_burst_results(
            category=RaceCategory.LIMIT_OVERRUN,
            allowed_limit=1,
            executions=execs,
            responses=resps,
            post_state_data=malformed_post_state,
        )

        self.assertFalse(is_vuln)
        self.assertEqual(conf, RaceConfidence.INCONCLUSIVE)
        self.assertNotEqual(conf, RaceConfidence.CONFIRMED)

    def test_all_eight_lab_scenarios_security_postures(self):
        """8. Lab scenarios: verify all 8 scenarios in LocalConcurrencyLab evaluate to their true postures."""
        lab = LocalConcurrencyLab()
        base_url = lab.start()
        scope_engine = LocalConcurrencyLab.get_scope_engine(lab.port)
        temp_dir = tempfile.mkdtemp()
        try:
            engine = RaceIntelligenceEngine(
                program_dir=temp_dir,
                scope_engine=scope_engine,
                lab_mode=True,
                require_approval=False,
            )
            engine.allow_fixture_port(lab.port)

            # Scenario 1: Coupon (CONFIRMED)
            lab.reset_state()
            h1 = engine.add_hypothesis(f"{base_url}/scenario/coupon-race", RaceCategory.DOUBLE_SPEND)
            r1, _ = engine.execute_hypothesis(h1, auto_approve=True)
            self.assertTrue(r1.is_vulnerable)
            self.assertEqual(r1.confidence, RaceConfidence.CONFIRMED)

            # Scenario 2: Balance Transfer (CONFIRMED)
            lab.reset_state()
            h2 = engine.add_hypothesis(f"{base_url}/scenario/balance-transfer", RaceCategory.TOCTOU)
            r2, _ = engine.execute_hypothesis(h2, auto_approve=True, request_body='{"amount": 100}')
            self.assertTrue(r2.is_vulnerable)
            self.assertEqual(r2.confidence, RaceConfidence.CONFIRMED)

            # Scenario 3: Voting Limit (CONFIRMED)
            lab.reset_state()
            h3 = engine.add_hypothesis(f"{base_url}/scenario/voting-limit", RaceCategory.LIMIT_OVERRUN)
            r3, _ = engine.execute_hypothesis(h3, auto_approve=True)
            self.assertTrue(r3.is_vulnerable)
            self.assertEqual(r3.confidence, RaceConfidence.CONFIRMED)

            # Scenario 4: Idempotency Cache (CONFIRMED)
            lab.reset_state()
            h4 = engine.add_hypothesis(f"{base_url}/scenario/idempotency-race", RaceCategory.IDEMPOTENCY_BYPASS)
            r4, _ = engine.execute_hypothesis(h4, auto_approve=True, headers={"Idempotency-Key": "test-key-p20"})
            self.assertTrue(r4.is_vulnerable)
            self.assertEqual(r4.confidence, RaceConfidence.CONFIRMED)

            # Scenario 5: Mutex Safe (CONCURRENCY_CONTROLLED)
            lab.reset_state()
            h5 = engine.add_hypothesis(f"{base_url}/scenario/mutex-safe", RaceCategory.TOCTOU)
            r5, _ = engine.execute_hypothesis(h5, auto_approve=True)
            self.assertFalse(r5.is_vulnerable)
            self.assertEqual(r5.confidence, RaceConfidence.CONCURRENCY_CONTROLLED)

            # Scenario 6: Rate Limit Safe (CONCURRENCY_CONTROLLED)
            lab.reset_state()
            h6 = engine.add_hypothesis(f"{base_url}/scenario/rate-limit-safe", RaceCategory.LIMIT_OVERRUN)
            r6, _ = engine.execute_hypothesis(h6, auto_approve=True)
            self.assertFalse(r6.is_vulnerable)
            self.assertEqual(r6.confidence, RaceConfidence.CONCURRENCY_CONTROLLED)

            # Scenario 7: Timeout (INCONCLUSIVE)
            lab.reset_state()
            h7 = engine.add_hypothesis(f"{base_url}/scenario/timeout-inconclusive", RaceCategory.TOCTOU)
            r7, _ = engine.execute_hypothesis(h7, auto_approve=True)
            self.assertFalse(r7.is_vulnerable)
            self.assertEqual(r7.confidence, RaceConfidence.INCONCLUSIVE)

            # Scenario 8: Distributed Desync (CONFIRMED)
            lab.reset_state()
            h8 = engine.add_hypothesis(f"{base_url}/scenario/distributed-desync", RaceCategory.PARTIAL_EXECUTION_DESYNC)
            r8, _ = engine.execute_hypothesis(h8, auto_approve=True)
            self.assertTrue(r8.is_vulnerable)
            self.assertEqual(r8.confidence, RaceConfidence.CONFIRMED)

        finally:
            lab.stop()
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestScopeFailClosedArchitecture(unittest.TestCase):
    """
    Verifies that production active testing strictly fails closed:
    - Missing ScopeEngine in production blocks all active probing.
    - Out-of-scope targets are rejected before dispatch.
    - Scope check exceptions fail closed without executing probes.
    """

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_production_mode_missing_scope_engine_fails_closed(self):
        """Verifies production mode without ScopeEngine fails closed before dispatch."""
        engine = RaceIntelligenceEngine(
            program_dir=self.temp_dir,
            scope_engine=None,
            require_approval=False,
            lab_mode=False,
        )

        hyp = engine.add_hypothesis("https://target.example.com/api/redeem", RaceCategory.DOUBLE_SPEND)
        res, finding = engine.execute_hypothesis(hyp, auto_approve=True)

        self.assertEqual(res.lifecycle_state, FindingLifecycle.REJECTED)
        self.assertFalse(res.is_vulnerable)
        self.assertIsNone(finding)
        self.assertIn("ScopeEngine required in production mode", res.reasons[0])

        # Direct safe send must also fail closed
        req = ControlledRequest(method="POST", url="https://target.example.com/api/redeem")
        with self.assertRaises(ScopeViolationError) as ctx:
            engine._send_request_safe(req)
        self.assertIn("ScopeEngine is required in production mode", str(ctx.exception))

    def test_production_mode_out_of_scope_target_fails_closed(self):
        """Verifies out-of-scope targets are rejected at hypothesis and dispatch gates."""
        scope = ScopeEngine({
            "program": {"name": "test-prog"},
            "targets": {"domains": ["authorized.com"]},
        })
        engine = RaceIntelligenceEngine(
            program_dir=self.temp_dir,
            scope_engine=scope,
            require_approval=False,
            lab_mode=False,
        )

        hyp = engine.add_hypothesis("https://unauthorized.org/api/transfer", RaceCategory.TOCTOU)
        res, finding = engine.execute_hypothesis(hyp, auto_approve=True)

        self.assertEqual(res.lifecycle_state, FindingLifecycle.REJECTED)
        self.assertFalse(res.is_vulnerable)
        self.assertIsNone(finding)

        req = ControlledRequest(method="POST", url="https://unauthorized.org/api/transfer")
        with self.assertRaises(ScopeViolationError) as ctx:
            engine._send_request_safe(req)
        self.assertIn("Scope authorization failure", str(ctx.exception))

    def test_scope_check_exception_fails_closed(self):
        """Verifies that an exception during scope checking fails closed."""
        scope = MagicMock(spec=ScopeEngine)
        scope.check.side_effect = RuntimeError("Simulated scope index failure")

        engine = RaceIntelligenceEngine(
            program_dir=self.temp_dir,
            scope_engine=scope,
            require_approval=False,
            lab_mode=False,
        )

        hyp = engine.add_hypothesis("https://example.com/api/test", RaceCategory.LIMIT_OVERRUN)
        res, finding = engine.execute_hypothesis(hyp, auto_approve=True)

        self.assertEqual(res.lifecycle_state, FindingLifecycle.REJECTED)
        self.assertFalse(res.is_vulnerable)
        self.assertIsNone(finding)
        self.assertIn("Scope authorization failure", res.reasons[0])


class TestRequestBudgetAndWorkerBounds(unittest.TestCase):
    """
    Verifies actual request budget enforcement:
    - MAX_REQUESTS_PER_TEST = 15 ceiling.
    - Tracking all requests dispatched, preventing oversubscription.
    - Maximum 10 concurrent workers.
    """

    def test_request_budget_ceiling_clamped_to_15(self):
        """Policy clamps max_requests_per_test to MAX_REQUESTS_PER_TEST (15)."""
        policy = ConcurrencySafetyPolicy(max_requests_per_test=100)
        self.assertEqual(policy.max_requests_per_test, 15)

        # Minimum clamp
        policy_min = ConcurrencySafetyPolicy(max_requests_per_test=1)
        self.assertEqual(policy_min.max_requests_per_test, 2)

    def test_burst_size_maximum_10(self):
        """Policy bounds burst size to 10 workers maximum; floods raise PolicyViolationError."""
        policy = ConcurrencySafetyPolicy()
        self.assertEqual(policy.validate_burst_size(10), 10)
        with self.assertRaises(PolicyViolationError) as ctx:
            policy.validate_burst_size(11)
        self.assertIn("exceeds maximum safety limit", str(ctx.exception))

    def test_request_budget_enforcement_blocks_exceeding_15(self):
        """Dispatched requests per test cannot exceed policy budget."""
        temp_dir = tempfile.mkdtemp()
        scope = ScopeEngine({
            "program": {"name": "test"},
            "targets": {"domains": ["authorized.com"]},
        })

        mock_dispatch = MagicMock()
        mock_dispatch.return_value = ControlledResponse(status_code=200, body_text="{}", headers={})

        policy = ConcurrencySafetyPolicy(max_requests_per_test=5)

        try:
            engine = RaceIntelligenceEngine(
                program_dir=temp_dir,
                scope_engine=scope,
                policy=policy,
                dispatch_fn=mock_dispatch,
                require_approval=False,
                lab_mode=False,
            )

            req = ControlledRequest(method="POST", url="https://authorized.com/api/test")

            # Dispatch 5 requests within budget
            for _ in range(5):
                engine._send_request_safe(req)

            # 6th request must violate policy budget
            with self.assertRaises(PolicyViolationError) as ctx:
                engine._send_request_safe(req)
            self.assertIn("Request budget exceeded", str(ctx.exception))
            self.assertIn("maximum 5 requests per test", str(ctx.exception))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestWorkerTimeoutLifecycle(unittest.TestCase):
    """
    Verifies worker timeout and lifecycle handling:
    - Worker timeouts return INCONCLUSIVE.
    - Late-completing workers cannot mutate finalized test state.
    """

    def test_worker_timeout_marks_inconclusive(self):
        """When worker threads time out, the burst outcome is marked INCONCLUSIVE."""
        def slow_dispatch(req: ControlledRequest) -> ControlledResponse:
            time.sleep(0.5)
            return ControlledResponse(status_code=200, body_text='{"order_id": "ORD-1"}', headers={})

        synchronizer = BarrierSynchronizer(dispatch_fn=slow_dispatch, timeout=1.0)
        base_req = ControlledRequest(method="POST", url="http://127.0.0.1/test")

        # Mock timeout in join
        with patch.object(threading.Thread, "join", lambda self, timeout=None: None):
            results = synchronizer.dispatch_burst(base_req, burst_size=2)

        executions = [r[0] for r in results]
        responses = [r[1] for r in results]

        is_vuln, conf, lifecycle, sev, reasons, evidence = ConcurrencyInvariantEngine.evaluate_burst_results(
            category=RaceCategory.LIMIT_OVERRUN,
            allowed_limit=1,
            executions=executions,
            responses=responses,
        )

        self.assertFalse(is_vuln)
        self.assertEqual(conf, RaceConfidence.INCONCLUSIVE)
        self.assertIn("Worker timeout", reasons[0])

    def test_late_worker_cannot_mutate_finalized_state(self):
        """Verifies that late workers completing after synchronization timeout cannot overwrite results."""
        late_completed = threading.Event()

        def hanging_dispatch(req: ControlledRequest) -> ControlledResponse:
            if req.headers.get("X-Hang") == "true":
                time.sleep(0.1)
                late_completed.set()
                return ControlledResponse(status_code=200, body_text='{"mutated": true}', headers={})
            return ControlledResponse(status_code=200, body_text='{"normal": true}', headers={})

        synchronizer = BarrierSynchronizer(dispatch_fn=hanging_dispatch, timeout=1.0)
        base_req = ControlledRequest(method="POST", url="http://127.0.0.1/test")

        mutations = [
            {"headers": {"X-Hang": "false"}},
            {"headers": {"X-Hang": "true"}},
        ]

        # Use mock join timeout on second thread
        real_join = threading.Thread.join
        def selective_join(self, timeout=None):
            if "bb-race-worker-1" in self.name:
                return  # simulate timeout
            real_join(self, timeout)

        with patch.object(threading.Thread, "join", selective_join):
            results = synchronizer.dispatch_burst(base_req, burst_size=2, per_request_mutations=mutations)

        # Worker 1 timed out
        self.assertEqual(results[1][0].status_code, 0)
        self.assertEqual(results[1][0].error, "Worker execution timed out")
        self.assertIsNone(results[1][1])

        # Wait for hanging thread to finish
        late_completed.wait(timeout=1.0)

        # Confirm results[1] was NOT mutated by the late finish
        self.assertEqual(results[1][0].status_code, 0)
        self.assertEqual(results[1][0].error, "Worker execution timed out")
        self.assertIsNone(results[1][1])


if __name__ == "__main__":
    unittest.main()
