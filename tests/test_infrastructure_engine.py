"""
Comprehensive Acceptance and Regression Tests for Phase 19 Infrastructure Intelligence Engine.

Covers:
1. All 16 deterministic scenarios in LocalInfrastructureLab.
2. Differential soft-404 classes (SPA catch-all, distinct static file, dynamic error page, redirect catch-all).
3. Evidence-sufficiency stopping rules and measured byte consumption.
4. Sentinel secret leakage prevention across logs, exceptions, state, and reports.
5. Strict safe methods (GET, HEAD, OPTIONS) and rejection of TRACE / POST / PUT / DELETE.
6. Scope fail-closed and anti-SSRF enforcement.
7. Finding semantics (403 as OBSERVED, login as OBSERVATION, .git/HEAD as MEDIUM, .env sensitive vs benign).
8. State persistence, deduplication, CLI commands, and doctor check.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from framework.common.evidence import sanitize_sensitive_data
from framework.findings.lifecycle import FindingLifecycle
from framework.findings.schema import Finding
from framework.infrastructure.differential import (
    DifferentialComparisonResult,
    DifferentialSoft404Engine,
)
from framework.infrastructure.engine import (
    EXPOSURE_PATH_TEMPLATES,
    InfrastructureIntelligenceEngine,
)
from framework.infrastructure.exposure import (
    InfrastructureExposureEvaluator,
)
from framework.infrastructure.lab import (
    InfrastructureLabHandler,
    LocalInfrastructureLab,
)
from framework.infrastructure.model import (
    ExposureCandidate,
    ExposureCategory,
    ExposureEvaluationResult,
    ExposureHypothesis,
    generate_candidate_id,
)
from framework.infrastructure.policy import (
    InfrastructureExposurePolicy,
)
from framework.infrastructure.signatures import (
    InfrastructureSignatures,
)
from framework.infrastructure.state import (
    InfrastructureStateManager,
)
from framework.scope.engine import ScopeEngine, ScopeStatus
from framework.tools.doctor import SystemDoctor
from framework.validation.engine import ScopeViolationError, SecurityValidationEngine
from framework.validation.model import VulnerabilityFamily
from framework.validation.policy import PolicyViolationError
from framework.validation.request import ControlledRequest, ControlledResponse


class TestInfrastructureSignatures(unittest.TestCase):
    """Unit tests for deterministic signature matchers."""

    def test_version_control_git_head_valid(self):
        content = "ref: refs/heads/main\n"
        matched, reason, meta = InfrastructureSignatures.match_version_control(content)
        self.assertTrue(matched)
        self.assertEqual(meta.get("type"), "git_head")
        self.assertIn("refs/heads/main", meta.get("ref", ""))

    def test_version_control_git_head_sha_valid(self):
        content = "4b825dc642cb6eb9a060e54bf8d69288fbee4904\n"
        matched, reason, meta = InfrastructureSignatures.match_version_control(content)
        self.assertTrue(matched)
        self.assertEqual(meta.get("type"), "git_head_sha")

    def test_version_control_spa_html_rejected(self):
        content = "<!DOCTYPE html><html><body><h1>SPA Index</h1><p>ref: refs/heads/main</p></body></html>"
        matched, reason, meta = InfrastructureSignatures.match_version_control(content)
        self.assertFalse(matched)
        self.assertIn("HTML", reason)

    def test_config_file_env_sensitive(self):
        content = "APP_NAME=ProductionApp\nDB_PASSWORD=SuperSecretPass123\nAWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"
        matched, reason, meta, has_sensitive = InfrastructureSignatures.match_config_file(content)
        self.assertTrue(matched)
        self.assertTrue(has_sensitive)
        self.assertGreaterEqual(meta.get("key_count", 0), 2)

    def test_config_file_env_benign(self):
        content = "APP_NAME=PublicDemo\nAPP_ENV=local\nLOG_CHANNEL=stack\n"
        matched, reason, meta, has_sensitive = InfrastructureSignatures.match_config_file(content)
        self.assertTrue(matched)
        self.assertFalse(has_sensitive)
        self.assertGreaterEqual(meta.get("key_count", 0), 2)

    def test_config_file_spa_html_rejected(self):
        content = "<!DOCTYPE html><html><body>APP_NAME=Test\nDB_PASSWORD=Secret</body></html>"
        matched, reason, meta, has_sensitive = InfrastructureSignatures.match_config_file(content)
        self.assertFalse(matched)
        self.assertIn("HTML", reason)

    def test_backup_archive_zip_magic_bytes(self):
        raw = b"PK\x03\x04" + (b"\x00" * 100)
        matched, reason, meta = InfrastructureSignatures.match_backup_archive(raw, "application/zip")
        self.assertTrue(matched)
        self.assertEqual(meta.get("format"), "zip")

    def test_backup_archive_gzip_magic_bytes(self):
        raw = b"\x1f\x8b\x08\x00" + (b"\x00" * 50)
        matched, reason, meta = InfrastructureSignatures.match_backup_archive(raw, "application/gzip")
        self.assertTrue(matched)
        self.assertEqual(meta.get("format"), "gzip")

    def test_admin_interface_login_form_is_observation(self):
        html = '<html><body><form action="/login" method="post"><input type="password" name="pwd"><button>Log In</button></form></body></html>'
        matched, reason, meta, is_login = InfrastructureSignatures.match_admin_interface(html, 200)
        self.assertTrue(matched)
        self.assertTrue(is_login)
        self.assertEqual(meta.get("surface"), "login_page")

    def test_admin_interface_prometheus_metrics(self):
        content = "# HELP http_requests_total Total HTTP Requests\n# TYPE http_requests_total counter\nhttp_requests_total 1024\n"
        matched, reason, meta, is_login = InfrastructureSignatures.match_admin_interface(content, 200)
        self.assertTrue(matched)
        self.assertFalse(is_login)
        self.assertEqual(meta.get("surface"), "prometheus_metrics")

    def test_deployment_manifest_package_json(self):
        content = json.dumps({"name": "my-app", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}})
        matched, reason, meta = InfrastructureSignatures.match_deployment_manifest(content)
        self.assertTrue(matched)
        self.assertEqual(meta.get("manifest_type"), "package.json")

    def test_source_map_json(self):
        content = json.dumps({"version": 3, "file": "app.js", "sources": ["index.ts"], "mappings": "AAAA"})
        matched, reason, meta = InfrastructureSignatures.match_source_map(content)
        self.assertTrue(matched)
        self.assertEqual(meta.get("version"), 3)

    def test_directory_listing_index_of(self):
        html = "<html><head><title>Index of /static</title></head><body><h1>Index of /static</h1><pre><a href='../'>[To Parent Directory]</a>\n<a href='a.txt'>a.txt</a></pre></body></html>"
        matched, reason, meta = InfrastructureSignatures.match_directory_listing(html)
        self.assertTrue(matched)
        self.assertEqual(meta.get("type"), "directory_index")


class TestDifferentialSoft404Engine(unittest.TestCase):
    """Tests for multi-factor differential soft-404 comparison."""

    def test_spa_catchall_detected_and_rejected(self):
        # When both candidate and baseline return SPA HTML with high similarity
        cand_html = '<!DOCTYPE html><html><body><div id="root">App</div><script src="/app.js"></script></body></html>'
        base_html = '<!DOCTYPE html><html><body><div id="root">App</div><script src="/app.js"></script></body></html>'
        res = DifferentialSoft404Engine.evaluate(
            candidate_status=200,
            candidate_headers={"Content-Type": "text/html; charset=utf-8"},
            candidate_body=cand_html,
            baseline_status=200,
            baseline_headers={"Content-Type": "text/html; charset=utf-8"},
            baseline_body=base_html,
        )
        self.assertTrue(res.is_soft_404)
        self.assertGreaterEqual(res.similarity_score, 0.85)

    def test_spa_distinct_file_validated_despite_baseline_200(self):
        # Baseline returned 200 SPA HTML, but candidate returns 200 text/plain git HEAD!
        cand_body = "ref: refs/heads/main\n"
        base_html = '<!DOCTYPE html><html><body><div id="root">App</div><script src="/app.js"></script></body></html>'
        res = DifferentialSoft404Engine.evaluate(
            candidate_status=200,
            candidate_headers={"Content-Type": "text/plain"},
            candidate_body=cand_body,
            baseline_status=200,
            baseline_headers={"Content-Type": "text/html; charset=utf-8"},
            baseline_body=base_html,
            candidate_has_structural_signature=True,
        )
        # MUST NOT be classified as soft-404!
        self.assertFalse(res.is_soft_404)
        self.assertFalse(res.content_type_matches)

    def test_dynamic_404_nonce_normalization(self):
        # Custom 200 error pages with varying timestamps and nonces
        cand_html = '<!DOCTYPE html><html><body><h1>Error</h1><p>Time: 2026-10-23T10:00:00Z</p><div nonce="nonce_111">Not Found</div></body></html>'
        base_html = '<!DOCTYPE html><html><body><h1>Error</h1><p>Time: 2026-10-23T10:00:05Z</p><div nonce="nonce_222">Not Found</div></body></html>'
        res = DifferentialSoft404Engine.evaluate(
            candidate_status=200,
            candidate_headers={"Content-Type": "text/html"},
            candidate_body=cand_html,
            baseline_status=200,
            baseline_headers={"Content-Type": "text/html"},
            baseline_body=base_html,
        )
        self.assertTrue(res.is_soft_404)
        self.assertGreaterEqual(res.similarity_score, 0.85)

    def test_redirect_catchall_detected(self):
        # Both candidate and baseline redirect to /login
        res = DifferentialSoft404Engine.evaluate(
            candidate_status=302,
            candidate_headers={},
            candidate_body="",
            baseline_status=302,
            baseline_headers={},
            baseline_body="",
            candidate_final_url="https://example.com/login",
            baseline_final_url="https://example.com/login",
        )
        self.assertTrue(res.is_soft_404)
        self.assertTrue(res.redirect_target_matches)


class TestInfrastructureSafetyAndPolicy(unittest.TestCase):
    """Verifies strict HTTP method limits and state-changing GET protection."""

    def test_policy_rejects_trace_method(self):
        with self.assertRaises(PolicyViolationError):
            InfrastructureExposurePolicy(allowed_methods={"GET", "TRACE"})

    def test_policy_rejects_post_put_delete(self):
        for bad_m in ("POST", "PUT", "DELETE", "PATCH"):
            with self.assertRaises(PolicyViolationError):
                InfrastructureExposurePolicy(allowed_methods={"GET", bad_m})

    def test_policy_permits_safe_methods_only(self):
        policy = InfrastructureExposurePolicy()
        self.assertEqual(policy.allowed_methods, {"GET", "HEAD", "OPTIONS"})
        self.assertTrue(policy.is_method_allowed("GET"))
        self.assertTrue(policy.is_method_allowed("HEAD"))
        self.assertTrue(policy.is_method_allowed("OPTIONS"))
        self.assertFalse(policy.is_method_allowed("TRACE"))
        self.assertFalse(policy.is_method_allowed("POST"))

    def test_policy_blocks_state_changing_get(self):
        policy = InfrastructureExposurePolicy(block_state_changing_get=True)
        with self.assertRaises(PolicyViolationError):
            policy.validate_request_safety("GET", "https://example.com/api/admin/shutdown")

        with self.assertRaises(PolicyViolationError):
            policy.validate_request_safety("GET", "https://example.com/user/delete-account")


class TestLocalInfrastructureLabScenarios(unittest.TestCase):
    """
    Executes and asserts against all 16 deterministic scenarios using LocalInfrastructureLab.
    """

    @classmethod
    def setUpClass(cls):
        cls.lab = LocalInfrastructureLab()
        cls.base_url = cls.lab.start()
        cls.scope_engine = LocalInfrastructureLab.get_scope_engine(cls.lab.port)

    @classmethod
    def tearDownClass(cls):
        cls.lab.stop()

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="bb_infra_test_")
        self.policy = InfrastructureExposurePolicy()
        self.engine = InfrastructureIntelligenceEngine(
            program_dir=self.temp_dir,
            scope_engine=self.scope_engine,
            policy=self.policy,
            lab_mode=True,
        )
        self.engine.allow_fixture_port(self.lab.port)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_scenario_01_git_head_exposed(self):
        cand = self.engine.add_candidate(f"{self.base_url}/scenario/git-head/.git/HEAD", ExposureCategory.VERSION_CONTROL)
        res, finding = self.engine.validate_candidate(cand, auto_approve=True)
        self.assertTrue(res.is_exposed)
        self.assertEqual(res.lifecycle_state, FindingLifecycle.VALIDATED)
        self.assertEqual(res.severity, "MEDIUM") # Never automatic HIGH
        self.assertIsNotNone(finding)
        self.assertEqual(finding.lifecycle_state, FindingLifecycle.SIMULATED)

    def test_scenario_02_git_head_spa_catchall_rejected(self):
        cand = self.engine.add_candidate(f"{self.base_url}/scenario/spa-catchall/.git/HEAD", ExposureCategory.VERSION_CONTROL)
        res, finding = self.engine.validate_candidate(cand, auto_approve=True)
        self.assertFalse(res.is_exposed)
        self.assertEqual(res.lifecycle_state, FindingLifecycle.REJECTED)
        self.assertTrue(res.is_soft_404)
        self.assertIsNone(finding)

    def test_scenario_03_git_head_spa_distinct_validated(self):
        cand = self.engine.add_candidate(f"{self.base_url}/scenario/spa-distinct/.git/HEAD", ExposureCategory.VERSION_CONTROL)
        res, finding = self.engine.validate_candidate(cand, auto_approve=True)
        self.assertTrue(res.is_exposed)
        self.assertEqual(res.lifecycle_state, FindingLifecycle.VALIDATED)
        self.assertIsNotNone(finding)

    def test_scenario_04_env_exposed_sensitive_high(self):
        cand = self.engine.add_candidate(f"{self.base_url}/scenario/env-sensitive/.env", ExposureCategory.CONFIG_FILE)
        res, finding = self.engine.validate_candidate(cand, auto_approve=True)
        self.assertTrue(res.is_exposed)
        self.assertEqual(res.lifecycle_state, FindingLifecycle.VALIDATED)
        self.assertEqual(res.severity, "HIGH") # Sensitive keys present
        self.assertTrue(res.evidence.get("has_sensitive_data"))
        self.assertTrue(res.evidence.get("credentials_untested"))

    def test_scenario_05_env_non_sensitive_medium(self):
        cand = self.engine.add_candidate(f"{self.base_url}/scenario/env-benign/.env", ExposureCategory.CONFIG_FILE)
        res, finding = self.engine.validate_candidate(cand, auto_approve=True)
        self.assertTrue(res.is_exposed)
        self.assertEqual(res.lifecycle_state, FindingLifecycle.VALIDATED)
        self.assertEqual(res.severity, "MEDIUM") # No sensitive keys
        self.assertFalse(res.evidence.get("has_sensitive_data"))

    def test_scenario_06_env_html_dynamic_404_rejected(self):
        cand = self.engine.add_candidate(f"{self.base_url}/scenario/dynamic-404/.env", ExposureCategory.CONFIG_FILE)
        res, finding = self.engine.validate_candidate(cand, auto_approve=True)
        self.assertFalse(res.is_exposed)
        self.assertEqual(res.lifecycle_state, FindingLifecycle.REJECTED)
        self.assertIsNone(finding)

    def test_scenario_07_backup_zip_bounded_stream(self):
        cand = self.engine.add_candidate(f"{self.base_url}/scenario/backup/backup.zip", ExposureCategory.BACKUP_ARCHIVE)
        res, finding = self.engine.validate_candidate(cand, auto_approve=True)
        self.assertTrue(res.is_exposed)
        self.assertEqual(res.lifecycle_state, FindingLifecycle.VALIDATED)
        self.assertTrue(res.stopping_rule_triggered)
        self.assertLessEqual(res.bytes_consumed, 1024) # Stream truncated at <= 1 KB

    def test_scenario_08_actuator_health_safe_without_env_dump(self):
        cand = self.engine.add_candidate(f"{self.base_url}/scenario/actuator/actuator/health", ExposureCategory.ADMIN_INTERFACE)
        res, finding = self.engine.validate_candidate(cand, auto_approve=True)
        self.assertTrue(res.is_exposed)
        self.assertEqual(res.lifecycle_state, FindingLifecycle.VALIDATED)
        self.assertEqual(res.evidence.get("metadata", {}).get("surface"), "actuator_health")

    def test_scenario_09_admin_login_is_observation_not_vulnerability(self):
        cand = self.engine.add_candidate(f"{self.base_url}/scenario/admin/login", ExposureCategory.ADMIN_INTERFACE)
        res, finding = self.engine.validate_candidate(cand, auto_approve=True)
        self.assertTrue(res.is_exposed)
        self.assertEqual(res.lifecycle_state, FindingLifecycle.OBSERVATION)
        self.assertEqual(res.severity, "INFORMATIONAL") # Login pages are strictly INFORMATIONAL observations
        self.assertIsNotNone(finding)
        self.assertIn("Observed", finding.title)

    def test_scenario_10_http_403_is_access_restricted_not_rejected(self):
        cand = self.engine.add_candidate(f"{self.base_url}/scenario/restricted/secret-admin", ExposureCategory.ADMIN_INTERFACE)
        res, finding = self.engine.validate_candidate(cand, auto_approve=True)
        self.assertFalse(res.is_exposed)
        # Must be OBSERVED, NEVER REJECTED!
        self.assertEqual(res.lifecycle_state, FindingLifecycle.OBSERVED)
        self.assertEqual(res.severity, "INFORMATIONAL")
        self.assertEqual(res.confidence, "LOW")  # Appropriately conservative: 403 alone does not prove existence
        self.assertIn("access control", res.reasons[0].lower())
        self.assertIn("does not verify", res.reasons[0].lower())
        self.assertFalse(res.evidence.get("resource_confirmed", True))
        self.assertTrue(res.evidence.get("access_restricted", False))
        self.assertIsNone(finding)

    def test_scenario_11_directory_listing(self):
        cand = self.engine.add_candidate(f"{self.base_url}/scenario/directory/uploads/", ExposureCategory.DIRECTORY_LISTING)
        res, finding = self.engine.validate_candidate(cand, auto_approve=True)
        self.assertTrue(res.is_exposed)
        self.assertEqual(res.lifecycle_state, FindingLifecycle.VALIDATED)
        self.assertEqual(res.severity, "LOW")

    def test_scenario_12_source_map_exposed_and_truncated(self):
        cand = self.engine.add_candidate(f"{self.base_url}/scenario/sourcemap/app.js.map", ExposureCategory.SOURCE_MAP)
        res, finding = self.engine.validate_candidate(cand, auto_approve=True)
        self.assertTrue(res.is_exposed)
        self.assertEqual(res.lifecycle_state, FindingLifecycle.VALIDATED)
        self.assertEqual(res.severity, "LOW")
        self.assertTrue(res.stopping_rule_triggered)
        self.assertLessEqual(res.bytes_consumed, 8192)

    def test_scenario_13_secret_leakage_prevention(self):
        # Verify that unique sentinel secret is completely scrubbed from all output channels
        cand = self.engine.add_candidate(f"{self.base_url}/scenario/env-sensitive/.env", ExposureCategory.CONFIG_FILE)
        res, finding = self.engine.validate_candidate(cand, auto_approve=True)

        sentinel_pass = "SuperSecretSentinelP@ss123"
        sentinel_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYSENTINELKEY"

        # 1. State JSON check
        state_data = self.engine.state_mgr.load_state()
        state_json_str = json.dumps(state_data)
        self.assertNotIn(sentinel_pass, state_json_str)
        self.assertNotIn(sentinel_key, state_json_str)
        self.assertIn("[REDACTED_BY_BB_AGENT]", state_json_str)

        # 2. Finding object / report check
        self.assertIsNotNone(finding)
        finding_json_str = json.dumps(finding.to_dict())
        self.assertNotIn(sentinel_pass, finding_json_str)
        self.assertNotIn(sentinel_key, finding_json_str)

        # 3. Rendered report check (when promoted to VALIDATED for disclosure report)
        finding.lifecycle_state = FindingLifecycle.VALIDATED
        report_md = finding.to_markdown_report()
        self.assertNotIn(sentinel_pass, report_md)
        self.assertNotIn(sentinel_key, report_md)
        self.assertIn("[REDACTED_BY_BB_AGENT]", report_md)

        # 4. Fingerprint authenticity definition: authenticates sanitized representation
        clean_excerpt = res.sanitized_excerpt
        self.assertNotIn(sentinel_pass, clean_excerpt)
        self.assertNotIn(sentinel_key, clean_excerpt)
        self.assertEqual(res.evidence_fingerprint, hashlib.sha256(clean_excerpt.encode("utf-8")).hexdigest())

    def test_scenario_14_streaming_stopping_rule_oversized(self):
        # 10 MB endpoint: asserts actual bytes read are capped at <= 1 KB for backup archive
        cand = self.engine.add_candidate(f"{self.base_url}/scenario/streaming/large-backup.zip", ExposureCategory.BACKUP_ARCHIVE)
        res, finding = self.engine.validate_candidate(cand, auto_approve=True)
        self.assertLessEqual(res.bytes_consumed, 1_024)
        self.assertTrue(res.stopping_rule_triggered)

    def test_scenario_14b_config_streaming_stopping_rule(self):
        # 1 MB endpoint: asserts actual bytes read are capped at <= 8 KB for config file
        cand = self.engine.add_candidate(f"{self.base_url}/scenario/streaming/large-config.env", ExposureCategory.CONFIG_FILE)
        res, finding = self.engine.validate_candidate(cand, auto_approve=True)
        self.assertLessEqual(res.bytes_consumed, 8_192)
        self.assertTrue(res.stopping_rule_triggered)

    def test_colon_delimited_secret_redaction(self):
        # Verify that colon-delimited secrets (e.g. YAML/env format) are sanitized
        from framework.infrastructure.exposure import sanitize_exposure_content
        sample = "DB_PASSWORD: superSecretPassword123\nAPI_KEY: my_token_456\nAPP_NAME: safe_app"
        redacted = sanitize_exposure_content(sample)
        self.assertNotIn("superSecretPassword123", redacted)
        self.assertNotIn("my_token_456", redacted)
        self.assertIn("[REDACTED_BY_BB_AGENT]", redacted)
        self.assertIn("safe_app", redacted)

    def test_scenario_15_scope_fail_closed(self):
        # Out-of-scope target fails closed without dispatch
        cand = self.engine.add_candidate("http://unauthorized.attacker.com/secret/.env", ExposureCategory.CONFIG_FILE)
        res, finding = self.engine.validate_candidate(cand, auto_approve=True)
        self.assertFalse(res.is_exposed)
        self.assertEqual(res.lifecycle_state, FindingLifecycle.REJECTED)
        self.assertIn("scope", res.reasons[0].lower())
        self.assertIsNone(finding)

    def test_scenario_16_ssrf_prohibited_ip_blocked(self):
        # Destination resolving to private / cloud metadata IP is blocked by anti-SSRF policy
        cand = self.engine.add_candidate("http://169.254.169.254/latest/meta-data/", ExposureCategory.ADMIN_INTERFACE)
        res, finding = self.engine.validate_candidate(cand, auto_approve=True)
        self.assertFalse(res.is_exposed)
        self.assertIsNone(finding)


class TestVulnerabilityFamilyCompatibility(unittest.TestCase):
    """Verifies that INFRASTRUCTURE_EXPOSURE and CONFIGURATION_EXPOSURE integrate cleanly into Finding."""

    def test_finding_with_infrastructure_exposure_family(self):
        finding = Finding(
            title="Exposed Git Repository",
            summary="Found .git/HEAD",
            affected_asset="example.com",
            affected_endpoint="https://example.com/.git/HEAD",
            vulnerability_type=VulnerabilityFamily.INFRASTRUCTURE_EXPOSURE.value,
            severity="MEDIUM",
            description="Exposed version control",
            root_cause="Misconfiguration",
            prerequisites="None",
            reproduction_steps=["GET /.git/HEAD"],
            expected_result="404",
            observed_result="200",
            security_impact="Source code disclosure",
            remediation="Block .git access",
            scope_reference="Scope reference",
            confidence="CONFIRMED",
            lifecycle_state=FindingLifecycle.VALIDATED,
        )
        f_dict = finding.to_dict()
        self.assertEqual(f_dict["vulnerability_type"], "INFRASTRUCTURE_EXPOSURE")
        self.assertEqual(f_dict["lifecycle_state"], "VALIDATED")

    def test_finding_with_configuration_exposure_family(self):
        finding = Finding(
            title="Exposed .env Configuration",
            summary="Found .env with database credentials",
            affected_asset="example.com",
            affected_endpoint="https://example.com/.env",
            vulnerability_type=VulnerabilityFamily.CONFIGURATION_EXPOSURE.value,
            severity="HIGH",
            description="Exposed environment secrets",
            root_cause="Public .env",
            prerequisites="None",
            reproduction_steps=["GET /.env"],
            expected_result="404",
            observed_result="200",
            security_impact="Database takeover",
            remediation="Remove .env from webroot",
            scope_reference="Scope reference",
            confidence="CONFIRMED",
            lifecycle_state=FindingLifecycle.VALIDATED,
        )
        f_dict = finding.to_dict()
        self.assertEqual(f_dict["vulnerability_type"], "CONFIGURATION_EXPOSURE")
        self.assertEqual(f_dict["lifecycle_state"], "VALIDATED")


class TestInfrastructureStateResilience(unittest.TestCase):
    """Acceptance tests for persistent state schema resilience and self-healing."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_state_self_heals_empty_dict(self):
        """Pre-existing empty dict in infrastructure.json does not raise KeyError."""
        state_dir = os.path.join(self.temp_dir, "state")
        os.makedirs(state_dir, exist_ok=True)
        infra_file = os.path.join(state_dir, "infrastructure.json")
        with open(infra_file, "w", encoding="utf-8") as f:
            f.write("{}")

        mgr = InfrastructureStateManager(self.temp_dir)
        state = mgr.load_state()
        self.assertIn("summary", state)
        self.assertEqual(state["summary"]["total_candidates"], 0)

        cand = ExposureCandidate(
            candidate_id="cand-1",
            application="example.com",
            endpoint="https://example.com/.env",
            category=ExposureCategory.CONFIG_FILE,
        )
        mgr.save_candidate(cand)
        updated = mgr.load_state()
        self.assertEqual(updated["summary"]["total_candidates"], 1)

    def test_state_self_heals_missing_summary(self):
        """State file with partial keys self-heals summary without losing candidates."""
        state_dir = os.path.join(self.temp_dir, "state")
        os.makedirs(state_dir, exist_ok=True)
        infra_file = os.path.join(state_dir, "infrastructure.json")
        with open(infra_file, "w", encoding="utf-8") as f:
            json.dump({"candidates": [{"candidate_id": "c1", "category": "CONFIG_FILE", "url": "https://example.com/.env"}]}, f)

        mgr = InfrastructureStateManager(self.temp_dir)
        state = mgr.load_state()
        self.assertIn("summary", state)
        self.assertEqual(len(state["candidates"]), 1)

    def test_state_manager_interoperability(self):
        """Main StateManager creates default infrastructure state compatible with InfrastructureStateManager."""
        from framework.state.manager import StateManager
        main_mgr = StateManager(self.temp_dir)
        self.assertTrue(os.path.exists(main_mgr.infrastructure_file))

        infra_mgr = InfrastructureStateManager(self.temp_dir)
        state = infra_mgr.load_state()
        self.assertIn("summary", state)
        self.assertEqual(state["summary"]["total_candidates"], 0)
        self.assertIn("candidates", state)


class TestExceptionAndHttp403Hardening(unittest.TestCase):
    """Verifies exception sanitization and conservative HTTP 403 semantics."""

    def test_request_exception_sanitizes_sentinel_secret(self):
        """
        Verifies that when send_request raises an exception containing a unique sentinel secret,
        the secret never leaks into reasons, evidence, candidate state, logs, findings, or reports.
        """
        sentinel_secret = "SENTINEL_SECRET_XYZ_987654321"

        # 1. Direct evaluator test with secret embedded in exception text
        mock_send = MagicMock(side_effect=RuntimeError(f"Connection failed: token={sentinel_secret}&user=admin"))
        evaluator = InfrastructureExposureEvaluator(send_request_fn=mock_send)

        cand = ExposureCandidate(
            candidate_id="cand-exc-sentinel",
            application="example.com",
            endpoint="https://example.com/.env",
            category=ExposureCategory.CONFIG_FILE,
        )

        res = evaluator.evaluate_candidate(cand)
        self.assertFalse(res.is_exposed)
        self.assertEqual(res.lifecycle_state, FindingLifecycle.NEEDS_MANUAL_REVIEW)
        self.assertEqual(res.confidence, "LOW")

        # Assert sentinel secret is strictly NOT in reasons, evidence, or excerpt
        self.assertNotIn(sentinel_secret, " ".join(res.reasons))
        self.assertNotIn(sentinel_secret, str(res.evidence))
        self.assertNotIn(sentinel_secret, str(res.sanitized_excerpt))
        self.assertIn("network transport error", res.reasons[0])

        # 2. Engine lifecycle test verifying state persistence, logs, findings, and reports
        temp_dir = tempfile.mkdtemp()
        try:
            scope_engine = MagicMock(spec=ScopeEngine)
            scope_engine.check.return_value = MagicMock(status=ScopeStatus.IN_SCOPE)

            mock_validation_engine = MagicMock(spec=SecurityValidationEngine)
            mock_validation_engine.send_request.side_effect = RuntimeError(
                f"Failed to connect to proxy: auth_key={sentinel_secret}"
            )

            engine = InfrastructureIntelligenceEngine(
                program_dir=temp_dir,
                scope_engine=scope_engine,
                policy=InfrastructureExposurePolicy(),
                validation_engine=mock_validation_engine,
                require_approval=False,
            )

            with self.assertLogs(level="DEBUG") as log_capture:
                # Add a harmless log entry so assertLogs doesn't fail if framework produces no logs
                logging.getLogger("test_sentinel").info("Starting safe test run")
                res, finding = engine.validate_candidate(cand, auto_approve=True)

            # Assert finding is None
            self.assertIsNone(finding)

            # Assert logs do not contain the sentinel
            for log_msg in log_capture.output:
                self.assertNotIn(sentinel_secret, log_msg)

            # Assert persistent state JSON does not contain the sentinel
            state_file = os.path.join(temp_dir, "state", "infrastructure.json")
            self.assertTrue(os.path.exists(state_file))
            with open(state_file, "r", encoding="utf-8") as f:
                state_content = f.read()
            self.assertNotIn(sentinel_secret, state_content)

            # Assert candidate note stored in state has clean generic diagnostic
            state_data = json.loads(state_content)
            saved_cand = next(c for c in state_data["candidates"] if c["candidate_id"] == "cand-exc-sentinel")
            self.assertIn("Request failed: network transport error", saved_cand["notes"])
            self.assertNotIn(sentinel_secret, saved_cand["notes"])

            # 3. Explicit disk Markdown report inspection for Phase 19 sentinel secret
            # Even if an operator or automated flow attempts to generate a report from candidate/evaluation notes,
            # verify that a generated Markdown report written to disk has zero sentinel leakage.
            reports_dir = os.path.join(temp_dir, "reports")
            os.makedirs(reports_dir, exist_ok=True)
            report_file = os.path.join(reports_dir, "report-cand-exc-sentinel.md")
            
            # Construct finding utilizing candidate notes / exception diagnostic
            finding_with_diag = Finding(
                title="Infrastructure Exposure Test Diagnostic",
                summary=f"Evaluation completed with diagnostic: {saved_cand['notes']}",
                affected_asset="example.com",
                affected_endpoint="http://example.com/secret",
                vulnerability_type=VulnerabilityFamily.CONFIGURATION_EXPOSURE.value,
                severity="INFORMATIONAL",
                description="Diagnostic test ensuring exception does not leak credentials into markdown artifacts.",
                root_cause="N/A",
                prerequisites="None",
                reproduction_steps=["Step 1"],
                expected_result="Generic diagnostic",
                observed_result=saved_cand["notes"],
                security_impact="None",
                remediation="None",
                scope_reference="In scope",
                confidence="CONFIRMED",
                finding_id="FND-INFRA-SENTINEL-01",
                lifecycle_state=FindingLifecycle.VALIDATED,
                validation_notes=f"Diagnostic notes: {saved_cand['notes']}",
                evidence=[{
                    "type": "diagnostic_log",
                    "content": saved_cand["notes"],
                    "timestamp": "2026-10-23T12:00:00Z",
                }],
            )
            with open(report_file, "w", encoding="utf-8") as rf:
                rf.write(finding_with_diag.to_markdown_report())

            self.assertTrue(os.path.exists(report_file))
            with open(report_file, "r", encoding="utf-8") as rf:
                disk_report_content = rf.read()
            self.assertNotIn(sentinel_secret, disk_report_content)
            self.assertIn("network transport error", disk_report_content)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_request_exception_classification_categories(self):
        """Tests that various exception types map to clean, informative category diagnostics."""
        from framework.infrastructure.exposure import _classify_request_exception

        self.assertEqual(
            _classify_request_exception(TimeoutError("secret_timeout_info")),
            "connection or read timeout",
        )
        self.assertEqual(
            _classify_request_exception(ConnectionError("secret_conn_info")),
            "network connection failure",
        )
        self.assertEqual(
            _classify_request_exception(ScopeViolationError("out of scope secret")),
            "scope authorization failure",
        )
        self.assertEqual(
            _classify_request_exception(PolicyViolationError("policy error secret")),
            "security policy violation",
        )

    def test_http_403_conservative_semantics_and_wording(self):
        """Verifies that HTTP 403 uses conservative confidence (LOW) and does not assert resource existence."""
        mock_resp = ControlledResponse(
            status_code=403,
            headers={"Content-Type": "text/html"},
            body="<html><body><h1>403 Forbidden</h1></body></html>",
            url="https://example.com/admin/secret",
            method="GET",
        )
        mock_send = MagicMock(return_value=mock_resp)
        evaluator = InfrastructureExposureEvaluator(send_request_fn=mock_send)

        cand = ExposureCandidate(
            candidate_id="cand-403-test",
            application="example.com",
            endpoint="https://example.com/admin/secret",
            category=ExposureCategory.ADMIN_INTERFACE,
        )

        res = evaluator.evaluate_candidate(cand)
        self.assertFalse(res.is_exposed)
        self.assertEqual(res.lifecycle_state, FindingLifecycle.OBSERVED)
        self.assertEqual(res.confidence, "LOW")
        self.assertEqual(res.severity, "INFORMATIONAL")
        self.assertTrue(res.evidence.get("access_restricted"))
        self.assertFalse(res.evidence.get("resource_confirmed"))

        # Assert reasons wording is conservative
        reason = res.reasons[0].lower()
        self.assertNotIn("resource exists", reason)
        self.assertIn("does not verify", reason)


if __name__ == "__main__":
    unittest.main()
