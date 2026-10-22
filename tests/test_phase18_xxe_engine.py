"""
Phase 18 Regression Tests: XXE & XML Parser Security Subsystem.

Covers:
1. Safe synthetic entity reflection without file system probing or network egress.
2. Strict prohibition on file://, /etc/passwd, win.ini, and cloud metadata (fails closed).
3. Signal classification: internal DTD entity reflection emits OBSERVATION (INFORMATIONAL),
   never false HIGH-severity VALIDATED XXE.
4. Parser errors and secure rejections emit zero findings (no false positives).
5. Evidence classification cannot be upgraded merely by a mock fixture label (Mock OOB produces SIMULATED).
6. Deterministic LocalXxeLab test harness across reflection, secure reject, error, and OOB modes.
7. State persistence, approval gate, and finding deduplication.
8. XxeValidator and SsrfValidator plugin integration with SecurityValidationEngine.
"""

from __future__ import annotations

import json
import os
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from framework.findings.lifecycle import FindingLifecycle
from framework.scope.engine import ScopeEngine
from framework.ssrf.model import OobProviderStatus
from framework.ssrf.provider import (
    CollaboratorOobProvider,
    InteractshOobProvider,
    MockOobProvider,
    OobProvider,
)
from framework.validation.baseline import BaselineComparison, BaselineObservation, compare_with_baseline
from framework.validation.engine import SecurityValidationEngine
from framework.validation.model import RiskLevel, SecurityTestCase, VulnerabilityFamily
from framework.validation.policy import PolicyViolationError, SecurityTestPolicy
from framework.validation.request import ControlledRequest, ControlledResponse
from framework.validation.validator import XxeValidator, SsrfValidator
from framework.xxe.engine import XxeIntelligenceEngine
from framework.xxe.lab import LocalXxeLab
from framework.xxe.model import (
    XxeCandidate,
    XxeCategory,
    XxeConfidence,
    XxeEvidence,
    XxeInteractionType,
)
from framework.xxe.state import XxeStateManager


def make_scope() -> ScopeEngine:
    return ScopeEngine({
        "program": {"name": "test-xxe"},
        "targets": {
            "domains": ["target.com", "*.target.com"],
            "urls": ["http://127.0.0.1", "http://127.0.0.1:8080"],
        },
    })


# ============================================================================
# 1. Non-Destructive Payload Construction & Safety Invariants
# ============================================================================

class TestXxePayloadSafety:
    """Verifies that XXE engine payloads never attempt file access or cloud metadata probing."""

    def test_synthetic_reflection_payload_contains_no_external_entities(self):
        tmp_dir = tempfile.mkdtemp()
        engine = XxeIntelligenceEngine(program_dir=tmp_dir, scope_engine=make_scope())
        cand = XxeCandidate(
            application="TestApp",
            endpoint="http://127.0.0.1:8080/xml",
            parameter="doc",
            param_location="XML_BODY",
        )
        payload = engine._build_synthetic_reflection_payload(cand, "safe_entity", "CONFIRMED_CANARY_123")
        assert "SYSTEM" not in payload.upper()
        assert "PUBLIC" not in payload.upper()
        assert "file://" not in payload
        assert "169.254.169.254" not in payload
        assert "<!ENTITY safe_entity \"CONFIRMED_CANARY_123\">" in payload
        assert "&safe_entity;" in payload

    def test_prohibited_targets_fail_closed(self):
        tmp_dir = tempfile.mkdtemp()
        engine = XxeIntelligenceEngine(program_dir=tmp_dir, scope_engine=make_scope())

        disallowed = [
            '<!ENTITY xxe SYSTEM "file:///etc/passwd">',
            '<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">',
            '<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">',
            '<!ENTITY xxe SYSTEM "http://metadata.google.internal/">',
        ]
        for payload in disallowed:
            with pytest.raises(ValueError, match="Disallowed payload pattern detected"):
                engine._validate_payload_safety(payload)


# ============================================================================
# 2. Local XXE Lab Simulation Modes
# ============================================================================

class TestLocalXxeLabSimulation:
    """Verifies LocalXxeLab deterministically simulates XML parser configurations."""

    def test_reflection_mode_reflects_internal_entity(self):
        lab = LocalXxeLab(mode="reflection")
        hook = lab.create_handler_hook()

        xml_body = '<!DOCTYPE root [ <!ENTITY test "EXPANDED_VALUE"> ]><root><val>&test;</val></root>'
        req = ControlledRequest(
            url="http://127.0.0.1:8080/xml",
            method="POST",
            headers={"Content-Type": "application/xml"},
            body=xml_body,
        )
        resp = hook(req)
        assert resp.status_code == 200
        assert "EXPANDED_VALUE" in resp.body

    def test_secure_reject_mode_blocks_doctype(self):
        lab = LocalXxeLab(mode="secure_reject")
        hook = lab.create_handler_hook()

        xml_body = '<!DOCTYPE root [ <!ENTITY test "EXPANDED_VALUE"> ]><root>&test;</root>'
        req = ControlledRequest(
            url="http://127.0.0.1:8080/xml",
            method="POST",
            headers={"Content-Type": "application/xml"},
            body=xml_body,
        )
        resp = hook(req)
        assert resp.status_code == 400
        assert "DOCTYPE declarations are prohibited" in resp.body

    def test_parser_error_mode_returns_syntax_error(self):
        lab = LocalXxeLab(mode="parser_error")
        hook = lab.create_handler_hook()

        req = ControlledRequest(
            url="http://127.0.0.1:8080/xml",
            method="POST",
            headers={"Content-Type": "application/xml"},
            body="<bad_xml>",
        )
        resp = hook(req)
        assert resp.status_code == 400
        assert "XML syntax error" in resp.body

    def test_lab_rejects_destructive_file_access(self):
        lab = LocalXxeLab(mode="reflection")
        hook = lab.create_handler_hook()

        req = ControlledRequest(
            url="http://127.0.0.1:8080/xml",
            method="POST",
            headers={"Content-Type": "application/xml"},
            body='<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><root>&xxe;</root>',
        )
        resp = hook(req)
        assert resp.status_code == 403
        assert "Forbidden target blocked" in resp.body


# ============================================================================
# 3. Active Validation Pipeline & Evidence Semantics
# ============================================================================

class TestXxeActiveValidation:
    """Verifies end-to-end controlled XXE validation and evidence classification."""

    def test_harmless_internal_entity_reflection_alone_does_not_generate_validated_xxe(self):
        """
        Critical semantic requirement: internal entity reflection proves internal DTD processing,
        NOT external entity resolution. Must emit an OBSERVATION (INFORMATIONAL), never a VALIDATED XXE.
        """
        tmp_dir = tempfile.mkdtemp()
        lab = LocalXxeLab(mode="reflection")
        scope = make_scope()
        policy = SecurityTestPolicy(allowed_methods={"GET", "HEAD", "OPTIONS", "POST"}, block_destructive_actions=False, max_requests_per_program=20)

        engine = XxeIntelligenceEngine(
            program_dir=tmp_dir,
            scope_engine=scope,
            policy=policy,
            send_request_hook=lab.create_handler_hook(),
        )
        engine.validation_engine.allow_fixture_port(8080)

        cand = XxeCandidate(
            application="DocumentProcessor",
            endpoint="http://127.0.0.1:8080/api/parse",
            parameter="content",
            param_location="XML_BODY",
            approval_status="APPROVED",
        )

        cand_res, finding_res = engine.validate_candidate(cand, force_approved=True)

        # Must be classified as OBSERVED, NOT VALIDATED
        assert cand_res.lifecycle_state == "OBSERVED"
        assert cand_res.confidence == XxeConfidence.OBSERVED

        # Finding must be an OBSERVATION with INFORMATIONAL severity
        assert finding_res is not None
        assert finding_res.lifecycle_state == FindingLifecycle.OBSERVATION
        assert finding_res.lifecycle_state != FindingLifecycle.VALIDATED
        assert finding_res.vulnerability_type == "XML Entity Processing Observation"
        assert finding_res.vulnerability_type != "XML External Entity (XXE)"
        assert finding_res.severity == "INFORMATIONAL"
        assert finding_res.severity != "HIGH"
        assert finding_res.confidence == "MEDIUM"
        assert "External entity resolution (XXE) was NOT established" in finding_res.summary

    def test_secure_hardened_endpoint_emits_no_finding(self):
        """A secure rejection (disallowing DOCTYPE) must produce zero findings and no false positive."""
        tmp_dir = tempfile.mkdtemp()
        lab = LocalXxeLab(mode="secure_reject")
        scope = make_scope()
        policy = SecurityTestPolicy(allowed_methods={"GET", "HEAD", "OPTIONS", "POST"}, block_destructive_actions=False, max_requests_per_program=20)

        engine = XxeIntelligenceEngine(
            program_dir=tmp_dir,
            scope_engine=scope,
            policy=policy,
            send_request_hook=lab.create_handler_hook(),
        )
        engine.validation_engine.allow_fixture_port(8080)

        cand = XxeCandidate(
            application="DocumentProcessor",
            endpoint="http://127.0.0.1:8080/api/parse",
            parameter="content",
            param_location="XML_BODY",
        )

        cand_res, finding_res = engine.validate_candidate(cand, force_approved=True)

        assert cand_res.lifecycle_state == "TESTED"
        assert cand_res.confidence == XxeConfidence.CANDIDATE
        assert finding_res is None

    def test_parser_error_classified_as_suspected_without_false_positive(self):
        """A parser or syntax error alone must NOT generate any finding."""
        tmp_dir = tempfile.mkdtemp()
        scope = make_scope()
        policy = SecurityTestPolicy(allowed_methods={"GET", "HEAD", "OPTIONS", "POST"}, block_destructive_actions=False, max_requests_per_program=20)

        # Baseline returns 200, test probe returns 400 XML syntax error
        def custom_hook(req: ControlledRequest) -> ControlledResponse:
            if "CONFIRMED_ENTITY_EXPANSION" in (req.body or ""):
                return ControlledResponse(status_code=400, headers={}, body="XML parser error: syntax error", size_bytes=30, elapsed_seconds=0.01)
            return ControlledResponse(status_code=200, headers={}, body="<ok/>", size_bytes=5, elapsed_seconds=0.01)

        engine = XxeIntelligenceEngine(
            program_dir=tmp_dir,
            scope_engine=scope,
            policy=policy,
            send_request_hook=custom_hook,
        )
        engine.validation_engine.allow_fixture_port(8080)

        cand = XxeCandidate(
            application="DocumentProcessor",
            endpoint="http://127.0.0.1:8080/api/parse",
            parameter="content",
            param_location="XML_BODY",
        )

        cand_res, finding_res = engine.validate_candidate(cand, force_approved=True)

        assert cand_res.lifecycle_state == "TESTED"
        assert cand_res.confidence == XxeConfidence.SUSPECTED
        assert finding_res is None  # Conservative signal: no finding emitted on parser error alone

    def test_unapproved_candidate_halts_safely(self):
        """Unapproved candidates must halt without sending active test probes."""
        tmp_dir = tempfile.mkdtemp()
        engine = XxeIntelligenceEngine(program_dir=tmp_dir, scope_engine=make_scope())
        cand = XxeCandidate(
            application="App",
            endpoint="http://127.0.0.1:8080/xml",
            parameter="body",
            approval_status="PENDING",
        )
        cand_res, finding = engine.validate_candidate(cand, force_approved=False)
        assert finding is None
        assert "awaiting explicit human approval gate" in cand_res.notes

    def test_evidence_classification_cannot_be_upgraded_by_mock_fixture_label(self):
        """
        Verifies that mock OOB interactions in the test harness yield SIMULATED (INFORMATIONAL)
        observations and CANNOT be upgraded to VALIDATED or HIGH severity.
        """
        tmp_dir = tempfile.mkdtemp()
        mock_provider = MockOobProvider()
        scope = make_scope()
        policy = SecurityTestPolicy(allowed_methods={"GET", "HEAD", "OPTIONS", "POST"}, block_destructive_actions=False, max_requests_per_program=20)

        # Custom hook that simulates an external entity callback into mock provider
        def oob_simulation_hook(req: ControlledRequest) -> ControlledResponse:
            body = req.body or ""
            if "SYSTEM" in body:
                # Simulate external interaction recorded in mock provider
                for token in list(mock_provider._storage.keys()):
                    mock_provider.simulate_interaction(
                        canary_token=token,
                        source_ip="192.0.2.1",
                        protocol="HTTP",
                    )
            return ControlledResponse(status_code=200, headers={}, body="<response>ok</response>", size_bytes=23, elapsed_seconds=0.02)

        engine = XxeIntelligenceEngine(
            program_dir=tmp_dir,
            scope_engine=scope,
            policy=policy,
            send_request_hook=oob_simulation_hook,
            oob_provider=mock_provider,
        )
        engine.validation_engine.allow_fixture_port(8080)

        cand = XxeCandidate(
            application="OobApp",
            endpoint="http://127.0.0.1:8080/api/oob",
            parameter="xml",
            category=XxeCategory.BLIND_OOB,
            approval_status="APPROVED",
        )

        cand_res, finding_res = engine.validate_oob_candidate(cand, force_approved=True)

        assert cand_res.lifecycle_state == "SIMULATED"
        assert cand_res.confidence == XxeConfidence.SIMULATED
        assert finding_res is not None
        assert finding_res.lifecycle_state == FindingLifecycle.SIMULATED
        assert finding_res.lifecycle_state != FindingLifecycle.VALIDATED
        assert finding_res.severity == "INFORMATIONAL"
        assert finding_res.severity != "HIGH"
        assert "[LOCAL HARNESS SIMULATION]" in finding_res.summary
        assert "does NOT prove an attributable remote target callback" in finding_res.summary


# ============================================================================
# 3b. OOB Provider Availability & Destination Trust Boundary
# ============================================================================

class TestOobProviderAvailabilityTruthfulness:
    """Verifies that OOB providers report operational status truthfully without overclaiming."""

    def test_interactsh_unconfigured_reports_config_required(self):
        prov = InteractshOobProvider(token="")
        prov.token = None
        assert prov.registration_status() == OobProviderStatus.CONFIG_REQUIRED

    def test_interactsh_configured_token_truthfully_reports_unavailable(self):
        """
        A configured token or hostname alone must not establish that live polling is operational.
        Since live network polling is not implemented, the provider reports UNAVAILABLE.
        """
        prov = InteractshOobProvider(server_url="oast.pro", token="fake_pdcp_token_123")
        assert prov.registration_status() == OobProviderStatus.UNAVAILABLE
        assert prov.registration_status() != OobProviderStatus.AVAILABLE

    def test_collaborator_unconfigured_reports_config_required(self):
        prov = CollaboratorOobProvider(collab_host=None)
        assert prov.registration_status() == OobProviderStatus.CONFIG_REQUIRED

    def test_collaborator_configured_host_truthfully_reports_unavailable(self):
        """
        A configured collaborator host alone must not establish live polling.
        Must truthfully report UNAVAILABLE.
        """
        prov = CollaboratorOobProvider(collab_host="burpcollaborator.net")
        assert prov.registration_status() == OobProviderStatus.UNAVAILABLE
        assert prov.registration_status() != OobProviderStatus.AVAILABLE

    def test_mock_provider_reports_available_and_simulation_flag(self):
        mock = MockOobProvider(base_domain="oob.local")
        assert mock.registration_status() == OobProviderStatus.AVAILABLE
        assert getattr(mock, "is_simulation", False) is True


class TestOobDestinationTrustPolicy:
    """Verifies that SecurityTestPolicy enforces strict boundaries on OOB canary destinations."""

    def test_trusted_default_domains_permitted(self):
        policy = SecurityTestPolicy()
        valid_urls = [
            "http://bb-xxe-01-abc.oob.local",
            "https://test-token.bugbounty-agent.local/path",
            "http://sub.oast.pro",
            "https://sub.oast.live",
            "http://sub.oast.site",
            "http://sub.oast.online",
            "http://sub.oast.fun",
            "http://sub.oast.me",
            "http://canary123.burpcollaborator.net",
            "https://canary123.oastify.com",
        ]
        for url in valid_urls:
            policy.validate_oob_destination(url)

    def test_untrusted_domain_rejected(self):
        policy = SecurityTestPolicy()
        untrusted = [
            "http://attacker.com/canary",
            "http://evil.org",
            "http://malicious-oob.xyz",
            "https://my-unapproved-server.net/callback",
        ]
        for url in untrusted:
            with pytest.raises(PolicyViolationError, match="Untrusted OOB destination host"):
                policy.validate_oob_destination(url)

    def test_unsupported_schemes_rejected(self):
        policy = SecurityTestPolicy()
        bad_schemes = [
            "file:///etc/passwd",
            "ftp://sub.oob.local/file",
            "gopher://sub.oob.local:70/_test",
            "dict://sub.oob.local/info",
        ]
        for url in bad_schemes:
            with pytest.raises(PolicyViolationError, match="Unsupported OOB scheme"):
                policy.validate_oob_destination(url)

    def test_credentials_in_url_rejected(self):
        policy = SecurityTestPolicy()
        with pytest.raises(PolicyViolationError, match="embedded user credentials"):
            policy.validate_oob_destination("http://admin:secret@sub.oob.local/canary")

    def test_prohibited_ip_literals_rejected(self):
        policy = SecurityTestPolicy()
        prohibited_ips = [
            "http://127.0.0.1/canary",
            "http://127.0.0.2:8080/canary",
            "http://169.254.169.254/latest/meta-data",
            "http://10.0.0.1/test",
            "http://192.168.1.1/test",
            "http://172.16.0.1/test",
            "http://[::1]/test",
        ]
        for url in prohibited_ips:
            with pytest.raises(PolicyViolationError, match="Prohibited IP address"):
                policy.validate_oob_destination(url)

    def test_alternate_ip_encodings_rejected(self):
        """Alternate IP encodings (octal, hex, dword) must also be rejected."""
        policy = SecurityTestPolicy()
        alternate_ips = [
            "http://0x7f000001/canary",
            "http://2130706433/canary",
            "http://017700000001/canary",
            "http://0xa9fea9fe/canary",
            "http://2852039166/canary",
            "http://0251.0376.0251.0376/canary",
        ]
        for url in alternate_ips:
            with pytest.raises(PolicyViolationError, match="Prohibited IP address"):
                policy.validate_oob_destination(url)

    def test_cloud_metadata_hostnames_rejected(self):
        policy = SecurityTestPolicy()
        with pytest.raises(PolicyViolationError, match="Prohibited host"):
            policy.validate_oob_destination("http://metadata.google.internal/computeMetadata/v1")
        with pytest.raises(PolicyViolationError, match="Prohibited host"):
            policy.validate_oob_destination("http://localhost/callback")

    def test_custom_trusted_oob_domains_policy(self):
        custom_policy = SecurityTestPolicy(trusted_oob_domains={"internal-canary.company.com"})
        custom_policy.validate_oob_destination("http://tok123.internal-canary.company.com/hit")
        with pytest.raises(PolicyViolationError, match="Untrusted OOB destination host"):
            custom_policy.validate_oob_destination("http://tok123.oast.pro/hit")


class TestXxeOobDispatchBoundary:
    """Verifies that XxeIntelligenceEngine enforces the OOB destination trust boundary before dispatch."""

    def test_oob_dispatch_rejects_untrusted_destination_before_network_call(self):
        """
        If the provider generates an untrusted destination (e.g. from an unvetted environment variable),
        the engine must reject it with POLICY_VIOLATION without sending any HTTP request.
        """
        tmp_dir = tempfile.mkdtemp()
        scope = make_scope()
        policy = SecurityTestPolicy(allowed_methods={"GET", "HEAD", "OPTIONS", "POST"}, block_destructive_actions=False)

        evil_provider = MockOobProvider(base_domain="attacker-controlled.net")

        dispatched_requests: List[ControlledRequest] = []
        def spy_hook(req: ControlledRequest) -> ControlledResponse:
            dispatched_requests.append(req)
            return ControlledResponse(status_code=200, headers={}, body="ok", size_bytes=2, elapsed_seconds=0.01)

        engine = XxeIntelligenceEngine(
            program_dir=tmp_dir,
            scope_engine=scope,
            policy=policy,
            send_request_hook=spy_hook,
            oob_provider=evil_provider,
        )
        engine.validation_engine.allow_fixture_port(8080)

        cand = XxeCandidate(
            application="OobApp",
            endpoint="http://127.0.0.1:8080/xml",
            parameter="doc",
            category=XxeCategory.BLIND_OOB,
            approval_status="APPROVED",
        )

        cand_res, finding = engine.validate_oob_candidate(cand, force_approved=True)

        assert finding is None
        assert cand_res.lifecycle_state == "POLICY_VIOLATION"
        assert "OOB canary destination rejected by policy" in cand_res.notes
        assert "Untrusted OOB destination host" in cand_res.notes
        assert len(dispatched_requests) == 0

    def test_oob_dispatch_rejects_metadata_ip_destination_before_network_call(self):
        """
        If canary destination targets cloud metadata IP (e.g. 169.254.169.254),
        must fail closed without dispatching.
        """
        tmp_dir = tempfile.mkdtemp()
        scope = make_scope()
        policy = SecurityTestPolicy(allowed_methods={"GET", "HEAD", "OPTIONS", "POST"}, block_destructive_actions=False)

        metadata_provider = MockOobProvider(base_domain="169.254.169.254")

        dispatched_requests: List[ControlledRequest] = []
        def spy_hook(req: ControlledRequest) -> ControlledResponse:
            dispatched_requests.append(req)
            return ControlledResponse(status_code=200, headers={}, body="ok", size_bytes=2, elapsed_seconds=0.01)

        engine = XxeIntelligenceEngine(
            program_dir=tmp_dir,
            scope_engine=scope,
            policy=policy,
            send_request_hook=spy_hook,
            oob_provider=metadata_provider,
        )
        engine.validation_engine.allow_fixture_port(8080)

        cand = XxeCandidate(
            application="OobApp",
            endpoint="http://127.0.0.1:8080/xml",
            parameter="doc",
            category=XxeCategory.BLIND_OOB,
            approval_status="APPROVED",
        )

        cand_res, finding = engine.validate_oob_candidate(cand, force_approved=True)

        assert finding is None
        assert cand_res.lifecycle_state == "POLICY_VIOLATION"
        assert "Prohibited IP address" in cand_res.notes
        assert len(dispatched_requests) == 0

    def test_oob_dispatch_halts_safely_when_provider_unavailable(self):
        """
        When provider is UNAVAILABLE (e.g. Interactsh adapter without live polling),
        engine halts safely with TESTED status, emits no finding, and dispatches zero requests.
        """
        tmp_dir = tempfile.mkdtemp()
        scope = make_scope()
        policy = SecurityTestPolicy(allowed_methods={"GET", "HEAD", "OPTIONS", "POST"}, block_destructive_actions=False)

        interactsh_provider = InteractshOobProvider(server_url="oast.pro", token="tok123")
        assert interactsh_provider.registration_status() == OobProviderStatus.UNAVAILABLE

        dispatched_requests: List[ControlledRequest] = []
        def spy_hook(req: ControlledRequest) -> ControlledResponse:
            dispatched_requests.append(req)
            return ControlledResponse(status_code=200, headers={}, body="ok", size_bytes=2, elapsed_seconds=0.01)

        engine = XxeIntelligenceEngine(
            program_dir=tmp_dir,
            scope_engine=scope,
            policy=policy,
            send_request_hook=spy_hook,
            oob_provider=interactsh_provider,
        )
        engine.validation_engine.allow_fixture_port(8080)

        cand = XxeCandidate(
            application="OobApp",
            endpoint="http://127.0.0.1:8080/xml",
            parameter="doc",
            category=XxeCategory.BLIND_OOB,
            approval_status="APPROVED",
        )

        cand_res, finding = engine.validate_oob_candidate(cand, force_approved=True)

        assert finding is None
        assert cand_res.lifecycle_state == "TESTED"
        assert "OOB external entity verification unavailable" in cand_res.notes
        assert "live polling not operational" in cand_res.notes
        assert len(dispatched_requests) == 0

    def test_oob_dispatch_scope_rejection_before_destination_check(self):
        """Target endpoint outside authorized scope halts before provider check or probe dispatch."""
        tmp_dir = tempfile.mkdtemp()
        scope = make_scope()
        policy = SecurityTestPolicy(allowed_methods={"GET", "HEAD", "OPTIONS", "POST"}, block_destructive_actions=False)

        dispatched_requests: List[ControlledRequest] = []
        def spy_hook(req: ControlledRequest) -> ControlledResponse:
            dispatched_requests.append(req)
            return ControlledResponse(status_code=200, headers={}, body="ok", size_bytes=2, elapsed_seconds=0.01)

        engine = XxeIntelligenceEngine(
            program_dir=tmp_dir,
            scope_engine=scope,
            policy=policy,
            send_request_hook=spy_hook,
            oob_provider=MockOobProvider(),
        )

        cand = XxeCandidate(
            application="OutOfScopeApp",
            endpoint="https://unauthorized-thirdparty.com/xml",
            parameter="doc",
            category=XxeCategory.BLIND_OOB,
            approval_status="APPROVED",
        )

        cand_res, finding = engine.validate_oob_candidate(cand, force_approved=True)

        assert finding is None
        assert cand_res.lifecycle_state == "OUT_OF_SCOPE"
        assert "is out of authorized scope" in cand_res.notes
        assert len(dispatched_requests) == 0

    def test_oob_dispatch_unapproved_halts_before_scope_or_destination_check(self):
        """Unapproved candidate halts immediately awaiting approval gate."""
        tmp_dir = tempfile.mkdtemp()
        engine = XxeIntelligenceEngine(program_dir=tmp_dir, scope_engine=make_scope())
        cand = XxeCandidate(
            application="App",
            endpoint="http://127.0.0.1:8080/xml",
            parameter="body",
            approval_status="PENDING",
        )
        cand_res, finding = engine.validate_oob_candidate(cand, force_approved=False)
        assert finding is None
        assert "awaiting explicit human approval gate" in cand_res.notes


# ============================================================================
# 4. State Persistence & Finding Deduplication
# ============================================================================

class TestXxeStateManagement:
    """Verifies atomic state persistence and duplicate finding suppression."""

    def test_state_persistence_and_summary(self):
        tmp_dir = tempfile.mkdtemp()
        state_mgr = XxeStateManager(tmp_dir)

        cand = XxeCandidate(
            application="App1",
            endpoint="http://127.0.0.1:8080/xml",
            parameter="doc",
            category=XxeCategory.INTERNAL_ENTITY_REFLECTION,
        )
        state_mgr.save_candidate(cand)

        cands = state_mgr.list_candidates()
        assert len(cands) == 1
        assert cands[0].endpoint == "http://127.0.0.1:8080/xml"

        # Approval gate
        state_mgr.approve_candidate(cand.candidate_id, approver="auditor")
        summary = state_mgr.get_summary()
        assert summary["total_candidates"] == 1
        assert summary["approved_tests"] == 1

    def test_duplicate_findings_suppressed(self):
        tmp_dir = tempfile.mkdtemp()
        lab = LocalXxeLab(mode="reflection")
        scope = make_scope()
        policy = SecurityTestPolicy(allowed_methods={"GET", "HEAD", "OPTIONS", "POST"}, block_destructive_actions=False, max_requests_per_program=20)

        engine = XxeIntelligenceEngine(
            program_dir=tmp_dir,
            scope_engine=scope,
            policy=policy,
            send_request_hook=lab.create_handler_hook(),
        )
        engine.validation_engine.allow_fixture_port(8080)

        cand = XxeCandidate(
            application="App",
            endpoint="http://127.0.0.1:8080/parse",
            parameter="xml",
            approval_status="APPROVED",
        )

        _, f1 = engine.validate_candidate(cand, force_approved=True)
        assert f1 is not None

        # Re-running validation against same endpoint must not create duplicate finding
        _, f2 = engine.validate_candidate(cand, force_approved=True)
        findings = engine.state_mgr.list_findings()
        assert len(findings) == 1


# ============================================================================
# 5. XxeValidator Plugin in SecurityValidationEngine
# ============================================================================

class TestXxeValidatorPlugin:
    """Verifies XxeValidator plugin contract compliance in SecurityValidationEngine."""

    def test_xxe_validator_contract(self):
        val = XxeValidator()
        assert val.is_available is True
        assert val.can_test("https://target.com/soap/service") is True
        assert val.can_test("https://target.com/api/data", "xml") is True
        assert val.can_test("https://target.com/api/upload", "doc") is True

        cases = val.prepare_test_cases("target.com", "https://target.com/soap", "xml")
        assert len(cases) == 1
        tc = cases[0]
        assert tc.vulnerability_family == VulnerabilityFamily.XXE
        assert tc.risk_level == RiskLevel.SAFE
        assert tc.payload_identifier == "PL-XXE-REFL-01"

    def test_xxe_validator_internal_reflection_emits_observation_not_validated_xxe(self):
        """
        Verifies that XxeValidator produces an OBSERVATION with INFORMATIONAL severity
        when internal entity expansion is reflected, preserving accurate risk classification.
        """
        val = XxeValidator()
        tc = SecurityTestCase(
            vulnerability_family=VulnerabilityFamily.XXE,
            target="target.com",
            endpoint="https://target.com/soap",
            parameter="xml",
            payload_identifier="PL-XXE-REFL-01",
            risk_level=RiskLevel.SAFE,
        )
        baseline = BaselineObservation.from_response(
            "https://target.com/soap",
            ControlledResponse(
                status_code=200,
                headers={"Content-Type": "application/xml"},
                body="<response>ok</response>",
                size_bytes=23,
                elapsed_seconds=0.01,
            ),
        )
        canary = f"BB_XXE_{tc.test_id}"
        resp = ControlledResponse(
            status_code=200,
            headers={"Content-Type": "application/xml"},
            body=f"<response><echo>{canary}</echo></response>",
            size_bytes=50,
            elapsed_seconds=0.02,
        )
        comp = compare_with_baseline(baseline, resp, test_marker=canary)

        res, finding = val.analyze(comp, baseline, resp, tc)
        assert res.lifecycle_state == FindingLifecycle.OBSERVATION
        assert res.lifecycle_state != FindingLifecycle.VALIDATED
        assert res.severity == "INFORMATIONAL"
        assert res.confidence == "MEDIUM"

        assert finding is not None
        assert finding.lifecycle_state == FindingLifecycle.OBSERVATION
        assert finding.vulnerability_type == "XML Entity Processing Observation"
        assert finding.vulnerability_type != "XML External Entity (XXE)"
        assert finding.severity == "INFORMATIONAL"
        assert finding.confidence == "MEDIUM"
