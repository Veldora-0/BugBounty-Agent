"""
Phase 18 Regression Tests: XXE & XML Parser Security Subsystem.

Covers:
1. Safe synthetic entity reflection without file system probing or network egress.
2. Strict prohibition on file://, /etc/passwd, win.ini, and cloud metadata (fails closed).
3. Signal classification distinguishing syntax/parser errors from confirmed entity expansion.
4. Deterministic LocalXxeLab test harness across reflection, secure reject, error, and OOB modes.
5. State persistence, approval gate, and finding deduplication.
6. XxeValidator and SsrfValidator plugin integration with SecurityValidationEngine.
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
from framework.ssrf.provider import MockOobProvider
from framework.validation.baseline import BaselineComparison, BaselineObservation, compare_with_baseline
from framework.validation.engine import SecurityValidationEngine
from framework.validation.model import RiskLevel, SecurityTestCase, VulnerabilityFamily
from framework.validation.policy import SecurityTestPolicy
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
    XxeSource,
)
from framework.xxe.state import XxeStateManager


def make_scope() -> ScopeEngine:
    return ScopeEngine({
        "program": {"name": "Test"},
        "targets": {"urls": ["http://127.0.0.1:8080"]},
    })


# ============================================================================
# 1. Safe Payload Generation & Strict Boundary Invariants
# ============================================================================

class TestXxePayloadSafety:
    """Verifies that XXE payload builders generate only benign markers and reject dangerous targets."""

    def test_synthetic_reflection_payload_contains_no_external_entities(self):
        tmp_dir = tempfile.mkdtemp()
        engine = XxeIntelligenceEngine(program_dir=tmp_dir, scope_engine=make_scope())
        cand = XxeCandidate(
            application="API",
            endpoint="http://127.0.0.1:8080/xml",
            parameter="val",
        )
        payload = engine._build_synthetic_reflection_payload(cand, "canary", "TEST_MARKER_123")
        assert "TEST_MARKER_123" in payload
        assert "&canary;" in payload
        assert "<!DOCTYPE" in payload
        # Ensure zero external SYSTEM or PUBLIC URIs
        assert "SYSTEM" not in payload
        assert "PUBLIC" not in payload
        assert "file://" not in payload

    def test_prohibited_targets_fail_closed(self):
        tmp_dir = tempfile.mkdtemp()
        engine = XxeIntelligenceEngine(program_dir=tmp_dir, scope_engine=make_scope())

        for dangerous in (
            "file:///etc/passwd",
            "file:///c:/windows/win.ini",
            "/etc/shadow",
            "/etc/hosts",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ):
            with pytest.raises(ValueError, match="Disallowed payload pattern detected"):
                engine._validate_payload_safety(f"<!DOCTYPE test SYSTEM '{dangerous}'>")


# ============================================================================
# 2. LocalXxeLab Deterministic Simulation
# ============================================================================

class TestLocalXxeLabSimulation:
    """Verifies LocalXxeLab behaviors across reflection, secure reject, and error modes."""

    def test_reflection_mode_reflects_internal_entity(self):
        lab = LocalXxeLab(mode="reflection")
        hook = lab.create_handler_hook()

        payload = (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE root [ <!ENTITY test "CONFIRMED_XXE_MARKER"> ]>\n'
            '<root><url>&test;</url></root>'
        )
        req = ControlledRequest(url="http://127.0.0.1:8080/xml", method="POST", body=payload)
        resp = hook(req)
        assert resp.status_code == 200
        assert "CONFIRMED_XXE_MARKER" in resp.body

    def test_secure_reject_mode_blocks_doctype(self):
        lab = LocalXxeLab(mode="secure_reject")
        hook = lab.create_handler_hook()

        payload = '<!DOCTYPE test [ <!ENTITY a "b"> ]><test>&a;</test>'
        req = ControlledRequest(url="http://127.0.0.1:8080/xml", method="POST", body=payload)
        resp = hook(req)
        assert resp.status_code == 400
        assert "DOCTYPE declarations are prohibited" in resp.body

        # Normal XML without DOCTYPE is permitted
        clean_req = ControlledRequest(url="http://127.0.0.1:8080/xml", method="POST", body="<test>clean</test>")
        clean_resp = hook(clean_req)
        assert clean_resp.status_code == 200

    def test_parser_error_mode_returns_syntax_error(self):
        lab = LocalXxeLab(mode="parser_error")
        hook = lab.create_handler_hook()

        req = ControlledRequest(url="http://127.0.0.1:8080/xml", method="POST", body="<test>syntax</test>")
        resp = hook(req)
        assert resp.status_code == 400
        assert "XML syntax error" in resp.body

    def test_lab_rejects_destructive_file_access(self):
        lab = LocalXxeLab(mode="reflection")
        hook = lab.create_handler_hook()

        req = ControlledRequest(
            url="http://127.0.0.1:8080/xml",
            method="POST",
            body="<!DOCTYPE x SYSTEM 'file:///etc/passwd'><x>&x;</x>",
        )
        resp = hook(req)
        assert resp.status_code == 403
        assert "Forbidden target blocked" in resp.body


# ============================================================================
# 3. Active Validation Pipeline & Signal Classification
# ============================================================================

class TestXxeActiveValidation:
    """Verifies end-to-end controlled XXE validation and finding generation."""

    def test_confirmed_synthetic_reflection_emits_validated_finding(self):
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

        assert cand_res.lifecycle_state == "VALIDATED"
        assert cand_res.confidence == XxeConfidence.VALIDATED
        assert finding_res is not None
        assert finding_res.vulnerability_type == "XML External Entity (XXE)"
        assert finding_res.severity == "HIGH"
        assert finding_res.confidence == "HIGH"
        assert finding_res.lifecycle_state == FindingLifecycle.VALIDATED
        assert "harmless synthetic entity expansion" in finding_res.summary

    def test_secure_hardened_endpoint_emits_no_finding(self):
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
        tmp_dir = tempfile.mkdtemp()
        lab = LocalXxeLab(mode="parser_error")
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
            category=XxeCategory.SYNTHETIC_REFLECTION,
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

    def test_xxe_validator_analyze_confirmed_reflection(self):
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
        assert res.lifecycle_state == FindingLifecycle.VALIDATED
        assert finding is not None
        assert finding.vulnerability_type == "XML External Entity (XXE)"
        assert finding.confidence == "HIGH"
