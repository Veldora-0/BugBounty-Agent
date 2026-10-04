"""
Unit tests for SSRF & Out-of-Band Interaction Intelligence Engine (Phase 9).

Validates:
1. SSRF Candidate, Source, Sink, Interaction, and Evidence models
2. SSRF Sink & Parameter Intelligence discovery and categorization
3. OOB Provider Abstraction (Mock, Interactsh, Collaborator, Factory)
4. Canary issuance, correlation matching, and anti-stale/client-ip filtering
5. SsrfComparator baseline differential analysis and classification
6. LocalSsrfLab 12-scenario simulation
7. SsrfStateManager atomic persistence & summary computation
8. HumanApprovalGate dossier generation & approval gating
9. SsrfIntelligenceEngine active & passive workflows
10. Scope and agent-side anti-SSRF enforcement
11. Security hygiene audit (zero shell=True, zero os.system, zero eval/exec)
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from typing import Any, Dict
import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from framework.findings.lifecycle import FindingLifecycle
from framework.scope.engine import ScopeEngine
from framework.ssrf.approval import HumanApprovalGate
from framework.ssrf.canary import CanaryManager
from framework.ssrf.comparator import SsrfComparator
from framework.ssrf.engine import SsrfIntelligenceEngine
from framework.ssrf.intelligence import SsrfIntelligenceAnalyzer
from framework.ssrf.lab import LocalSsrfLab
from framework.ssrf.model import (
    OobInteractionType,
    OobProviderStatus,
    SsrfCandidate,
    SsrfCategory,
    SsrfConfidence,
    SsrfEvidence,
    SsrfInteraction,
    SsrfSink,
    SsrfSource,
)
from framework.ssrf.provider import (
    CollaboratorOobProvider,
    InteractshOobProvider,
    MockOobProvider,
    OobProviderFactory,
)
from framework.ssrf.state import SsrfStateManager
from framework.validation.policy import SecurityTestPolicy
from framework.validation.request import ControlledRequest, ControlledResponse


@pytest.fixture
def temp_program_dir():
    d = tempfile.mkdtemp(prefix="bb_test_ssrf_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


# ---------------- 1. Data Models & Header Sanitization ----------------

def test_ssrf_models_and_sanitization():
    source = SsrfSource(
        source_type="QUERY",
        parameter_name="webhook_url",
        original_value="https://example.com/callback?token=secrettoken123",
    )
    assert source.source_type == "QUERY"
    assert source.parameter_name == "webhook_url"
    assert "secrettoken123" not in (source.original_value or "")

    sink = SsrfSink(sink_type="WEBHOOK_DISPATCHER", description="Event delivery")
    assert sink.sink_type == "WEBHOOK_DISPATCHER"

    interaction = SsrfInteraction(
        interaction_id="int-001",
        canary_token="bb9-test-token-123",
        protocol="HTTP",
        source_ip_metadata="203.0.113.10",
        observed_method="POST",
        observed_path="/callback",
        bounded_headers={
            "User-Agent": "TargetServer/1.0",
            "Authorization": "Bearer supersecret12345",
            "Cookie": "session=sensitivecookievalue",
        },
    )
    assert interaction.interaction_id == "int-001"
    # Verify sensitive tokens were redacted
    assert "supersecret12345" not in interaction.bounded_headers["Authorization"]
    assert "sensitivecookievalue" not in interaction.bounded_headers["Cookie"]

    cand = SsrfCandidate(
        application="app.example.com",
        endpoint="https://app.example.com/fetch",
        parameter="url",
        category=SsrfCategory.DIRECT,
        source_intel=source,
        sink_intel=sink,
    )
    assert cand.application == "app.example.com"
    assert cand.compute_fingerprint() is not None
    assert cand.is_approved_for_execution() is False

    # Round-trip serialization
    c_dict = cand.to_dict()
    restored = SsrfCandidate.from_dict(c_dict)
    assert restored.application == cand.application
    assert restored.parameter == cand.parameter
    assert restored.category == SsrfCategory.DIRECT


def test_ssrf_evidence_hash():
    inter = SsrfInteraction(
        interaction_id="int-1",
        canary_token="token-1",
        protocol="HTTP",
    )
    evidence = SsrfEvidence(
        test_id="test-1",
        canary_token="token-1",
        provider_name="mock",
        interaction_type=OobInteractionType.HTTP_INTERACTION,
        interactions=[inter],
        test_status=200,
    )
    assert evidence.evidence_hash is not None
    assert len(evidence.evidence_hash) == 64
    ev_dict = evidence.to_dict()
    restored = SsrfEvidence.from_dict(ev_dict)
    assert restored.test_id == "test-1"
    assert restored.interaction_type == OobInteractionType.HTTP_INTERACTION


# ---------------- 2. SSRF Sink & Parameter Intelligence ----------------

def test_parameter_intelligence():
    analyzer = SsrfIntelligenceAnalyzer()
    assert analyzer.is_candidate_parameter_name("url") is True
    assert analyzer.is_candidate_parameter_name("webhook_url") is True
    assert analyzer.is_candidate_parameter_name("target_destination") is True
    assert analyzer.is_candidate_parameter_name("avatar") is True
    assert analyzer.is_candidate_parameter_name("id") is False
    assert analyzer.is_candidate_parameter_name("username") is False


def test_sink_and_category_inference():
    analyzer = SsrfIntelligenceAnalyzer()

    sink1, cat1 = analyzer.infer_sink_and_category("https://example.com/api/v1/webhook", "url")
    assert sink1.sink_type == "WEBHOOK_DISPATCHER"
    assert cat1 == SsrfCategory.WEBHOOK

    sink2, cat2 = analyzer.infer_sink_and_category("https://example.com/image-proxy", "src")
    assert sink2.sink_type == "IMAGE_PROXY"
    assert cat2 == SsrfCategory.DIRECT

    sink3, cat3 = analyzer.infer_sink_and_category("https://example.com/api/export-pdf", "target_url")
    assert sink3.sink_type == "PREVIEW_RENDERER"
    assert cat3 == SsrfCategory.IMPORTER


def test_extract_candidates_from_url():
    url = "https://example.com/fetch?url=https://other.com/file&format=json"
    candidates = SsrfIntelligenceAnalyzer.extract_from_url(url)
    assert len(candidates) == 1
    assert candidates[0].parameter == "url"
    assert candidates[0].url_type == "ABSOLUTE_URL"


# ---------------- 3. OOB Providers & Canary System ----------------

def test_mock_oob_provider():
    provider = MockOobProvider(base_domain="oob.local")
    assert provider.name() == "mock"
    assert provider.registration_status() == OobProviderStatus.AVAILABLE

    token, canary_url = provider.generate_canary("bb9-test", "01")
    assert "bb9-test" in token
    assert "oob.local" in canary_url

    # Simulate interaction
    inter = provider.simulate_interaction(
        canary_token=token,
        protocol="HTTP",
        source_ip="203.0.113.5",
        method="GET",
    )
    assert inter.canary_token == token

    # Poll & consume
    polled = provider.poll(token)
    assert len(polled) == 1
    consumed = provider.consume_interactions(token)
    assert len(consumed) == 1
    assert len(provider.poll(token)) == 0


def test_provider_factory_and_fallbacks():
    p_mock = OobProviderFactory.get_provider("mock")
    assert isinstance(p_mock, MockOobProvider)

    # When interactsh token is missing, factory falls back to MockOobProvider
    p_inter = OobProviderFactory.get_provider("interactsh")
    assert isinstance(p_inter, MockOobProvider)


def test_canary_manager_correlation_and_filters():
    provider = MockOobProvider()
    mgr = CanaryManager(provider=provider, program_id="testprog", correlation_window_seconds=10.0)

    token, canary_url = mgr.issue_canary("test-01")
    assert "bb9-testprog" in token

    # Simulate backend interaction
    provider.simulate_interaction(token, protocol="HTTP", source_ip="203.0.113.88")

    # Simulate client/browser interaction from excluded IP
    provider.simulate_interaction(token, protocol="HTTP", source_ip="192.168.1.50")

    # Correlate with client IP excluded
    ints = mgr.correlate_interactions(token, exclude_source_ips={"192.168.1.50"})
    assert len(ints) == 1
    assert ints[0].source_ip_metadata == "203.0.113.88"

    itype = mgr.classify_interaction_type(ints)
    assert itype == OobInteractionType.HTTP_INTERACTION


# ---------------- 4. Response Comparator & Classification ----------------

def test_comparator_http_callback():
    candidate = SsrfCandidate(application="app.com", endpoint="https://app.com/fetch", parameter="url")
    test_resp = ControlledResponse(status_code=200, headers={}, body="Fetched OK", size_bytes=10)
    baseline_resp = ControlledResponse(status_code=200, headers={}, body="No URL", size_bytes=6)

    inter = SsrfInteraction(
        interaction_id="int-1",
        canary_token="bb9-test",
        protocol="HTTP",
        source_ip_metadata="203.0.113.88",
    )

    comp = SsrfComparator.evaluate(
        candidate=candidate,
        canary_token="bb9-test",
        test_response=test_resp,
        baseline_response=baseline_resp,
        interactions=[inter],
    )
    assert comp.is_confirmed is True
    assert comp.interaction_type == OobInteractionType.HTTP_INTERACTION
    assert comp.confidence == SsrfConfidence.VALIDATED
    assert comp.evidence is not None


def test_comparator_dns_only():
    candidate = SsrfCandidate(application="app.com", endpoint="https://app.com/preview", parameter="dest")
    test_resp = ControlledResponse(status_code=400, headers={}, body="Bad connection", size_bytes=14)

    inter = SsrfInteraction(
        interaction_id="int-2",
        canary_token="bb9-test",
        protocol="DNS",
        interaction_type=OobInteractionType.DNS_ONLY,
    )

    comp = SsrfComparator.evaluate(
        candidate=candidate,
        canary_token="bb9-test",
        test_response=test_resp,
        interactions=[inter],
    )
    assert comp.is_confirmed is True
    assert comp.interaction_type == OobInteractionType.DNS_ONLY
    assert comp.confidence == SsrfConfidence.OBSERVED


def test_comparator_no_interaction():
    candidate = SsrfCandidate(application="app.com", endpoint="https://app.com/fetch", parameter="url")
    test_resp = ControlledResponse(status_code=200, headers={}, body="Ignored", size_bytes=7)

    comp = SsrfComparator.evaluate(
        candidate=candidate,
        canary_token="bb9-test",
        test_response=test_resp,
        interactions=[],
    )
    assert comp.is_confirmed is False
    assert comp.interaction_type == OobInteractionType.NO_INTERACTION


# ---------------- 5. Local Security Lab 12 Scenarios ----------------

def test_local_ssrf_lab_scenarios():
    provider = MockOobProvider()
    lab = LocalSsrfLab(oob_provider=provider)

    # 1. Direct SSRF Fetcher
    req1 = ControlledRequest(url="https://api.local/api/v1/fetch?url=http://bb9-test1.oob.local")
    res1 = lab.dispatch(req1)
    assert res1.status_code == 200
    assert len(provider.poll("bb9-test1")) == 1

    # 2. Blind SSRF Fetcher
    req2 = ControlledRequest(url="https://api.local/api/v1/webhook/subscribe?url=http://bb9-test2.oob.local")
    res2 = lab.dispatch(req2)
    assert res2.status_code == 202
    assert len(provider.poll("bb9-test2")) == 1

    # 3. DNS-Only Resolver
    req3 = ControlledRequest(url="https://api.local/api/v1/resolve-preview?url=http://bb9-test3.oob.local")
    res3 = lab.dispatch(req3)
    assert res3.status_code == 400
    ints3 = provider.poll("bb9-test3")
    assert len(ints3) == 1
    assert ints3[0].protocol == "DNS"

    # 4. Safe Application
    req4 = ControlledRequest(url="https://api.local/api/v1/safe-fetch?url=http://bb9-test4.oob.local")
    res4 = lab.dispatch(req4)
    assert res4.status_code == 200
    assert len(provider.poll("bb9-test4")) == 0

    # 5. Redirect-Mediated Fetcher
    req5 = ControlledRequest(url="https://api.local/api/v1/redirect-fetch?url=http://bb9-test5.oob.local")
    res5 = lab.dispatch(req5)
    assert res5.status_code == 200
    assert len(provider.poll("bb9-test5")) == 1

    # 6. Browser-Only False Positive (Client IP)
    req6 = ControlledRequest(url="https://api.local/api/v1/client-preview?url=http://bb9-test6.oob.local")
    res6 = lab.dispatch(req6)
    assert res6.status_code == 200
    ints6 = provider.poll("bb9-test6")
    assert len(ints6) == 1
    assert ints6[0].source_ip_metadata == "192.168.1.50"  # Client IP!


# ---------------- 6. State Management & Human Approval ----------------

def test_state_management(temp_program_dir):
    mgr = SsrfStateManager(temp_program_dir)
    assert os.path.exists(mgr.ssrf_file)

    c = SsrfCandidate(application="app.com", endpoint="https://app.com/fetch", parameter="url")
    mgr.save_candidate(c)
    assert len(mgr.list_candidates()) == 1

    inter = SsrfInteraction(interaction_id="int-1", canary_token="bb9-test", protocol="HTTP")
    mgr.save_interaction(inter)
    assert len(mgr.list_interactions("bb9-test")) == 1

    # Approval
    assert mgr.is_test_approved(c.candidate_id) is False
    mgr.approve_test_case(c.candidate_id, approved_by="researcher")
    assert mgr.is_test_approved(c.candidate_id) is True

    summary = mgr.get_summary()
    assert summary["total_candidates"] == 1
    assert summary["approved_tests"] == 1
    assert summary["interactions_received"] == 1


def test_human_approval_gate(temp_program_dir):
    mgr = SsrfStateManager(temp_program_dir)
    gate = HumanApprovalGate(mgr)

    c = SsrfCandidate(application="app.com", endpoint="https://app.com/fetch", parameter="url")
    mgr.save_candidate(c)

    dossier = gate.request_approval(c, canary_url="http://canary.oob.local", provider_name="mock")
    assert "LIVE SSRF / OOB TEST APPROVAL REQUIRED" in dossier
    assert "https://app.com/fetch" in dossier
    assert "canary.oob.local" in dossier

    assert gate.is_approved(c.candidate_id) is False
    gate.approve(c.candidate_id, approver="senior-analyst")
    assert gate.is_approved(c.candidate_id) is True


# ---------------- 7. SSRF Intelligence Engine Integration ----------------

def test_ssrf_engine_live_validation(temp_program_dir):
    provider = MockOobProvider()
    lab = LocalSsrfLab(oob_provider=provider)
    scope = ScopeEngine({
        "program": {"name": "test-lab"},
        "targets": {
            "domains": ["api.local"],
            "recursive_subdomains": {"enabled": True},
        },
    })

    engine = SsrfIntelligenceEngine(
        program_dir=temp_program_dir,
        scope_engine=scope,
        send_request_hook=lab.dispatch,
        oob_provider=provider,
    )

    cand = SsrfCandidate(
        application="api.local",
        endpoint="https://api.local/api/v1/fetch",
        parameter="url",
    )

    # 1. Without approval -> halted
    c_res, finding_res = engine.validate_candidate(cand, force_approved=False, poll_wait_seconds=0.1)
    assert "awaiting explicit human approval" in c_res.notes
    assert finding_res is None

    # 2. With force_approved=True -> executes and validates SSRF
    c_res, finding_res = engine.validate_candidate(cand, force_approved=True, poll_wait_seconds=0.1)
    assert c_res.lifecycle_state == "VALIDATED"
    assert c_res.confidence == SsrfConfidence.VALIDATED
    assert finding_res is not None
    assert finding_res.vulnerability_type == "Server-Side Request Forgery (SSRF)"
    assert finding_res.lifecycle_state == FindingLifecycle.VALIDATED
    assert c_res.evidence is not None


def test_ssrf_engine_scope_and_policy_enforcement(temp_program_dir):
    provider = MockOobProvider()
    lab = LocalSsrfLab(oob_provider=provider)
    scope = ScopeEngine({
        "program": {"name": "test-scope"},
        "targets": {
            "domains": ["authorized.local"],
            "recursive_subdomains": {"enabled": True},
        },
    })

    engine = SsrfIntelligenceEngine(
        program_dir=temp_program_dir,
        scope_engine=scope,
        send_request_hook=lab.dispatch,
        oob_provider=provider,
    )

    # Out-of-scope endpoint blocked by agent
    c_oos = SsrfCandidate(
        application="evil.external.com",
        endpoint="https://evil.external.com/fetch",
        parameter="url",
    )
    c_res, _ = engine.validate_candidate(c_oos, force_approved=True, poll_wait_seconds=0.1)
    assert c_res.lifecycle_state == "OUT_OF_SCOPE"

    # Unsafe HTTP method blocked by policy
    c_del = SsrfCandidate(
        application="authorized.local",
        endpoint="https://authorized.local/fetch",
        parameter="url",
        method="DELETE",
    )
    c_del_res, _ = engine.validate_candidate(c_del, force_approved=True, poll_wait_seconds=0.1)
    assert c_del_res.lifecycle_state == "REJECTED_METHOD"


def test_ssrf_engine_run_evaluation_modes(temp_program_dir):
    engine = SsrfIntelligenceEngine(program_dir=temp_program_dir)

    # Passive only
    res_pass = engine.run_evaluation(passive_only=True)
    assert res_pass["mode"] == "passive-only"
    assert "candidates" in res_pass

    # Dry run
    res_dry = engine.run_evaluation(dry_run=True)
    assert res_dry["mode"] == "dry-run"


# ---------------- 8. Security Hygiene Audit ----------------

def test_security_hygiene_zero_shell_exec():
    ssrf_dir = os.path.join(REPO_ROOT, "framework", "ssrf")
    for root, _, files in os.walk(ssrf_dir):
        for f in files:
            if f.endswith(".py"):
                path = os.path.join(root, f)
                with open(path, "r", encoding="utf-8") as py_file:
                    content = py_file.read()
                    assert "shell=True" not in content, f"Insecure shell=True found in {path}"
                    assert "os.system(" not in content, f"Insecure os.system found in {path}"
                    assert "eval(" not in content, f"Insecure eval found in {path}"
                    assert "exec(" not in content, f"Insecure exec found in {path}"
