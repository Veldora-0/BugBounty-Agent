"""
Comprehensive Offline Test Suite for HTTP / Header Trust & Protocol Security (Phase 11).

Tests all 15 local security lab scenarios, validators, comparator, prioritization,
approval gates, state persistence, deduplication, false positive reduction, and security invariants.
All tests run deterministically and offline without network access.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import pytest

from framework.findings.lifecycle import FindingLifecycle
from framework.http_trust.approval import HumanApprovalGate
from framework.http_trust.comparator import (
    HttpTrustComparator,
    HttpTrustComparisonResult,
)
from framework.http_trust.engine import HttpTrustEngine
from framework.http_trust.lab import LocalHttpTrustLab
from framework.http_trust.model import (
    HeaderTrustCandidate,
    HeaderTrustEvidence,
    HttpTrustCategory,
    HttpTrustConfidence,
    HttpTrustTestCase,
    TrustClassification,
    TrustSource,
    generate_canary_host,
)
from framework.http_trust.prioritization import HttpTrustPrioritizer
from framework.http_trust.state import HttpTrustStateManager
from framework.http_trust.validator import (
    CorsValidator,
    ForwardedValidator,
    HostInjectionValidator,
    HppValidator,
    HttpTrustValidatorFactory,
    SchemeValidator,
)
from framework.scope.engine import ScopeEngine
from framework.validation.policy import SecurityTestPolicy
from framework.validation.request import ControlledRequest, ControlledResponse


@pytest.fixture
def temp_program_dir():
    tmp = tempfile.mkdtemp(prefix="test_bb_http_trust_")
    state_dir = os.path.join(tmp, "state")
    os.makedirs(state_dir, exist_ok=True)
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def mock_lab():
    return LocalHttpTrustLab()


# ============================================================================
# 1. Models & Fingerprinting
# ============================================================================

def test_canary_generation_and_candidate_model():
    canary = generate_canary_host("acme-corp", test_id="abc12345", lab_mode=False)
    assert "bb11-acme-corp-" in canary
    assert "researcher-controlled.example" in canary

    lab_canary = generate_canary_host("anything", lab_mode=True)
    assert lab_canary == "bb11-lab-canary.researcher-controlled.example"

    cand = HeaderTrustCandidate(
        candidate_id="htc-001",
        header_name="Host",
        endpoint="https://example.com/login",
        application="example.com",
        method="GET",
        category=HttpTrustCategory.HOST_INJECTION,
        priority=85,
    )
    fp1 = cand.compute_fingerprint()
    assert fp1 is not None

    # Matching candidate should produce identical fingerprint
    cand2 = HeaderTrustCandidate(
        candidate_id="htc-002",
        header_name="Host",
        endpoint="https://example.com/login",
        application="example.com",
        category=HttpTrustCategory.HOST_INJECTION,
    )
    assert cand2.compute_fingerprint() == fp1


def test_evidence_sanitization_and_integrity_hash():
    ev = HeaderTrustEvidence(
        evidence_id="ev-001",
        candidate_id="htc-001",
        category=HttpTrustCategory.HOST_INJECTION,
        header_name="Host",
        supplied_value="attacker.com",
        baseline_status=200,
        test_status=302,
        baseline_headers={"Set-Cookie": "session=secret_token_12345", "Server": "nginx"},
        test_headers={"Location": "https://attacker.com/dash", "Authorization": "Bearer supersecret"},
        match_signals=["REDIRECT_HOST_POISONING"],
        body_snippet="Redirecting to https://attacker.com/dash with token: secret_xyz",
    )
    # Check redaction
    assert "secret_token_12345" not in json.dumps(ev.baseline_headers)
    assert "supersecret" not in json.dumps(ev.test_headers)
    assert ev.integrity_hash is not None
    assert len(ev.integrity_hash) == 64


# ============================================================================
# 2. Prioritization Engine
# ============================================================================

def test_prioritization_rules_and_separation():
    # Password reset should receive high priority
    score_pwd, reasons_pwd, sev_pwd, wf_pwd = HttpTrustPrioritizer.evaluate(
        "Host",
        "https://example.com/auth/forgot-password",
        HttpTrustCategory.HOST_INJECTION,
    )
    assert score_pwd >= 75
    assert sev_pwd == "HIGH"
    assert "critical account workflow" in reasons_pwd[0]

    # Static CSS should receive low priority
    score_static, reasons_static, sev_static, _ = HttpTrustPrioritizer.evaluate(
        "Host",
        "https://example.com/static/style.css",
        HttpTrustCategory.HOST_INJECTION,
    )
    assert score_static < 30
    assert sev_static == "INFO"

    # CORS on user profile
    score_cors, _, sev_cors, _ = HttpTrustPrioritizer.evaluate(
        "Origin",
        "https://example.com/api/user/profile",
        HttpTrustCategory.CORS_TRUST,
    )
    assert score_cors >= 65


# ============================================================================
# 3. Host Injection & Poisoning (Lab Scenarios 1-4)
# ============================================================================

def test_lab_scenario_1_host_harmless_reflection(mock_lab):
    # /echo-host echoes Host in body without links or redirects
    req_base = ControlledRequest(url="http://lab.local/echo-host", headers={"Host": "lab.local"})
    res_base = mock_lab.handle_request(req_base)

    canary = "bb11-lab-canary.researcher-controlled.example"
    req_test = ControlledRequest(url="http://lab.local/echo-host", headers={"Host": canary})
    res_test = mock_lab.handle_request(req_test)

    comp = HttpTrustComparator.compare(
        HttpTrustCategory.HOST_INJECTION,
        "Host",
        canary,
        res_base,
        res_test,
    )
    assert comp.is_false_positive is True
    assert "HARMLESS_HOST_REFLECTION" in comp.signals
    assert comp.is_validated is False
    assert comp.confidence == HttpTrustConfidence.OBSERVED


def test_lab_scenario_2_host_controls_canonical_url(mock_lab):
    req_base = ControlledRequest(url="http://lab.local/page", headers={"Host": "lab.local"})
    res_base = mock_lab.handle_request(req_base)

    canary = "bb11-lab-canary.researcher-controlled.example"
    req_test = ControlledRequest(url="http://lab.local/page", headers={"Host": canary})
    res_test = mock_lab.handle_request(req_test)

    comp = HttpTrustComparator.compare(
        HttpTrustCategory.HOST_INJECTION,
        "Host",
        canary,
        res_base,
        res_test,
    )
    assert comp.is_validated is True
    assert "CANONICAL_URL_POISONING" in comp.signals
    assert comp.trust_classification == TrustClassification.USED_FOR_URL_GENERATION


def test_lab_scenario_3_host_controls_redirect(mock_lab):
    req_base = ControlledRequest(url="http://lab.local/login-redirect", headers={"Host": "lab.local"})
    res_base = mock_lab.handle_request(req_base)

    canary = "bb11-lab-canary.researcher-controlled.example"
    req_test = ControlledRequest(url="http://lab.local/login-redirect", headers={"Host": canary})
    res_test = mock_lab.handle_request(req_test)

    comp = HttpTrustComparator.compare(
        HttpTrustCategory.HOST_INJECTION,
        "Host",
        canary,
        res_base,
        res_test,
    )
    assert comp.is_validated is True
    assert "REDIRECT_HOST_POISONING" in comp.signals
    assert comp.trust_classification == TrustClassification.USED_FOR_REDIRECT


def test_lab_scenario_4_host_controls_password_reset(mock_lab):
    req_base = ControlledRequest(url="http://lab.local/auth/forgot-password", headers={"Host": "lab.local"})
    res_base = mock_lab.handle_request(req_base)

    canary = "bb11-lab-canary.researcher-controlled.example"
    req_test = ControlledRequest(url="http://lab.local/auth/forgot-password", headers={"Host": canary})
    res_test = mock_lab.handle_request(req_test)

    comp = HttpTrustComparator.compare(
        HttpTrustCategory.HOST_INJECTION,
        "Host",
        canary,
        res_base,
        res_test,
    )
    assert comp.is_validated is True
    assert "ACTION_LINK_POISONING" in comp.signals
    assert comp.trust_classification == TrustClassification.USED_FOR_URL_GENERATION


# ============================================================================
# 4. Proxy & Scheme Trust (Lab Scenarios 5-8)
# ============================================================================

def test_lab_scenario_5_xfh_trusted(mock_lab):
    # Host header legitimate, X-Forwarded-Host injected
    canary = "bb11-lab-canary.researcher-controlled.example"
    req_base = ControlledRequest(url="http://lab.local/api/config", headers={"Host": "lab.local"})
    res_base = mock_lab.handle_request(req_base)

    req_test = ControlledRequest(url="http://lab.local/api/config", headers={"Host": "lab.local", "X-Forwarded-Host": canary})
    res_test = mock_lab.handle_request(req_test)

    comp = HttpTrustComparator.compare(
        HttpTrustCategory.FORWARDED_TRUST,
        "X-Forwarded-Host",
        canary,
        res_base,
        res_test,
    )
    assert "OPENGRAPH_URL_POISONING" in comp.signals
    assert comp.trust_classification == TrustClassification.USED_FOR_URL_GENERATION


def test_lab_scenario_6_forwarded_header_trusted(mock_lab):
    canary = "bb11-lab-canary.researcher-controlled.example"
    req_base = ControlledRequest(url="http://lab.local/forwarded-test", headers={"Host": "lab.local"})
    res_base = mock_lab.handle_request(req_base)

    req_test = ControlledRequest(url="http://lab.local/forwarded-test", headers={"Host": "lab.local", "Forwarded": f"host={canary}"})
    res_test = mock_lab.handle_request(req_test)

    comp = HttpTrustComparator.compare(
        HttpTrustCategory.FORWARDED_TRUST,
        "Forwarded",
        canary,
        res_base,
        res_test,
    )
    assert "CANONICAL_URL_POISONING" in comp.signals
    assert comp.is_validated is True


def test_lab_scenario_7_scheme_proto_downgrade(mock_lab):
    req_base = ControlledRequest(url="http://lab.local/proto-test", headers={"Host": "lab.local", "X-Forwarded-Proto": "https"})
    res_base = mock_lab.handle_request(req_base)

    req_test = ControlledRequest(url="http://lab.local/proto-test", headers={"Host": "lab.local", "X-Forwarded-Proto": "http"})
    res_test = mock_lab.handle_request(req_test)

    comp = HttpTrustComparator.compare(
        HttpTrustCategory.SCHEME_TRUST,
        "X-Forwarded-Proto",
        "http",
        res_base,
        res_test,
    )
    assert "SCHEME_DOWNGRADE_CANONICAL" in comp.signals
    assert comp.trust_classification == TrustClassification.USED_FOR_URL_GENERATION


def test_lab_scenario_8_secure_proxy_ignores_xfh(mock_lab):
    canary = "bb11-lab-canary.researcher-controlled.example"
    req_base = ControlledRequest(url="http://lab.local/secure-proxy", headers={"Host": "lab.local"})
    res_base = mock_lab.handle_request(req_base)

    req_test = ControlledRequest(url="http://lab.local/secure-proxy", headers={"Host": "lab.local", "X-Forwarded-Host": canary})
    res_test = mock_lab.handle_request(req_test)

    comp = HttpTrustComparator.compare(
        HttpTrustCategory.FORWARDED_TRUST,
        "X-Forwarded-Host",
        canary,
        res_base,
        res_test,
    )
    assert comp.is_validated is False
    assert comp.trust_classification in (TrustClassification.ACCEPTED, TrustClassification.UNUSED)


# ============================================================================
# 5. CORS Trust (Lab Scenarios 9-11)
# ============================================================================

def test_lab_scenario_9_cors_reflected_no_credentials(mock_lab):
    attacker_origin = "https://evil.example.com"
    req_base = ControlledRequest(url="http://lab.local/public-cors", headers={"Host": "lab.local"})
    res_base = mock_lab.handle_request(req_base)

    req_test = ControlledRequest(url="http://lab.local/public-cors", headers={"Host": "lab.local", "Origin": attacker_origin})
    res_test = mock_lab.handle_request(req_test)

    comp = HttpTrustComparator.compare(
        HttpTrustCategory.CORS_TRUST,
        "Origin",
        attacker_origin,
        res_base,
        res_test,
    )
    assert "CORS_REFLECTED_NO_CREDENTIALS" in comp.signals
    assert comp.is_validated is False  # Reflected without creds is OBSERVED, not critical validation
    assert comp.confidence == HttpTrustConfidence.OBSERVED


def test_lab_scenario_10_cors_credentialed_reflection(mock_lab):
    attacker_origin = "https://evil.example.com"
    req_base = ControlledRequest(url="http://lab.local/api/user/profile", headers={"Host": "lab.local"})
    res_base = mock_lab.handle_request(req_base)

    req_test = ControlledRequest(url="http://lab.local/api/user/profile", headers={"Host": "lab.local", "Origin": attacker_origin})
    res_test = mock_lab.handle_request(req_test)

    comp = HttpTrustComparator.compare(
        HttpTrustCategory.CORS_TRUST,
        "Origin",
        attacker_origin,
        res_base,
        res_test,
    )
    assert comp.is_validated is True
    assert "CORS_CREDENTIALED_REFLECTION" in comp.signals
    assert comp.confidence == HttpTrustConfidence.VALIDATED


def test_lab_scenario_11_cors_safe_allowlist(mock_lab):
    attacker_origin = "https://evil.example.com"
    req_base = ControlledRequest(url="http://lab.local/api/allowlist-cors", headers={"Host": "lab.local"})
    res_base = mock_lab.handle_request(req_base)

    req_test = ControlledRequest(url="http://lab.local/api/allowlist-cors", headers={"Host": "lab.local", "Origin": attacker_origin})
    res_test = mock_lab.handle_request(req_test)

    comp = HttpTrustComparator.compare(
        HttpTrustCategory.CORS_TRUST,
        "Origin",
        attacker_origin,
        res_base,
        res_test,
    )
    assert "CORS_ALLOWLIST_ENFORCED" in comp.signals
    assert comp.is_validated is False
    assert comp.trust_classification == TrustClassification.USED_FOR_SECURITY_DECISION


# ============================================================================
# 6. HPP, Cache & False Positives (Lab Scenarios 12-15)
# ============================================================================

def test_lab_scenario_12_hpp_parser_difference(mock_lab):
    req_base = ControlledRequest(url="http://lab.local/api/account?user=guest", headers={"Host": "lab.local"})
    res_base = mock_lab.handle_request(req_base)

    req_test = ControlledRequest(url="http://lab.local/api/account?user=bbval1&user=bbval2", headers={"Host": "lab.local"})
    res_test = mock_lab.handle_request(req_test)

    comp = HttpTrustComparator.compare(
        HttpTrustCategory.HPP,
        "user",
        "user=bbval1&user=bbval2",
        res_base,
        res_test,
    )
    assert comp.confidence == HttpTrustConfidence.OBSERVED
    assert "HPP_PARSER_LAST_VALUE" in comp.signals


def test_lab_scenario_13_cache_variation_without_poisoning(mock_lab):
    canary = "bb11-lab-canary.researcher-controlled.example"
    req_base = ControlledRequest(url="http://lab.local/static-cache", headers={"Host": "lab.local"})
    res_base = mock_lab.handle_request(req_base)

    req_test = ControlledRequest(url="http://lab.local/static-cache", headers={"Host": "lab.local", "X-Forwarded-Host": canary})
    res_test = mock_lab.handle_request(req_test)

    comp = HttpTrustComparator.compare(
        HttpTrustCategory.CACHE_POISONING,
        "X-Forwarded-Host",
        canary,
        res_base,
        res_test,
    )
    assert comp.is_false_positive is True
    assert "CACHE_VARIATION_WITHOUT_POISONING" in comp.signals


def test_lab_scenario_14_cache_poisoning_simulation(mock_lab):
    canary = "bb11-lab-canary.researcher-controlled.example"
    req_base = ControlledRequest(url="http://lab.local/cached-page", headers={"Host": "lab.local"})
    res_base = mock_lab.handle_request(req_base)

    req_test = ControlledRequest(url="http://lab.local/cached-page", headers={"Host": "lab.local", "X-Forwarded-Host": canary})
    res_test = mock_lab.handle_request(req_test)

    comp = HttpTrustComparator.compare(
        HttpTrustCategory.CACHE_POISONING,
        "X-Forwarded-Host",
        canary,
        res_base,
        res_test,
    )
    assert "CACHE_UNKEYED_INPUT_REFLECTED" in comp.signals
    assert comp.trust_classification == TrustClassification.USED_FOR_CACHE_KEY


def test_lab_scenario_15_debug_reflection_false_positive(mock_lab):
    canary = "bb11-lab-canary.researcher-controlled.example"
    req_base = ControlledRequest(url="http://lab.local/debug-error", headers={"Host": "lab.local"})
    res_base = mock_lab.handle_request(req_base)

    req_test = ControlledRequest(url="http://lab.local/debug-error", headers={"Host": canary})
    res_test = mock_lab.handle_request(req_test)

    comp = HttpTrustComparator.compare(
        HttpTrustCategory.HOST_INJECTION,
        "Host",
        canary,
        res_base,
        res_test,
    )
    assert comp.is_false_positive is True
    assert "DEBUG_PAGE_ECHO" in comp.signals


# ============================================================================
# 7. End-to-End Engine Pipeline & State Persistence
# ============================================================================

def test_engine_pipeline_and_approval_gate(temp_program_dir, mock_lab):
    engine = HttpTrustEngine(
        program_dir=temp_program_dir,
        send_request_hook=mock_lab.handle_request,
        auto_approve=False,
        lab_mode=True,
    )

    cand = HeaderTrustCandidate(
        candidate_id="htc-test-1",
        header_name="Host",
        endpoint="http://lab.local/auth/forgot-password",
        application="lab.local",
        category=HttpTrustCategory.HOST_INJECTION,
        priority=90,
    )
    engine.state_mgr.save_candidate(cand)

    # 1. Unapproved execution should be blocked by Approval Gate
    comp, tc = engine.execute_candidate(cand)
    assert comp is None and tc is None

    # 2. Approve candidate and execute
    engine.approval_gate.approve_candidate("htc-test-1")
    comp, tc = engine.execute_candidate(cand)
    assert comp is not None and tc is not None
    assert comp.is_validated is True
    assert tc.lifecycle == FindingLifecycle.VALIDATED

    # 3. Check state persistence
    reloaded_cand = engine.state_mgr.get_candidate("htc-test-1")
    assert reloaded_cand.lifecycle == FindingLifecycle.VALIDATED
    assert len(reloaded_cand.evidence_references) == 1

    # Check verified findings
    findings = engine.state_mgr.list_findings()
    assert len(findings) == 1
    assert "auth/forgot-password" in findings[0]["endpoint"]


def test_scope_enforcement_blocks_out_of_scope(temp_program_dir, mock_lab):
    scope_eng = ScopeEngine({
        "program": {"name": "test"},
        "targets": {
            "domains": ["lab.local"],
            "urls": ["http://lab.local/"],
        },
    })
    engine = HttpTrustEngine(
        program_dir=temp_program_dir,
        scope_engine=scope_eng,
        send_request_hook=mock_lab.handle_request,
        auto_approve=True,
        lab_mode=True,
    )

    cand_out = HeaderTrustCandidate(
        candidate_id="htc-out",
        header_name="Host",
        endpoint="https://external-target.com/login",
        application="external-target.com",
        category=HttpTrustCategory.HOST_INJECTION,
    )
    engine.state_mgr.save_candidate(cand_out)

    comp, tc = engine.execute_candidate(cand_out)
    assert comp is None and tc is None
    updated = engine.state_mgr.get_candidate("htc-out")
    assert updated.lifecycle == FindingLifecycle.REJECTED


def test_security_hygiene_no_shell_exec():
    """Verify strictly zero shell execution, eval, or exec in the framework."""
    framework_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "framework", "http_trust"))
    for root, _, files in os.walk(framework_dir):
        for fname in files:
            if fname.endswith(".py"):
                fpath = os.path.join(root, fname)
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
                    assert "shell=True" not in content
                    assert "os.system(" not in content
                    assert "subprocess.Popen" not in content
                    assert "eval(" not in content
                    assert "exec(" not in content
