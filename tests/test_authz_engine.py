"""
Unit tests for Authorization & Access-Control Intelligence Engine (Phase 8).

Validates:
1. PrincipalProfile, SessionProfile, ResourceAccessTarget data models
2. ObjectIdentifierAnalyzer classification & candidate extraction
3. AccessControlComparator false-positive elimination (soft-404, generic-200, login form, redirect)
4. LocalAuthzLab 8-scenario simulation
5. AuthorizationStateManager atomic persistence & summary computation
6. HumanApprovalGate dossier generation & approval gating
7. AuthorizationIntelligenceEngine active & passive workflows
8. Scope & policy enforcement (safe methods only)
9. Security hygiene audit (zero shell=True, zero os.system, zero eval/exec)
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

from framework.authz.approval import HumanApprovalGate
from framework.authz.comparator import AccessControlComparator
from framework.authz.engine import AuthorizationIntelligenceEngine
from framework.authz.identifiers import ObjectIdentifierAnalyzer
from framework.authz.lab import LocalAuthzLab
from framework.authz.model import (
    AccessDecisionInferred,
    AuthorizationCategory,
    AuthorizationTestCase,
    AuthzComparisonResult,
    AuthzEvidence,
    ExpectedAccessDecision,
    ExpectedAccessPolicy,
    PrincipalProfile,
    ResourceAccessTarget,
    SessionProfile,
)
from framework.authz.state import AuthorizationStateManager
from framework.scope.engine import ScopeEngine
from framework.validation.policy import SecurityTestPolicy
from framework.validation.request import ControlledRequest, ControlledResponse


@pytest.fixture
def temp_program_dir():
    d = tempfile.mkdtemp(prefix="bb_test_authz_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


# ---------------- 1. Model & Sanitization Tests ----------------

def test_principal_and_session_models():
    principal = PrincipalProfile(
        principal_id="user_a",
        role="USER",
        tenant_id="tenant_10",
        privilege_level=10,
        ownership_context=["doc-101", "inv-202"],
        masked_metadata={"api_key": "secret_key_1234567890"},
    )
    assert principal.principal_id == "user_a"
    assert principal.role == "USER"
    assert principal.owns_resource("doc-101") is True
    assert principal.owns_resource("doc-999") is False

    # Check that metadata was sanitized
    assert "secret_key" not in principal.masked_metadata["api_key"]

    p_dict = principal.to_dict()
    restored_p = PrincipalProfile.from_dict(p_dict)
    assert restored_p.principal_id == "user_a"
    assert restored_p.ownership_context == ["doc-101", "inv-202"]

    session = SessionProfile(
        session_id="sess_123",
        principal_id="user_a",
        headers_ref={"Authorization": "Bearer supersecretjwttoken"},
        cookies_ref={"session": "cookieval"},
    )
    # Check that tokens are sanitized in stored refs
    assert "supersecretjwttoken" not in session.headers_ref["Authorization"]
    s_dict = session.to_dict()
    restored_s = SessionProfile.from_dict(s_dict)
    assert restored_s.session_id == "sess_123"


def test_resource_access_target_model():
    target = ResourceAccessTarget(
        resource_id="101",
        resource_type="document",
        endpoint="https://api.example.com/api/v1/documents/101",
        method="GET",
        tenant_id="tenant_a",
        owner_principal_id="user_a",
        param_location="PATH",
        identifier_type="NUMERIC",
    )
    assert target.resource_id == "101"
    assert target.resource_type == "document"
    t_dict = target.to_dict()
    restored = ResourceAccessTarget.from_dict(t_dict)
    assert restored.resource_id == "101"
    assert restored.owner_principal_id == "user_a"


def test_expected_access_policy():
    user_a = PrincipalProfile(principal_id="user_a", role="USER", tenant_id="tenant_a")
    user_b = PrincipalProfile(principal_id="user_b", role="USER", tenant_id="tenant_a")
    user_c = PrincipalProfile(principal_id="user_c", role="USER", tenant_id="tenant_b")
    admin = PrincipalProfile(principal_id="admin_1", role="ADMIN", tenant_id="tenant_a")

    res = ResourceAccessTarget(
        resource_id="101",
        resource_type="document",
        endpoint="https://api.example.com/api/v1/documents/101",
        owner_principal_id="user_a",
        tenant_id="tenant_a",
    )

    # Owner -> ALLOW
    pol_owner = ExpectedAccessPolicy.infer_default(user_a, res, "READ")
    assert pol_owner.expected_decision == ExpectedAccessDecision.ALLOW

    # Peer in same tenant -> DENY (Horizontal IDOR boundary)
    pol_peer = ExpectedAccessPolicy.infer_default(user_b, res, "READ")
    assert pol_peer.expected_decision == ExpectedAccessDecision.DENY

    # Cross-tenant -> DENY (Cross-tenant boundary)
    pol_tenant = ExpectedAccessPolicy.infer_default(user_c, res, "READ")
    assert pol_tenant.expected_decision == ExpectedAccessDecision.DENY

    # Admin -> ALLOW
    pol_admin = ExpectedAccessPolicy.infer_default(admin, res, "READ")
    assert pol_admin.expected_decision == ExpectedAccessDecision.ALLOW


# ---------------- 2. Object Identifier Intelligence Tests ----------------

def test_identifier_type_classification():
    analyzer = ObjectIdentifierAnalyzer()
    assert analyzer.classify_identifier_type("12345") == "NUMERIC"
    assert analyzer.classify_identifier_type("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d") == "UUID"
    assert analyzer.classify_identifier_type("4f53cda18c2baa0c0354bb5f9a3ecbe5") == "OPAQUE"
    assert analyzer.classify_identifier_type("report-summary-q1") == "SLUG"
    assert analyzer.classify_identifier_type("!!@@##") == "UNKNOWN"


def test_infer_resource_type():
    analyzer = ObjectIdentifierAnalyzer()
    assert analyzer.infer_resource_type("https://api.example.com/api/v1/users/123") == "user"
    assert analyzer.infer_resource_type("https://api.example.com/invoices/{id}") == "invoice"
    assert analyzer.infer_resource_type("https://api.example.com/orders", param_name="order_id") == "order"


def test_extract_candidates_from_endpoint():
    analyzer = ObjectIdentifierAnalyzer()
    # Path template
    targets = analyzer.extract_from_endpoint("https://api.example.com/api/v1/documents/{doc_id}")
    assert len(targets) >= 1
    assert targets[0].param_location == "PATH"
    assert targets[0].resource_type == "document"

    # Query parameter
    targets_q = analyzer.extract_from_endpoint(
        "https://api.example.com/api/v1/reports?report_id=8842",
        parameters=[{"name": "report_id", "in": "query"}],
    )
    assert len(targets_q) >= 1
    assert targets_q[0].param_location == "QUERY"
    assert targets_q[0].resource_id == "8842"
    assert targets_q[0].identifier_type == "NUMERIC"


# ---------------- 3. AccessControlComparator & False Positive Elimination ----------------

def test_comparator_http_rejections():
    policy = ExpectedAccessPolicy(expected_decision=ExpectedAccessDecision.DENY)
    res = ResourceAccessTarget(resource_id="101", resource_type="document", endpoint="https://api.example.com/doc/101")

    # 403 Forbidden
    resp_403 = ControlledResponse(status_code=403, headers={}, body="Forbidden", size_bytes=9, final_url="https://api.example.com/doc/101")
    comp = AccessControlComparator.compare(resp_403, policy, res)
    assert comp.is_vulnerable is False
    assert comp.decision_inferred == AccessDecisionInferred.DENY

    # 404 Not Found
    resp_404 = ControlledResponse(status_code=404, headers={}, body="Not Found", size_bytes=9, final_url="https://api.example.com/doc/101")
    comp404 = AccessControlComparator.compare(resp_404, policy, res)
    assert comp404.is_vulnerable is False
    assert comp404.decision_inferred == AccessDecisionInferred.DENY


def test_comparator_login_redirect_and_form():
    policy = ExpectedAccessPolicy(expected_decision=ExpectedAccessDecision.DENY)
    res = ResourceAccessTarget(resource_id="101", resource_type="document", endpoint="https://api.example.com/doc/101")

    # Login Redirect
    resp_302 = ControlledResponse(
        status_code=302,
        headers={"location": "/auth/login"},
        body="",
        size_bytes=0,
        final_url="https://api.example.com/doc/101",
    )
    comp302 = AccessControlComparator.compare(resp_302, policy, res)
    assert comp302.is_vulnerable is False
    assert comp302.decision_inferred == AccessDecisionInferred.DENY

    # Login Form in 200 Body
    resp_login_form = ControlledResponse(
        status_code=200,
        headers={"content-type": "text/html"},
        body="<html><body><form action='/login'><input type='password' name='pass'></form></body></html>",
        size_bytes=80,
        final_url="https://api.example.com/doc/101",
    )
    comp_form = AccessControlComparator.compare(resp_login_form, policy, res)
    assert comp_form.is_vulnerable is False
    assert comp_form.decision_inferred == AccessDecisionInferred.DENY


def test_comparator_generic_denial_and_soft_404():
    policy = ExpectedAccessPolicy(expected_decision=ExpectedAccessDecision.DENY)
    res = ResourceAccessTarget(resource_id="101", resource_type="document", endpoint="https://api.example.com/doc/101")

    # Generic Denial in 200 OK
    resp_denial = ControlledResponse(
        status_code=200,
        headers={"content-type": "text/html"},
        body="<html><body><h1>Access Denied</h1><p>You do not have permission to view this resource.</p></body></html>",
        size_bytes=95,
        final_url="https://api.example.com/doc/101",
    )
    comp_denial = AccessControlComparator.compare(resp_denial, policy, res)
    assert comp_denial.is_vulnerable is False
    assert comp_denial.generic_error_page is True
    assert comp_denial.decision_inferred == AccessDecisionInferred.DENY

    # Soft-404 in 200 OK
    resp_soft404 = ControlledResponse(
        status_code=200,
        headers={"content-type": "text/html"},
        body="<html><body><h1>Page Not Found</h1><p>The requested record does not exist.</p></body></html>",
        size_bytes=85,
        final_url="https://api.example.com/doc/101",
    )
    comp_soft404 = AccessControlComparator.compare(resp_soft404, policy, res)
    assert comp_soft404.is_vulnerable is False
    assert comp_soft404.soft_404 is True
    assert comp_soft404.decision_inferred == AccessDecisionInferred.DENY


def test_comparator_baseline_invalid_resource_match():
    policy = ExpectedAccessPolicy(expected_decision=ExpectedAccessDecision.DENY)
    res = ResourceAccessTarget(resource_id="101", resource_type="document", endpoint="https://api.example.com/doc/101")

    # Baseline B (Nonexistent resource response)
    baseline_inv = ControlledResponse(
        status_code=200,
        headers={"content-type": "application/json"},
        body=json.dumps({"status": "empty", "data": []}),
        size_bytes=30,
        final_url="https://api.example.com/doc/99999",
    )

    # Test response is identical to Baseline B
    test_resp = ControlledResponse(
        status_code=200,
        headers={"content-type": "application/json"},
        body=json.dumps({"status": "empty", "data": []}),
        size_bytes=30,
        final_url="https://api.example.com/doc/101",
    )

    comp = AccessControlComparator.compare(
        test_response=test_resp,
        expected_policy=policy,
        resource=res,
        baseline_invalid_response=baseline_inv,
    )
    assert comp.is_vulnerable is False
    assert comp.soft_404 is True
    assert comp.decision_inferred == AccessDecisionInferred.DENY


def test_comparator_true_positive_idor():
    policy = ExpectedAccessPolicy(expected_decision=ExpectedAccessDecision.DENY)
    res = ResourceAccessTarget(
        resource_id="101",
        resource_type="document",
        endpoint="https://api.example.com/doc/101",
        owner_principal_id="user_a",
    )

    baseline_owner = ControlledResponse(
        status_code=200,
        headers={"content-type": "application/json"},
        body=json.dumps({"id": "101", "owner": "user_a", "title": "Secret Document"}),
        size_bytes=60,
        final_url="https://api.example.com/doc/101",
    )

    baseline_inv = ControlledResponse(
        status_code=404,
        headers={"content-type": "application/json"},
        body=json.dumps({"error": "not found"}),
        size_bytes=25,
        final_url="https://api.example.com/doc/999999",
    )

    # Testing principal gets identical document data
    test_resp = ControlledResponse(
        status_code=200,
        headers={"content-type": "application/json"},
        body=json.dumps({"id": "101", "owner": "user_a", "title": "Secret Document"}),
        size_bytes=60,
        final_url="https://api.example.com/doc/101",
    )

    comp = AccessControlComparator.compare(
        test_response=test_resp,
        expected_policy=policy,
        resource=res,
        baseline_owner_response=baseline_owner,
        baseline_invalid_response=baseline_inv,
    )
    assert comp.is_vulnerable is True
    assert comp.decision_inferred == AccessDecisionInferred.ALLOW
    assert comp.ownership_identifier_found is True
    assert comp.body_similarity > 0.95


# ---------------- 4. LocalAuthzLab Fixture Scenarios ----------------

def test_local_authz_lab_scenarios():
    lab = LocalAuthzLab()

    # Scenario 1: Horizontal IDOR on documents
    req_owner = ControlledRequest(
        method="GET",
        url="https://api.local/api/v1/documents/101",
        headers={"Authorization": "Bearer user_a_token"},
    )
    res_owner = lab.dispatch(req_owner)
    assert res_owner.status_code == 200
    assert "user_a" in res_owner.body

    req_peer = ControlledRequest(
        method="GET",
        url="https://api.local/api/v1/documents/101",
        headers={"Authorization": "Bearer user_b_token"},
    )
    res_peer = lab.dispatch(req_peer)
    assert res_peer.status_code == 200
    assert "user_a" in res_peer.body  # Vulnerable!

    # Scenario 2: Vertical Privilege Escalation
    req_user_admin = ControlledRequest(
        method="GET",
        url="https://api.local/admin/users",
        headers={"Authorization": "Bearer user_a_token"},
    )
    res_user_admin = lab.dispatch(req_user_admin)
    assert res_user_admin.status_code == 200
    assert "admin_access" in res_user_admin.body  # Vulnerable!

    # Scenario 3: Tenant Isolation Failure
    req_tenant = ControlledRequest(
        method="GET",
        url="https://api.local/api/v1/invoices/inv-001",
        headers={"Authorization": "Bearer user_b_token"},  # user_b is in tenant_b
    )
    res_tenant = lab.dispatch(req_tenant)
    assert res_tenant.status_code == 200
    assert "inv-001" in res_tenant.body  # Leaks tenant_a invoice!

    # Scenario 4: Defended Endpoint
    req_defended = ControlledRequest(
        method="GET",
        url="https://api.local/api/v1/documents/101?mode=defended",
        headers={"Authorization": "Bearer user_b_token"},
    )
    res_defended = lab.dispatch(req_defended)
    assert res_defended.status_code == 403

    # Scenario 5: Soft-404 Response
    req_soft404 = ControlledRequest(
        method="GET",
        url="https://api.local/api/v1/documents/101?mode=soft-404",
        headers={"Authorization": "Bearer user_b_token"},
    )
    res_soft404 = lab.dispatch(req_soft404)
    assert res_soft404.status_code == 200
    assert "Page Not Found" in res_soft404.body

    # Scenario 6: Generic 200 Denial
    req_generic = ControlledRequest(
        method="GET",
        url="https://api.local/api/v1/documents/101?mode=generic-denial",
        headers={"Authorization": "Bearer user_b_token"},
    )
    res_generic = lab.dispatch(req_generic)
    assert res_generic.status_code == 200
    assert "Access Denied" in res_generic.body

    # Scenario 7: Unauthenticated Protected Resource
    req_anon = ControlledRequest(method="GET", url="https://api.local/api/v1/profile")
    res_anon = lab.dispatch(req_anon)
    assert res_anon.status_code == 200
    assert "user_a@example.com" in res_anon.body

    # Scenario 8: Intentionally Public Resource
    req_pub = ControlledRequest(method="GET", url="https://api.local/public/terms")
    res_pub = lab.dispatch(req_pub)
    assert res_pub.status_code == 200
    assert "Terms of Service" in res_pub.body


# ---------------- 5. State Management Tests ----------------

def test_state_manager_persistence(temp_program_dir):
    mgr = AuthorizationStateManager(temp_program_dir)
    assert os.path.exists(mgr.authz_file)

    p = PrincipalProfile(principal_id="test_user", role="USER", tenant_id="t1")
    mgr.save_principal(p)
    loaded_p = mgr.get_principal("test_user")
    assert loaded_p is not None
    assert loaded_p.tenant_id == "t1"

    r = ResourceAccessTarget(resource_id="doc_55", resource_type="document", endpoint="https://example.com/doc/55")
    mgr.save_resource(r)
    assert len(mgr.list_resources()) == 1

    tc = AuthorizationTestCase(
        category=AuthorizationCategory.HORIZONTAL,
        endpoint="https://example.com/doc/55",
        resource=r,
        testing_principal=p,
    )
    mgr.save_test_case(tc)
    assert len(mgr.list_test_cases()) == 1

    # Human Approval
    assert mgr.is_test_approved(tc.test_id) is False
    mgr.approve_test_case(tc.test_id, approved_by="senior-analyst")
    assert mgr.is_test_approved(tc.test_id) is True

    summary = mgr.get_summary()
    assert summary["total_principals"] == 1
    assert summary["total_resources"] == 1
    assert summary["total_test_cases"] == 1
    assert summary["approved_test_cases"] == 1


# ---------------- 6. Human Approval Gate Tests ----------------

def test_human_approval_gate(temp_program_dir):
    mgr = AuthorizationStateManager(temp_program_dir)
    gate = HumanApprovalGate(mgr)

    p1 = PrincipalProfile(principal_id="user_a", role="USER")
    p2 = PrincipalProfile(principal_id="user_b", role="USER")
    r = ResourceAccessTarget(resource_id="101", resource_type="doc", endpoint="https://api.example.com/doc/101")
    tc = AuthorizationTestCase(
        category=AuthorizationCategory.HORIZONTAL,
        endpoint="https://api.example.com/doc/101",
        resource=r,
        testing_principal=p2,
        source_principal=p1,
    )
    mgr.save_test_case(tc)

    dossier_text = gate.request_approval(tc)
    assert "LIVE AUTHORIZATION TEST APPROVAL REQUIRED" in dossier_text
    assert "https://api.example.com/doc/101" in dossier_text
    assert "user_b" in dossier_text

    assert gate.is_approved(tc.test_id) is False
    gate.approve(tc.test_id, approver="alice")
    assert gate.is_approved(tc.test_id) is True


# ---------------- 7. AuthorizationIntelligenceEngine Tests ----------------

def test_authz_engine_live_evaluation(temp_program_dir):
    lab = LocalAuthzLab()
    scope = ScopeEngine({
        "program": {"name": "test-lab"},
        "targets": {
            "domains": ["api.local"],
            "recursive_subdomains": {"enabled": True},
        },
    })

    engine = AuthorizationIntelligenceEngine(
        program_dir=temp_program_dir,
        scope_engine=scope,
        send_request_hook=lab.dispatch,
    )

    # Register volatile session credentials in memory
    engine.register_volatile_credentials("user_a", {"Authorization": "Bearer user_a"})
    engine.register_volatile_credentials("user_b", {"Authorization": "Bearer user_b"})

    # Setup resource and test case for horizontal IDOR
    target = ResourceAccessTarget(
        resource_id="101",
        resource_type="document",
        endpoint="https://api.local/api/v1/documents/101",
        owner_principal_id="user_a",
        param_location="PATH",
        identifier_type="NUMERIC",
    )
    user_a = PrincipalProfile(principal_id="user_a", role="USER", tenant_id="tenant_a", ownership_context=["101"])
    user_b = PrincipalProfile(principal_id="user_b", role="USER", tenant_id="tenant_b")

    tc = AuthorizationTestCase(
        category=AuthorizationCategory.HORIZONTAL,
        endpoint="https://api.local/api/v1/documents/101",
        resource=target,
        testing_principal=user_b,
        source_principal=user_a,
    )

    # 1. Without approval -> halted
    tc_res, finding_res = engine.execute_test_case(tc, force_approved=False)
    assert "awaiting explicit human approval" in tc_res.notes
    assert finding_res is None

    # 2. With force_approved=True -> executes and validates IDOR
    tc_res, finding_res = engine.execute_test_case(tc, force_approved=True)
    assert tc_res.lifecycle_state == "VERIFIED"
    assert tc_res.comparison_result is not None
    assert tc_res.comparison_result.is_vulnerable is True
    assert finding_res is not None
    assert finding_res.vulnerability_type == "Broken Object Level Authorization (BOLA/IDOR)"
    assert tc_res.evidence is not None
    assert tc_res.evidence.evidence_hash != ""


def test_authz_engine_scope_and_policy_enforcement(temp_program_dir):
    lab = LocalAuthzLab()
    scope = ScopeEngine({
        "program": {"name": "test-scope"},
        "targets": {
            "domains": ["authorized.local"],
            "recursive_subdomains": {"enabled": True},
        },
    })
    engine = AuthorizationIntelligenceEngine(
        program_dir=temp_program_dir,
        scope_engine=scope,
        send_request_hook=lab.dispatch,
    )

    p = PrincipalProfile(principal_id="user_b", role="USER")
    r_outofscope = ResourceAccessTarget(
        resource_id="101",
        resource_type="doc",
        endpoint="https://evil.external.com/doc/101",
    )
    tc_oos = AuthorizationTestCase(
        category=AuthorizationCategory.HORIZONTAL,
        endpoint="https://evil.external.com/doc/101",
        resource=r_outofscope,
        testing_principal=p,
    )

    tc_res, _ = engine.execute_test_case(tc_oos, force_approved=True)
    assert tc_res.lifecycle_state == "OUT_OF_SCOPE"

    # Unsafe method (DELETE) rejected by policy
    r_inscope = ResourceAccessTarget(
        resource_id="101",
        resource_type="doc",
        endpoint="https://authorized.local/doc/101",
    )
    tc_del = AuthorizationTestCase(
        category=AuthorizationCategory.HORIZONTAL,
        endpoint="https://authorized.local/doc/101",
        resource=r_inscope,
        testing_principal=p,
        method="DELETE",
    )
    tc_del_res, _ = engine.execute_test_case(tc_del, force_approved=True)
    assert tc_del_res.lifecycle_state == "REJECTED_METHOD"


def test_authz_engine_run_evaluation_modes(temp_program_dir):
    engine = AuthorizationIntelligenceEngine(program_dir=temp_program_dir)

    # Passive only
    res_pass = engine.run_evaluation(passive_only=True)
    assert res_pass["mode"] == "passive-only"
    assert "test_cases" in res_pass

    # Dry run
    res_dry = engine.run_evaluation(dry_run=True)
    assert res_dry["mode"] == "dry-run"


# ---------------- 8. Security Hygiene Audit ----------------

def test_security_hygiene_zero_shell_exec():
    authz_dir = os.path.join(os.path.dirname(__file__), "..", "framework", "authz")
    for root, _, files in os.walk(authz_dir):
        for f in files:
            if f.endswith(".py"):
                path = os.path.join(root, f)
                with open(path, "r", encoding="utf-8") as py_file:
                    content = py_file.read()
                    assert "shell=True" not in content, f"Insecure shell=True found in {path}"
                    assert "os.system(" not in content, f"Insecure os.system found in {path}"
                    assert "eval(" not in content, f"Insecure eval found in {path}"
                    assert "exec(" not in content, f"Insecure exec found in {path}"
