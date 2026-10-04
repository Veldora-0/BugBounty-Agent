"""
Authorization & Access-Control Intelligence Engine (Phase 8).

Orchestrates passive candidate discovery, object identifier classification,
human approval gating, and rigorous 3-point comparative baseline verification
for BOLA/IDOR, privilege escalation, and tenant isolation vulnerabilities.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import uuid

from framework.authz.approval import HumanApprovalGate
from framework.authz.comparator import AccessControlComparator
from framework.authz.identifiers import ObjectIdentifierAnalyzer
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
from framework.findings.schema import Finding
from framework.scope.engine import ScopeEngine
from framework.state.dedup import FindingDeduplicator
from framework.validation.engine import SecurityValidationEngine
from framework.validation.policy import SecurityTestPolicy
from framework.validation.request import ControlledRequest, ControlledResponse


class AuthorizationIntelligenceEngine:
    """
    Primary orchestrator for Authorization & Access Control analysis.
    Executes controlled, non-destructive hypothesis verification with
    differential baseline analysis.
    """

    def __init__(
        self,
        program_dir: str,
        scope_engine: Optional[ScopeEngine] = None,
        policy: Optional[SecurityTestPolicy] = None,
        validation_engine: Optional[SecurityValidationEngine] = None,
        send_request_hook: Optional[Callable[[ControlledRequest], ControlledResponse]] = None,
        session_credentials_provider: Optional[Callable[[str], Dict[str, str]]] = None,
    ):
        self.program_dir = os.path.abspath(program_dir)
        self.scope_engine = scope_engine
        self.policy = policy or SecurityTestPolicy()
        self.validation_engine = validation_engine or SecurityValidationEngine(
            program_dir=self.program_dir,
            scope_engine=self.scope_engine,
            policy=self.policy,
            send_request_hook=send_request_hook,
        )
        self.send_request_hook = send_request_hook
        self.state_mgr = AuthorizationStateManager(self.program_dir)
        self.approval_gate = HumanApprovalGate(self.state_mgr)

        # In-memory volatile credentials provider: principal_id -> {"Authorization": "...", "Cookie": "..."}
        # Tokens reside only in volatile memory and are NEVER written to disk
        self._session_credentials_provider = session_credentials_provider
        self._volatile_credentials: Dict[str, Dict[str, str]] = {}

    def register_volatile_credentials(self, principal_id: str, headers: Dict[str, str]) -> None:
        """Stores session headers in volatile memory for the duration of execution."""
        self._volatile_credentials[principal_id] = dict(headers)

    def get_principal_headers(self, principal_id: str) -> Dict[str, str]:
        """Retrieves runtime request headers for a principal."""
        if self._session_credentials_provider:
            h = self._session_credentials_provider(principal_id)
            if h:
                return dict(h)
        return dict(self._volatile_credentials.get(principal_id, {}))

    # ---------------- Passive Candidate Discovery & Ingestion ----------------

    def discover_candidates_from_state(
        self,
        asset_filter: Optional[str] = None,
        endpoint_filter: Optional[str] = None,
    ) -> List[ResourceAccessTarget]:
        """
        Discovers authorization resource targets from API (Phase 5),
        Web Applications (Phase 3), and JavaScript (Phase 4) states.
        """
        targets: List[ResourceAccessTarget] = []
        seen_targets: Set[str] = set()

        # 1. Inspect API catalog (state/api.json)
        api_state_file = os.path.join(self.program_dir, "state", "api.json")
        if os.path.exists(api_state_file):
            try:
                with open(api_state_file, "r", encoding="utf-8") as f:
                    api_data = json.load(f)
                catalog = api_data.get("catalog", {})
                for path, ep_data in catalog.items():
                    for op in ep_data.get("operations", []):
                        method = op.get("method", "GET")
                        url = op.get("url") or path
                        if endpoint_filter and endpoint_filter not in url:
                            continue
                        if asset_filter and asset_filter not in url:
                            continue

                        extracted = ObjectIdentifierAnalyzer.extract_from_endpoint(
                            endpoint_url=url,
                            method=method,
                            parameters=op.get("parameters", []),
                        )
                        for t in extracted:
                            key = f"{t.method}:{t.endpoint}:{t.resource_id}"
                            if key not in seen_targets:
                                seen_targets.add(key)
                                targets.append(t)
                                self.state_mgr.save_resource(t)
            except Exception:
                pass

        # 2. Inspect Web Applications state (state/webapps.json)
        webapps_state_file = os.path.join(self.program_dir, "state", "webapps.json")
        if os.path.exists(webapps_state_file):
            try:
                with open(webapps_state_file, "r", encoding="utf-8") as f:
                    web_data = json.load(f)
                for app in web_data.get("web_applications", {}).values():
                    for ep in app.get("endpoints", []):
                        url = ep.get("url", "")
                        method = ep.get("method", "GET")
                        if not url:
                            continue
                        if endpoint_filter and endpoint_filter not in url:
                            continue
                        if asset_filter and asset_filter not in url:
                            continue

                        extracted = ObjectIdentifierAnalyzer.extract_from_endpoint(
                            endpoint_url=url,
                            method=method,
                            parameters=ep.get("parameters", []),
                        )
                        for t in extracted:
                            key = f"{t.method}:{t.endpoint}:{t.resource_id}"
                            if key not in seen_targets:
                                seen_targets.add(key)
                                targets.append(t)
                                self.state_mgr.save_resource(t)
            except Exception:
                pass

        # 3. Inspect JavaScript routes (state/javascript.json)
        js_state_file = os.path.join(self.program_dir, "state", "javascript.json")
        if os.path.exists(js_state_file):
            try:
                with open(js_state_file, "r", encoding="utf-8") as f:
                    js_data = json.load(f)
                for route in js_data.get("routes", []):
                    route_path = route.get("path") or route.get("route", "")
                    if not route_path or not route_path.startswith("http"):
                        continue
                    if endpoint_filter and endpoint_filter not in route_path:
                        continue
                    if asset_filter and asset_filter not in route_path:
                        continue

                    extracted = ObjectIdentifierAnalyzer.extract_from_endpoint(
                        endpoint_url=route_path,
                        method="GET",
                    )
                    for t in extracted:
                        key = f"{t.method}:{t.endpoint}:{t.resource_id}"
                        if key not in seen_targets:
                            seen_targets.add(key)
                            targets.append(t)
                            self.state_mgr.save_resource(t)
            except Exception:
                pass

        return targets

    # ---------------- Hypothesis & Test Case Generation ----------------

    def generate_test_cases(
        self,
        resources: Optional[List[ResourceAccessTarget]] = None,
        principals: Optional[List[PrincipalProfile]] = None,
        category: Optional[str] = None,
    ) -> List[AuthorizationTestCase]:
        """
        Synthesizes structured comparative test cases from resources and principals.
        """
        res_list = resources if resources is not None else self.state_mgr.list_resources()
        prin_list = principals if principals is not None else self.state_mgr.list_principals()

        # If no principals configured, provision default benchmark profiles
        if not prin_list:
            prin_list = [
                PrincipalProfile(
                    principal_id="user_a",
                    role="USER",
                    tenant_id="tenant_a",
                    privilege_level=10,
                    ownership_context=["101", "inv-001"],
                ),
                PrincipalProfile(
                    principal_id="user_b",
                    role="USER",
                    tenant_id="tenant_b",
                    privilege_level=10,
                    ownership_context=["102", "inv-002"],
                ),
                PrincipalProfile(
                    principal_id="admin_user",
                    role="ADMIN",
                    tenant_id="tenant_a",
                    privilege_level=100,
                ),
                PrincipalProfile(
                    principal_id="ANONYMOUS",
                    role="ANONYMOUS",
                    privilege_level=0,
                ),
            ]
            for p in prin_list:
                self.state_mgr.save_principal(p)

        user_a = next((p for p in prin_list if p.principal_id == "user_a"), prin_list[0])
        user_b = next((p for p in prin_list if p.principal_id == "user_b"), prin_list[1] if len(prin_list) > 1 else prin_list[0])
        admin_u = next((p for p in prin_list if p.role == "ADMIN"), None)
        anon_u = next((p for p in prin_list if p.principal_id == "ANONYMOUS"), PrincipalProfile(principal_id="ANONYMOUS", role="ANONYMOUS", privilege_level=0))

        test_cases: List[AuthorizationTestCase] = []

        for r in res_list:
            cat_filter = category.lower() if category else None

            # 1. Horizontal BOLA/IDOR (User B accessing User A's resource)
            if not cat_filter or cat_filter in ("horizontal", "all"):
                tc_h = AuthorizationTestCase(
                    category=AuthorizationCategory.HORIZONTAL,
                    endpoint=r.endpoint,
                    resource=r,
                    testing_principal=user_b,
                    source_principal=user_a,
                    method=r.method,
                    expected_decision=ExpectedAccessDecision.DENY,
                    notes=f"Verify User B cannot access User A resource {r.resource_id}",
                )
                self.state_mgr.save_test_case(tc_h)
                test_cases.append(tc_h)

            # 2. Vertical Privilege Escalation (User accessing administrative route/resource)
            if admin_u and (not cat_filter or cat_filter in ("vertical", "all")):
                # Only if endpoint or resource indicates administrative function
                if "admin" in r.endpoint.lower() or "manage" in r.endpoint.lower():
                    tc_v = AuthorizationTestCase(
                        category=AuthorizationCategory.VERTICAL,
                        endpoint=r.endpoint,
                        resource=r,
                        testing_principal=user_a,
                        source_principal=admin_u,
                        method=r.method,
                        expected_decision=ExpectedAccessDecision.DENY,
                        notes=f"Verify standard user cannot access administrative resource {r.resource_id}",
                    )
                    self.state_mgr.save_test_case(tc_v)
                    test_cases.append(tc_v)

            # 3. Tenant Isolation (User from tenant_b accessing tenant_a resource)
            if not cat_filter or cat_filter in ("tenant", "all"):
                if r.tenant_id or (r.owner_principal_id and user_b.tenant_id):
                    tc_t = AuthorizationTestCase(
                        category=AuthorizationCategory.TENANT,
                        endpoint=r.endpoint,
                        resource=r,
                        testing_principal=user_b,
                        source_principal=user_a,
                        method=r.method,
                        expected_decision=ExpectedAccessDecision.DENY,
                        notes=f"Verify cross-tenant boundary isolation for resource {r.resource_id}",
                    )
                    self.state_mgr.save_test_case(tc_t)
                    test_cases.append(tc_t)

            # 4. Unauthenticated Access (Anonymous accessing protected resource)
            if not cat_filter or cat_filter in ("unauthenticated", "all"):
                tc_u = AuthorizationTestCase(
                    category=AuthorizationCategory.UNAUTHENTICATED,
                    endpoint=r.endpoint,
                    resource=r,
                    testing_principal=anon_u,
                    source_principal=user_a,
                    method=r.method,
                    expected_decision=ExpectedAccessDecision.DENY,
                    notes=f"Verify protected resource {r.resource_id} requires authentication",
                )
                self.state_mgr.save_test_case(tc_u)
                test_cases.append(tc_u)

        return test_cases

    # ---------------- Active Controlled Execution Pipeline ----------------

    def _substitute_url_identifier(self, endpoint_url: str, param_location: str, old_id: str, new_id: str) -> str:
        """Replaces resource identifier in endpoint URL."""
        if param_location == "PATH":
            # Direct substitution
            if old_id in endpoint_url:
                return endpoint_url.replace(old_id, new_id)
            # Template substitution
            for tpl in (f"{{{old_id}}}", f":{old_id}", f"<{old_id}>"):
                if tpl in endpoint_url:
                    return endpoint_url.replace(tpl, new_id)
            # Suffix replace
            parsed = urlparse(endpoint_url)
            segments = parsed.path.rstrip("/").split("/")
            if segments:
                segments[-1] = new_id
                new_path = "/".join(segments)
                return urlunparse((parsed.scheme, parsed.netloc, new_path, parsed.params, parsed.query, parsed.fragment))
        elif param_location == "QUERY":
            parsed = urlparse(endpoint_url)
            qsl = parse_qsl(parsed.query, keep_blank_values=True)
            new_qsl = []
            replaced = False
            for k, v in qsl:
                if v == old_id or k.lower() in ("id", "user_id", "userid"):
                    new_qsl.append((k, new_id))
                    replaced = True
                else:
                    new_qsl.append((k, v))
            if not replaced:
                new_qsl.append(("id", new_id))
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(new_qsl), parsed.fragment))

        return endpoint_url

    def _generate_nonexistent_identifier(self, id_type: str) -> str:
        """Produces a nonexistent identifier for Baseline B comparison."""
        if id_type == "UUID":
            return "00000000-0000-0000-0000-000000000000"
        if id_type == "NUMERIC":
            return "999999999"
        return "bb_nonexistent_res_9999"

    def execute_test_case(
        self,
        test_case: AuthorizationTestCase,
        force_approved: bool = False,
    ) -> Tuple[AuthorizationTestCase, Optional[Finding]]:
        """
        Executes a controlled 3-point comparative baseline verification for a test case.
        Requires human approval unless force_approved=True.
        """
        # 1. Approval Gate Enforcement
        if not test_case.is_approved_for_execution() and not force_approved:
            test_case.notes = "Execution halted: awaiting explicit human approval gate."
            self.state_mgr.save_test_case(test_case)
            return test_case, None

        # 2. Scope Validation
        if self.validation_engine:
            try:
                self.validation_engine.check_request_scope(test_case.endpoint)
            except Exception as e:
                test_case.lifecycle_state = "OUT_OF_SCOPE"
                test_case.notes = f"Target endpoint {test_case.endpoint} is out of authorized scope: {e}"
                self.state_mgr.save_test_case(test_case)
                return test_case, None

        # 3. Policy Verification (Safe HTTP methods only: GET, HEAD, OPTIONS)
        if test_case.method not in ("GET", "HEAD", "OPTIONS"):
            test_case.lifecycle_state = "REJECTED_METHOD"
            test_case.notes = f"Method {test_case.method} is rejected: only non-destructive safe methods allowed."
            self.state_mgr.save_test_case(test_case)
            return test_case, None

        # 4. Construct Baseline A: Authorized Owner Accessing Target Resource
        baseline_owner_resp: Optional[ControlledResponse] = None
        if test_case.source_principal and test_case.source_principal.principal_id != "ANONYMOUS":
            owner_headers = self.get_principal_headers(test_case.source_principal.principal_id)
            owner_url = self._substitute_url_identifier(
                endpoint_url=test_case.endpoint,
                param_location=test_case.resource.param_location,
                old_id=test_case.resource.resource_id,
                new_id=test_case.resource.resource_id,
            )
            req_owner = ControlledRequest(
                method=test_case.method,
                url=owner_url,
                headers=owner_headers,
            )
            baseline_owner_resp = self.validation_engine.send_request(req_owner)

        # 5. Construct Baseline B: Testing Principal Accessing Nonexistent Resource
        nonexistent_id = self._generate_nonexistent_identifier(test_case.resource.identifier_type)
        invalid_url = self._substitute_url_identifier(
            endpoint_url=test_case.endpoint,
            param_location=test_case.resource.param_location,
            old_id=test_case.resource.resource_id,
            new_id=nonexistent_id,
        )
        test_headers = self.get_principal_headers(test_case.testing_principal.principal_id)
        req_invalid = ControlledRequest(
            method=test_case.method,
            url=invalid_url,
            headers=test_headers,
        )
        baseline_invalid_resp = self.validation_engine.send_request(req_invalid)

        # 6. Construct Testing Probe: Testing Principal Accessing Target Resource
        target_url = self._substitute_url_identifier(
            endpoint_url=test_case.endpoint,
            param_location=test_case.resource.param_location,
            old_id=test_case.resource.resource_id,
            new_id=test_case.substitute_identifier or test_case.resource.resource_id,
        )
        req_probe = ControlledRequest(
            method=test_case.method,
            url=target_url,
            headers=test_headers,
        )
        test_probe_resp = self.validation_engine.send_request(req_probe)

        # 7. Access Control Comparison & False-Positive Elimination
        expected_policy = ExpectedAccessPolicy.infer_default(
            principal=test_case.testing_principal,
            resource=test_case.resource,
            operation="READ",
        )
        # If test case specified an explicit expected decision, use it
        if test_case.expected_decision:
            expected_policy.expected_decision = test_case.expected_decision

        comparison = AccessControlComparator.compare(
            test_response=test_probe_resp,
            expected_policy=expected_policy,
            resource=test_case.resource,
            baseline_owner_response=baseline_owner_resp,
            baseline_invalid_response=baseline_invalid_resp,
        )
        test_case.comparison_result = comparison

        # 8. Cryptographic Evidence Capture
        evidence = AuthzEvidence(
            test_id=test_case.test_id,
            baseline_owner_status=baseline_owner_resp.status_code if baseline_owner_resp else 0,
            test_principal_status=test_probe_resp.status_code,
            baseline_invalid_status=baseline_invalid_resp.status_code if baseline_invalid_resp else 0,
            evidence_summary=comparison.evidence_summary,
            request_summary={
                "method": test_case.method,
                "url": target_url,
                "testing_principal": test_case.testing_principal.principal_id,
            },
            response_summary={
                "status_code": test_probe_resp.status_code,
                "body_snippet": test_probe_resp.body[:300],
                "signals": comparison.signals,
            },
        )
        test_case.evidence = evidence

        # 9. Finding Generation & Deduplication
        finding: Optional[Finding] = None
        if comparison.is_vulnerable:
            test_case.lifecycle_state = "VERIFIED"
            test_case.confidence = "HIGH"

            # Vulnerability classification
            if test_case.category == AuthorizationCategory.HORIZONTAL:
                vuln_type = "Broken Object Level Authorization (BOLA/IDOR)"
                title = f"Broken Object Level Authorization (IDOR) on {test_case.endpoint}"
                root_cause = "Missing ownership check on object identifier parameter."
            elif test_case.category == AuthorizationCategory.VERTICAL:
                vuln_type = "Privilege Escalation (Vertical Authorization Bypass)"
                title = f"Vertical Privilege Escalation on {test_case.endpoint}"
                root_cause = "Unprivileged user permitted access to administrative endpoint."
            elif test_case.category == AuthorizationCategory.TENANT:
                vuln_type = "Tenant Isolation Failure (Cross-Tenant BOLA)"
                title = f"Tenant Boundary Isolation Bypass on {test_case.endpoint}"
                root_cause = "Missing multi-tenant organization scoping check."
            elif test_case.category == AuthorizationCategory.UNAUTHENTICATED:
                vuln_type = "Improper Access Control (Unauthenticated Resource Access)"
                title = f"Unauthenticated Access to Protected Resource on {test_case.endpoint}"
                root_cause = "Endpoint fails to enforce authentication requirement."
            else:
                vuln_type = "Broken Access Control"
                title = f"Authorization Inconsistency on {test_case.endpoint}"
                root_cause = "Inconsistent access control enforcement across operations."

            finding = Finding(
                title=title,
                summary=comparison.evidence_summary,
                affected_asset=urlparse(test_case.endpoint).netloc or "target.local",
                affected_endpoint=test_case.endpoint,
                vulnerability_type=vuln_type,
                severity=test_case.severity,
                confidence="HIGH",
                lifecycle_state="VALIDATED",
                description=(
                    f"Differential baseline testing revealed an authorization bypass. "
                    f"Testing principal '{test_case.testing_principal.principal_id}' successfully accessed "
                    f"resource '{test_case.resource.resource_id}' owned by '{test_case.resource.owner_principal_id or 'another user'}'. "
                    f"Differential comparison confirmed the response is NOT a soft-404 or generic denial."
                ),
                root_cause=root_cause,
                prerequisites=f"Valid session for testing principal '{test_case.testing_principal.principal_id}'.",
                reproduction_steps=[
                    f"1. Authenticate as principal '{test_case.testing_principal.principal_id}'.",
                    f"2. Send {test_case.method} request to '{target_url}'.",
                    f"3. Observe HTTP {test_probe_resp.status_code} returning valid object data instead of 403/404.",
                ],
                expected_result=f"Access rejected (HTTP 401 or 403 Forbidden).",
                observed_result=f"Access permitted with HTTP {test_probe_resp.status_code} and verified object contents.",
                security_impact="Unauthorized disclosure or manipulation of sensitive user/tenant records.",
                remediation="Enforce server-side authorization checks verifying caller ownership and tenant scope before returning object data.",
                scope_reference=f"Target {test_case.endpoint} in authorized scope.",
            )

            # Deduplication
            existing_findings_list = list(self.state_mgr._read_json().get("findings", {}).values())
            is_dup, _ = FindingDeduplicator.check_duplicate(
                candidate_asset=finding.affected_asset,
                candidate_endpoint=finding.affected_endpoint,
                candidate_vuln=finding.vulnerability_type,
                candidate_root_cause=finding.root_cause,
                existing_findings=existing_findings_list,
            )
            if not is_dup:
                self.state_mgr.save_finding(finding.finding_id, finding.to_dict())
        else:
            test_case.lifecycle_state = "TESTED"
            test_case.confidence = "CONFIRMED_SAFE" if comparison.decision_inferred == AccessDecisionInferred.DENY else "INCONCLUSIVE"

        self.state_mgr.save_test_case(test_case)
        return test_case, finding

    # ---------------- Top-Level Execution Orchestrator ----------------

    def run_evaluation(
        self,
        asset: Optional[str] = None,
        endpoint: Optional[str] = None,
        resource: Optional[str] = None,
        category: Optional[str] = None,
        approve_all: bool = False,
        passive_only: bool = False,
        dry_run: bool = False,
        resume: bool = False,
        max_tests: int = 50,
    ) -> Dict[str, Any]:
        """
        Orchestrates full authorization intelligence analysis workflow.
        """
        # Step 1: Discover or load candidate targets
        discovered = self.discover_candidates_from_state(asset_filter=asset, endpoint_filter=endpoint)
        existing = self.state_mgr.list_resources()
        all_targets_map = {f"{t.method}:{t.endpoint}:{t.resource_id}": t for t in (discovered + existing)}
        targets = list(all_targets_map.values())
        if endpoint:
            targets = [t for t in targets if endpoint in t.endpoint]
        if asset:
            targets = [t for t in targets if asset in t.endpoint]
        if resource:
            targets = [t for t in targets if t.resource_id == resource or t.target_id == resource]

        # Step 2: Generate test cases
        test_cases = self.generate_test_cases(resources=targets, category=category)

        # Apply approval if requested
        if approve_all:
            for tc in test_cases:
                self.approval_gate.approve(tc.test_id, approver="security-researcher-cli")
                tc.approval_status = "APPROVED"
                tc.lifecycle_state = "APPROVED"
                self.state_mgr.save_test_case(tc)

        # If passive-only or dry-run, do not dispatch active probes
        if passive_only or dry_run:
            return {
                "program": os.path.basename(self.program_dir),
                "mode": "dry-run" if dry_run else "passive-only",
                "total_targets": len(targets),
                "total_test_cases": len(test_cases),
                "test_cases": [tc.to_dict() for tc in test_cases[:max_tests]],
                "summary": self.state_mgr.get_summary(),
            }

        # Step 3: Execute approved test cases up to limit
        executed_cases: List[AuthorizationTestCase] = []
        verified_findings: List[Finding] = []

        count = 0
        for tc in test_cases:
            if count >= max_tests:
                break

            # Handle resume mode: skip already verified or tested cases
            if resume and tc.lifecycle_state in ("VERIFIED", "TESTED"):
                continue

            # Only execute if approved or force_approved
            if not tc.is_approved_for_execution() and not approve_all:
                continue

            case_res, finding_res = self.execute_test_case(tc, force_approved=approve_all)
            executed_cases.append(case_res)
            if finding_res:
                verified_findings.append(finding_res)
            count += 1

        return {
            "program": os.path.basename(self.program_dir),
            "mode": "active",
            "total_targets": len(targets),
            "total_test_cases": len(test_cases),
            "executed_cases": len(executed_cases),
            "verified_findings": len(verified_findings),
            "findings": [f.to_dict() for f in verified_findings],
            "summary": self.state_mgr.get_summary(),
        }
