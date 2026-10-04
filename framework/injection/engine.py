"""
Injection Intelligence & Controlled Validation Orchestration Engine (Phase 10).

Orchestrates parameter discovery, test prioritization, human approval gating,
bounded differential execution (SQLi, NoSQLi, SSTI, Command foundation),
multi-signal comparator analysis, evidence recording, and deduplicated findings.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlparse
import uuid

from framework.findings.lifecycle import FindingLifecycle
from framework.findings.schema import Finding
from framework.injection.approval import HumanApprovalGate
from framework.injection.comparator import (
    InjectionComparator,
    InjectionComparisonResult,
)
from framework.injection.model import (
    InjectionCandidate,
    InjectionConfidence,
    InjectionContext,
    InjectionEvidence,
    InjectionType,
)
from framework.injection.payloads import is_destructive_payload
from framework.injection.prioritization import InjectionPrioritizer
from framework.injection.state import InjectionStateManager
from framework.injection.validator import (
    BaseInjectionValidator,
    InjectionValidatorFactory,
)
from framework.scope.engine import ScopeEngine
from framework.state.dedup import FindingDeduplicator
from framework.validation.engine import SecurityValidationEngine
from framework.validation.policy import SecurityTestPolicy
from framework.validation.request import ControlledRequest, ControlledResponse


class InjectionIntelligenceEngine:
    """
    Primary orchestrator for injection parameter intelligence,
    prioritization, differential testing, and finding management.
    """

    def __init__(
        self,
        program_dir: str,
        scope_engine: Optional[ScopeEngine] = None,
        policy: Optional[SecurityTestPolicy] = None,
        validation_engine: Optional[SecurityValidationEngine] = None,
        send_request_hook: Optional[Callable[[ControlledRequest], ControlledResponse]] = None,
        enable_timing: bool = False,
        auto_approve: bool = False,
    ):
        self.program_dir = os.path.abspath(program_dir)
        self.state_mgr = InjectionStateManager(self.program_dir)
        self.policy = policy or SecurityTestPolicy()
        if scope_engine:
            self.scope_engine = scope_engine
        else:
            scope_yaml = os.path.join(self.program_dir, "scope.yaml")
            if os.path.isfile(scope_yaml):
                self.scope_engine = ScopeEngine.from_file(scope_yaml)
            else:
                self.scope_engine = ScopeEngine({
                    "program": {"name": os.path.basename(self.program_dir)},
                    "targets": {
                        "domains": ["lab.local", "*.local", "localhost", "127.0.0.1", "*.example.com", "example.com"],
                        "urls": ["http://lab.local/", "https://lab.local/"],
                    },
                })
        self.validation_engine = validation_engine or SecurityValidationEngine(
            program_dir=self.program_dir,
            scope_engine=self.scope_engine,
            policy=self.policy,
        )
        self.send_request_hook = send_request_hook or self.validation_engine.execute_request
        self.enable_timing = enable_timing
        self.approval_gate = HumanApprovalGate(auto_approve=auto_approve)

    # ---------------- 1. Candidate Discovery & Prioritization ----------------

    def discover_candidates_from_url(
        self,
        endpoint_url: str,
        method: str = "GET",
        application: str = "",
        technologies: Optional[List[str]] = None,
        is_authenticated: bool = False,
    ) -> List[InjectionCandidate]:
        """
        Extracts query parameters from an endpoint URL and constructs
        prioritized injection candidates.
        """
        candidates: List[InjectionCandidate] = []
        parsed = urlparse(endpoint_url)
        app = application or parsed.netloc or "target.local"
        qsl = parse_qsl(parsed.query, keep_blank_values=True)

        for param, val in qsl:
            score, reasons, fam, ctx = InjectionPrioritizer.evaluate(
                parameter_name=param,
                endpoint=endpoint_url,
                parameter_location="QUERY",
                method=method,
                inferred_input_type="INTEGER" if (val.isdigit() if val else False) else "STRING",
                technologies=technologies,
                is_authenticated=is_authenticated,
            )

            cid = f"inj-{uuid.uuid4().hex[:8]}"
            cand = InjectionCandidate(
                candidate_id=cid,
                family=fam,
                application=app,
                endpoint=endpoint_url,
                parameter=param,
                parameter_location="QUERY",
                method=method,
                inferred_input_type="INTEGER" if (val.isdigit() if val else False) else "STRING",
                backend_context=ctx,
                source_intelligence={"original_value": val, "url": endpoint_url},
                confidence=InjectionConfidence.CANDIDATE,
                priority_score=score,
                priority_reasons=reasons,
                lifecycle=FindingLifecycle.CANDIDATE,
            )
            candidates.append(cand)

        # Also evaluate path template if dynamic segment detected
        path_segments = [s for s in parsed.path.split("/") if s]
        for seg in path_segments:
            if seg.isdigit() or (seg.startswith("{") and seg.endswith("}")):
                param_name = seg.strip("{}")
                score, reasons, fam, ctx = InjectionPrioritizer.evaluate(
                    parameter_name=param_name,
                    endpoint=endpoint_url,
                    parameter_location="PATH",
                    method=method,
                    inferred_input_type="INTEGER" if seg.isdigit() else "STRING",
                    technologies=technologies,
                    is_authenticated=is_authenticated,
                )
                cid = f"inj-{uuid.uuid4().hex[:8]}"
                cand = InjectionCandidate(
                    candidate_id=cid,
                    family=fam,
                    application=app,
                    endpoint=endpoint_url,
                    parameter=param_name,
                    parameter_location="PATH",
                    method=method,
                    inferred_input_type="INTEGER" if seg.isdigit() else "STRING",
                    backend_context=ctx,
                    source_intelligence={"segment": seg, "url": endpoint_url},
                    confidence=InjectionConfidence.CANDIDATE,
                    priority_score=score,
                    priority_reasons=reasons,
                    lifecycle=FindingLifecycle.CANDIDATE,
                )
                candidates.append(cand)

        return InjectionPrioritizer.rank_candidates(candidates)

    def import_candidates_from_state(self) -> List[InjectionCandidate]:
        """
        Consumes Phase 3 (webapps.json), Phase 4 (javascript.json), and Phase 5 (api.json)
        state files to extract all endpoints and parameters for prioritization.
        """
        all_candidates: List[InjectionCandidate] = []
        state_dir = os.path.join(self.program_dir, "state")

        # 1. API state (Phase 5)
        api_file = os.path.join(state_dir, "api.json")
        if os.path.exists(api_file):
            try:
                with open(api_file, "r", encoding="utf-8") as f:
                    api_data = json.load(f)
                    for ep in api_data.get("endpoints", {}).values():
                        url = ep.get("url") or ep.get("path")
                        if url and ("http://" in url or "https://" in url):
                            cands = self.discover_candidates_from_url(
                                endpoint_url=url,
                                method=ep.get("method", "GET"),
                            )
                            all_candidates.extend(cands)
            except Exception:
                pass

        # 2. WebApp state (Phase 3)
        web_file = os.path.join(state_dir, "webapps.json")
        if os.path.exists(web_file):
            try:
                with open(web_file, "r", encoding="utf-8") as f:
                    web_data = json.load(f)
                    for app in web_data.get("applications", {}).values():
                        for ep_url in app.get("discovered_endpoints", []):
                            if "?" in ep_url:
                                cands = self.discover_candidates_from_url(endpoint_url=ep_url)
                                all_candidates.extend(cands)
            except Exception:
                pass

        # Deduplicate candidates by fingerprint
        unique_map: Dict[str, InjectionCandidate] = {}
        for c in all_candidates:
            fp = c.compute_fingerprint()
            if fp not in unique_map:
                unique_map[fp] = c

        return InjectionPrioritizer.rank_candidates(list(unique_map.values()))

    # ---------------- 2. Controlled Active Execution ----------------

    def execute_candidate(
        self,
        candidate: InjectionCandidate,
        dry_run: bool = False,
    ) -> Tuple[InjectionComparisonResult, Optional[Finding]]:
        """
        Executes bounded validation for an individual candidate.
        Enforces scope checks, human approval gating, rate limiting, and finding generation.
        """
        # 1. Scope Validation
        if not self.scope_engine.is_in_scope(candidate.endpoint):
            res = InjectionComparisonResult(
                is_candidate_signal=False,
                confidence=InjectionConfidence.CANDIDATE,
                signals=["OUT_OF_SCOPE"],
                reasons=[f"Target endpoint '{candidate.endpoint}' is strictly OUT OF SCOPE"],
                is_false_positive=True,
                false_positive_reason="Out of scope",
            )
            return res, None

        # 2. Method Validation
        if candidate.method not in self.policy.allowed_methods:
            res = InjectionComparisonResult(
                is_candidate_signal=False,
                confidence=InjectionConfidence.CANDIDATE,
                signals=["METHOD_NOT_ALLOWED"],
                reasons=[f"HTTP method '{candidate.method}' prohibited by SecurityTestPolicy"],
                is_false_positive=True,
                false_positive_reason="Disallowed HTTP method",
            )
            return res, None

        # 3. Dry-Run Bypass
        if dry_run:
            res = InjectionComparisonResult(
                is_candidate_signal=True,
                confidence=candidate.confidence,
                signals=["DRY_RUN_PLAN_VALID"],
                reasons=[
                    f"Dry run planned for candidate {candidate.candidate_id}",
                    f"Family: {candidate.family.value.upper()} | Context: {candidate.backend_context.value}",
                    f"Priority Score: {candidate.priority_score} / 100",
                    f"Target: {candidate.method} {candidate.endpoint} (param: {candidate.parameter})",
                ],
            )
            return res, None

        # 4. Human Approval Gating
        if not self.approval_gate.is_candidate_approved(candidate):
            res = InjectionComparisonResult(
                is_candidate_signal=False,
                confidence=InjectionConfidence.CANDIDATE,
                signals=["PENDING_APPROVAL"],
                reasons=[f"Candidate {candidate.candidate_id} requires explicit human approval before live probe dispatch"],
            )
            return res, None

        # 5. Anti-Redundancy & Fingerprint Check
        fp = candidate.compute_fingerprint()
        if self.state_mgr.is_fingerprint_tested(fp):
            res = InjectionComparisonResult(
                is_candidate_signal=False,
                confidence=candidate.confidence,
                signals=["ALREADY_TESTED"],
                reasons=[f"Candidate fingerprint {fp[:12]} was previously tested; skipping redundant probe"],
            )
            return res, None

        # 6. Instantiate Validator & Dispatch Probes
        validator = InjectionValidatorFactory.get_validator(
            family=candidate.family,
            send_request_hook=self.send_request_hook,
            enable_timing=self.enable_timing,
        )

        candidate.lifecycle = FindingLifecycle.TESTING
        comp_result, evidence = validator.validate(candidate)

        # 7. Record Evidence and Update Lifecycle
        finding: Optional[Finding] = None
        if evidence:
            self.state_mgr.record_evidence(evidence)
            candidate.evidence_refs.append(evidence.evidence_id)

        if comp_result.is_candidate_signal and comp_result.confidence in (InjectionConfidence.VALIDATED, InjectionConfidence.OBSERVED):
            candidate.confidence = comp_result.confidence
            candidate.lifecycle = (
                FindingLifecycle.VALIDATED
                if comp_result.confidence == InjectionConfidence.VALIDATED
                else FindingLifecycle.OBSERVED
            )

            # Generate Finding
            finding = self._build_finding(candidate, comp_result, evidence)
            if finding:
                # Deduplication
                existing_findings = self.state_mgr.list_findings()
                is_dup, _ = FindingDeduplicator.check_duplicate(
                    candidate_asset=finding.affected_asset,
                    candidate_endpoint=finding.affected_endpoint,
                    candidate_vuln=finding.vulnerability_type,
                    candidate_root_cause=finding.root_cause,
                    existing_findings=existing_findings,
                )
                if not is_dup:
                    self.state_mgr.record_finding(finding.to_dict())

        elif comp_result.is_false_positive:
            candidate.lifecycle = FindingLifecycle.REJECTED
        else:
            candidate.lifecycle = FindingLifecycle.CANDIDATE

        # Mark tested & persist
        self.state_mgr.record_test_fingerprint(fp, status=candidate.lifecycle.value)
        self.state_mgr.save_candidate(candidate)

        return comp_result, finding

    def _build_finding(
        self,
        candidate: InjectionCandidate,
        comp_result: InjectionComparisonResult,
        evidence: Optional[InjectionEvidence],
    ) -> Optional[Finding]:
        """Constructs a normalized Finding object for verified injection flaws."""
        fam_str = candidate.family.value.upper()
        if candidate.family == InjectionType.SQL:
            vuln_name = "SQL Injection (SQLi)"
            root_cause = "Application interpolates unvalidated parameter directly into SQL query structure."
        elif candidate.family == InjectionType.NOSQL:
            vuln_name = "NoSQL Injection"
            root_cause = "Application accepts unvalidated query operators in document store criteria."
        elif candidate.family == InjectionType.SSTI:
            vuln_name = "Server-Side Template Injection (SSTI)"
            root_cause = "Application evaluates user-controlled input within server template engine."
        elif candidate.family == InjectionType.COMMAND:
            vuln_name = "Command Injection Foundation"
            root_cause = "Parameter interacts with system utility (requires specialized validation)."
        else:
            vuln_name = "Injection Flaw"
            root_cause = "Improper input sanitization before interpreter execution."

        title = f"{vuln_name} on {candidate.endpoint} ({candidate.parameter})"
        summary = "; ".join(comp_result.reasons)

        parsed_ep = urlparse(candidate.endpoint)
        asset_name = parsed_ep.netloc or candidate.application

        severity = "HIGH"
        if candidate.family == InjectionType.SSTI and comp_result.confidence == InjectionConfidence.VALIDATED:
            severity = "CRITICAL"
        elif comp_result.confidence == InjectionConfidence.OBSERVED:
            severity = "MEDIUM"

        finding = Finding(
            title=title,
            summary=summary,
            affected_asset=asset_name,
            affected_endpoint=candidate.endpoint,
            vulnerability_type=vuln_name,
            severity=severity,
            confidence="HIGH" if comp_result.confidence == InjectionConfidence.VALIDATED else "MEDIUM",
            lifecycle_state=candidate.lifecycle,
            description=(
                f"Controlled verification detected injection vulnerability. "
                f"Parameter '{candidate.parameter}' at '{candidate.endpoint}' triggered "
                f"differential responses confirming interpreter execution. "
                f"Signals: {', '.join(comp_result.signals)}. Zero destructive payloads were used."
            ),
            root_cause=root_cause,
            prerequisites="Endpoint accepts user input over HTTP.",
            reproduction_steps=[
                f"1. Target endpoint: {candidate.method} {candidate.endpoint}",
                f"2. Mutate parameter '{candidate.parameter}' with controlled verification probes.",
                f"3. Observe differential response behavior or mathematical evaluation.",
            ],
            expected_result="Input is validated, parameterized, or safely escaped.",
            observed_result=summary,
            security_impact="Unauthorized data disclosure or interpreter manipulation.",
            remediation="Implement parameterized queries, strict schema validation, and context-aware escaping.",
            scope_reference=f"Target {candidate.endpoint} in scope.",
            parameter=candidate.parameter,
        )
        return finding

    # ---------------- 3. Pipeline Execution ----------------

    def run_pipeline(
        self,
        endpoint: Optional[str] = None,
        parameter: Optional[str] = None,
        category: Optional[str] = None,
        min_priority: int = 0,
        passive_only: bool = False,
        dry_run: bool = False,
        resume: bool = True,
        max_tests: int = 50,
    ) -> Dict[str, Any]:
        """
        Executes end-to-end injection testing pipeline.
        """
        candidates: List[InjectionCandidate] = []

        if endpoint:
            cands = self.discover_candidates_from_url(endpoint)
            if parameter:
                cands = [c for c in cands if c.parameter == parameter]
            candidates.extend(cands)
        else:
            candidates = self.import_candidates_from_state()

        # Filter or override by category if specified
        if category and category.lower() != "all":
            target_fam = InjectionType.from_string(category)
            if endpoint:
                for c in candidates:
                    c.family = target_fam
            else:
                candidates = [c for c in candidates if c.family == target_fam]

        # Filter by min_priority
        candidates = [c for c in candidates if c.priority_score >= min_priority]

        # Sort by priority score descending
        candidates = InjectionPrioritizer.rank_candidates(candidates)

        # Save discovered candidates to state
        for c in candidates:
            self.state_mgr.save_candidate(c)

        if passive_only:
            return {
                "mode": "passive-only",
                "total_candidates": len(candidates),
                "candidates": [c.to_dict() for c in candidates],
                "tested": 0,
                "findings": 0,
            }

        # Active or Dry Run execution
        tested_count = 0
        findings_count = 0
        results: List[Dict[str, Any]] = []

        for cand in candidates[:max_tests]:
            if resume and self.state_mgr.is_fingerprint_tested(cand.compute_fingerprint()):
                continue

            comp_res, finding = self.execute_candidate(cand, dry_run=dry_run)
            tested_count += 1
            if finding:
                findings_count += 1

            results.append({
                "candidate_id": cand.candidate_id,
                "endpoint": cand.endpoint,
                "parameter": cand.parameter,
                "priority_score": cand.priority_score,
                "confidence": comp_res.confidence.value,
                "lifecycle": cand.lifecycle.value,
                "signals": comp_res.signals,
                "reasons": comp_res.reasons,
                "has_finding": finding is not None,
            })

        return {
            "mode": "dry-run" if dry_run else "active",
            "total_candidates": len(candidates),
            "tested": tested_count,
            "findings": findings_count,
            "results": results,
            "summary": self.state_mgr.load_state().get("summary", {}),
        }
