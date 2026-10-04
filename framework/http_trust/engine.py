"""
HTTP / Header Trust & Protocol Security Orchestration Engine (Phase 11).

Orchestrates candidate discovery, semantic prioritization, human approval gating,
controlled validator execution (Host, Forwarded, Scheme, CORS, HPP, Cache),
differential comparator analysis, evidence recording, and deduplicated findings.
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
from framework.http_trust.approval import HumanApprovalGate
from framework.http_trust.comparator import (
    HttpTrustComparator,
    HttpTrustComparisonResult,
)
from framework.http_trust.model import (
    HeaderTrustCandidate,
    HeaderTrustEvidence,
    HttpTrustCategory,
    HttpTrustConfidence,
    HttpTrustTestCase,
)
from framework.http_trust.prioritization import HttpTrustPrioritizer
from framework.http_trust.state import HttpTrustStateManager
from framework.http_trust.validator import (
    BaseHttpTrustValidator,
    HttpTrustValidatorFactory,
)
from framework.scope.engine import ScopeEngine
from framework.state.dedup import FindingDeduplicator
from framework.validation.engine import SecurityValidationEngine
from framework.validation.policy import SecurityTestPolicy
from framework.validation.request import ControlledRequest, ControlledResponse


class HttpTrustEngine:
    """
    Primary orchestrator for HTTP / Header trust intelligence,
    prioritization, differential testing, and finding management.
    """

    def __init__(
        self,
        program_dir: str,
        scope_engine: Optional[ScopeEngine] = None,
        policy: Optional[SecurityTestPolicy] = None,
        validation_engine: Optional[SecurityValidationEngine] = None,
        send_request_hook: Optional[Callable[[ControlledRequest], ControlledResponse]] = None,
        auto_approve: bool = False,
        lab_mode: bool = False,
    ):
        self.program_dir = os.path.abspath(program_dir)
        self.state_mgr = HttpTrustStateManager(self.program_dir)
        self.policy = policy or SecurityTestPolicy()
        self.lab_mode = lab_mode
        self.program_name = os.path.basename(self.program_dir)

        if scope_engine:
            self.scope_engine = scope_engine
        else:
            scope_yaml = os.path.join(self.program_dir, "scope.yaml")
            if os.path.isfile(scope_yaml):
                self.scope_engine = ScopeEngine.from_file(scope_yaml)
            else:
                self.scope_engine = ScopeEngine({
                    "program": {"name": self.program_name},
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

        self.approval_gate = HumanApprovalGate(auto_approve=auto_approve)
        self.deduplicator = FindingDeduplicator()

        self._send_request_hook = send_request_hook

    def send_request(self, req: ControlledRequest) -> ControlledResponse:
        """Sends controlled request via hooked transport or validation engine."""
        if self._send_request_hook:
            return self._send_request_hook(req)
        return self.validation_engine.send_request(req)

    def discover_candidates(self) -> List[HeaderTrustCandidate]:
        """
        Passively extracts candidate endpoints and headers from webapps.json,
        api.json, recon.json, or current program state.
        """
        candidates: List[HeaderTrustCandidate] = []
        state_dir = os.path.join(self.program_dir, "state")
        endpoints_seen: set = set()

        # 1. Read webapps.json
        webapps_file = os.path.join(state_dir, "webapps.json")
        if os.path.isfile(webapps_file):
            try:
                with open(webapps_file, "r", encoding="utf-8") as f:
                    wdata = json.load(f)
                    for ep in wdata.get("endpoints", []):
                        url = ep.get("url") or ep.get("path")
                        if url and url not in endpoints_seen:
                            endpoints_seen.add(url)
                            self._add_endpoint_candidates(url, candidates)
            except Exception:
                pass

        # 2. Read api.json
        api_file = os.path.join(state_dir, "api.json")
        if os.path.isfile(api_file):
            try:
                with open(api_file, "r", encoding="utf-8") as f:
                    adata = json.load(f)
                    for ep in adata.get("endpoints", []):
                        url = ep.get("url")
                        if url and url not in endpoints_seen:
                            endpoints_seen.add(url)
                            self._add_endpoint_candidates(url, candidates)
            except Exception:
                pass

        # Persist discovered candidates
        for c in candidates:
            if not self.state_mgr.get_candidate(c.candidate_id):
                self.state_mgr.save_candidate(c)

        return candidates

    def _add_endpoint_candidates(self, url: str, candidates: List[HeaderTrustCandidate]) -> None:
        """Helper to create candidate variations for an endpoint."""
        parsed = urlparse(url)
        app = parsed.netloc or "unknown"

        # Host Injection Candidate
        h_score, h_reasons, h_sev, _ = HttpTrustPrioritizer.evaluate("Host", url, HttpTrustCategory.HOST_INJECTION)
        cid_host = f"htc-host-{uuid.uuid4().hex[:8]}"
        candidates.append(
            HeaderTrustCandidate(
                candidate_id=cid_host,
                header_name="Host",
                endpoint=url,
                application=app,
                category=HttpTrustCategory.HOST_INJECTION,
                priority=h_score,
                severity=h_sev,
                provenance={"reasons": h_reasons},
            )
        )

        # CORS Candidate for API / Auth endpoints
        if "/api" in url.lower() or "/auth" in url.lower():
            c_score, c_reasons, c_sev, _ = HttpTrustPrioritizer.evaluate("Origin", url, HttpTrustCategory.CORS_TRUST)
            cid_cors = f"htc-cors-{uuid.uuid4().hex[:8]}"
            candidates.append(
                HeaderTrustCandidate(
                    candidate_id=cid_cors,
                    header_name="Origin",
                    endpoint=url,
                    application=app,
                    category=HttpTrustCategory.CORS_TRUST,
                    priority=c_score,
                    severity=c_sev,
                    provenance={"reasons": c_reasons},
                )
            )

        # HPP Candidate if query parameters exist
        if parsed.query:
            q_params = [k for k, _ in parse_qsl(parsed.query)]
            for p in q_params[:2]:
                hpp_score, hpp_reasons, hpp_sev, _ = HttpTrustPrioritizer.evaluate(p, url, HttpTrustCategory.HPP)
                cid_hpp = f"htc-hpp-{uuid.uuid4().hex[:8]}"
                candidates.append(
                    HeaderTrustCandidate(
                        candidate_id=cid_hpp,
                        header_name=p,
                        endpoint=url,
                        application=app,
                        category=HttpTrustCategory.HPP,
                        priority=hpp_score,
                        severity=hpp_sev,
                        provenance={"reasons": hpp_reasons},
                    )
                )

    def execute_candidate(
        self,
        candidate: HeaderTrustCandidate,
        dry_run: bool = False,
    ) -> Tuple[Optional[HttpTrustComparisonResult], Optional[HttpTrustTestCase]]:
        """
        Executes bounded, safe HTTP trust validation against a single candidate.
        Enforces scope checks, human approval gating, and test deduplication.
        """
        # 1. Offline Scope Enforcement
        if not self.scope_engine.is_in_scope(candidate.endpoint):
            candidate.lifecycle = FindingLifecycle.REJECTED
            self.state_mgr.save_candidate(candidate)
            return None, None

        # 2. Test Fingerprint check (Deduplication / Resuming)
        fp = candidate.compute_fingerprint()
        if self.state_mgr.is_fingerprint_tested(fp):
            return None, None

        # 3. Human Approval Gate
        if not self.approval_gate.is_candidate_approved(candidate):
            return None, None

        if dry_run:
            return None, None

        # 4. Instantiate Validator
        validator = HttpTrustValidatorFactory.get_validator(
            category=candidate.category,
            send_request_hook=self.send_request,
            policy=self.policy,
            program_name=self.program_name,
            lab_mode=self.lab_mode,
        )

        # 5. Execute Validation
        comp_res, test_case = validator.validate(candidate)

        # 6. Record State & Evidence
        self.state_mgr.record_test_fingerprint(fp, status="TESTED")
        if test_case.evidence:
            self.state_mgr.record_evidence(test_case.evidence)
            candidate.evidence_references.append(test_case.evidence.evidence_id)
        self.state_mgr.record_test_case(test_case)

        # Update candidate state
        candidate.trust_classification = comp_res.trust_classification
        candidate.trust_source = comp_res.trust_source
        candidate.observed_behavior = comp_res.security_effect_summary
        candidate.confidence = comp_res.confidence

        if comp_res.is_false_positive:
            candidate.lifecycle = FindingLifecycle.REJECTED
        elif comp_res.is_validated:
            candidate.lifecycle = FindingLifecycle.VALIDATED
            # Emit verified Finding
            finding_id = f"find-http-{uuid.uuid4().hex[:8]}"
            finding_dict = {
                "id": finding_id,
                "title": f"HTTP Trust Boundary Vulnerability ({candidate.category.value.upper()}) at {candidate.endpoint}",
                "category": f"http_trust_{candidate.category.value}",
                "severity": candidate.severity,
                "endpoint": candidate.endpoint,
                "header": candidate.header_name,
                "signals": comp_res.signals,
                "description": comp_res.security_effect_summary,
                "evidence_id": test_case.evidence.evidence_id if test_case.evidence else None,
                "lifecycle": FindingLifecycle.VALIDATED.value,
                "priority": candidate.priority,
                "remediation": "Do not trust user-supplied Host, Forwarded, or Origin headers without strict validation against a whitelist.",
            }
            self.state_mgr.record_finding(finding_dict)
        elif comp_res.confidence == HttpTrustConfidence.OBSERVED:
            candidate.lifecycle = FindingLifecycle.OBSERVED
        else:
            candidate.lifecycle = FindingLifecycle.CANDIDATE

        self.state_mgr.save_candidate(candidate)
        return comp_res, test_case

    def run_pipeline(
        self,
        endpoint_filter: Optional[str] = None,
        header_filter: Optional[str] = None,
        category_filter: Optional[str] = None,
        min_priority: int = 0,
        passive_only: bool = False,
        dry_run: bool = False,
        resume: bool = True,
        max_tests: int = 50,
    ) -> Dict[str, Any]:
        """Runs candidate discovery, ranking, and controlled execution."""
        candidates = self.state_mgr.list_candidates()
        if not candidates or not resume:
            candidates = self.discover_candidates()

        filtered: List[HeaderTrustCandidate] = []
        for c in candidates:
            if c.priority < min_priority:
                continue
            if endpoint_filter and endpoint_filter.lower() not in c.endpoint.lower():
                continue
            if header_filter and header_filter.lower() != c.header_name.lower():
                continue
            if category_filter and category_filter.lower() not in (c.category.value, "all"):
                continue
            filtered.append(c)

        # Sort by priority descending
        filtered.sort(key=lambda x: x.priority, reverse=True)

        if passive_only:
            return {
                "status": "PASSIVE_ONLY_COMPLETED",
                "candidates_count": len(filtered),
                "candidates": [c.to_dict() for c in filtered],
                "tests_executed": 0,
            }

        executed_count = 0
        results: List[Dict[str, Any]] = []

        for cand in filtered[:max_tests]:
            comp, tc = self.execute_candidate(cand, dry_run=dry_run)
            if tc:
                executed_count += 1
                results.append({
                    "candidate_id": cand.candidate_id,
                    "endpoint": cand.endpoint,
                    "header": cand.header_name,
                    "category": cand.category.value,
                    "result": tc.result,
                    "confidence": tc.confidence.value,
                    "signals": comp.signals if comp else [],
                    "summary": comp.security_effect_summary if comp else "",
                })

        return {
            "status": "PIPELINE_COMPLETED",
            "candidates_evaluated": len(filtered),
            "tests_executed": executed_count,
            "results": results,
            "state_summary": self.state_mgr.load_state().get("summary", {}),
        }
