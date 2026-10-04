"""
SSRF & Out-of-Band Interaction Orchestration Engine (Phase 9).

Orchestrates passive candidate discovery, sink intelligence, canary issuance,
human approval gating, controlled baseline dispatch, and OOB correlation.
Converts verified server-side callbacks into deduplicated, non-exaggerated findings.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

from framework.findings.lifecycle import FindingLifecycle
from framework.findings.schema import Finding
from framework.scope.engine import ScopeEngine
from framework.ssrf.approval import HumanApprovalGate
from framework.ssrf.canary import CanaryManager
from framework.ssrf.comparator import SsrfComparator, SsrfComparisonResult
from framework.ssrf.intelligence import SsrfIntelligenceAnalyzer
from framework.ssrf.model import (
    OobInteractionType,
    SsrfCandidate,
    SsrfCategory,
    SsrfConfidence,
    SsrfEvidence,
)
from framework.ssrf.provider import (
    MockOobProvider,
    OobProvider,
    OobProviderFactory,
    OobProviderStatus,
)
from framework.ssrf.state import SsrfStateManager
from framework.state.dedup import FindingDeduplicator
from framework.validation.engine import SecurityValidationEngine
from framework.validation.policy import SecurityTestPolicy
from framework.validation.request import ControlledRequest, ControlledResponse


class SsrfIntelligenceEngine:
    """
    Primary orchestrator for Server-Side Request Forgery intelligence,
    out-of-band canary correlation, and baseline verification.
    """

    def __init__(
        self,
        program_dir: str,
        scope_engine: Optional[ScopeEngine] = None,
        policy: Optional[SecurityTestPolicy] = None,
        validation_engine: Optional[SecurityValidationEngine] = None,
        send_request_hook: Optional[Callable[[ControlledRequest], ControlledResponse]] = None,
        oob_provider: Optional[OobProvider] = None,
        correlation_window_seconds: float = 60.0,
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
        self.state_mgr = SsrfStateManager(self.program_dir)
        self.approval_gate = HumanApprovalGate(self.state_mgr)

        program_name = os.path.basename(self.program_dir)
        self.oob_provider = oob_provider or OobProviderFactory.get_provider(provider_name="auto")
        self.canary_mgr = CanaryManager(
            provider=self.oob_provider,
            program_id=program_name,
            correlation_window_seconds=correlation_window_seconds,
        )

        # Scanner / client host IPs to exclude from server-side callback correlation
        self.excluded_source_ips: Set[str] = {"127.0.0.1", "::1", "192.168.1.50"}

    # ---------------- Passive Discovery Pipeline ----------------

    def discover_candidates(
        self,
        asset_filter: Optional[str] = None,
        endpoint_filter: Optional[str] = None,
        param_filter: Optional[str] = None,
    ) -> List[SsrfCandidate]:
        """
        Discovers SSRF candidates from Phase 3 (WebApps), Phase 4 (JS),
        and Phase 5 (API) states. Merges with existing recorded candidates.
        """
        discovered = SsrfIntelligenceAnalyzer.discover_from_program_state(
            program_dir=self.program_dir,
            asset_filter=asset_filter,
            endpoint_filter=endpoint_filter,
        )

        existing = self.state_mgr.list_candidates()
        all_map: Dict[str, SsrfCandidate] = {}

        for c in existing:
            all_map[c.compute_fingerprint()] = c

        for c in discovered:
            fp = c.compute_fingerprint()
            if fp not in all_map:
                all_map[fp] = c
                self.state_mgr.save_candidate(c)

        candidates = list(all_map.values())
        if endpoint_filter:
            candidates = [c for c in candidates if endpoint_filter in c.endpoint]
        if asset_filter:
            candidates = [c for c in candidates if asset_filter in c.endpoint or asset_filter in c.application]
        if param_filter:
            candidates = [c for c in candidates if c.parameter.lower() == param_filter.lower()]

        return candidates

    # ---------------- Controlled Request Builders ----------------

    def _build_mutated_request(
        self,
        candidate: SsrfCandidate,
        injected_value: str,
    ) -> ControlledRequest:
        """Constructs a request with parameter mutated to the canary or baseline value."""
        endpoint = candidate.endpoint
        param = candidate.parameter
        loc = candidate.param_location

        if loc == "PATH":
            # Direct path parameter substitution
            mutated_path = endpoint
            for tpl in (f"{{{param}}}", f":{param}", f"<{param}>"):
                if tpl in mutated_path:
                    mutated_path = mutated_path.replace(tpl, quote(injected_value, safe=""))
            return ControlledRequest(
                url=mutated_path,
                method=candidate.method,
                headers={"User-Agent": "BugBounty-Agent/1.0 (SSRF-Intelligence)"},
            )

        # Default QUERY parameter mutation
        parsed = urlparse(endpoint)
        qsl = parse_qsl(parsed.query, keep_blank_values=True)
        new_qsl = []
        replaced = False
        for k, v in qsl:
            if k == param:
                new_qsl.append((k, injected_value))
                replaced = True
            else:
                new_qsl.append((k, v))
        if not replaced:
            new_qsl.append((param, injected_value))

        new_query = urlencode(new_qsl)
        mutated_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        ))

        return ControlledRequest(
            url=mutated_url,
            method=candidate.method,
            headers={"User-Agent": "BugBounty-Agent/1.0 (SSRF-Intelligence)"},
        )

    # ---------------- Active Controlled Validation ----------------

    def validate_candidate(
        self,
        candidate: SsrfCandidate,
        force_approved: bool = False,
        poll_wait_seconds: float = 3.0,
    ) -> Tuple[SsrfCandidate, Optional[Finding]]:
        """
        Executes controlled, non-destructive SSRF verification for a candidate:
        1. Human approval check
        2. Scope boundary check (Agent-side safety)
        3. Policy check (Safe methods only: GET, HEAD, OPTIONS)
        4. Canary issuance
        5. Benign Baseline capture
        6. Canary Probe dispatch
        7. OOB Provider polling & correlation
        8. Differential analysis & false-positive elimination
        9. Finding deduplication
        """
        # 1. Human Approval Gate
        if not candidate.is_approved_for_execution() and not force_approved:
            candidate.notes = "Execution halted: awaiting explicit human approval gate."
            self.state_mgr.save_candidate(candidate)
            return candidate, None

        # 2. Scope Validation (Agent Network Safety)
        if self.validation_engine:
            try:
                self.validation_engine.check_request_scope(candidate.endpoint)
            except Exception as e:
                candidate.lifecycle_state = "OUT_OF_SCOPE"
                candidate.notes = f"Target endpoint {candidate.endpoint} is out of authorized scope: {e}"
                self.state_mgr.save_candidate(candidate)
                return candidate, None

        # 3. Policy Verification (Safe HTTP methods only)
        if candidate.method not in ("GET", "HEAD", "OPTIONS"):
            candidate.lifecycle_state = "REJECTED_METHOD"
            candidate.notes = f"Method {candidate.method} rejected: only non-destructive safe methods permitted."
            self.state_mgr.save_candidate(candidate)
            return candidate, None

        # 4. Canary Issuance
        canary_token, canary_url = self.canary_mgr.issue_canary(candidate.candidate_id)
        candidate.callback_token = canary_token

        # 5. Baseline Capture (Normal input / Benign control)
        baseline_resp: Optional[ControlledResponse] = None
        try:
            baseline_req = self._build_mutated_request(candidate, injected_value="https://example.com/favicon.ico")
            baseline_resp = self.validation_engine.send_request(baseline_req)
        except Exception:
            pass

        # 6. Canary Probe Dispatch
        probe_req = self._build_mutated_request(candidate, injected_value=canary_url)
        test_resp = self.validation_engine.send_request(probe_req)

        # 7. OOB Interaction Polling & Correlation
        time.sleep(poll_wait_seconds)
        interactions = self.canary_mgr.correlate_interactions(
            canary_token=canary_token,
            timeout=poll_wait_seconds,
            exclude_source_ips=self.excluded_source_ips,
        )

        # Record interactions in state
        for inter in interactions:
            self.state_mgr.save_interaction(inter)

        # 8. Comparison & False-Positive Elimination
        comp = SsrfComparator.evaluate(
            candidate=candidate,
            canary_token=canary_token,
            test_response=test_resp,
            baseline_response=baseline_resp,
            interactions=interactions,
            provider_name=self.oob_provider.name(),
        )

        candidate.evidence = comp.evidence
        candidate.notes = comp.summary

        # 9. Finding Generation & Deduplication
        finding: Optional[Finding] = None
        if comp.is_confirmed:
            if comp.interaction_type == OobInteractionType.DNS_ONLY:
                candidate.lifecycle_state = "OBSERVED"
                candidate.confidence = SsrfConfidence.OBSERVED
                vuln_type = "Server-Side DNS Resolution (Blind SSRF Primitive)"
                title = f"Server-Side DNS Resolution on {candidate.endpoint} ({candidate.parameter})"
                root_cause = "Application resolves remote hostnames supplied in user-controlled parameter."
            else:
                candidate.lifecycle_state = "VALIDATED"
                candidate.confidence = SsrfConfidence.VALIDATED
                vuln_type = "Server-Side Request Forgery (SSRF)"
                title = f"Blind Server-Side Request Forgery on {candidate.endpoint} ({candidate.parameter})"
                root_cause = "Application initiates outbound server-side HTTP connections to user-controlled URLs."

            finding = Finding(
                title=title,
                summary=comp.summary,
                affected_asset=urlparse(candidate.endpoint).netloc or candidate.application,
                affected_endpoint=candidate.endpoint,
                vulnerability_type=vuln_type,
                severity=candidate.severity,
                confidence="HIGH" if comp.confidence == SsrfConfidence.VALIDATED else "MEDIUM",
                lifecycle_state=FindingLifecycle.VALIDATED if comp.confidence == SsrfConfidence.VALIDATED else FindingLifecycle.OBSERVED,
                description=(
                    f"Controlled out-of-band verification confirmed server-side network interaction. "
                    f"Injected canary URL '{canary_url}' into parameter '{candidate.parameter}' at '{candidate.endpoint}'. "
                    f"The OOB callback provider '{self.oob_provider.name()}' recorded a matching {comp.interaction_type.value} interaction. "
                    f"No internal network probing or cloud metadata was accessed."
                ),
                root_cause=root_cause,
                prerequisites="Endpoint accessible over HTTP/HTTPS with URL parameter acceptance.",
                reproduction_steps=[
                    f"1. Generate a unique canary identifier.",
                    f"2. Send {candidate.method} request to '{candidate.endpoint}' with parameter '{candidate.parameter}' set to canary URL.",
                    f"3. Observe asynchronous {comp.interaction_type.value} callback on OOB provider.",
                ],
                expected_result="Endpoint validates and rejects arbitrary remote destination URLs.",
                observed_result=f"Server initiated {comp.interaction_type.value} interaction to external canary.",
                security_impact="Unauthorized outbound network requests may allow internal reconnaissance or protocol abuse.",
                remediation="Implement strict domain whitelisting, disable HTTP redirects to external hosts, and enforce egress firewall rules.",
                scope_reference=f"Target {candidate.endpoint} in authorized scope.",
                parameter=candidate.parameter,
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
            candidate.lifecycle_state = "TESTED"
            candidate.confidence = SsrfConfidence.CANDIDATE

        self.state_mgr.save_candidate(candidate)
        return candidate, finding

    # ---------------- Top-Level Workflow Pipeline ----------------

    def run_evaluation(
        self,
        asset: Optional[str] = None,
        endpoint: Optional[str] = None,
        parameter: Optional[str] = None,
        category: Optional[str] = None,
        approve_all: bool = False,
        passive_only: bool = False,
        dry_run: bool = False,
        resume: bool = False,
        max_tests: int = 30,
        poll_wait_seconds: float = 3.0,
    ) -> Dict[str, Any]:
        """
        Orchestrates complete SSRF intelligence workflow.
        """
        candidates = self.discover_candidates(
            asset_filter=asset,
            endpoint_filter=endpoint,
            param_filter=parameter,
        )

        if category:
            candidates = [c for c in candidates if c.category.value == category.lower()]

        # Apply approval if requested
        if approve_all:
            for c in candidates:
                self.approval_gate.approve(c.candidate_id, approver="security-researcher-cli")
                c.approval_status = "APPROVED"
                c.lifecycle_state = "APPROVED"
                self.state_mgr.save_candidate(c)

        if passive_only or dry_run:
            return {
                "program": os.path.basename(self.program_dir),
                "mode": "dry-run" if dry_run else "passive-only",
                "provider": self.oob_provider.name(),
                "provider_status": self.oob_provider.registration_status().value,
                "total_candidates": len(candidates),
                "candidates": [c.to_dict() for c in candidates[:max_tests]],
                "summary": self.state_mgr.get_summary(),
            }

        # Active evaluation
        executed: List[SsrfCandidate] = []
        verified_findings: List[Finding] = []

        count = 0
        for c in candidates:
            if count >= max_tests:
                break

            if resume and c.lifecycle_state in ("VALIDATED", "OBSERVED", "TESTED"):
                continue

            if not c.is_approved_for_execution() and not approve_all:
                continue

            cand_res, finding_res = self.validate_candidate(
                candidate=c,
                force_approved=approve_all,
                poll_wait_seconds=poll_wait_seconds,
            )
            executed.append(cand_res)
            if finding_res:
                verified_findings.append(finding_res)
            count += 1

        return {
            "program": os.path.basename(self.program_dir),
            "mode": "active",
            "provider": self.oob_provider.name(),
            "provider_status": self.oob_provider.registration_status().value,
            "total_candidates": len(candidates),
            "executed_tests": len(executed),
            "verified_findings": len(verified_findings),
            "findings": [f.to_dict() for f in verified_findings],
            "summary": self.state_mgr.get_summary(),
        }
