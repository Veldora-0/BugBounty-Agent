"""
Infrastructure Intelligence & Configuration Exposure Engine for BugBounty-Agent.

Primary orchestrator for Phase 19:
- Correlates multi-source passive and crawled observations into exposure hypotheses.
- Safely verifies the 8 exposure classes using differential soft-404 testing.
- Bounded response consumption with evidence-sufficiency stopping rules.
- Strictly adheres to ScopeEngine, anti-SSRF, and safe read-only HTTP methods.
- Preserves single-agent / 18-skill catalog invariants.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urlunparse

from framework.common.config import get_program_dir
from framework.common.evidence import sanitize_sensitive_data
from framework.findings.lifecycle import FindingLifecycle
from framework.findings.schema import Finding
from framework.infrastructure.differential import DifferentialSoft404Engine
from framework.infrastructure.exposure import InfrastructureExposureEvaluator
from framework.infrastructure.model import (
    ExposureCandidate,
    ExposureCategory,
    ExposureEvaluationResult,
    ExposureHypothesis,
    generate_candidate_id,
)
from framework.infrastructure.policy import InfrastructureExposurePolicy
from framework.infrastructure.state import InfrastructureStateManager
from framework.scope.engine import ScopeEngine, ScopeStatus
from framework.state.dedup import FindingDeduplicator, generate_test_fingerprint
from framework.state.manager import StateManager
from framework.validation.engine import ScopeViolationError, SecurityValidationEngine
from framework.validation.model import VulnerabilityFamily
from framework.validation.request import ControlledRequest, ControlledResponse


# High-probability paths per exposure category for candidate formulation
EXPOSURE_PATH_TEMPLATES: Dict[ExposureCategory, List[str]] = {
    ExposureCategory.VERSION_CONTROL: [
        "/.git/HEAD",
        "/.git/config",
        "/.svn/wc.db",
    ],
    ExposureCategory.CONFIG_FILE: [
        "/.env",
        "/.env.local",
        "/.env.production",
        "/web.config",
        "/config.json",
    ],
    ExposureCategory.BACKUP_ARCHIVE: [
        "/backup.zip",
        "/backup.tar.gz",
        "/app.zip",
        "/dump.sql",
        "/index.php.bak",
    ],
    ExposureCategory.ADMIN_INTERFACE: [
        "/admin",
        "/admin/",
        "/actuator",
        "/actuator/health",
        "/actuator/info",
        "/prometheus/metrics",
        "/grafana",
        "/solr/admin/info/system",
    ],
    ExposureCategory.DEPLOYMENT_MANIFEST: [
        "/composer.json",
        "/package.json",
        "/Dockerfile",
    ],
    ExposureCategory.SOURCE_MAP: [
        "/static/js/main.js.map",
        "/static/bundle.js.map",
        "/app.js.map",
    ],
    ExposureCategory.DIRECTORY_LISTING: [
        "/uploads/",
        "/static/",
        "/backup/",
        "/files/",
    ],
    ExposureCategory.DEBUG_INTERFACE: [
        "/debug",
        "/error",
        "/_debug",
    ],
}


class InfrastructureIntelligenceEngine:
    """
    Subsystem engine coordinating candidate formulation, baseline acquisition,
    targeted safe probing, and structured finding generation.
    """

    def __init__(
        self,
        program_dir: str,
        scope_engine: Optional[ScopeEngine] = None,
        policy: Optional[InfrastructureExposurePolicy] = None,
        validation_engine: Optional[SecurityValidationEngine] = None,
        passive_only: bool = False,
        dry_run: bool = False,
        require_approval: bool = True,
        lab_mode: bool = False,
    ):
        self.program_dir = os.path.abspath(program_dir)
        self.scope_engine = scope_engine
        self.policy = policy or InfrastructureExposurePolicy()
        self.passive_only = passive_only
        self.dry_run = dry_run
        self.require_approval = require_approval
        self.lab_mode = lab_mode

        # Initialize persistence managers
        self.state_mgr = InfrastructureStateManager(self.program_dir)
        self.main_state_mgr: Optional[StateManager] = None
        try:
            self.main_state_mgr = StateManager(self.program_dir)
        except Exception:
            pass

        # Shared validation engine and request transport
        self.validation_engine = validation_engine or SecurityValidationEngine(
            program_dir=self.program_dir,
            scope_engine=self.scope_engine,
            policy=self.policy,
        )

        # Active evaluator with stopping rules
        self.evaluator = InfrastructureExposureEvaluator(
            send_request_fn=self.validation_engine.send_request,
            max_response_bytes=self.policy.max_response_bytes,
            max_manifest_bytes=self.policy.max_manifest_bytes,
            max_binary_magic_bytes=self.policy.max_binary_magic_bytes,
        )

        # Cache baseline soft-404 responses per origin to minimize network requests
        self._baseline_cache: Dict[str, ControlledResponse] = {}

    def allow_fixture_port(self, port: int) -> None:
        """Registers a local test fixture port on loopback without weakening global policy."""
        if hasattr(self.validation_engine, "allow_fixture_port"):
            self.validation_engine.allow_fixture_port(port)

    # ---------------- Candidate Discovery & Ingestion ----------------

    def discover_candidates_from_state(self) -> List[ExposureCandidate]:
        """
        Ingests prior research state (recon.json, webapps.json, api.json, assets.json)
        and formulates candidate targets for each applicable exposure category.
        """
        discovered: List[ExposureCandidate] = []
        program_id = os.path.basename(self.program_dir)

        # 1. Collect origins/hosts from recon and webapps
        candidate_origins: Set[str] = set()

        if self.main_state_mgr:
            # Check recon.json for observed HTTP hosts
            recon_data = self.main_state_mgr._read_json(self.main_state_mgr.recon_file) if hasattr(self.main_state_mgr, "_read_json") else {}
            if isinstance(recon_data, dict):
                obs_list = recon_data.get("http_observations", [])
                for obs in obs_list:
                    u = obs.get("url")
                    if u:
                        p = urlparse(u)
                        if p.scheme and p.netloc:
                            candidate_origins.add(f"{p.scheme}://{p.netloc}")

            # Check webapps.json for crawled origins and script paths
            webapps_data = self.main_state_mgr._read_json(self.main_state_mgr.webapps_file) if hasattr(self.main_state_mgr, "_read_json") else {}
            if isinstance(webapps_data, dict):
                endpoints = webapps_data.get("endpoints", [])
                for ep in endpoints:
                    u = ep.get("url") if isinstance(ep, dict) else ep
                    if u:
                        p = urlparse(u)
                        if p.scheme and p.netloc:
                            candidate_origins.add(f"{p.scheme}://{p.netloc}")
                            # If endpoint is a JS bundle, formulate source map candidate
                            if p.path.endswith(".js"):
                                map_url = f"{p.scheme}://{p.netloc}{p.path}.map"
                                cid = generate_candidate_id(map_url, ExposureCategory.SOURCE_MAP, program_id)
                                cand = ExposureCandidate(
                                    candidate_id=cid,
                                    application=p.netloc,
                                    endpoint=map_url,
                                    category=ExposureCategory.SOURCE_MAP,
                                    notes=f"Derived from discovered script: {p.path}",
                                )
                                discovered.append(cand)

        # 2. For each discovered origin, formulate exposure candidates across categories
        for origin in sorted(list(candidate_origins)):
            p = urlparse(origin)
            app_host = p.netloc

            for category, paths in EXPOSURE_PATH_TEMPLATES.items():
                if category == ExposureCategory.SOURCE_MAP:
                    continue  # Already formulated from JS scripts above

                for path in paths:
                    target_url = f"{origin}{path}"
                    cid = generate_candidate_id(target_url, category, program_id)
                    cand = ExposureCandidate(
                        candidate_id=cid,
                        application=app_host,
                        endpoint=target_url,
                        category=category,
                        notes=f"Standard candidate heuristic for {category.value}",
                    )
                    discovered.append(cand)

        # Save all discovered candidates to state
        for c in discovered:
            self.state_mgr.save_candidate(c)

        return discovered

    def add_candidate(self, endpoint: str, category: ExposureCategory, application: Optional[str] = None) -> ExposureCandidate:
        """Manually registers an exposure candidate."""
        p = urlparse(endpoint)
        app = application or p.netloc or "target"
        program_id = os.path.basename(self.program_dir)
        cid = generate_candidate_id(endpoint, category, program_id)
        cand = ExposureCandidate(
            candidate_id=cid,
            application=app,
            endpoint=endpoint,
            category=category,
            notes="Manually registered candidate",
        )
        self.state_mgr.save_candidate(cand)
        return cand

    # ---------------- Hypothesis Formulation ----------------

    def formulate_hypotheses(self) -> List[ExposureHypothesis]:
        """
        Creates structured exposure hypotheses for all candidates in state.
        """
        state = self.state_mgr.load_state()
        candidates = state.get("candidates", [])
        hypotheses: List[ExposureHypothesis] = []

        for c_dict in candidates:
            cand = ExposureCandidate.from_dict(c_dict)
            hid = f"HYP-{cand.candidate_id}"
            cat_name = cand.category.value

            rationale = f"Heuristic check for unauthenticated access to {cat_name} at {cand.endpoint}"
            expected_signals = [f"HTTP 200 with {cat_name} structural signature distinct from soft-404"]

            hyp = ExposureHypothesis(
                hypothesis_id=hid,
                candidate_id=cand.candidate_id,
                application=cand.application,
                endpoint=cand.endpoint,
                category=cand.category,
                rationale=rationale,
                expected_signals=expected_signals,
                severity_hint="MEDIUM",
            )
            self.state_mgr.save_hypothesis(hyp)
            hypotheses.append(hyp)

        return hypotheses

    # ---------------- Baseline Acquisition ----------------

    def _get_baseline_response(self, target_url: str) -> Optional[ControlledResponse]:
        """
        Retrieves or acquires the baseline soft-404 response for the target origin or path prefix.
        """
        parsed = urlparse(target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        path = parsed.path or "/"
        app_prefix = ""
        known_segments = [
            "/.git", "/.svn", "/.env", "/web.config", "/config.json",
            "/backup", "/app.zip", "/dump.sql", "/index.php", "/composer.json",
            "/package.json", "/Dockerfile", "/uploads", "/static", "/actuator",
            "/admin", "/prometheus", "/grafana", "/solr", "/debug", "/error",
        ]
        for seg in known_segments:
            idx = path.lower().find(seg)
            if idx > 0:
                app_prefix = path[:idx]
                break

        cache_key = f"{origin}{app_prefix}"
        if cache_key in self._baseline_cache:
            return self._baseline_cache[cache_key]

        baseline_seed = hashlib.sha256(cache_key.lower().encode("utf-8")).hexdigest()[:10]
        baseline_path = f"{app_prefix}/__bb_differential_baseline_{baseline_seed}__"
        baseline_url = f"{origin}{baseline_path}"

        req = ControlledRequest(
            method="GET",
            url=baseline_url,
            headers={
                "User-Agent": "BugBounty-Agent/Infrastructure-Intelligence (Baseline Verification)",
                "Accept": "*/*",
            },
        )

        try:
            resp = self.validation_engine.send_request(req)
            self._baseline_cache[cache_key] = resp
            return resp
        except Exception:
            return None

    # ---------------- Validation Pipeline ----------------

    def validate_candidate(
        self,
        candidate: ExposureCandidate,
        auto_approve: bool = False,
    ) -> Tuple[ExposureEvaluationResult, Optional[Finding]]:
        """
        Validates an individual candidate subject to scope, approval, and policy gates.
        """
        # Scope fail-closed preflight check: MUST execute before network dispatch
        if self.scope_engine:
            scope_decision = self.scope_engine.check(candidate.endpoint)
            if scope_decision.status != ScopeStatus.IN_SCOPE:
                res = ExposureEvaluationResult(
                    is_exposed=False,
                    confidence="CONFIRMED",
                    lifecycle_state=FindingLifecycle.REJECTED,
                    severity="INFORMATIONAL",
                    reasons=[f"Scope policy violation: {candidate.endpoint} is {scope_decision.status.value}"],
                )
                candidate.lifecycle_state = FindingLifecycle.REJECTED
                candidate.notes = f"Rejected: out of scope ({scope_decision.reason})"
                self.state_mgr.save_candidate(candidate)
                return res, None

        # Approval gate
        if self.require_approval and not auto_approve and candidate.approval_status != "APPROVED":
            candidate.lifecycle_state = FindingLifecycle.CANDIDATE
            candidate.notes = "Awaiting operator approval before active probe dispatch"
            self.state_mgr.save_candidate(candidate)
            return ExposureEvaluationResult(
                is_exposed=False,
                confidence="LOW",
                lifecycle_state=FindingLifecycle.CANDIDATE,
                severity="INFORMATIONAL",
                reasons=["Operator approval required"],
            ), None

        # Passive-only mode check
        if self.passive_only:
            candidate.notes = "Skipped active validation: passive-only mode enabled"
            self.state_mgr.save_candidate(candidate)
            return ExposureEvaluationResult(
                is_exposed=False,
                confidence="LOW",
                lifecycle_state=FindingLifecycle.CANDIDATE,
                severity="INFORMATIONAL",
                reasons=["Passive-only mode enabled: active probe skipped"],
            ), None

        # Dry-run mode check
        if self.dry_run:
            candidate.notes = "Dry-run mode: probe planned but not dispatched"
            self.state_mgr.save_candidate(candidate)
            return ExposureEvaluationResult(
                is_exposed=False,
                confidence="LOW",
                lifecycle_state=FindingLifecycle.CANDIDATE,
                severity="INFORMATIONAL",
                reasons=["Dry-run mode: zero requests dispatched"],
            ), None

        # Deduplication check: skip if fingerprint already evaluated
        test_fp = candidate.compute_fingerprint()
        if self.state_mgr.is_fingerprint_tested(test_fp):
            candidate.notes = "Skipped: test fingerprint already evaluated"
            self.state_mgr.save_candidate(candidate)
            return ExposureEvaluationResult(
                is_exposed=False,
                confidence="HIGH",
                lifecycle_state=FindingLifecycle.DUPLICATE,
                severity="INFORMATIONAL",
                reasons=["Duplicate test fingerprint"],
            ), None

        # Acquire differential baseline
        baseline_resp = self._get_baseline_response(candidate.endpoint)

        # Execute safe active probe and evaluate
        eval_result = self.evaluator.evaluate_candidate(candidate, baseline_response=baseline_resp)

        # Update candidate state
        candidate.lifecycle_state = eval_result.lifecycle_state
        candidate.confidence = eval_result.confidence
        candidate.evidence_fingerprint = eval_result.evidence_fingerprint or None
        candidate.notes = "; ".join(eval_result.reasons)
        self.state_mgr.save_candidate(candidate)
        self.state_mgr.record_tested_fingerprint(test_fp)

        # Generate Finding if exposed or login observation
        finding: Optional[Finding] = None
        if eval_result.is_exposed:
            finding_state = FindingLifecycle.SIMULATED if self.lab_mode else eval_result.lifecycle_state
            confidence = "HIGH" if not self.lab_mode else "CONFIRMED"

            title = f"Exposed {candidate.category.value.replace('_', ' ').title()}: {candidate.endpoint}"
            summary = (
                f"Safe non-destructive probe confirmed unauthenticated exposure of "
                f"{candidate.category.value} on {candidate.application}."
            )
            if eval_result.lifecycle_state == FindingLifecycle.OBSERVATION:
                title = f"Administrative Login Interface Observed: {candidate.endpoint}"
                summary = f"Administrative login portal observed on {candidate.application}."

            finding_id = f"FND-{candidate.candidate_id}"

            evidence_content = (
                eval_result.sanitized_excerpt
                or eval_result.evidence.get("sanitized_excerpt")
                or "Exposed infrastructure response verified."
            )
            evidence_item = {
                "type": "http_response",
                "content": evidence_content,
                "metadata": {
                    "status_code": eval_result.evidence.get("status_code", 200),
                    "content_type": eval_result.evidence.get("content_type", ""),
                    "category": candidate.category.value,
                    "sha256": eval_result.evidence_fingerprint or hashlib.sha256(evidence_content.encode("utf-8")).hexdigest(),
                    "details": eval_result.evidence.get("metadata", {}),
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            finding = Finding(
                title=title,
                summary=summary,
                affected_asset=candidate.application,
                affected_endpoint=candidate.endpoint,
                vulnerability_type=VulnerabilityFamily.INFRASTRUCTURE_EXPOSURE.value,
                severity=eval_result.severity,
                description=f"Automated safe intelligence probe identified exposure under category {candidate.category.value}.",
                root_cause="Unintentional public exposure of sensitive files or administrative surfaces.",
                prerequisites="Network access to target endpoint.",
                reproduction_steps=[
                    f"Send HTTP GET request to '{candidate.endpoint}'.",
                    f"Observe status {eval_result.evidence.get('status_code', 200)} and structural signature.",
                ],
                expected_result="Access should be restricted or return HTTP 404.",
                observed_result=f"Endpoint returned active exposure: {'; '.join(eval_result.reasons)}",
                security_impact=f"Exposure of {candidate.category.value} may assist adversary reconnaissance or disclose deployment configuration.",
                remediation="Restrict web server access via access controls, remove backup/config files from web root, or disable public diagnostic handlers.",
                scope_reference="ScopeEngine authorized target.",
                confidence=confidence,
                finding_id=finding_id,
                lifecycle_state=finding_state,
                evidence=[evidence_item],
                validation_notes=f"Differential structural signature verified distinct from baseline for {candidate.category.value}.",
                provenance={
                    "engine": "InfrastructureIntelligenceEngine",
                    "category": candidate.category.value,
                    "evidence_fingerprint": eval_result.evidence_fingerprint,
                    "validation_notes": f"Differential structural signature verified distinct from baseline for {candidate.category.value}.",
                },
            )

            # Persist finding into infrastructure state
            self.state_mgr.record_finding(finding.to_dict())

            # Save to main program findings.json if available
            if self.main_state_mgr and hasattr(self.main_state_mgr, "save_finding"):
                try:
                    self.main_state_mgr.save_finding(finding)
                except Exception:
                    pass

        return eval_result, finding

    def run_all(self, auto_approve: bool = False) -> Dict[str, Any]:
        """
        Executes complete discovery and validation pipeline across all candidates.
        """
        # Discover candidates if state is empty
        candidates = self.discover_candidates_from_state()
        if not candidates:
            state = self.state_mgr.load_state()
            candidates = [ExposureCandidate.from_dict(c) for c in state.get("candidates", [])]

        self.formulate_hypotheses()

        validated_findings: List[Finding] = []
        observations: List[Finding] = []

        for cand in candidates:
            res, finding = self.validate_candidate(cand, auto_approve=auto_approve)
            if finding:
                if finding.lifecycle_state in (FindingLifecycle.VALIDATED, FindingLifecycle.SIMULATED):
                    validated_findings.append(finding)
                elif finding.lifecycle_state == FindingLifecycle.OBSERVATION:
                    observations.append(finding)

        summary = self.state_mgr.get_summary()
        return {
            "total_candidates": len(candidates),
            "validated_findings_count": len(validated_findings),
            "observations_count": len(observations),
            "summary": summary,
        }
