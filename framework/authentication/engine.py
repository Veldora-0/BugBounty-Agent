"""
Primary Orchestrator for Authentication, Session & Identity Security Intelligence (Phase 14).

Coordinates authentication surface discovery, identity modeling, hypothesis formulation,
approval gating, safe differential validation, prioritization, and evidence persistence.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple
import uuid

from framework.authentication.discovery import AuthenticationSurfaceDiscoverer
from framework.authentication.evidence import AuthenticationEvidenceManager
from framework.authentication.hypotheses import AuthenticationHypothesisEngine
from framework.authentication.identity import IdentityManager
from framework.authentication.lab import LocalAuthenticationSecurityLab
from framework.authentication.models import (
    AuthenticationFindingCandidate,
    AuthenticationFindingFamily,
    AuthenticationFlow,
    AuthenticationHypothesis,
    AuthenticationState,
    AuthenticationStep,
    HypothesisValidationStatus,
    IdentityProfile,
    SessionProfile,
    TokenMetadata,
)
from framework.authentication.policy import (
    AuthenticationApprovalGate,
    AuthenticationSecurityPolicy,
)
from framework.authentication.prioritization import AuthenticationPrioritizer
from framework.authentication.storage import AuthenticationStateManager
from framework.authentication.validators import (
    AuthenticationFalsePositiveClassifier,
    SafeAuthenticationValidator,
)
from framework.scope.engine import ScopeEngine


class AuthenticationSecurityEngine:
    """Primary orchestrator for Phase 14 authentication and identity intelligence."""

    def __init__(
        self,
        workspace_dir: str,
        scope_engine: Optional[ScopeEngine] = None,
    ) -> None:
        self.workspace_dir = os.path.abspath(workspace_dir)
        self.scope_engine = scope_engine
        self.policy = AuthenticationSecurityPolicy(scope_engine=scope_engine)
        self.identity_mgr = IdentityManager()
        self.storage = AuthenticationStateManager(workspace_dir=self.workspace_dir)

        # In-memory session and finding collections
        self.surfaces: List[AuthenticationStep] = []
        self.identities: List[IdentityProfile] = []
        self.flows: List[AuthenticationFlow] = []
        self.sessions: List[SessionProfile] = []
        self.hypotheses: List[AuthenticationHypothesis] = []
        self.findings: List[AuthenticationFindingCandidate] = []
        self.evidence_records: List[Dict[str, Any]] = []
        self.token_metadata: List[TokenMetadata] = []

    def load_existing_state(self) -> None:
        """Loads previously saved state from disk (supporting --resume)."""
        st = self.storage.load_state()
        self.surfaces = st.get("surfaces", [])
        self.identities = st.get("identities", [])
        self.flows = st.get("flows", [])
        self.sessions = st.get("sessions", [])
        self.hypotheses = st.get("hypotheses", [])
        self.findings = st.get("findings", [])
        self.evidence_records = st.get("evidence", [])
        self.token_metadata = st.get("tokens", [])

    def discover_surfaces(self) -> List[AuthenticationStep]:
        """Discovers authentication endpoints and actions from previous workspace state."""
        new_surfaces = AuthenticationSurfaceDiscoverer.discover_from_workspace(self.workspace_dir)
        # Deduplicate
        existing_endpoints = {s.endpoint for s in self.surfaces}
        for ns in new_surfaces:
            if ns.endpoint not in existing_endpoints:
                self.surfaces.append(ns)
                existing_endpoints.add(ns.endpoint)
        return self.surfaces

    def formulate_hypotheses(self) -> List[AuthenticationHypothesis]:
        """Generates structured authentication hypotheses for all cataloged surfaces."""
        existing_ids = {h.hypothesis_id for h in self.hypotheses}
        for surf in self.surfaces:
            hyps = AuthenticationHypothesisEngine.generate_hypotheses_for_endpoint(
                endpoint=surf.endpoint,
                step=surf,
            )
            for h in hyps:
                if h.hypothesis_id not in existing_ids:
                    self.hypotheses.append(h)
                    existing_ids.add(h.hypothesis_id)
        return self.hypotheses

    def execute_lab_simulation(self) -> Dict[str, Any]:
        """Executes all 21 scenarios in the deterministic local authentication lab."""
        results = LocalAuthenticationSecurityLab.run_all()
        passed = sum(1 for r in results if r["matches_expectation"])
        total = len(results)

        for r in results:
            if r["verdict"] == HypothesisValidationStatus.VALIDATED.value:
                scen = LocalAuthenticationSecurityLab.SCENARIOS[r["scenario_id"]]
                family = scen.get("expected_family") or AuthenticationFindingFamily.AUTHENTICATION_BYPASS
                sev, cvss = AuthenticationPrioritizer.score_finding(family)
                candidate = AuthenticationFindingCandidate(
                    finding_id=f"FIND-AUTH-{uuid.uuid4().hex[:8]}",
                    title=f"Authentication Flaw: {scen['name']}",
                    family=family,
                    severity=sev,
                    confidence="CONFIRMED",
                    endpoint=f"local-lab://{r['scenario_id']}",
                    identity_id="researcher-lab",
                    description=scen["description"],
                    evidence_chain=[{"scenario": r["scenario_id"], "reason": r["reason"]}],
                    cvss_score=cvss,
                    remediation="Remediate authentication state or session invalidation logic.",
                )
                self.findings.append(candidate)

        return {
            "total_scenarios": total,
            "passed_scenarios": passed,
            "success_rate": round(passed / total * 100, 1),
            "findings_generated": len(self.findings),
            "details": results,
        }

    def render_tree(self) -> str:
        """Renders an ASCII tree view of authentication surfaces, hypotheses, and findings."""
        lines = [
            "BugBounty-Agent - Authentication, Session & Identity Intelligence",
            "==================================================================",
            f"Workspace: {self.workspace_dir}",
            f"Surfaces:  {len(self.surfaces)} discovered",
            f"Identities: {len(self.identities)} tracked",
            f"Hypotheses: {len(self.hypotheses)} generated",
            f"Findings:   {len(self.findings)} validated",
            "",
            "[+] AUTHENTICATION SURFACES & FLOWS:",
        ]

        if not self.surfaces:
            lines.append("    (No authentication endpoints discovered)")
        else:
            for s in self.surfaces:
                lines.append(f"    \\-- [{s.method}] {s.endpoint} ({s.flow_type.value})")

        lines.append("")
        lines.append("[+] HYPOTHESES & VALIDATION STATUS:")
        if not self.hypotheses:
            lines.append("    (No active hypotheses)")
        else:
            for h in self.hypotheses:
                lines.append(f"    |-- [{h.validation_status.value}] [{h.impact_hint}] {h.endpoint}")
                lines.append(f"    |   Family: {h.family}")
                lines.append(f"    |   Rationale: {h.rationale}")

        lines.append("")
        lines.append("[+] VALIDATED FINDING CANDIDATES:")
        if not self.findings:
            lines.append("    (No finding candidates validated)")
        else:
            for f in self.findings:
                lines.append(f"    \\-- [{f.severity}] {f.title} (CVSS {f.cvss_score})")
                lines.append(f"        Endpoint: {f.endpoint}")
                lines.append(f"        Family:   {f.family}")
                lines.append(f"        Guidance: {f.remediation}")

        lines.append("==================================================================")
        return "\n".join(lines)

    def persist_state(self) -> None:
        """Atomically saves current intelligence to disk."""
        self.storage.save_state(
            surfaces=self.surfaces,
            identities=self.identities,
            flows=self.flows,
            sessions=self.sessions,
            hypotheses=self.hypotheses,
            findings=self.findings,
            evidence_records=self.evidence_records,
            token_metadata=self.token_metadata,
        )
