"""
Phase 21: AuthCorrelationEngine.

Primary orchestrator coordinating discovery, preflight health gating,
revocation verification, pre-MFA auditing, multi-tenant desynchronization,
evidence capture, deduplication, and atomic state persistence.
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional, Tuple

from framework.auth_correlation.cvss import (
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    CIAImpact,
    CVSS31Metrics,
    CVSS31Calculator,
)
from framework.auth_correlation.model import (
    CorrelatedPrincipalContext,
    CorrelatedSessionContext,
    CorrelationHypothesis,
    CorrelationFinding,
    CorrelationLifecycle,
    ProbeStatus,
)
from framework.auth_correlation.preflight import DualControlPreflightValidator
from framework.auth_correlation.revocation import PostRevocationResourceValidator
from framework.auth_correlation.pre_mfa import PreMfaPrivilegeValidator
from framework.auth_correlation.tenant import MultiTenantDesyncValidator
from framework.auth_correlation.state import AuthCorrelationStateManager
from framework.authz.model import ResourceAccessTarget
from framework.validation.engine import SecurityValidationEngine
from framework.validation.request import ControlledResponse


class AuthCorrelationEngine:
    """Coordinates authentication and authorization correlation analysis."""

    def __init__(
        self,
        program_id: str,
        workspace_root: Optional[str] = None,
        validation_engine: Optional[Any] = None,
        state_manager: Optional[AuthCorrelationStateManager] = None,
    ):
        self.program_id = program_id
        self.workspace_root = workspace_root or os.getcwd()
        self.state_manager = state_manager or AuthCorrelationStateManager(
            program_id=self.program_id,
            workspace_root=self.workspace_root,
        )
        self.validation_engine = validation_engine or SecurityValidationEngine(program_dir=self.workspace_root)
        self.preflight_validator = DualControlPreflightValidator(validation_engine=self.validation_engine)
        self.revocation_validator = PostRevocationResourceValidator(validation_engine=self.validation_engine)
        self.pre_mfa_validator = PreMfaPrivilegeValidator(validation_engine=self.validation_engine)
        self.tenant_validator = MultiTenantDesyncValidator(validation_engine=self.validation_engine)

        self.principals: Dict[str, CorrelatedPrincipalContext] = {}
        self.sessions: Dict[str, CorrelatedSessionContext] = {}
        self.hypotheses: List[CorrelationHypothesis] = []
        self.findings: List[CorrelationFinding] = []

    def register_principal(self, principal: CorrelatedPrincipalContext) -> None:
        """Registers a principal context into the orchestrator."""
        validated = principal.validate()
        self.principals[principal.principal_id] = principal
        self.state_manager.principals[principal.principal_id] = principal

    def register_session(self, session: CorrelatedSessionContext) -> None:
        """Registers an active session context into the orchestrator."""
        session.validate()
        self.sessions[session.session_ref] = session

    def find_session_for_principal(self, principal_id: str) -> Optional[CorrelatedSessionContext]:
        """Finds the registered active session bound to a specific principal ID."""
        for s in self.sessions.values():
            if s.principal_id == principal_id:
                return s
        return None

    def discover_candidates(self, target_asset: Optional[str] = None) -> List[CorrelationHypothesis]:
        """Formulates correlation hypotheses across registered principals and endpoints."""
        discovered: List[CorrelationHypothesis] = []
        p_ids = list(self.principals.keys())
        ep_tenant = "/api/v1/tenant/invoices"
        ep_mfa = "/api/v1/profile"

        if len(p_ids) >= 2:
            p_a = p_ids[0]
            p_b = p_ids[1]
            discovered.append(CorrelationHypothesis(
                hypothesis_id=f"HYP-TENANT-{len(discovered)+1:03d}",
                category="TENANT_ISOLATION",
                target_endpoint=ep_tenant,
                principal_a_id=p_a,
                principal_b_id=p_b,
                preflight_status=CorrelationLifecycle.CREATED,
                expected_result="ISOLATED",
                validation_status="PENDING",
            ))
            discovered.append(CorrelationHypothesis(
                hypothesis_id=f"HYP-MFA-{len(discovered)+1:03d}",
                category="PRE_MFA_PRIVILEGE",
                target_endpoint=ep_mfa,
                principal_a_id=p_a,
                principal_b_id=p_b,
                preflight_status=CorrelationLifecycle.CREATED,
                expected_result="ACCESS_DENIED",
                validation_status="PENDING",
            ))
        elif len(p_ids) == 1:
            p_a = p_ids[0]
            discovered.append(CorrelationHypothesis(
                hypothesis_id=f"HYP-MFA-{len(discovered)+1:03d}",
                category="PRE_MFA_PRIVILEGE",
                target_endpoint=ep_mfa,
                principal_a_id=p_a,
                principal_b_id=p_a,
                preflight_status=CorrelationLifecycle.CREATED,
                expected_result="ACCESS_DENIED",
                validation_status="PENDING",
            ))
        self.hypotheses.extend(discovered)
        return discovered

    def execute_preflight_gate(self, hypotheses: List[CorrelationHypothesis]) -> List[CorrelationHypothesis]:
        """Executes preflight health checks for each registered hypothesis."""
        verified_hypotheses: List[CorrelationHypothesis] = []

        for hyp in hypotheses:
            sess_a = self.find_session_for_principal(hyp.principal_a_id)
            sess_b = self.find_session_for_principal(hyp.principal_b_id)
            if not sess_a or not sess_b:
                hyp.preflight_status = CorrelationLifecycle.FAILED
                hyp.validation_status = "SESSION_HEALTH_FAILED"
                continue

            success, status, details = self.preflight_validator.validate_session_pair(
                sess_a, sess_b, hyp.target_endpoint
            )
            if success:
                hyp.preflight_status = CorrelationLifecycle.VERIFIED
                verified_hypotheses.append(hyp)
            else:
                hyp.preflight_status = CorrelationLifecycle.FAILED
                hyp.validation_status = "SESSION_HEALTH_FAILED"

        return verified_hypotheses

    def run_correlation(
        self,
        target_asset: Optional[str] = None,
        preflight_only: bool = False,
        dry_run: bool = False,
        workflow_filter: Optional[Set[str]] = None,
        approved_action_id: Optional[str] = None,
        action_dossier: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Executes the 12-step correlation orchestration sequence.
        Respects --dry-run, --preflight-only, workflow filters, and fail-closed persistence.
        """
        start_time = time.time()
        
        # Step 2: Discover Candidates if none present
        if not self.hypotheses:
            self.discover_candidates(target_asset=target_asset)

        if dry_run:
            return {
                "status": "DRY_RUN_COMPLETED",
                "hypotheses_planned": len(self.hypotheses),
                "principals_registered": len(self.principals),
                "sessions_registered": len(self.sessions),
                "findings": [],
            }

        # Step 4 & 5: Preflight Gating
        verified = self.execute_preflight_gate(self.hypotheses)
        if preflight_only:
            return {
                "status": "PREFLIGHT_COMPLETED",
                "total_hypotheses": len(self.hypotheses),
                "verified_hypotheses": len(verified),
                "findings": [],
            }

        allowed_workflows = workflow_filter if workflow_filter is not None else {"tenant", "pre_mfa", "revocation"}

        # Step 6: Mode B Controlled Invalidation (if approved action provided)
        if "revocation" in allowed_workflows and approved_action_id and action_dossier:
            target_account = action_dossier.get("test_account", "")
            target_sess = self.find_session_for_principal(target_account)
            if target_sess:
                rev_ok, rev_msg = self.revocation_validator.execute_controlled_invalidation(
                    target_sess, approved_action_id, action_dossier
                )
                if rev_ok:
                    target_ep = action_dossier.get("target_endpoint", "")
                    try:
                        probe_resp = None
                        if hasattr(self.validation_engine, "send_request"):
                            probe_resp = self.validation_engine.send_request("GET", target_ep, headers=target_sess.volatile_headers)
                        elif hasattr(self.validation_engine, "execute_request"):
                            probe_resp = self.validation_engine.execute_request("GET", target_ep, headers=target_sess.volatile_headers)
                        if probe_resp:
                            finding = self.revocation_validator.verify_post_revocation_access(
                                target_sess, target_ep, probe_resp
                            )
                            if finding:
                                self.findings.append(finding)
                    except Exception:
                        pass

        # Step 7: Pre-MFA privilege testing
        if "pre_mfa" in allowed_workflows:
            for hyp in verified:
                if hyp.category == "PRE_MFA_PRIVILEGE":
                    sess_pre = self.find_session_for_principal(hyp.principal_a_id)
                    sess_full = self.find_session_for_principal(hyp.principal_b_id)
                    if sess_pre and getattr(sess_pre, "is_pre_mfa", False):
                        target = ResourceAccessTarget(
                            resource_id=f"res_mfa_{hyp.hypothesis_id}",
                            resource_type="PROFILE",
                            endpoint=hyp.target_endpoint,
                        )
                        baseline = None
                        if sess_full and not getattr(sess_full, "is_pre_mfa", False):
                            try:
                                if hasattr(self.validation_engine, "send_request"):
                                    baseline = self.validation_engine.send_request("GET", hyp.target_endpoint, headers=sess_full.volatile_headers)
                                elif hasattr(self.validation_engine, "execute_request"):
                                    baseline = self.validation_engine.execute_request("GET", hyp.target_endpoint, headers=sess_full.volatile_headers)
                            except Exception:
                                baseline = None
                        finding = self.pre_mfa_validator.evaluate_pre_mfa_boundary(sess_pre, target, baseline)
                        if finding:
                            self.findings.append(finding)
                            hyp.validation_status = "VALIDATED"

        # Step 8: Multi-tenant testing
        if "tenant" in allowed_workflows:
            for hyp in verified:
                if hyp.category == "TENANT_ISOLATION":
                    sess_a = self.find_session_for_principal(hyp.principal_a_id)
                    sess_b = self.find_session_for_principal(hyp.principal_b_id)
                    if sess_a and sess_b:
                        res_a = ResourceAccessTarget(
                            resource_id=f"res_a_{hyp.hypothesis_id}",
                            resource_type="INVOICE",
                            endpoint=hyp.target_endpoint,
                        )
                        res_b = ResourceAccessTarget(
                            resource_id=f"res_b_{hyp.hypothesis_id}",
                            resource_type="INVOICE",
                            endpoint=hyp.target_endpoint,
                        )
                        t_findings = self.tenant_validator.evaluate_tenant_isolation(sess_a, sess_b, res_a, res_b)
                        self.findings.extend(t_findings)
                        if t_findings:
                            hyp.validation_status = "VALIDATED"

        # Step 11: Atomically Persist Sanitized State
        try:
            self.state_manager.save_state(
                contexts=list(self.sessions.values()),
                hypotheses=self.hypotheses,
                findings=self.findings,
            )
        except Exception as e:
            return {
                "status": "PERSISTENCE_FAILED",
                "error": str(e),
                "execution_seconds": round(time.time() - start_time, 3),
                "principals_evaluated": len(self.principals),
                "sessions_evaluated": len(self.sessions),
                "hypotheses_evaluated": len(self.hypotheses),
                "findings_count": len(self.findings),
                "findings": [f.to_dict() for f in self.findings],
            }

        return {
            "status": "COMPLETED",
            "execution_seconds": round(time.time() - start_time, 3),
            "principals_evaluated": len(self.principals),
            "sessions_evaluated": len(self.sessions),
            "hypotheses_evaluated": len(self.hypotheses),
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }

    def render_tree(self) -> str:
        """Renders a portable ASCII correlation hierarchy."""
        lines = [
            f"Correlation Hierarchy: {self.program_id}",
            "\\-- Principals",
        ]
        for p in self.principals.values():
            lines.append(f"    +-- {p.principal_id} (Role: {p.role}, Tenant: {p.tenant_id or 'DEFAULT'})")
        lines.append("\\-- Active Sessions")
        for s in self.sessions.values():
            lines.append(f"    +-- {s.session_ref} [Principal: {s.principal_id}, Status: {s.lifecycle.value}]")
        lines.append("\\-- Hypotheses")
        for h in self.hypotheses:
            lines.append(f"    +-- [{h.hypothesis_id}] {h.category} -> {h.target_endpoint} (Status: {h.validation_status})")
        lines.append(f"\\-- Findings ({len(self.findings)})")
        for f in self.findings:
            lines.append(f"    \\-- [{f.finding_id}] {f.title} ({f.severity}, CVSS: {f.cvss_score})")
        return "\n".join(lines)
