"""
Phase 21: AuthCorrelationEngine.

Primary orchestrator coordinating discovery, preflight health gating,
revocation verification, pre-MFA auditing, multi-tenant desynchronization,
evidence capture, deduplication, and atomic state persistence.
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

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
from framework.auth_correlation.revocation import PostRevocationResourceValidator, ApprovalSecurityError
from framework.auth_correlation.pre_mfa import PreMfaPrivilegeValidator
from framework.auth_correlation.tenant import MultiTenantDesyncValidator
from framework.auth_correlation.state import AuthCorrelationStateManager
from framework.authz.model import ResourceAccessTarget
from framework.validation.engine import SecurityValidationEngine
from framework.validation.request import ControlledRequest, ControlledResponse


class AuthCorrelationEngine:
    """Coordinates authentication and authorization correlation analysis."""

    def __init__(
        self,
        program_id: str,
        workspace_root: Optional[str] = None,
        validation_engine: Optional[Any] = None,
        state_manager: Optional[AuthCorrelationStateManager] = None,
        target_asset: Optional[str] = None,
        scope_engine: Optional[Any] = None,
        evidence_store: Optional[Any] = None,
    ):
        self.program_id = program_id
        self.workspace_root = workspace_root or os.getcwd()
        self.target_asset = target_asset
        self.state_manager = state_manager or AuthCorrelationStateManager(
            program_id=self.program_id,
            workspace_root=self.workspace_root,
        )
        self.validation_engine = validation_engine or SecurityValidationEngine(program_dir=self.workspace_root)
        
        self.scope_engine = scope_engine or getattr(self.validation_engine, "scope_engine", None)
        if self.scope_engine is None:
            scope_file = os.path.join(self.workspace_root, "scope.yaml")
            if os.path.exists(scope_file):
                try:
                    from framework.scope.engine import ScopeEngine
                    self.scope_engine = ScopeEngine.from_file(scope_file)
                    if hasattr(self.validation_engine, "scope_engine") and self.validation_engine.scope_engine is None:
                        self.validation_engine.scope_engine = self.scope_engine
                except Exception:
                    pass

        self.evidence_store = evidence_store or getattr(self.validation_engine, "evidence_store", None)
        if self.evidence_store is None:
            from framework.common.evidence import EvidenceStore
            self.evidence_store = EvidenceStore(os.path.join(self.workspace_root, "evidence"))
        self.preflight_validator = DualControlPreflightValidator(
            validation_engine=self.validation_engine,
            program_dir=self.workspace_root,
        )
        self.revocation_validator = PostRevocationResourceValidator(
            validation_engine=self.validation_engine,
            program_dir=self.workspace_root,
            program_id=self.program_id,
            state_dir=os.path.join(self.workspace_root, "state"),
            scope_engine=self.scope_engine,
            evidence_store=self.evidence_store,
        )
        self.pre_mfa_validator = PreMfaPrivilegeValidator(
            validation_engine=self.validation_engine,
            program_dir=self.workspace_root,
            evidence_store=self.evidence_store,
        )
        self.tenant_validator = MultiTenantDesyncValidator(
            validation_engine=self.validation_engine,
            program_dir=self.workspace_root,
            evidence_store=self.evidence_store,
        )

        self.principals: Dict[str, CorrelatedPrincipalContext] = {}
        self.sessions: Dict[str, CorrelatedSessionContext] = {}
        self.resource_targets: List[ResourceAccessTarget] = []
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

    def register_resource_target(self, target: ResourceAccessTarget) -> None:
        """Registers a resource target for target-aware correlation."""
        self.resource_targets.append(target)

    def find_session_for_principal(self, principal_id: str) -> Optional[CorrelatedSessionContext]:
        """Finds the registered active session bound to a specific principal ID."""
        for s in self.sessions.values():
            if s.principal_id == principal_id:
                return s
        return None

    def _build_and_validate_target_url(
        self,
        endpoint: str,
        target_asset: Optional[str] = None,
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Derives valid target URL, preserving scheme, hostname, and authorized port.
        Rejects origin substitution and validates against ScopeEngine policy.
        Returns (full_url, error_message).
        """
        eff_target = target_asset or self.target_asset
        target_base = ""
        base_parsed = None
        if eff_target:
            base_parsed = urlparse(eff_target)
            if base_parsed.scheme in ("http", "https") and base_parsed.netloc:
                target_base = f"{base_parsed.scheme}://{base_parsed.netloc}"

        ep_parsed = urlparse(endpoint)
        if ep_parsed.scheme in ("http", "https"):
            # Absolute candidate URL: verify origin matches target_base if target_base is set
            if target_base and base_parsed and ep_parsed.netloc.lower() != base_parsed.netloc.lower():
                return None, f"Origin mismatch: candidate '{endpoint}' changes target origin from '{target_base}'"
            full_url = endpoint
        elif endpoint.startswith("/"):
            if not target_base:
                return None, f"Cannot resolve relative endpoint '{endpoint}' without target base URL"
            full_url = f"{target_base}{endpoint}"
        else:
            if not target_base:
                return None, f"Cannot resolve candidate endpoint '{endpoint}' without target base URL"
            full_url = f"{target_base}/{endpoint}"

        # ScopeEngine validation
        if self.scope_engine is not None:
            try:
                if not self.scope_engine.is_in_scope(full_url):
                    return None, f"Candidate URL '{full_url}' is out of scope"
            except Exception as e:
                return None, f"Scope verification failed for '{full_url}': {e}"

        return full_url, None

    def discover_candidates(
        self,
        target_asset: Optional[str] = None,
        resource_endpoints: Optional[List[str]] = None,
    ) -> List[CorrelationHypothesis]:
        """
        Formulates correlation hypotheses across registered principals and verified target endpoints.
        Consumes target_asset or registered resource endpoints. Does not invent fabricated routes.
        """
        eff_target = target_asset or self.target_asset
        endpoints: List[str] = []
        if resource_endpoints:
            for ep in resource_endpoints:
                if ep and ep not in endpoints:
                    endpoints.append(ep)

        if self.resource_targets:
            for r in self.resource_targets:
                ep = getattr(r, "endpoint", None) or getattr(r, "url", None)
                if ep:
                    parsed_ep = urlparse(ep)
                    if parsed_ep.scheme in ("http", "https") and parsed_ep.path:
                        path_ep = parsed_ep.path + (f"?{parsed_ep.query}" if parsed_ep.query else "")
                        if path_ep not in endpoints:
                            endpoints.append(path_ep)
                    elif ep not in endpoints:
                        endpoints.append(ep)

        if eff_target:
            parsed = urlparse(eff_target)
            if parsed.scheme in ("http", "https"):
                if parsed.path and parsed.path not in ("/", ""):
                    path_ep = parsed.path + (f"?{parsed.query}" if parsed.query else "")
                    if path_ep not in endpoints:
                        endpoints.append(path_ep)
            elif eff_target.startswith("/"):
                if eff_target not in endpoints:
                    endpoints.append(eff_target)

        # STRICTLY NO FABRICATED APPLICATION ROUTES!
        if not endpoints:
            return []

        # Validate candidates against scope policy if scope_engine is available
        valid_endpoints: List[str] = []
        for ep in endpoints:
            full_url, err = self._build_and_validate_target_url(ep, eff_target)
            if err is None:
                valid_endpoints.append(ep)
            elif "without target base URL" in err:
                valid_endpoints.append(ep)

        if not valid_endpoints:
            return []

        discovered: List[CorrelationHypothesis] = []
        p_ids = list(self.principals.keys())

        for ep in valid_endpoints:
            if len(p_ids) >= 2:
                p_a = p_ids[0]
                p_b = p_ids[1]
                discovered.append(CorrelationHypothesis(
                    hypothesis_id=f"HYP-TENANT-{len(self.hypotheses) + len(discovered) + 1:03d}",
                    category="TENANT_ISOLATION",
                    target_endpoint=ep,
                    principal_a_id=p_a,
                    principal_b_id=p_b,
                    preflight_status=CorrelationLifecycle.CREATED,
                    expected_result="ISOLATED",
                    validation_status="PENDING",
                ))
                discovered.append(CorrelationHypothesis(
                    hypothesis_id=f"HYP-MFA-{len(self.hypotheses) + len(discovered) + 1:03d}",
                    category="PRE_MFA_PRIVILEGE",
                    target_endpoint=ep,
                    principal_a_id=p_a,
                    principal_b_id=p_b,
                    preflight_status=CorrelationLifecycle.CREATED,
                    expected_result="ACCESS_DENIED",
                    validation_status="PENDING",
                ))
                discovered.append(CorrelationHypothesis(
                    hypothesis_id=f"HYP-REVOKE-{len(self.hypotheses) + len(discovered) + 1:03d}",
                    category="REVOCATION_ENFORCEMENT",
                    target_endpoint=ep,
                    principal_a_id=p_a,
                    principal_b_id=p_b,
                    preflight_status=CorrelationLifecycle.CREATED,
                    expected_result="ACCESS_DENIED",
                    validation_status="PENDING",
                ))
            elif len(p_ids) == 1:
                p_a = p_ids[0]
                discovered.append(CorrelationHypothesis(
                    hypothesis_id=f"HYP-MFA-{len(self.hypotheses) + len(discovered) + 1:03d}",
                    category="PRE_MFA_PRIVILEGE",
                    target_endpoint=ep,
                    principal_a_id=p_a,
                    principal_b_id=p_a,
                    preflight_status=CorrelationLifecycle.CREATED,
                    expected_result="ACCESS_DENIED",
                    validation_status="PENDING",
                ))
                discovered.append(CorrelationHypothesis(
                    hypothesis_id=f"HYP-REVOKE-{len(self.hypotheses) + len(discovered) + 1:03d}",
                    category="REVOCATION_ENFORCEMENT",
                    target_endpoint=ep,
                    principal_a_id=p_a,
                    principal_b_id=p_a,
                    preflight_status=CorrelationLifecycle.CREATED,
                    expected_result="ACCESS_DENIED",
                    validation_status="PENDING",
                ))

        self.hypotheses.extend(discovered)
        return discovered

    def execute_preflight_gate(
        self,
        hypotheses: List[CorrelationHypothesis],
        target_asset: Optional[str] = None,
    ) -> List[CorrelationHypothesis]:
        """Executes preflight health checks for each registered hypothesis."""
        verified_hypotheses: List[CorrelationHypothesis] = []
        eff_target = target_asset or self.target_asset

        for hyp in hypotheses:
            sess_a = self.find_session_for_principal(hyp.principal_a_id)
            sess_b = self.find_session_for_principal(hyp.principal_b_id) if hyp.principal_b_id != hyp.principal_a_id else sess_a
            if not sess_a or not sess_b:
                hyp.preflight_status = CorrelationLifecycle.FAILED
                hyp.validation_status = "SESSION_HEALTH_FAILED"
                continue

            full_url, err = self._build_and_validate_target_url(hyp.target_endpoint, eff_target)
            if err is not None or not full_url:
                hyp.preflight_status = CorrelationLifecycle.FAILED
                hyp.validation_status = "FAILED"
                continue

            # Invalidation observation: if session carries verified invalidation evidence and valid baseline
            if hyp.category == "REVOCATION_ENFORCEMENT":
                inv_ref = getattr(sess_a, "invalidation_evidence_ref", None)
                base = getattr(sess_a, "pre_revocation_baseline", None)
                if inv_ref and base and getattr(base, "status_code", 0) == 200:
                    prov_ok, prov_reason, _ = self.revocation_validator.verify_invalidation_provenance(
                        inv_ref, sess_a, program_id=self.program_id
                    )
                    if prov_ok:
                        hyp.preflight_status = CorrelationLifecycle.VERIFIED
                        verified_hypotheses.append(hyp)
                        continue
                    else:
                        hyp.preflight_status = CorrelationLifecycle.FAILED
                        hyp.validation_status = "SESSION_HEALTH_FAILED"
                        continue
                elif inv_ref:
                    hyp.preflight_status = CorrelationLifecycle.FAILED
                    hyp.validation_status = "SESSION_HEALTH_FAILED"
                    continue

            success, status, details = self.preflight_validator.validate_session_pair(
                sess_a, sess_b, full_url
            )
            if success:
                hyp.preflight_status = CorrelationLifecycle.VERIFIED
                verified_hypotheses.append(hyp)
                if "probe_1" in details and hasattr(details["probe_1"], "status_code") and details["probe_1"].status_code == 200:
                    if getattr(sess_a, "pre_revocation_baseline", None) is None:
                        sess_a.pre_revocation_baseline = details["probe_1"]
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
        revocation: bool = False,
        pre_mfa: bool = False,
        tenant: bool = False,
    ) -> Dict[str, Any]:
        """
        Executes the 12-step correlation orchestration sequence.
        Respects --dry-run, --preflight-only, workflow filters, and fail-closed persistence.
        """
        start_time = time.time()
        eff_target = target_asset or self.target_asset
        
        # Merge individual workflow toggles into workflow_filter if provided
        if revocation or pre_mfa or tenant:
            workflow_filter = set(workflow_filter) if workflow_filter else set()
            if revocation:
                workflow_filter.add("revocation")
            if pre_mfa:
                workflow_filter.add("pre_mfa")
            if tenant:
                workflow_filter.add("tenant")
        
        # Step 2: Discover Candidates if none present
        if not self.hypotheses:
            candidates = self.discover_candidates(target_asset=eff_target)
            if not candidates and not dry_run:
                return {
                    "status": "INPUT_REQUIRED",
                    "message": "No target endpoints or resource targets configured. Please provide --target or register candidate endpoints.",
                    "hypotheses_planned": 0,
                    "principals_registered": len(self.principals),
                    "sessions_registered": len(self.sessions),
                    "findings_count": 0,
                    "findings": [],
                }

        if dry_run:
            return {
                "status": "DRY_RUN_COMPLETED",
                "hypotheses_planned": len(self.hypotheses),
                "principals_registered": len(self.principals),
                "sessions_registered": len(self.sessions),
                "findings": [],
            }

        target_base = ""
        if eff_target:
            parsed = urlparse(eff_target)
            if parsed.scheme in ("http", "https"):
                target_base = f"{parsed.scheme}://{parsed.netloc}"

        # Step 4 & 5: Preflight Gating
        verified = self.execute_preflight_gate(self.hypotheses, target_asset=eff_target)
        if preflight_only:
            return {
                "status": "PREFLIGHT_COMPLETED",
                "total_hypotheses": len(self.hypotheses),
                "verified_hypotheses": len(verified),
                "findings": [],
            }

        allowed_workflows = workflow_filter if workflow_filter is not None else {"tenant", "pre_mfa", "revocation"}

        # Step 6: Revocation Testing (Mode A vs Mode B)
        if "revocation" in allowed_workflows:
            is_mode_b = bool(approved_action_id and action_dossier)
            if is_mode_b:
                # Mode B: Controlled Invalidation (strictly requires operator-approved action)
                target_account = action_dossier.get("test_account", "")
                target_sess = self.find_session_for_principal(target_account)
                if target_sess:
                    try:
                        rev_ok = self.revocation_validator.execute_controlled_invalidation(
                            target_sess, approved_action_id, action_dossier
                        )
                        if rev_ok:
                            target_ep = action_dossier.get("target_endpoint", "")
                            full_url, err = self._build_and_validate_target_url(target_ep, eff_target)
                            if not err and full_url:
                                probe_req = ControlledRequest(
                                    url=full_url,
                                    method="GET",
                                    headers=dict(target_sess.volatile_headers),
                                )
                                probe_resp = self.validation_engine.send_request(probe_req)
                                baseline = target_sess.metadata.get("pre_revocation_baseline")
                                finding = self.revocation_validator.verify_post_revocation_access(
                                    target_sess, full_url, probe_resp, baseline_target=baseline
                                )
                                if finding:
                                    self.findings.append(finding)
                    except Exception as e:
                        return {
                            "status": "REVOCATION_MUTATION_FAILED",
                            "error": str(e),
                            "findings": [f.to_dict() for f in self.findings],
                        }
            else:
                # Mode A: Observation-Only Workflow (strictly read-only)
                for hyp in verified:
                    if hyp.category == "REVOCATION_ENFORCEMENT":
                        sess = self.find_session_for_principal(hyp.principal_a_id)
                        if not sess:
                            hyp.validation_status = "INCONCLUSIVE"
                            continue

                        full_url, err = self._build_and_validate_target_url(hyp.target_endpoint, eff_target)
                        if err or not full_url:
                            hyp.validation_status = "FAILED"
                            continue

                        resource = ResourceAccessTarget(
                            resource_id=f"res_rev_{hyp.hypothesis_id}",
                            resource_type="PROTECTED_RESOURCE",
                            endpoint=full_url,
                            method="GET",
                        )
                        baseline = getattr(sess, "pre_revocation_baseline", None) or sess.metadata.get("pre_revocation_baseline")
                        invalidation_ref = getattr(sess, "invalidation_evidence_ref", None) or sess.metadata.get("invalidation_evidence_ref")

                        status, finding = self.revocation_validator.evaluate_revoked_session(
                            sess, resource, baseline, invalidation_ref
                        )
                        if status == "SESSION_NOT_INVALIDATED" and finding:
                            self.findings.append(finding)
                            hyp.validation_status = "VALIDATED"
                        elif status == "INCONCLUSIVE":
                            hyp.validation_status = "INCONCLUSIVE"
                        else:
                            hyp.validation_status = "FAILED"

        # Step 7: Pre-MFA privilege testing
        if "pre_mfa" in allowed_workflows:
            for hyp in verified:
                if hyp.category == "PRE_MFA_PRIVILEGE":
                    sess_pre = self.find_session_for_principal(hyp.principal_a_id)
                    sess_full = self.find_session_for_principal(hyp.principal_b_id)
                    if sess_pre and getattr(sess_pre, "is_pre_mfa", False):
                        full_url, err = self._build_and_validate_target_url(hyp.target_endpoint, eff_target)
                        if err or not full_url:
                            hyp.validation_status = "FAILED"
                            continue
                        target = ResourceAccessTarget(
                            resource_id=f"res_mfa_{hyp.hypothesis_id}",
                            resource_type="PROFILE",
                            endpoint=full_url,
                        )
                        baseline = None
                        if sess_full and getattr(sess_full, "metadata", {}).get("mfa_level") == "FULL_MFA":
                            try:
                                base_req = ControlledRequest(
                                    url=full_url,
                                    method="GET",
                                    headers=dict(sess_full.volatile_headers),
                                )
                                baseline = self.validation_engine.send_request(base_req)
                            except Exception:
                                baseline = None
                        finding = self.pre_mfa_validator.evaluate_pre_mfa_boundary(
                            sess_pre, target, baseline, full_session_ctx=sess_full
                        )
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
                        full_url, err = self._build_and_validate_target_url(hyp.target_endpoint, eff_target)
                        if err or not full_url:
                            hyp.validation_status = "FAILED"
                            continue
                        res_a = ResourceAccessTarget(
                            resource_id=f"res_a_{hyp.hypothesis_id}",
                            resource_type="INVOICE",
                            endpoint=full_url,
                        )
                        res_b = ResourceAccessTarget(
                            resource_id=f"res_b_{hyp.hypothesis_id}",
                            resource_type="INVOICE",
                            endpoint=full_url,
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
