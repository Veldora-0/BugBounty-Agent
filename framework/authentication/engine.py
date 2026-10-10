"""
Primary Orchestrator for Authentication, Session & Identity Security Intelligence (Phase 14.1).

Coordinates authentication surface discovery, identity modeling, hypothesis formulation,
approval gating, safe differential validation, prioritization, and evidence persistence.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunsplit
import uuid

from framework.authentication.discovery import AuthenticationSurfaceDiscoverer
from framework.authentication.evidence import AuthenticationEvidenceManager
from framework.authentication.executor import BoundedAuthenticationExecutor
from framework.authentication.hypotheses import AuthenticationHypothesisEngine
from framework.authentication.identity import IdentityManager
from framework.authentication.lab import LocalAuthenticationSecurityLab
from framework.authentication.models import (
    AuthenticationFindingCandidate,
    AuthenticationFindingFamily,
    AuthenticationFlow,
    AuthenticationFlowType,
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
    resolve_scope_file,
)
from framework.authentication.prioritization import AuthenticationPrioritizer
from framework.authentication.storage import AuthenticationStateManager
from framework.authentication.validators import (
    AuthenticationFalsePositiveClassifier,
    SafeAuthenticationValidator,
)
from framework.scope.engine import ScopeEngine, ScopeStatus
from framework.state.dedup import generate_test_fingerprint
from framework.state.manager import StateManager


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
        self.executor = BoundedAuthenticationExecutor(scope_engine=scope_engine)
        self.identity_mgr = IdentityManager()
        self.storage = AuthenticationStateManager(workspace_dir=self.workspace_dir)
        self.state_manager = StateManager(self.workspace_dir)

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
        # Merge surfaces
        existing_surf = {s.endpoint for s in self.surfaces}
        for s in st.get("surfaces", []):
            if s.endpoint not in existing_surf:
                self.surfaces.append(s)
                existing_surf.add(s.endpoint)
        # Merge identities
        existing_ident = {i.identity_id for i in self.identities}
        for i in st.get("identities", []):
            if i.identity_id not in existing_ident:
                self.identities.append(i)
                existing_ident.add(i.identity_id)
        # Merge flows
        self.flows.extend([fl for fl in st.get("flows", []) if fl not in self.flows])
        # Merge sessions
        self.sessions.extend([sp for sp in st.get("sessions", []) if sp not in self.sessions])
        # Merge hypotheses preserving terminal statuses
        hypo_map = {h.hypothesis_id: h for h in self.hypotheses}
        for h in st.get("hypotheses", []):
            if h.hypothesis_id not in hypo_map:
                self.hypotheses.append(h)
                hypo_map[h.hypothesis_id] = h
            else:
                if h.validation_status in (
                    HypothesisValidationStatus.VALIDATED,
                    HypothesisValidationStatus.REJECTED,
                    HypothesisValidationStatus.SKIPPED,
                    HypothesisValidationStatus.CONFIRMED,
                ):
                    hypo_map[h.hypothesis_id].validation_status = h.validation_status
                    hypo_map[h.hypothesis_id].rationale = h.rationale
        # Merge findings
        existing_find = {f.finding_id for f in self.findings}
        for f in st.get("findings", []):
            if f.finding_id not in existing_find:
                self.findings.append(f)
                existing_find.add(f.finding_id)
        self.evidence_records.extend(st.get("evidence", []))
        self.token_metadata.extend(st.get("tokens", []))

    def discover_surfaces(self) -> List[AuthenticationStep]:
        """Discovers authentication endpoints and actions from previous workspace state."""
        new_surfaces = AuthenticationSurfaceDiscoverer.discover_all(self.workspace_dir)
        existing_endpoints = {s.endpoint for s in self.surfaces}
        for ns in new_surfaces:
            if ns.endpoint not in existing_endpoints:
                self.surfaces.append(ns)
                existing_endpoints.add(ns.endpoint)
        # Seed identities from authorization state
        seeded = self.identity_mgr.seed_from_authorization_state(self.workspace_dir)
        existing_ids = {i.identity_id for i in self.identities}
        for s in seeded:
            if s.identity_id not in existing_ids:
                self.identities.append(s)
                existing_ids.add(s.identity_id)
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

    def validate_hypotheses(
        self,
        dry_run: bool = False,
        passive_only: bool = False,
        lab_mode: bool = False,
        approve: bool = False,
        resume: bool = False,
    ) -> List[AuthenticationFindingCandidate]:
        """
        Executes safe, differential validation for all hypotheses.
        Zero external network requests in dry_run, passive_only, or lab_mode.
        """
        if passive_only:
            return self.findings

        if resume:
            self.load_existing_state()

        if lab_mode:
            self.execute_lab_simulation()
            # Update matching hypotheses validation status
            lab_scenarios = LocalAuthenticationSecurityLab.SCENARIOS
            for h in self.hypotheses:
                scen_id = h.endpoint.replace("local-lab://", "")
                if scen_id in lab_scenarios:
                    expected = lab_scenarios[scen_id]["expected_verdict"]
                    h.validation_status = expected
            return self.findings

        # Real target validation
        for h in self.hypotheses:
            if h.validation_status in (
                HypothesisValidationStatus.VALIDATED,
                HypothesisValidationStatus.REJECTED,
                HypothesisValidationStatus.SKIPPED,
                HypothesisValidationStatus.CONFIRMED,
            ):
                continue

            # Scope check
            is_allowed, scope_reason = self.policy.is_target_allowed(h.endpoint)
            if not is_allowed:
                h.validation_status = HypothesisValidationStatus.SKIPPED
                h.rationale = f"Scope restriction: {scope_reason}"
                continue

            # Context-aware deduplication check
            parsed = urlparse(h.endpoint)
            host = parsed.hostname or "localhost"
            context = f"principal:{h.principal}|family:{h.family}"
            if self.state_manager.has_test_run(
                target=host,
                endpoint=h.endpoint,
                method="GET",
                parameter=context,
                test_category="authentication",
            ):
                h.validation_status = HypothesisValidationStatus.SKIPPED
                h.rationale = "Skipped as duplicate test run from prior execution"
                continue

            # State mutation check & approval gate
            op_name = "INSPECT"
            if "RESET" in h.family:
                op_name = "PASSWORD_RESET_SUBMIT"
            elif "CHANGE" in h.family:
                op_name = "PASSWORD_CHANGE"
            elif "MFA" in h.family:
                op_name = "MFA_ENROLLMENT"

            if self.policy.requires_human_approval(op_name):
                dossier = AuthenticationApprovalGate.create_audit_dossier(
                    target=h.endpoint,
                    identity="researcher-test",
                    planned_operation=op_name,
                    endpoint=h.endpoint,
                    method="POST",
                    reason=f"Validating {h.family}",
                    security_hypothesis=h.rationale,
                    expected_result=h.expected_behavior,
                    rollback_guidance="Restore test user state in test database",
                )
                appr_ok, appr_msg = AuthenticationApprovalGate.check_approval(
                    dossier=dossier,
                    is_approved=approve,
                    is_in_scope=is_allowed,
                )
                if not appr_ok:
                    h.validation_status = HypothesisValidationStatus.NEEDS_APPROVAL
                    h.rationale = appr_msg
                    continue

            if dry_run:
                self.executor.execute_request(h.endpoint, method="GET", dry_run=True)
                continue

            # Retrieve active researcher context for principal if configured
            active_identity = self.identity_mgr.get_identity(h.principal)
            active_session = next((s for s in self.sessions if s.identity_id == h.principal or s.username == h.principal), None)
            active_token = next((t for t in self.token_metadata if t.associated_identity == h.principal), None)

            # Pre-flight prerequisite check: fail-safe skip before issuing network requests
            if h.family == AuthenticationFindingFamily.SESSION_NOT_INVALIDATED and (not active_session or not active_session.session_id):
                h.validation_status = HypothesisValidationStatus.SKIPPED
                h.rationale = "Skipped: Missing researcher session context (session_id required to test invalidation)"
                continue
            if h.family == AuthenticationFindingFamily.SESSION_FIXATION and (not active_identity or not active_identity.attributes.get("credentials_available")):
                h.validation_status = HypothesisValidationStatus.SKIPPED
                h.rationale = "Skipped: Missing researcher test credentials for login boundary verification"
                continue
            if h.family == AuthenticationFindingFamily.ACCOUNT_ENUMERATION and (not active_identity or not active_identity.username):
                h.validation_status = HypothesisValidationStatus.SKIPPED
                h.rationale = "Skipped: Missing target account identifier parameter for enumeration testing"
                continue
            if h.family == AuthenticationFindingFamily.PASSWORD_RESET_TOKEN_REUSE and (not active_identity or not active_identity.attributes.get("reset_token")):
                h.validation_status = HypothesisValidationStatus.SKIPPED
                h.rationale = "Skipped: Missing valid researcher-controlled password reset token"
                continue
            if h.family == AuthenticationFindingFamily.PASSWORD_RESET_STATE_CONFUSION and (not active_identity or not active_identity.username):
                h.validation_status = HypothesisValidationStatus.SKIPPED
                h.rationale = "Skipped: Missing researcher test identity to validate password reset state machine"
                continue
            if h.family == AuthenticationFindingFamily.REFRESH_TOKEN_REUSE and (not active_token or not active_token.attributes.get("refresh_token")):
                h.validation_status = HypothesisValidationStatus.SKIPPED
                h.rationale = "Skipped: Missing valid test refresh token"
                continue
            if h.family == AuthenticationFindingFamily.PRE_AUTH_PRIVILEGE_EXPOSURE and (not active_session or not active_session.attributes.get("pre_mfa_token")):
                h.validation_status = HypothesisValidationStatus.SKIPPED
                h.rationale = "Skipped: Missing intermediate pre-MFA session token"
                continue
            if h.family == AuthenticationFindingFamily.MFA_BYPASS:
                pre_mfa_tok = active_session.attributes.get("pre_mfa_token") if (active_session and active_session.attributes) else None
                if not pre_mfa_tok and active_token and getattr(active_token, "token_value", None):
                    pre_mfa_tok = active_token.token_value
                if not pre_mfa_tok:
                    h.validation_status = HypothesisValidationStatus.SKIPPED
                    h.rationale = "Skipped: Missing pre-MFA researcher test session or token"
                    continue
            if h.family == AuthenticationFindingFamily.MFA_STATE_CONFUSION:
                dual_sessions = [s for s in self.sessions if s.session_id]
                session_b = active_identity.attributes.get("session_b") if (active_identity and active_identity.attributes) else None
                if len(dual_sessions) < 2 and not session_b:
                    h.validation_status = HypothesisValidationStatus.SKIPPED
                    h.rationale = "Skipped: Missing dual test sessions to validate cross-session MFA state isolation"
                    continue
            if h.family == AuthenticationFindingFamily.AUTHENTICATION_STATE_INCONSISTENCY:
                status_surface = next((s for s in self.surfaces if any(seg in s.endpoint.lower() for seg in ["/status", "/check", "/me", "/whoami"])), None)
                test_sess = active_session.session_id if active_session else None
                test_tok = active_token.token_value if active_token and getattr(active_token, "token_value", None) else None
                if not status_surface:
                    h.validation_status = HypothesisValidationStatus.SKIPPED
                    h.rationale = "Skipped: Missing discovered authentication status verification endpoint (e.g. /status, /me)"
                    continue
                if not test_sess and not test_tok:
                    h.validation_status = HypothesisValidationStatus.SKIPPED
                    h.rationale = "Skipped: Missing researcher test session or token to verify cross-boundary state consistency"
                    continue

            # Execute controlled baseline differential probe
            anon_res = self.executor.execute_request(h.endpoint, method="GET")
            evidence_id = anon_res.get("evidence", {}).get("evidence_id") if isinstance(anon_res.get("evidence"), dict) else None
            self.state_manager.record_test(
                target=host,
                endpoint=h.endpoint,
                method="GET",
                parameter=context,
                test_category="authentication",
                result="SUCCESS" if anon_res.get("success") else "FAILURE",
                evidence_reference=evidence_id,
            )

            if not anon_res.get("success"):
                h.validation_status = HypothesisValidationStatus.REJECTED
                h.rationale = f"Request error: {anon_res.get('error')}"
                continue

            status_code = anon_res.get("status_code", 0)
            body = anon_res.get("body", "")

            # Filter generic login forms / WAF pages
            if AuthenticationFalsePositiveClassifier.is_login_page_false_positive(status_code, body):
                h.validation_status = HypothesisValidationStatus.REJECTED
                h.rationale = "Rejected as normal login/auth page (HTTP 200 false positive)"
                continue
            if AuthenticationFalsePositiveClassifier.is_waf_or_challenge_page(status_code, body):
                h.validation_status = HypothesisValidationStatus.REJECTED
                h.rationale = "Rejected as WAF challenge/block page"
                continue

            # Evaluate based on family with genuine verification procedures
            is_valid = False
            verdict = HypothesisValidationStatus.REJECTED
            reason = ""
            evidence_chain = [anon_res.get("evidence")] if anon_res.get("evidence") else []

            # Retrieve active researcher context for principal if configured
            active_identity = self.identity_mgr.get_identity(h.principal)
            active_session = next((s for s in self.sessions if s.identity_id == h.principal or s.username == h.principal), None)
            active_token = next((t for t in self.token_metadata if t.associated_identity == h.principal), None)

            if h.family == AuthenticationFindingFamily.AUTHENTICATION_BYPASS:
                # 1. AUTHENTICATION_BYPASS: Requires both anonymous and authenticated differential
                auth_res = None
                if active_token and getattr(active_token, "token_value", None):
                    auth_res = self.executor.execute_request(
                        h.endpoint,
                        method="GET",
                        headers={"Authorization": f"Bearer {active_token.token_value}"},
                    )
                elif active_session and getattr(active_session, "session_id", None):
                    auth_res = self.executor.execute_request(
                        h.endpoint,
                        method="GET",
                        headers={"Cookie": f"session={active_session.session_id}"},
                    )

                if auth_res:
                    if auth_res.get("evidence"):
                        evidence_chain.append(auth_res["evidence"])
                    verdict, reason = SafeAuthenticationValidator.validate_authentication_bypass(
                        endpoint=h.endpoint,
                        anon_status=status_code,
                        anon_body=body,
                        auth_status=auth_res.get("status_code", 0),
                        auth_body=auth_res.get("body", ""),
                    )
                    is_valid = (verdict == HypothesisValidationStatus.VALIDATED)
                else:
                    # Missing authenticated context: evaluate negative controls or return CANDIDATE
                    verdict, reason = SafeAuthenticationValidator.validate_authentication_bypass(
                        endpoint=h.endpoint,
                        anon_status=status_code,
                        anon_body=body,
                        auth_status=0,
                        auth_body="",
                    )
                    is_valid = False

            elif h.family == AuthenticationFindingFamily.SESSION_NOT_INVALIDATED:
                # 2. SESSION_NOT_INVALIDATED: Requires researcher session
                if not active_session or not active_session.session_id:
                    verdict = HypothesisValidationStatus.SKIPPED
                    reason = "Skipped: Missing researcher session context (session_id required to test invalidation)"
                    is_valid = False
                else:
                    logout_step = next((s for s in self.surfaces if s.flow_type == AuthenticationFlowType.LOGOUT), None)
                    if logout_step:
                        logout_res = self.executor.execute_request(
                            logout_step.endpoint,
                            method="POST",
                            headers={"Cookie": f"session={active_session.session_id}"},
                        )
                        if logout_res.get("evidence"):
                            evidence_chain.append(logout_res["evidence"])
                        post_res = self.executor.execute_request(
                            h.endpoint,
                            method="GET",
                            headers={"Cookie": f"session={active_session.session_id}"},
                        )
                        if post_res.get("evidence"):
                            evidence_chain.append(post_res["evidence"])
                        verdict, reason = SafeAuthenticationValidator.validate_session_invalidation(
                            endpoint=h.endpoint,
                            session_id=active_session.session_id,
                            post_logout_status=post_res.get("status_code", 0),
                            post_logout_body=post_res.get("body", ""),
                        )
                        is_valid = (verdict == HypothesisValidationStatus.VALIDATED)
                    else:
                        verdict = HypothesisValidationStatus.SKIPPED
                        reason = "Skipped: No logout endpoint identified in attack surface to perform invalidation sequence"
                        is_valid = False

            elif h.family == AuthenticationFindingFamily.SESSION_FIXATION:
                # 3. SESSION_FIXATION: Requires login boundary verification
                if not active_identity or not active_identity.attributes.get("credentials_available"):
                    verdict = HypothesisValidationStatus.SKIPPED
                    reason = "Skipped: Missing researcher test credentials for login boundary verification"
                    is_valid = False
                else:
                    pre_cookie = anon_res.get("headers", {}).get("set-cookie", "")
                    post_login_res = self.executor.execute_request(h.endpoint, method="POST")
                    if post_login_res.get("evidence"):
                        evidence_chain.append(post_login_res["evidence"])
                    post_cookie = post_login_res.get("headers", {}).get("set-cookie", "")
                    verdict, reason = SafeAuthenticationValidator.validate_session_fixation(
                        session_pre=pre_cookie,
                        session_post=post_cookie,
                        state_post=AuthenticationState.AUTHENTICATED,
                    )
                    is_valid = (verdict == HypothesisValidationStatus.VALIDATED)

            elif h.family == AuthenticationFindingFamily.ACCOUNT_ENUMERATION:
                # 4. ACCOUNT_ENUMERATION: Requires target user identifier parameter and at least 3 controlled trials
                if not active_identity or not active_identity.username:
                    verdict = HypothesisValidationStatus.SKIPPED
                    reason = "Skipped: Missing target account identifier parameter for enumeration testing"
                    is_valid = False
                else:
                    parsed_u = urlparse(h.endpoint)
                    base_qsl = parse_qsl(parsed_u.query, keep_blank_values=True)
                    param_name = "username"
                    for k, _ in base_qsl:
                        if k.lower() in ("username", "user", "email", "account", "login", "id"):
                            param_name = k
                            break

                    trials_data = []

                    # Execute 3 controlled trials comparing researcher-controlled valid user vs distinct nonexistent synthetic identities
                    for trial_idx in range(3):
                        rand_user = f"nonexistent_{trial_idx}_{hashlib.sha256(f'{h.endpoint}_{trial_idx}'.encode()).hexdigest()[:6]}@example.invalid"
                        q_valid = [(k, v) for k, v in base_qsl if k != param_name] + [(param_name, active_identity.username)]
                        q_invalid = [(k, v) for k, v in base_qsl if k != param_name] + [(param_name, rand_user)]

                        url_valid = urlunsplit((parsed_u.scheme, parsed_u.netloc, parsed_u.path, urlencode(q_valid), parsed_u.fragment))
                        url_invalid = urlunsplit((parsed_u.scheme, parsed_u.netloc, parsed_u.path, urlencode(q_invalid), parsed_u.fragment))

                        t_val = self.executor.execute_request(url_valid, method="GET")
                        t_inv = self.executor.execute_request(url_invalid, method="GET")

                        if t_val.get("evidence"):
                            evidence_chain.append(t_val["evidence"])
                        if t_inv.get("evidence"):
                            evidence_chain.append(t_inv["evidence"])

                        trials_data.append({
                            "valid_status": t_val.get("status_code", 0),
                            "valid_body": t_val.get("body", ""),
                            "valid_redirect": t_val.get("headers", {}).get("location"),
                            "invalid_status": t_inv.get("status_code", 0),
                            "invalid_body": t_inv.get("body", ""),
                            "invalid_redirect": t_inv.get("headers", {}).get("location"),
                        })

                        # Stop if rate-limited
                        if t_val.get("status_code") == 429 or t_inv.get("status_code") == 429:
                            break

                    verdict, reason = SafeAuthenticationValidator.validate_account_enumeration(
                        trials=trials_data,
                    )
                    is_valid = (verdict == HypothesisValidationStatus.VALIDATED)

            elif h.family == AuthenticationFindingFamily.PRE_AUTH_PRIVILEGE_EXPOSURE:
                # 5. PRE_AUTH_PRIVILEGE_EXPOSURE: Requires intermediate/pre-MFA token
                pre_mfa = active_session.attributes.get("pre_mfa_token") if active_session else None
                if not pre_mfa:
                    verdict = HypothesisValidationStatus.SKIPPED
                    reason = "Skipped: Missing intermediate pre-MFA session token"
                    is_valid = False
                else:
                    probe_res = self.executor.execute_request(
                        h.endpoint,
                        method="GET",
                        headers={"Authorization": f"Bearer {pre_mfa}"},
                    )
                    if probe_res.get("evidence"):
                        evidence_chain.append(probe_res["evidence"])
                    verdict, reason = SafeAuthenticationValidator.validate_pre_mfa_exposure(
                        endpoint=h.endpoint,
                        mfa_status=probe_res.get("status_code", 0),
                        mfa_body=probe_res.get("body", ""),
                        verified_status=status_code,
                        verified_body=body,
                    )
                    is_valid = (verdict == HypothesisValidationStatus.VALIDATED)

            elif h.family == AuthenticationFindingFamily.PASSWORD_RESET_TOKEN_REUSE:
                # 6. PASSWORD_RESET_TOKEN_REUSE: Requires approved test reset token
                reset_tok = active_identity.attributes.get("reset_token") if active_identity else None
                if not reset_tok:
                    verdict = HypothesisValidationStatus.SKIPPED
                    reason = "Skipped: Missing valid researcher-controlled password reset token"
                    is_valid = False
                else:
                    use1 = self.executor.execute_request(f"{h.endpoint}?token={reset_tok}", method="POST")
                    use2 = self.executor.execute_request(f"{h.endpoint}?token={reset_tok}", method="POST")
                    if use1.get("evidence"):
                        evidence_chain.append(use1["evidence"])
                    if use2.get("evidence"):
                        evidence_chain.append(use2["evidence"])
                    verdict, reason = SafeAuthenticationValidator.validate_reset_token_reuse(
                        first_status=use1.get("status_code", 0),
                        first_body=use1.get("body", ""),
                        second_status=use2.get("status_code", 0),
                        second_body=use2.get("body", ""),
                    )
                    is_valid = (verdict == HypothesisValidationStatus.VALIDATED)

            elif h.family == AuthenticationFindingFamily.REFRESH_TOKEN_REUSE:
                # 7. REFRESH_TOKEN_REUSE: Requires test refresh token
                r_token = active_token.attributes.get("refresh_token") if active_token and hasattr(active_token, "attributes") else None
                if not r_token:
                    verdict = HypothesisValidationStatus.SKIPPED
                    reason = "Skipped: Missing valid test refresh token"
                    is_valid = False
                else:
                    payload = json.dumps({"refresh_token": r_token})
                    use1 = self.executor.execute_request(h.endpoint, method="POST", data=payload)
                    use2 = self.executor.execute_request(h.endpoint, method="POST", data=payload)
                    if use1.get("evidence"):
                        evidence_chain.append(use1["evidence"])
                    if use2.get("evidence"):
                        evidence_chain.append(use2["evidence"])
                    verdict, reason = SafeAuthenticationValidator.validate_refresh_token_reuse(
                        first_status=use1.get("status_code", 0),
                        second_status=use2.get("status_code", 0),
                        second_body=use2.get("body", ""),
                    )
                    is_valid = (verdict == HypothesisValidationStatus.VALIDATED)

            elif h.family == AuthenticationFindingFamily.PASSWORD_RESET_STATE_CONFUSION:
                # 8. PASSWORD_RESET_STATE_CONFUSION: Requires reset workflow endpoint, researcher-controlled test identity, and parameter info
                reset_surface = next((s for s in self.surfaces if s.flow_type == AuthenticationFlowType.PASSWORD_RESET), None)
                target_ep = reset_surface.endpoint if reset_surface else h.endpoint

                # Check researcher-controlled identity requirement
                is_controlled = (
                    active_identity and active_identity.username and (
                        active_identity.attributes.get("researcher_controlled") is True
                        or active_identity.attributes.get("credentials_available") is True
                    )
                )
                test_mutation = active_identity.attributes.get("test_mutation_credential") if active_identity and active_identity.attributes else None

                if not is_controlled:
                    verdict = HypothesisValidationStatus.SKIPPED
                    reason = "Skipped: Missing explicitly configured researcher-controlled test identity for password reset state validation"
                    is_valid = False
                elif not any(seg in target_ep.lower() for seg in ["reset", "password", "confirm", "update"]):
                    verdict = HypothesisValidationStatus.SKIPPED
                    reason = "Skipped: Missing discovered password reset workflow endpoint"
                    is_valid = False
                elif not test_mutation:
                    verdict = HypothesisValidationStatus.SKIPPED
                    reason = "Skipped: Missing explicitly configured researcher test mutation credential (refusing to invent arbitrary passwords)"
                    is_valid = False
                else:
                    # Parameter discovery
                    discovered_params = (getattr(reset_surface, "parameter_names", None) or getattr(reset_surface, "parameters", None)) if reset_surface else None
                    user_param = "username"
                    pass_param = "new_password"
                    token_param = "token"
                    if discovered_params and isinstance(discovered_params, list):
                        for p in discovered_params:
                            p_lower = str(p).lower()
                            if any(k in p_lower for k in ["user", "login", "account", "email"]):
                                user_param = str(p)
                            elif any(k in p_lower for k in ["pass", "pwd", "secret"]):
                                pass_param = str(p)
                            elif any(k in p_lower for k in ["token", "code", "key", "state", "ticket"]):
                                token_param = str(p)

                    # Build probe using discovered parameter names and researcher-controlled test parameters (unverified empty token)
                    probe_dict = {
                        user_param: active_identity.username,
                        pass_param: test_mutation,
                        token_param: "",
                    }
                    probe_payload = json.dumps(probe_dict)
                    probe_res = self.executor.execute_request(
                        target_ep,
                        method="POST",
                        data=probe_payload,
                        headers={"Content-Type": "application/json"},
                    )
                    if probe_res.get("evidence"):
                        evidence_chain.append(probe_res["evidence"])

                    # Determine if actual security invariant violation / state transition occurred
                    state_transition_confirmed = False
                    issued_session = None

                    # Check for session token issuance in response
                    resp_headers = probe_res.get("headers", {})
                    resp_cookies = resp_headers.get("set-cookie", "")
                    if "session=" in resp_cookies or "auth=" in resp_cookies:
                        issued_session = resp_cookies

                    resp_body = probe_res.get("body", "")
                    try:
                        resp_json = json.loads(resp_body)
                        if isinstance(resp_json, dict) and any(k in resp_json for k in ["session", "token", "access_token"]):
                            issued_session = str(resp_json.get("session") or resp_json.get("token") or resp_json.get("access_token"))
                    except Exception:
                        pass

                    # If login endpoint exists in discovered surfaces, verify if credential was actually mutated
                    login_surface = next((s for s in self.surfaces if s.flow_type == AuthenticationFlowType.LOGIN), None)
                    if login_surface and probe_res.get("status_code") in (200, 201, 204, 302):
                        login_payload = json.dumps({"username": active_identity.username, "password": test_mutation})
                        login_check = self.executor.execute_request(
                            login_surface.endpoint,
                            method="POST",
                            data=login_payload,
                            headers={"Content-Type": "application/json"},
                        )
                        if login_check.get("evidence"):
                            evidence_chain.append(login_check["evidence"])
                        if login_check.get("status_code") in (200, 201) and "session" in login_check.get("headers", {}).get("set-cookie", "").lower():
                            state_transition_confirmed = True

                    verdict, reason = SafeAuthenticationValidator.validate_password_reset_state_confusion(
                        endpoint=target_ep,
                        step_status=probe_res.get("status_code", 0),
                        step_body=probe_res.get("body", ""),
                        is_prerequisite_satisfied=False,
                        state_transition_confirmed=state_transition_confirmed,
                        issued_session_token=issued_session,
                    )
                    is_valid = (verdict == HypothesisValidationStatus.VALIDATED)

            elif h.family == AuthenticationFindingFamily.MFA_BYPASS:
                # 9. MFA_BYPASS: Requires MFA verification endpoint and researcher pre-MFA test session/token
                mfa_surface = next((s for s in self.surfaces if s.flow_type == AuthenticationFlowType.MFA_VERIFICATION), None)
                mfa_ep = mfa_surface.endpoint if mfa_surface else h.endpoint
                pre_mfa_tok = None
                if active_session and active_session.attributes:
                    pre_mfa_tok = active_session.attributes.get("pre_mfa_token")
                if not pre_mfa_tok and active_token and getattr(active_token, "token_value", None):
                    pre_mfa_tok = active_token.token_value

                if not pre_mfa_tok:
                    verdict = HypothesisValidationStatus.SKIPPED
                    reason = "Skipped: Missing pre-MFA researcher test session or token"
                    is_valid = False
                elif not any(seg in mfa_ep.lower() for seg in ["mfa", "2fa", "verify", "otp"]):
                    verdict = HypothesisValidationStatus.SKIPPED
                    reason = "Skipped: Missing discovered MFA verification challenge endpoint"
                    is_valid = False
                else:
                    mfa_payload = json.dumps({"code": "000000", "otp": "000000"})
                    mfa_headers = {"Authorization": f"Bearer {pre_mfa_tok}"} if pre_mfa_tok else {}
                    mfa_res = self.executor.execute_request(mfa_ep, method="POST", data=mfa_payload, headers=mfa_headers)
                    if mfa_res.get("evidence"):
                        evidence_chain.append(mfa_res["evidence"])

                    # Verify whether the resulting researcher session can access a known protected resource
                    session_elevated = False
                    issued_token = None

                    # Extract issued cookie or token from mfa_res
                    resp_hdrs = mfa_res.get("headers", {})
                    resp_cookie = resp_hdrs.get("set-cookie", "")
                    mfa_b = mfa_res.get("body", "")
                    try:
                        bj = json.loads(mfa_b)
                        if isinstance(bj, dict):
                            issued_token = bj.get("token") or bj.get("access_token") or bj.get("session_token")
                    except Exception:
                        pass

                    # Locate protected resource surface
                    protected_surface = next(
                        (s for s in self.surfaces if s.flow_type not in (AuthenticationFlowType.LOGIN, AuthenticationFlowType.MFA_VERIFICATION, AuthenticationFlowType.LOGOUT)
                         or any(p in s.endpoint.lower() for p in ["/profile", "/settings", "/account", "/dashboard", "/user", "/me"])),
                        None
                    )
                    test_resource_ep = protected_surface.endpoint if protected_surface else (
                        h.endpoint if not any(seg in h.endpoint.lower() for seg in ["mfa", "2fa", "otp", "verify"]) else None
                    )

                    if test_resource_ep and mfa_res.get("status_code") in (200, 201, 302):
                        # Construct test headers using resulting credentials
                        prot_headers = {}
                        if resp_cookie:
                            prot_headers["Cookie"] = resp_cookie
                        elif active_session and active_session.session_id:
                            prot_headers["Cookie"] = f"session={active_session.session_id}"

                        if issued_token:
                            prot_headers["Authorization"] = f"Bearer {issued_token}"
                        elif pre_mfa_tok:
                            prot_headers["Authorization"] = f"Bearer {pre_mfa_tok}"

                        res_check = self.executor.execute_request(test_resource_ep, method="GET", headers=prot_headers)
                        if res_check.get("evidence"):
                            evidence_chain.append(res_check["evidence"])

                        rc_status = res_check.get("status_code", 0)
                        rc_body = res_check.get("body", "")
                        rc_lower = rc_body.lower()
                        # Verify access to protected resource without MFA prompt
                        if rc_status in (200, 201) and not any(p in rc_lower for p in ["enter code", "otp", "two-factor", "2fa", "challenge"]):
                            if not AuthenticationFalsePositiveClassifier.is_public_landing_or_generic_shell(rc_status, rc_body) and \
                               not AuthenticationFalsePositiveClassifier.is_generic_status_or_empty_response(rc_status, rc_body) and \
                               not AuthenticationFalsePositiveClassifier.is_login_page_false_positive(rc_status, rc_body):
                                if any(k in rc_lower for k in ['"user_id"', '"account_id"', '"email"', 'user-profile', 'dashboard', 'settings', 'account']):
                                    session_elevated = True

                    verdict, reason = SafeAuthenticationValidator.validate_mfa_bypass(
                        endpoint=mfa_ep,
                        status_code=mfa_res.get("status_code", 0),
                        response_body=mfa_res.get("body", ""),
                        submitted_valid_code=False,
                        session_elevated=session_elevated,
                        issued_auth_token=issued_token,
                    )
                    is_valid = (verdict == HypothesisValidationStatus.VALIDATED)

            elif h.family == AuthenticationFindingFamily.MFA_STATE_CONFUSION:
                # 10. MFA_STATE_CONFUSION: Requires dual test sessions to test cross-session state isolation
                mfa_surface = next((s for s in self.surfaces if s.flow_type == AuthenticationFlowType.MFA_VERIFICATION), None)
                dual_sessions = [s for s in self.sessions if s.session_id]
                session_b_id = active_identity.attributes.get("session_b") if active_identity and active_identity.attributes else None

                if len(dual_sessions) < 2 and not session_b_id:
                    verdict = HypothesisValidationStatus.SKIPPED
                    reason = "Skipped: Missing dual test sessions to validate cross-session MFA state isolation"
                    is_valid = False
                elif not mfa_surface and not any(seg in h.endpoint.lower() for seg in ["mfa", "2fa"]):
                    verdict = HypothesisValidationStatus.SKIPPED
                    reason = "Skipped: Missing discovered MFA state transition endpoint"
                    is_valid = False
                else:
                    target_ep = mfa_surface.endpoint if mfa_surface else h.endpoint
                    sess_a_id = active_session.session_id if active_session else dual_sessions[0].session_id
                    sess_b = session_b_id or dual_sessions[1].session_id

                    # Identify protected resource to evaluate
                    protected_surf = next((s for s in self.surfaces if any(seg in s.endpoint.lower() for seg in ["/settings", "/profile", "/account", "/dashboard", "/user", "/me"])), None)
                    protected_ep = protected_surf.endpoint if protected_surf else h.endpoint

                    # 1. Baseline observation: verify Session B is initially challenged / unverified on protected resource
                    pre_res_b = self.executor.execute_request(
                        protected_ep,
                        method="GET",
                        headers={"Cookie": f"session={sess_b}"},
                    )
                    if pre_res_b.get("evidence"):
                        evidence_chain.append(pre_res_b["evidence"])

                    # 2. Session A completes/submits factor verification (Session B does NOT submit)
                    action_res_a = self.executor.execute_request(
                        target_ep,
                        method="POST",
                        headers={"Cookie": f"session={sess_a_id}"},
                        data=json.dumps({"factor_step": "complete"}),
                    )
                    if action_res_a.get("evidence"):
                        evidence_chain.append(action_res_a["evidence"])

                    # 3. Post-action observation: check whether Session B gained unauthorized access to protected resource
                    post_res_b = self.executor.execute_request(
                        protected_ep,
                        method="GET",
                        headers={"Cookie": f"session={sess_b}"},
                    )
                    if post_res_b.get("evidence"):
                        evidence_chain.append(post_res_b["evidence"])

                    # Cross-session escalation occurs ONLY if Session B was challenged pre-action and gained access post-action
                    pre_b_challenged = pre_res_b.get("status_code") in (401, 403) or any(
                        p in pre_res_b.get("body", "").lower() for p in ["enter code", "otp", "2fa", "verify identity", "challenge"]
                    )
                    post_b_status = post_res_b.get("status_code", 0)
                    post_b_body = post_res_b.get("body", "")
                    not_generic = not AuthenticationFalsePositiveClassifier.is_public_landing_or_generic_shell(post_b_status, post_b_body) and \
                                  not AuthenticationFalsePositiveClassifier.is_generic_status_or_empty_response(post_b_status, post_b_body) and \
                                  not AuthenticationFalsePositiveClassifier.is_login_page_false_positive(post_b_status, post_b_body)
                    has_protected = any(
                        k in post_b_body.lower() for k in ['"user_id"', '"account_id"', '"email"', 'user-profile', 'dashboard', 'settings', 'account balance', 'user details']
                    )
                    no_mfa_prompt = not any(p in post_b_body.lower() for p in ["enter code", "otp", "two-factor", "2fa", "verify identity", "challenge"])
                    cross_session_elevated = pre_b_challenged and (post_b_status in (200, 201)) and not_generic and has_protected and no_mfa_prompt

                    verdict, reason = SafeAuthenticationValidator.validate_mfa_state_confusion(
                        endpoint=protected_ep,
                        pre_status_b=pre_res_b.get("status_code", 0),
                        pre_body_b=pre_res_b.get("body", ""),
                        post_status_b=post_b_status,
                        post_body_b=post_b_body,
                        cross_session_elevated=cross_session_elevated,
                    )
                    is_valid = (verdict == HypothesisValidationStatus.VALIDATED)

            elif h.family == AuthenticationFindingFamily.AUTHENTICATION_STATE_INCONSISTENCY:
                # 11. AUTHENTICATION_STATE_INCONSISTENCY: Requires multi-component check endpoint and session context
                status_surface = next((s for s in self.surfaces if any(seg in s.endpoint.lower() for seg in ["/status", "/check", "/me", "/whoami"])), None)
                test_sess = active_session.session_id if active_session else None
                test_tok = active_token.token_value if active_token and getattr(active_token, "token_value", None) else None

                if not status_surface:
                    h.validation_status = HypothesisValidationStatus.SKIPPED
                    h.rationale = "Skipped: Missing discovered authentication status verification endpoint (e.g. /status, /me)"
                    continue
                elif not test_sess and not test_tok:
                    h.validation_status = HypothesisValidationStatus.SKIPPED
                    h.rationale = "Skipped: Missing researcher test session or token to verify cross-boundary state consistency"
                    continue
                else:
                    auth_headers = {}
                    if test_tok:
                        auth_headers["Authorization"] = f"Bearer {test_tok}"
                    if test_sess:
                        auth_headers["Cookie"] = f"session={test_sess}"

                    # 1. Authenticated baseline check on resource endpoint
                    baseline_res = self.executor.execute_request(h.endpoint, method="GET", headers=auth_headers)
                    if baseline_res.get("evidence"):
                        evidence_chain.append(baseline_res["evidence"])

                    # 2. Check auth status component response (reports unauthenticated / logged out)
                    status_res = self.executor.execute_request(status_surface.endpoint, method="GET")
                    if status_res.get("evidence"):
                        evidence_chain.append(status_res["evidence"])

                    # 3. Check unauthenticated access to resource endpoint
                    unauth_resource_res = self.executor.execute_request(h.endpoint, method="GET")
                    if unauth_resource_res.get("evidence"):
                        evidence_chain.append(unauth_resource_res["evidence"])

                    verdict, reason = SafeAuthenticationValidator.validate_authentication_state_inconsistency(
                        endpoint=h.endpoint,
                        auth_status_code=status_res.get("status_code", 0),
                        auth_status_body=status_res.get("body", ""),
                        resource_status_code=unauth_resource_res.get("status_code", 0),
                        resource_body=unauth_resource_res.get("body", ""),
                        baseline_status_code=baseline_res.get("status_code", 0),
                        baseline_body=baseline_res.get("body", ""),
                    )
                    is_valid = (verdict == HypothesisValidationStatus.VALIDATED)

            elif h.family in (
                AuthenticationFindingFamily.SESSION_NOT_ROTATED,
                AuthenticationFindingFamily.TOKEN_TRANSPORT_EXPOSURE,
                AuthenticationFindingFamily.AUTHENTICATION_CONFIGURATION_WEAKNESS,
            ):
                # 12, 13, 14. Observation-only families
                verdict = HypothesisValidationStatus.INFORMATIONAL
                reason = f"Observation-only property noted for {h.family}; incomplete evidence cannot escalate without differential proof."
                is_valid = False

            else:
                verdict = HypothesisValidationStatus.REJECTED
                reason = f"Validation rules for {h.family} did not confirm vulnerability."
                is_valid = False

            h.validation_status = verdict
            h.rationale = reason

            if verdict in (HypothesisValidationStatus.VALIDATED, HypothesisValidationStatus.INFORMATIONAL):
                sev, cvss = AuthenticationPrioritizer.score_finding(h.family)
                clean_ep = AuthenticationEvidenceManager.sanitize_url(h.endpoint)
                clean_reason = AuthenticationEvidenceManager.sanitize(reason)
                f = AuthenticationFindingCandidate(
                    finding_id=f"FIND-AUTH-{hashlib.sha256(f'{h.hypothesis_id}|{clean_ep}'.encode()).hexdigest()[:8]}",
                    title=f"Authentication Flaw: {h.family} on {clean_ep}",
                    family=h.family,
                    severity=sev,
                    confidence="CONFIRMED" if is_valid else "MEDIUM",
                    endpoint=clean_ep,
                    identity_id=h.principal,
                    description=clean_reason,
                    evidence_chain=evidence_chain,
                    cvss_score=cvss,
                    remediation="Remediate authentication state or session invalidation logic.",
                )
                self.findings.append(f)
                scope_ref = getattr(self.policy, "scope_file", "scope/scope.yaml") or "scope/scope.yaml"
                try:
                    native_f = f.to_native_finding(scope_ref=scope_ref, is_validated=is_valid)
                    self.state_manager.save_finding(native_f)
                except Exception as ex:
                    import sys
                    print(f"[-] Persistence error saving finding {f.finding_id}: {ex}", file=sys.stderr)
                    f.description += f" [PERSISTENCE_ERROR: {ex}]"

        return self.findings

    def execute_lab_simulation(self) -> Dict[str, Any]:
        """Executes all 21 scenarios in the deterministic local authentication lab."""
        results = LocalAuthenticationSecurityLab.run_all()
        passed = sum(1 for r in results if r["matches_expectation"])
        total = len(results)

        for r in results:
            if r["verdict"] == HypothesisValidationStatus.VALIDATED.value:
                scen = LocalAuthenticationSecurityLab.SCENARIOS[r["scenario_id"]]
                family = scen.get("expected_family") or AuthenticationFindingFamily.AUTHENTICATION_BYPASS
                scen_id = r["scenario_id"]
                finding_suffix = hashlib.sha256(f"lab_{scen_id}".encode()).hexdigest()[:8]
                sev, cvss = AuthenticationPrioritizer.score_finding(family)
                candidate = AuthenticationFindingCandidate(
                    finding_id=f"FIND-AUTH-{finding_suffix}",
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
                try:
                    native_finding = candidate.to_native_finding(scope_ref="scope/scope.yaml", is_validated=True)
                    self.state_manager.save_finding(native_finding)
                except Exception as ex:
                    import sys
                    print(f"[-] Persistence error saving lab finding {candidate.finding_id}: {ex}", file=sys.stderr)
                    candidate.description += f" [PERSISTENCE_ERROR: {ex}]"

        return {
            "total_scenarios": total,
            "passed_scenarios": passed,
            "success_rate": round(passed / total * 100, 1),
            "findings_generated": len(self.findings),
            "details": results,
        }

    def render_tree(self) -> str:
        """Renders an ASCII tree view of authentication surfaces, hypotheses, and findings."""
        validated_findings = [f for f in self.findings if f.confidence == "CONFIRMED"]
        informational_findings = [f for f in self.findings if f.confidence != "CONFIRMED"]
        skipped_count = sum(1 for h in self.hypotheses if h.validation_status == HypothesisValidationStatus.SKIPPED)
        needs_appr_count = sum(1 for h in self.hypotheses if h.validation_status == HypothesisValidationStatus.NEEDS_APPROVAL)

        lines = [
            "BugBounty-Agent - Authentication, Session & Identity Intelligence",
            "==================================================================",
            f"Workspace:    {self.workspace_dir}",
            f"Surfaces:     {len(self.surfaces)} discovered",
            f"Identities:   {len(self.identities)} tracked",
            f"Hypotheses:   {len(self.hypotheses)} generated",
            f"Validated:    {len(validated_findings)} verified",
            f"Information:  {len(informational_findings)} observations",
            f"Skipped:      {skipped_count} missing prerequisites",
            f"Pending Appr: {needs_appr_count} pending confirmation",
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
        lines.append("[+] VALIDATED FINDINGS (OPERATIONAL PROOF):")
        if not validated_findings:
            lines.append("    (No validated findings)")
        else:
            for f in validated_findings:
                lines.append(f"    \\-- [VALIDATED FINDING] [{f.severity}] {f.title} (CVSS {f.cvss_score})")
                lines.append(f"        Endpoint: {f.endpoint}")
                lines.append(f"        Family:   {f.family}")
                lines.append(f"        Guidance: {f.remediation}")

        if informational_findings:
            lines.append("")
            lines.append("[+] INFORMATIONAL OBSERVATIONS & HARDENING NOTES:")
            for f in informational_findings:
                lines.append(f"    \\-- [OBSERVATION / INFORMATIONAL] [{f.severity}] {f.title}")
                lines.append(f"        Endpoint: {f.endpoint}")
                lines.append(f"        Family:   {f.family}")
                lines.append(f"        Note:     {f.description}")

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
        self.state_manager.update_coverage("authentication", "high" if self.findings else "partial")
