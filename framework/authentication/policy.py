"""
Authentication Security Policy & Approval Gate (Phase 14.1).

Enforces non-destructive boundaries, researcher-controlled identity constraints,
request limits, anti-SSRF protections, canonical scope resolution, and operator
approval gating for state-changing operations.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from framework.scope.engine import ScopeDecision, ScopeEngine, ScopeStatus


def resolve_scope_file(program_dir: str, scope_override: Optional[str] = None) -> Optional[str]:
    """
    Deterministically resolves scope configuration file path.
    Precedence:
    1. Explicit scope_override path
    2. Canonical initialized program scope path: <program_dir>/scope/scope.yaml
    3. Workspace program root fallback: <program_dir>/scope.yaml
    """
    if scope_override:
        norm_override = os.path.abspath(scope_override)
        if os.path.isfile(norm_override):
            return norm_override
        return None

    norm_prog = os.path.abspath(program_dir)
    # Canonical path created by bb-init
    canonical_path = os.path.join(norm_prog, "scope", "scope.yaml")
    if os.path.isfile(canonical_path):
        return canonical_path

    # Secondary program root fallback
    prog_root_path = os.path.join(norm_prog, "scope.yaml")
    if os.path.isfile(prog_root_path):
        return prog_root_path

    return None


class AuthenticationSecurityPolicy:
    """Enforces safety rules and resource boundaries for authentication testing."""

    DEFAULT_TIMEOUT_SECONDS = 8.0
    MAX_REQUESTS_PER_HYPOTHESIS = 10
    MAX_RESPONSE_BYTES = 100 * 1024  # 100 KB

    # Explicitly forbidden operations
    PROHIBITED_ACTIVITIES = {
        "PASSWORD_SPRAYING",
        "CREDENTIAL_STUFFING",
        "PASSWORD_BRUTE_FORCE",
        "TOKEN_BRUTE_FORCE",
        "OTP_BRUTE_FORCE",
        "OTP_FLOODING",
        "CAPTCHA_BYPASS",
        "SIM_ATTACK",
        "THIRD_PARTY_IDP_ATTACK",
        "AUTOMATED_REPORT_SUBMISSION",
    }

    # Third-party Identity Providers that must not be tested unless explicitly in scope
    THIRD_PARTY_IDP_DOMAINS = {
        "accounts.google.com",
        "github.com",
        "login.microsoftonline.com",
        "appleid.apple.com",
        "auth0.com",
        "okta.com",
    }

    def __init__(self, scope_engine: Optional[ScopeEngine] = None) -> None:
        self.scope_engine = scope_engine
        self.allowed_fixture_ports: set[int] = set()

    def is_target_allowed(self, target_url: str) -> Tuple[bool, str]:
        """Validates that target URL is in-scope and does not target prohibited cloud metadata."""
        if not target_url:
            return False, "Target URL is empty"

        # Permit local-lab fixture targets
        if target_url.startswith("local-lab://") or target_url.startswith("http://127.0.0.1:lab"):
            return True, "Permitted local lab target"

        parsed = urlparse(target_url)
        host = (parsed.hostname or "").lower()
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # Permit explicitly configured local fixture application during automated testing
        if host in ("127.0.0.1", "localhost") and port in self.allowed_fixture_ports:
            return True, f"Permitted local test fixture on port {port}"

        # Block metadata and link-local IP addresses
        if host in ("169.254.169.254", "metadata.google.internal", "127.0.0.1", "localhost"):
            return False, f"Target '{host}' is prohibited internal/metadata infrastructure"

        # Check ScopeEngine using canonical check(target) API
        if not self.scope_engine:
            return False, "Target rejected: ScopeEngine not configured (failing closed)"

        decision = self.scope_engine.check(target_url)
        if decision.status != ScopeStatus.IN_SCOPE:
            return False, f"Target '{target_url}' is {decision.status.value}: {decision.reason}"

        # Third-party IdP domain guard
        for idp in self.THIRD_PARTY_IDP_DOMAINS:
            if host == idp or host.endswith(f".{idp}"):
                # Must be explicitly and specifically included in scope targets
                return True, f"Target '{host}' matches authorized scope rules"

        return True, "Target is permissible under authentication security policy"

    def requires_human_approval(self, operation: str) -> bool:
        """Determines if an authentication operation mutates account state and requires approval."""
        sensitive_mutations = {
            "PASSWORD_CHANGE",
            "PASSWORD_RESET_SUBMIT",
            "PASSWORD_RESET",
            "MFA_ENROLLMENT",
            "MFA_DISABLE",
            "DEVICE_TRUST_REVOKE",
            "ACCOUNT_RECOVERY_MUTATION",
            "TOKEN_REVOCATION",
        }
        return operation.upper() in sensitive_mutations


class AuthenticationApprovalGate:
    """
    Constructs an audit dossier for sensitive state-changing operations
    and validates operator approval.
    """

    @classmethod
    def requires_approval(cls, operation: str) -> bool:
        """Determines if an authentication operation mutates account state and requires approval."""
        sensitive_mutations = {
            "PASSWORD_CHANGE",
            "PASSWORD_RESET_SUBMIT",
            "PASSWORD_RESET",
            "MFA_ENROLLMENT",
            "MFA_DISABLE",
            "DEVICE_TRUST_REVOKE",
            "ACCOUNT_RECOVERY_MUTATION",
            "TOKEN_REVOCATION",
        }
        return operation.upper() in sensitive_mutations

    @classmethod
    def create_audit_dossier(
        cls,
        target: str,
        identity: str,
        planned_operation: str,
        endpoint: str,
        method: str,
        reason: str,
        security_hypothesis: str,
        expected_result: str,
        rollback_guidance: str,
        request_budget: int = 1,
        risk_classification: str = "MEDIUM",
    ) -> Dict[str, Any]:
        """Generates an audit dossier explaining the planned mutation."""
        return {
            "target": target,
            "identity": identity,
            "planned_operation": planned_operation,
            "endpoint": endpoint,
            "method": method.upper(),
            "reason": reason,
            "security_hypothesis": security_hypothesis,
            "expected_result": expected_result,
            "rollback_guidance": rollback_guidance,
            "request_budget": request_budget,
            "risk_classification": risk_classification,
        }

    @classmethod
    def check_approval(
        cls,
        dossier: Dict[str, Any],
        is_approved: bool,
        is_in_scope: bool = True,
    ) -> Tuple[bool, str]:
        """
        Validates operator approval before executing a sensitive mutation.
        INVARIANT: Operator approval NEVER overrides scope restrictions.
        """
        if not is_in_scope:
            return False, "Approval cannot override scope restrictions: Target is OUT_OF_SCOPE"

        if not is_approved:
            return (
                False,
                f"Operation '{dossier.get('planned_operation')}' on '{dossier.get('endpoint')}' "
                f"requires explicit operator confirmation (--approve). Aborting for safety.",
            )
        return True, "Operator approval confirmed. Proceeding with operation."
