"""
Authentication Security Policy & Approval Gate (Phase 14).

Enforces non-destructive boundaries, researcher-controlled identity constraints,
request limits, anti-SSRF protections, and human approval gating for state-changing operations.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from framework.scope.engine import ScopeEngine


class AuthenticationSecurityPolicy:
    """Enforces safety rules and resource boundaries for authentication testing."""

    DEFAULT_TIMEOUT_SECONDS = 8.0
    MAX_REQUESTS_PER_HYPOTHESIS = 5
    MAX_RESPONSE_BYTES = 1024 * 1024  # 1 MB

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

    def __init__(self, scope_engine: Optional[ScopeEngine] = None) -> None:
        self.scope_engine = scope_engine

    def is_target_allowed(self, target_url: str) -> Tuple[bool, str]:
        """Validates that target URL is in-scope and does not target prohibited cloud metadata."""
        if not target_url:
            return False, "Target URL is empty"

        parsed = urlparse(target_url)
        host = parsed.hostname or ""

        # Block metadata and link-local IP addresses
        if host in ("169.254.169.254", "metadata.google.internal", "127.0.0.1", "localhost"):
            # Only permit localhost if explicitly in local lab mode
            if not target_url.startswith("http://127.0.0.1:lab") and not target_url.startswith("local-lab://"):
                return False, f"Target '{host}' is prohibited internal/metadata infrastructure"

        # Check ScopeEngine if configured
        if self.scope_engine:
            decision = self.scope_engine.evaluate(host)
            if not decision.allowed:
                return False, f"Target host '{host}' is out-of-scope: {decision.reason}"

        return True, "Target is permissible under authentication security policy"

    def requires_human_approval(self, operation: str) -> bool:
        """Determines if an authentication operation mutates account state and requires approval."""
        sensitive_mutations = {
            "PASSWORD_CHANGE",
            "PASSWORD_RESET_SUBMIT",
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
    ) -> Tuple[bool, str]:
        """Validates operator approval before executing a sensitive mutation."""
        if not is_approved:
            return (
                False,
                f"Operation '{dossier.get('planned_operation')}' on '{dossier.get('endpoint')}' "
                f"requires explicit operator confirmation (--approve). Aborting for safety.",
            )
        return True, "Operator approval confirmed. Proceeding with operation."
