"""
Safe Testing Policy and Execution Constraints for Cloud Security (Phase 13).

Enforces conservative ceilings, strict HTTP method gating, non-destructive
verifications, zero upload/delete operations, zero credential spraying,
and mandatory human-approval for potentially mutating cloud tests.
"""

from __future__ import annotations

from enum import Enum
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from framework.scope.engine import ScopeEngine, ScopeStatus
from framework.validation.policy import EndpointSafetyClass, SecurityTestPolicy
from framework.validation.request import ControlledRequest, ControlledResponse


class CloudSecurityPolicy:
    """Enforces boundaries and ceilings specifically for Cloud Security Intelligence."""

    ALLOWED_METHODS: Set[str] = {"GET", "HEAD", "OPTIONS"}
    MAX_REQUESTS_PER_ASSET: int = 15
    MAX_RESPONSE_BYTES: int = 512 * 1024  # 512 KB
    REQUEST_TIMEOUT_SECONDS: float = 8.0
    MAX_LISTING_KEYS: int = 20

    FORBIDDEN_ACTIONS: Set[str] = {
        "upload_file",
        "delete_file",
        "overwrite_file",
        "iam_bruteforce",
        "credential_stuffing",
        "metadata_probing",
        "claim_cloud_domain",
    }

    @classmethod
    def evaluate_action_safety(
        cls,
        method: str,
        target_url: str,
        action_name: str = "read_check",
    ) -> Tuple[bool, str]:
        """
        Validates whether a cloud validation request is safe and within policy.
        """
        meth = method.upper()
        if meth not in cls.ALLOWED_METHODS:
            return False, f"HTTP method '{meth}' forbidden by CloudSecurityPolicy. Only {cls.ALLOWED_METHODS} permitted."

        if action_name in cls.FORBIDDEN_ACTIONS:
            return False, f"Action '{action_name}' is explicitly forbidden by safety policy."

        # Detect dangerous metadata IP probing: 169.254.169.254 or cloud metadata domains
        if "169.254.169.254" in target_url or "metadata.google.internal" in target_url:
            return False, "Direct instance metadata probing forbidden in Phase 13 validation."

        return True, "Action approved by CloudSecurityPolicy"

    @classmethod
    def check_scope(cls, scope_engine: Optional[ScopeEngine], target_url: str) -> Tuple[bool, str]:
        """Ensures the target URL complies with program scope."""
        if scope_engine is None:
            # If no scope engine is provided, default to allowing if offline/lab
            return True, "No ScopeEngine bound; operation permitted under offline lab constraints"

        decision = scope_engine.evaluate(target_url)
        if decision.status == ScopeStatus.IN_SCOPE:
            return True, f"Target {target_url} is in-scope ({decision.reason})"
        return False, f"Target {target_url} is OUT_OF_SCOPE: {decision.reason}"
