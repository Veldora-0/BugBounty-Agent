"""
Authorization Validation Foundation for BugBounty-Agent.

Provides data models and comparative abstractions for dual-principal access control
analysis (IDOR, BOLA, BFLA, Multi-tenant Isolation) without destructive exploitation,
automated account creation, or credential harvesting.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from framework.common.evidence import sanitize_sensitive_data


class Principal:
    """Represents an authenticated or anonymous security principal."""

    def __init__(
        self,
        principal_id: str,
        role: str = "USER",
        tenant_id: Optional[str] = None,
        auth_token_masked: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.principal_id = principal_id.strip()
        self.role = role.strip().upper()
        self.tenant_id = tenant_id.strip() if tenant_id else None
        # Always sanitize auth token representation
        clean_tok = sanitize_sensitive_data(auth_token_masked or "")
        self.auth_token_masked = clean_tok if clean_tok else "[MASKED_TOKEN]"
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        """Serializes principal metadata."""
        return {
            "principal_id": self.principal_id,
            "role": self.role,
            "tenant_id": self.tenant_id,
            "auth_token_masked": self.auth_token_masked,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Principal:
        """Deserializes principal."""
        return cls(
            principal_id=data.get("principal_id", ""),
            role=data.get("role", "USER"),
            tenant_id=data.get("tenant_id"),
            auth_token_masked=data.get("auth_token_masked"),
            metadata=data.get("metadata", {}),
        )


class SessionContext:
    """Session credentials and contextual headers for a specific principal."""

    def __init__(
        self,
        principal: Principal,
        session_id: str,
        headers_template: Optional[Dict[str, str]] = None,
        cookies_template: Optional[Dict[str, str]] = None,
        is_authenticated: bool = True,
    ):
        self.principal = principal
        self.session_id = session_id
        # Sanitize headers and cookies templates to prevent token persistence
        clean_headers = {}
        for k, v in (headers_template or {}).items():
            sanitized_line = sanitize_sensitive_data(f"{k}: {v}")
            if ": " in sanitized_line:
                clean_headers[k] = sanitized_line.split(": ", 1)[1]
            else:
                clean_headers[k] = sanitized_line
        self.headers_template = clean_headers

        clean_cookies = {}
        for k, v in (cookies_template or {}).items():
            sanitized_cookie = sanitize_sensitive_data(f"Cookie: {k}={v}")
            if "=" in sanitized_cookie:
                clean_cookies[k] = sanitized_cookie.split("=", 1)[1]
            else:
                clean_cookies[k] = sanitized_cookie
        self.cookies_template = clean_cookies

        self.is_authenticated = bool(is_authenticated)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "principal": self.principal.to_dict(),
            "session_id": self.session_id,
            "headers_template": self.headers_template,
            "cookies_template": self.cookies_template,
            "is_authenticated": self.is_authenticated,
        }


class ResourceIdentifier:
    """Represents an application resource subject to access control checks."""

    def __init__(
        self,
        resource_id: str,
        resource_type: str,
        owner_principal_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        endpoint_template: str = "",
    ):
        self.resource_id = str(resource_id).strip()
        self.resource_type = resource_type.strip().lower()
        self.owner_principal_id = str(owner_principal_id).strip() if owner_principal_id else None
        self.tenant_id = str(tenant_id).strip() if tenant_id else None
        self.endpoint_template = endpoint_template.strip()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "owner_principal_id": self.owner_principal_id,
            "tenant_id": self.tenant_id,
            "endpoint_template": self.endpoint_template,
        }


class ExpectedAccessPolicy:
    """Defines expected access control permissions for a resource."""

    def __init__(
        self,
        policy_id: str,
        allowed_principals: Optional[List[str]] = None,
        allowed_roles: Optional[List[str]] = None,
        expected_status_allowed: int = 200,
        expected_status_denied: int = 403,
    ):
        self.policy_id = policy_id.strip()
        self.allowed_principals = list(allowed_principals or [])
        self.allowed_roles = list(allowed_roles or [])
        self.expected_status_allowed = int(expected_status_allowed)
        self.expected_status_denied = int(expected_status_denied)

    def is_principal_authorized(self, principal: Principal) -> bool:
        """Evaluates whether the principal is authorized under this policy."""
        if principal.principal_id in self.allowed_principals:
            return True
        if principal.role in self.allowed_roles:
            return True
        return False


class AuthorizationComparisonResult:
    """
    Comparison outcome of two principals attempting access to the same resource.
    Does not assume vulnerability unless access policy divergence is confirmed.
    """

    def __init__(
        self,
        resource: ResourceIdentifier,
        principal_a: Principal,
        principal_b: Principal,
        status_a: int,
        status_b: int,
        access_divergence: bool,
        is_violation_suspected: bool,
        notes: str = "",
    ):
        self.resource = resource
        self.principal_a = principal_a
        self.principal_b = principal_b
        self.status_a = int(status_a)
        self.status_b = int(status_b)
        self.access_divergence = bool(access_divergence)
        self.is_violation_suspected = bool(is_violation_suspected)
        self.notes = notes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource": self.resource.to_dict(),
            "principal_a": self.principal_a.to_dict(),
            "principal_b": self.principal_b.to_dict(),
            "status_a": self.status_a,
            "status_b": self.status_b,
            "access_divergence": self.access_divergence,
            "is_violation_suspected": self.is_violation_suspected,
            "notes": self.notes,
        }


def compare_dual_principal_access(
    resource: ResourceIdentifier,
    owner_principal: Principal,
    owner_status: int,
    unauthorized_principal: Principal,
    unauthorized_status: int,
    policy: ExpectedAccessPolicy,
) -> AuthorizationComparisonResult:
    """
    Compares responses between authorized owner and unauthorized principal.
    Identifies candidate authorization divergence without destructive side effects.
    """
    # Does unauthorized principal get 200 OK when policy expected 403 / 401 / 404?
    divergence = False
    violation = False
    notes = []

    if unauthorized_status == 200 and not policy.is_principal_authorized(unauthorized_principal):
        divergence = True
        violation = True
        notes.append(
            f"Unauthorized principal '{unauthorized_principal.principal_id}' received HTTP {unauthorized_status} "
            f"for resource owned by '{owner_principal.principal_id}'."
        )
    elif unauthorized_status in (401, 403, 404):
        notes.append(f"Endpoint properly enforced access control: HTTP {unauthorized_status}.")
    else:
        divergence = owner_status != unauthorized_status
        notes.append(f"Status codes differed: owner={owner_status}, unauthorized={unauthorized_status}.")

    return AuthorizationComparisonResult(
        resource=resource,
        principal_a=owner_principal,
        principal_b=unauthorized_principal,
        status_a=owner_status,
        status_b=unauthorized_status,
        access_divergence=divergence,
        is_violation_suspected=violation,
        notes=" ".join(notes),
    )
