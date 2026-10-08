"""
Identity Modeling Engine for BugBounty-Agent (Phase 14).

Models security identities, researcher-controlled principals, and their authentication states.
Provides bi-directional bridging with Phase 8 PrincipalProfile.
Enforces credential safety: strictly forbids storing raw passwords or session tokens.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import uuid

from framework.authentication.models import (
    AuthenticationState,
    IdentityProfile,
    PrincipalType,
)
from framework.authz.model import PrincipalProfile


class IdentityManager:
    """Manages identity profiles and bridges with Phase 8 authorization principals."""

    def __init__(self) -> None:
        self._identities: Dict[str, IdentityProfile] = {}

    def register_identity(
        self,
        username: str,
        role: str = "USER",
        tenant: Optional[str] = None,
        identity_id: Optional[str] = None,
        state: AuthenticationState = AuthenticationState.UNKNOWN,
        source: str = "RESEARCHER",
        attributes: Optional[Dict[str, Any]] = None,
    ) -> IdentityProfile:
        """
        Registers a researcher-controlled or observed identity.
        Sanitizes attributes to ensure no password or secret data can be persisted.
        """
        clean_attrs = attributes or {}
        # Strip any credential-like fields proactively
        forbidden_keys = {"password", "pass", "pwd", "secret", "token", "raw_cookie", "api_key"}
        sanitized_attrs = {
            k: v for k, v in clean_attrs.items()
            if not any(fk in k.lower() for fk in forbidden_keys)
        }

        iid = identity_id or f"id_{uuid.uuid4().hex[:8]}"
        profile = IdentityProfile(
            identity_id=iid,
            username=username,
            display_name=username,
            role=role.upper(),
            tenant=tenant,
            authentication_state=state,
            source=source,
            confidence=1.0,
            evidence_refs=[],
            attributes=sanitized_attrs,
        )
        self._identities[iid] = profile
        return profile

    def get_identity(self, identity_id: str) -> Optional[IdentityProfile]:
        return self._identities.get(identity_id)

    def list_identities(self) -> List[IdentityProfile]:
        return list(self._identities.values())

    def update_state(self, identity_id: str, new_state: AuthenticationState) -> bool:
        if identity_id in self._identities:
            self._identities[identity_id].authentication_state = new_state
            return True
        return False

    @staticmethod
    def to_principal_profile(identity: IdentityProfile) -> PrincipalProfile:
        """Converts an IdentityProfile to Phase 8 PrincipalProfile for authorization checks."""
        privilege_map = {
            "ANONYMOUS": 0,
            "USER": 10,
            "PRIVILEGED_USER": 50,
            "ADMIN": 100,
            "SERVICE_ACCOUNT": 30,
        }
        priv_level = privilege_map.get(identity.role, 10)
        return PrincipalProfile(
            principal_id=identity.identity_id,
            role=identity.role,
            tenant_id=identity.tenant,
            privilege_level=priv_level,
            masked_metadata={"source": identity.source, "username": identity.username, "auth_state": identity.authentication_state.value},
        )

    @staticmethod
    def from_principal_profile(principal: PrincipalProfile) -> IdentityProfile:
        """Constructs an IdentityProfile from Phase 8 PrincipalProfile."""
        is_active = (
            principal.masked_metadata.get("auth_state") == AuthenticationState.AUTHENTICATED.value
            or principal.privilege_level > 0
        )
        state = (
            AuthenticationState.AUTHENTICATED
            if is_active
            else AuthenticationState.ANONYMOUS
        )
        username = principal.masked_metadata.get("username", principal.principal_id)
        return IdentityProfile(
            identity_id=principal.principal_id,
            username=username,
            role=principal.role,
            tenant=principal.tenant_id,
            authentication_state=state,
            source="PHASE_8_AUTHZ",
            confidence=0.9,
            attributes={"privilege_level": principal.privilege_level},
        )
