"""
Identity Modeling Engine for BugBounty-Agent (Phase 14.1).

Models security identities, researcher-controlled principals, and their authentication states.
Provides bi-directional bridging with Phase 8 PrincipalProfile and ingests principals from
state/authorization.json.
Enforces credential safety: strictly forbids storing raw passwords or session tokens.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple
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

    def seed_from_authorization_state(self, program_dir: str) -> List[IdentityProfile]:
        """
        Ingests principals from Phase 8 state/authorization.json.
        Schema: 'principals' is a dictionary of {principal_id: dict}.
        Gracefully tolerates missing, empty, or corrupted files.
        """
        seeded: List[IdentityProfile] = []
        filepath = os.path.join(program_dir, "state", "authorization.json")
        if not os.path.isfile(filepath):
            filepath = os.path.join(program_dir, "authorization.json")

        if not os.path.isfile(filepath):
            return seeded

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return seeded

        if not isinstance(data, dict):
            return seeded

        principals = data.get("principals", {})
        principal_items: List[Tuple[str, Dict[str, Any]]] = []
        if isinstance(principals, dict):
            for pid, pdata in principals.items():
                if isinstance(pdata, dict):
                    principal_items.append((pid, pdata))
        elif isinstance(principals, list):
            for item in principals:
                if isinstance(item, dict):
                    pid = item.get("principal_id") or item.get("username") or f"id_{uuid.uuid4().hex[:8]}"
                    principal_items.append((pid, item))

        for pid, pdata in principal_items:
            username = pdata.get("username") or pdata.get("principal_id") or pid
            role = pdata.get("role", "USER")
            tenant = pdata.get("tenant") or pdata.get("tenant_id")
            priv_level = pdata.get("privilege_level", 10)
            is_active = pdata.get("is_active", True)
            state = AuthenticationState.AUTHENTICATED if is_active else AuthenticationState.ANONYMOUS

            prof = self.register_identity(
                username=username,
                role=role,
                tenant=tenant,
                identity_id=pid,
                state=state,
                source="PHASE_8_AUTHORIZATION",
                attributes={"privilege_level": priv_level},
            )
            seeded.append(prof)

        return seeded

    def get_identity(self, identity_id: str) -> Optional[IdentityProfile]:
        if identity_id in self._identities:
            return self._identities[identity_id]
        for p in self._identities.values():
            if p.username == identity_id:
                return p
        return None

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
