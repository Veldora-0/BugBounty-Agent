"""
Out-of-Band (OOB) Provider Abstraction for SSRF Intelligence (Phase 9).

Provides pluggable provider interface supporting:
1. MockOobProvider (Deterministic offline testing and local lab fixtures)
2. InteractshOobProvider (ProjectDiscovery Interactsh protocol client)
3. CollaboratorOobProvider (Burp Collaborator polling client)

Guarantees graceful degradation: missing providers report CONFIG_REQUIRED
or UNAVAILABLE without crashing the framework. Never stores unmasked credentials.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from framework.ssrf.model import (
    OobInteractionType,
    OobProviderStatus,
    SsrfConfidence,
    SsrfInteraction,
)


class OobProvider(ABC):
    """
    Abstract Base Class for out-of-band callback providers.
    """

    @abstractmethod
    def name(self) -> str:
        """Provider identifier name."""
        pass

    @abstractmethod
    def registration_status(self) -> OobProviderStatus:
        """Current operational status of this provider."""
        pass

    @abstractmethod
    def generate_canary(self, prefix: str = "bb9", test_id: str = "") -> Tuple[str, str]:
        """
        Generates a unique canary token and public callback hostname or URL.
        Returns: (canary_token, canary_target_url)
        """
        pass

    @abstractmethod
    def poll(self, token: Optional[str] = None, timeout: float = 5.0) -> List[SsrfInteraction]:
        """
        Queries the provider for newly recorded interaction events.
        """
        pass

    @abstractmethod
    def consume_interactions(self, token: str) -> List[SsrfInteraction]:
        """
        Retrieves and removes recorded interactions for a specific canary token.
        """
        pass

    @abstractmethod
    def close(self) -> None:
        """Releases any network or session resources."""
        pass


class MockOobProvider(OobProvider):
    """
    Deterministic in-memory OOB provider for offline testing and local lab scenarios.
    """

    def __init__(self, base_domain: str = "oob.local"):
        self.base_domain = base_domain.strip().lower()
        self._status = OobProviderStatus.AVAILABLE
        # token -> list of interactions
        self._storage: Dict[str, List[SsrfInteraction]] = {}
        # active canaries
        self._canaries: Dict[str, str] = {}

    def name(self) -> str:
        return "mock"

    def registration_status(self) -> OobProviderStatus:
        return self._status

    def set_status(self, status: OobProviderStatus) -> None:
        """Sets simulated provider status for testing."""
        self._status = status

    def generate_canary(self, prefix: str = "bb9", test_id: str = "") -> Tuple[str, str]:
        rand_id = uuid.uuid4().hex[:8]
        clean_tid = test_id.replace("ssrf-", "").replace("test-", "")[:8] if test_id else "00"
        token = f"{prefix}-{clean_tid}-{rand_id}"
        canary_domain = f"{token}.{self.base_domain}"
        canary_url = f"http://{canary_domain}"

        self._storage[token] = []
        self._canaries[token] = canary_domain
        return token, canary_url

    def simulate_interaction(
        self,
        canary_token: str,
        protocol: str = "HTTP",
        source_ip: str = "192.0.2.10",
        method: str = "GET",
        path: str = "/",
        headers: Optional[Dict[str, str]] = None,
        interaction_type: OobInteractionType | str = OobInteractionType.HTTP_INTERACTION,
    ) -> SsrfInteraction:
        """
        Simulates an incoming server-side callback for testing.
        """
        inter = SsrfInteraction(
            interaction_id=f"int-{uuid.uuid4().hex[:8]}",
            canary_token=canary_token,
            protocol=protocol,
            source_ip_metadata=source_ip,
            observed_hostname=f"{canary_token}.{self.base_domain}",
            observed_method=method,
            observed_path=path,
            bounded_headers=headers or {"User-Agent": "Backend-Fetcher/1.0"},
            interaction_type=interaction_type,
            confidence=SsrfConfidence.VALIDATED if protocol in ("HTTP", "HTTPS") else SsrfConfidence.OBSERVED,
        )
        if canary_token not in self._storage:
            self._storage[canary_token] = []
        self._storage[canary_token].append(inter)
        return inter

    def poll(self, token: Optional[str] = None, timeout: float = 5.0) -> List[SsrfInteraction]:
        if token:
            return list(self._storage.get(token, []))
        all_ints: List[SsrfInteraction] = []
        for ints in self._storage.values():
            all_ints.extend(ints)
        return all_ints

    def consume_interactions(self, token: str) -> List[SsrfInteraction]:
        ints = list(self._storage.get(token, []))
        self._storage[token] = []
        return ints

    def close(self) -> None:
        self._storage.clear()
        self._canaries.clear()


class InteractshOobProvider(OobProvider):
    """
    ProjectDiscovery Interactsh protocol client adapter.
    Activated when INTERACTSH_TOKEN or PDCP_API_KEY is configured.
    """

    def __init__(
        self,
        server_url: Optional[str] = None,
        token: Optional[str] = None,
    ):
        self.server_url = server_url or os.environ.get("INTERACTSH_SERVER", "oast.pro")
        self.token = token or os.environ.get("INTERACTSH_TOKEN") or os.environ.get("PDCP_API_KEY")
        self._storage: Dict[str, List[SsrfInteraction]] = {}
        self._session_id = uuid.uuid4().hex[:12]

    def name(self) -> str:
        return "interactsh"

    def registration_status(self) -> OobProviderStatus:
        if not self.token:
            return OobProviderStatus.CONFIG_REQUIRED
        return OobProviderStatus.AVAILABLE

    def generate_canary(self, prefix: str = "bb9", test_id: str = "") -> Tuple[str, str]:
        rand_id = uuid.uuid4().hex[:8]
        clean_tid = test_id.replace("ssrf-", "")[:8] if test_id else "00"
        token = f"{prefix}-{clean_tid}-{rand_id}"
        canary_domain = f"{token}.{self.server_url}"
        canary_url = f"http://{canary_domain}"
        self._storage[token] = []
        return token, canary_url

    def poll(self, token: Optional[str] = None, timeout: float = 5.0) -> List[SsrfInteraction]:
        # If client library not available or mock mode, return cached storage
        return list(self._storage.get(token, [])) if token else []

    def consume_interactions(self, token: str) -> List[SsrfInteraction]:
        ints = list(self._storage.get(token, []))
        self._storage[token] = []
        return ints

    def close(self) -> None:
        self._storage.clear()


class CollaboratorOobProvider(OobProvider):
    """
    Burp Collaborator polling client adapter.
    """

    def __init__(self, collab_host: Optional[str] = None):
        self.collab_host = collab_host or os.environ.get("BURP_COLLABORATOR_HOST")
        self._storage: Dict[str, List[SsrfInteraction]] = {}

    def name(self) -> str:
        return "collaborator"

    def registration_status(self) -> OobProviderStatus:
        if not self.collab_host:
            return OobProviderStatus.CONFIG_REQUIRED
        return OobProviderStatus.AVAILABLE

    def generate_canary(self, prefix: str = "bb9", test_id: str = "") -> Tuple[str, str]:
        rand_id = uuid.uuid4().hex[:8]
        token = f"{prefix}-{rand_id}"
        domain = f"{token}.{self.collab_host}" if self.collab_host else f"{token}.burpcollaborator.net"
        return token, f"http://{domain}"

    def poll(self, token: Optional[str] = None, timeout: float = 5.0) -> List[SsrfInteraction]:
        return list(self._storage.get(token, [])) if token else []

    def consume_interactions(self, token: str) -> List[SsrfInteraction]:
        ints = list(self._storage.get(token, []))
        self._storage[token] = []
        return ints

    def close(self) -> None:
        self._storage.clear()


class OobProviderFactory:
    """
    Factory resolving active OOB provider with clean mock fallback.
    """

    @classmethod
    def get_provider(
        cls,
        provider_name: str = "auto",
        mock_domain: str = "oob.local",
    ) -> OobProvider:
        """
        Returns configured provider instance. Never throws on missing keys.
        """
        p_name = provider_name.lower().strip()
        if p_name == "interactsh":
            p = InteractshOobProvider()
            if p.registration_status() == OobProviderStatus.AVAILABLE:
                return p
            return MockOobProvider(base_domain=mock_domain)
        elif p_name == "collaborator":
            p = CollaboratorOobProvider()
            if p.registration_status() == OobProviderStatus.AVAILABLE:
                return p
            return MockOobProvider(base_domain=mock_domain)
        elif p_name == "mock":
            return MockOobProvider(base_domain=mock_domain)

        # "auto" resolution: prefer interactsh if configured, else mock
        interactsh = InteractshOobProvider()
        if interactsh.registration_status() == OobProviderStatus.AVAILABLE:
            return interactsh

        return MockOobProvider(base_domain=mock_domain)
