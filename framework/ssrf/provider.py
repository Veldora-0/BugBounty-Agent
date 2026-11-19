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
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit
import uuid

from framework.common.config import ensure_private_directory, write_private_text_file
from framework.common.evidence import sanitize_sensitive_data
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

    @property
    def is_simulation(self) -> bool:
        """Indicates this provider runs strictly in-memory simulation for local testing."""
        return True

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
    Live ProjectDiscovery Interactsh adapter backed by its official CLI client.

    Credentials are written to a mode-0600 config in a mode-0700 temporary
    directory; they are never passed in argv or copied into interaction records.
    Each canary has a bounded polling process and exact full-id correlation.
    """

    MAX_SESSIONS = 4
    MAX_SESSION_SECONDS = 120.0
    MAX_POLL_SECONDS = 10.0
    MAX_OUTPUT_BYTES = 2 * 1024 * 1024
    MAX_OUTPUT_LINE_BYTES = 64 * 1024
    REGISTRATION_TIMEOUT_SECONDS = 8.0

    def __init__(
        self,
        server_url: Optional[str] = None,
        token: Optional[str] = None,
    ):
        self.server_url = server_url or os.environ.get("INTERACTSH_SERVER", "oast.pro")
        self.token = token or os.environ.get("INTERACTSH_TOKEN") or os.environ.get("PDCP_API_KEY")
        self._client_path: Optional[str] = shutil.which("interactsh-client")
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._validated_server = self._normalize_server(self.server_url)

    @staticmethod
    def _normalize_server(server: str) -> Optional[str]:
        """Accept one HTTPS host (or host:port), never a URL with credentials or path."""
        candidate = (server or "").strip()
        if not candidate or "," in candidate or any(ord(char) <= 32 for char in candidate):
            return None
        parsed = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
        if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
            return None
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            return None
        try:
            parsed.port
        except ValueError:
            return None
        host = parsed.hostname.rstrip(".").lower()
        if not host or "/" in host or "\\" in host:
            return None
        return parsed.netloc.lower()

    def _cleanup_expired(self) -> None:
        now = time.monotonic()
        expired = []
        with self._lock:
            for token, session in self._sessions.items():
                if now - session["created_monotonic"] > self.MAX_SESSION_SECONDS:
                    expired.append(token)
        for token in expired:
            self._finish_session(token)

    def _finish_session(self, token: str) -> None:
        with self._lock:
            session = self._sessions.pop(token, None)
        if not session:
            return
        process = session.get("process")
        if process is not None and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                    process.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        shutil.rmtree(session["directory"], ignore_errors=True)

    def _expire_session_later(self, token: str) -> None:
        timer = threading.Timer(self.MAX_SESSION_SECONDS, self._finish_session, args=(token,))
        timer.daemon = True
        timer.start()

    @staticmethod
    def _payload_hostname(payload: str, server: str) -> Optional[Tuple[str, str]]:
        candidate = payload.strip()
        parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
        host = (parsed.hostname or "").rstrip(".").lower()
        port = parsed.port
        if port is not None or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            return None
        suffix = server.split(":", 1)[0].strip("[]").lower()
        if host == suffix or not host.endswith("." + suffix):
            return None
        token = host[: -(len(suffix) + 1)]
        if not token or any(not label or len(label) > 63 for label in token.split(".")):
            return None
        return token, host

    @staticmethod
    def _read_events(path: str, token: str, hostname: str) -> List[SsrfInteraction]:
        try:
            if os.path.islink(path) or os.path.getsize(path) > InteractshOobProvider.MAX_OUTPUT_BYTES:
                return []
            with open(path, "rb") as stream:
                raw_lines = stream.readlines(InteractshOobProvider.MAX_OUTPUT_BYTES + 1)
        except OSError:
            return []

        interactions: List[SsrfInteraction] = []
        seen: Set[str] = set()
        for raw_line in raw_lines:
            if len(raw_line) > InteractshOobProvider.MAX_OUTPUT_LINE_BYTES:
                continue
            try:
                event = json.loads(raw_line.decode("utf-8", errors="strict"))
            except (UnicodeError, json.JSONDecodeError):
                continue
            if not isinstance(event, dict):
                continue
            full_id = str(event.get("full-id") or event.get("full_id") or "").lower().strip(".")
            if full_id != token.lower():
                continue
            event_id = hashlib.sha256(raw_line).hexdigest()
            if event_id in seen:
                continue
            seen.add(event_id)
            protocol = str(event.get("protocol") or "").upper()
            if protocol not in {"DNS", "HTTP", "HTTPS", "SMTP", "SMTPS", "LDAP", "TCP"}:
                continue
            if protocol == "DNS":
                interaction_type = OobInteractionType.DNS_ONLY
                confidence = SsrfConfidence.OBSERVED
            elif protocol in {"HTTP", "HTTPS"}:
                interaction_type = (
                    OobInteractionType.HTTPS_INTERACTION if protocol == "HTTPS" else OobInteractionType.HTTP_INTERACTION
                )
                confidence = SsrfConfidence.VALIDATED
            else:
                interaction_type = OobInteractionType.TCP_INTERACTION
                confidence = SsrfConfidence.OBSERVED

            raw_request = event.get("raw-request") or event.get("raw_request") or ""
            first_line = str(raw_request).splitlines()[0] if raw_request else ""
            request_match = re.match(r"^([A-Z]{1,12})\s+(\S+)\s+HTTP/\d(?:\.\d)?$", first_line)
            method = request_match.group(1) if request_match else "GET"
            path = sanitize_sensitive_data(request_match.group(2))[:2048] if request_match else "/"
            timestamp = str(event.get("timestamp") or datetime.now(timezone.utc).isoformat())
            try:
                parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                if parsed_timestamp.tzinfo is None:
                    parsed_timestamp = parsed_timestamp.replace(tzinfo=timezone.utc)
                timestamp = parsed_timestamp.astimezone(timezone.utc).isoformat()
            except ValueError:
                timestamp = datetime.now(timezone.utc).isoformat()
            interactions.append(SsrfInteraction(
                interaction_id=f"oob-{event_id[:24]}",
                canary_token=token,
                protocol=protocol,
                timestamp=timestamp,
                source_ip_metadata=sanitize_sensitive_data(str(event.get("remote-address") or "unknown"))[:128],
                observed_hostname=hostname,
                observed_method=method,
                observed_path=path,
                bounded_headers={},
                interaction_type=interaction_type,
                confidence=confidence,
            ))
        return interactions

    def name(self) -> str:
        return "interactsh"

    def registration_status(self) -> OobProviderStatus:
        self._cleanup_expired()
        self._client_path = shutil.which("interactsh-client") or self._client_path
        if self._validated_server is None:
            return OobProviderStatus.CONFIG_REQUIRED
        return OobProviderStatus.AVAILABLE if self._client_path else OobProviderStatus.UNAVAILABLE

    def generate_canary(self, prefix: str = "bb9", test_id: str = "") -> Tuple[str, str]:
        if self.registration_status() != OobProviderStatus.AVAILABLE or not self._client_path or not self._validated_server:
            raise RuntimeError("Interactsh client is unavailable or its server configuration is invalid")
        with self._lock:
            if len(self._sessions) >= self.MAX_SESSIONS:
                raise RuntimeError("Interactsh session limit reached; finish or expire an existing canary first")

        directory = tempfile.mkdtemp(prefix="bb-interactsh-")
        ensure_private_directory(directory)
        config_path = os.path.join(directory, "client.yaml")
        payload_path = os.path.join(directory, "payload.txt")
        output_path = os.path.join(directory, "interactions.jsonl")
        # JSON is a YAML subset. A config file avoids exposing an auth token in
        # process arguments, which are visible to other local users on Linux.
        write_private_text_file(config_path, json.dumps({"token": self.token} if self.token else {}) + "\n")
        write_private_text_file(payload_path, "")
        write_private_text_file(output_path, "")
        command = [
            self._client_path,
            "-server", self._validated_server,
            "-number", "1",
            "-poll-interval", "1",
            "-config", config_path,
            "-output", output_path,
            "-json",
            "-payload-store",
            "-payload-store-file", payload_path,
            "-disable-update-check",
            "-auth=false",
        ]
        env = dict(os.environ)
        env.pop("INTERACTSH_TOKEN", None)
        env.pop("PDCP_API_KEY", None)
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
                close_fds=True,
                start_new_session=(os.name != "nt"),
            )
            deadline = time.monotonic() + self.REGISTRATION_TIMEOUT_SECONDS
            generated: Optional[Tuple[str, str]] = None
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("Interactsh client exited before registering a canary")
                try:
                    with open(payload_path, "r", encoding="utf-8") as stream:
                        for line in stream:
                            generated = self._payload_hostname(line, self._validated_server)
                            if generated:
                                break
                except OSError:
                    pass
                if generated:
                    break
                time.sleep(0.05)
            if not generated:
                raise RuntimeError("Interactsh client did not produce a payload before the registration deadline")
            token, hostname = generated
            with self._lock:
                if len(self._sessions) >= self.MAX_SESSIONS:
                    process.terminate()
                    raise RuntimeError("Interactsh session limit reached")
                self._sessions[token] = {
                    "process": process,
                    "directory": directory,
                    "output_path": output_path,
                    "hostname": hostname,
                    "created_monotonic": time.monotonic(),
                    "interactions": [],
                }
            self._expire_session_later(token)
            return token, f"http://{hostname}"
        except Exception:
            try:
                if "process" in locals() and process.poll() is None:
                    process.terminate()
                    process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                except OSError:
                    pass
            shutil.rmtree(directory, ignore_errors=True)
            raise

    def poll(self, token: Optional[str] = None, timeout: float = 5.0) -> List[SsrfInteraction]:
        if not token:
            return []
        with self._lock:
            session = self._sessions.get(token)
        if not session:
            return []
        wait_for = max(0.0, min(float(timeout), self.MAX_POLL_SECONDS))
        deadline = time.monotonic() + wait_for
        while True:
            discovered = self._read_events(session["output_path"], token, session["hostname"])
            known = {item.interaction_id for item in session["interactions"]}
            session["interactions"].extend(item for item in discovered if item.interaction_id not in known)
            if time.monotonic() >= deadline:
                break
            time.sleep(min(0.1, deadline - time.monotonic()))
        return list(session["interactions"])

    def consume_interactions(self, token: str) -> List[SsrfInteraction]:
        with self._lock:
            session = self._sessions.get(token)
        if not session:
            return []
        interactions = list(session["interactions"])
        session["interactions"].clear()
        return interactions

    def close(self) -> None:
        with self._lock:
            tokens = list(self._sessions)
        for token in tokens:
            self._finish_session(token)


class CollaboratorOobProvider(OobProvider):
    """
    Burp Collaborator polling client adapter.
    Reports CONFIG_REQUIRED when collaborator host is missing.
    Reports UNAVAILABLE when configured because live polling over the Burp Collaborator
    protocol is not implemented in this adapter (storage is local in-memory only).
    """

    def __init__(self, collab_host: Optional[str] = None):
        self.collab_host = collab_host or os.environ.get("BURP_COLLABORATOR_HOST")
        self._storage: Dict[str, List[SsrfInteraction]] = {}

    def name(self) -> str:
        return "collaborator"

    def registration_status(self) -> OobProviderStatus:
        if not self.collab_host:
            return OobProviderStatus.CONFIG_REQUIRED
        # Live Burp Collaborator polling protocol is not implemented in this adapter
        # (storage is in-memory only). A configured host alone does not establish
        # operational live polling. Truthfully report UNAVAILABLE.
        return OobProviderStatus.UNAVAILABLE

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
