"""No-network tests for the Interactsh CLI adapter."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from framework.ssrf.model import OobInteractionType, OobProviderStatus
from framework.ssrf.provider import InteractshOobProvider


class _FakeProcess:
    def __init__(self, command):
        self.command = command
        self.returncode = None
        self.payload_path = command[command.index("-payload-store-file") + 1]
        self.output_path = command[command.index("-output") + 1]
        Path(self.payload_path).write_text("abc123.correlation.oast.pro\n", encoding="utf-8")

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = 0

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def kill(self):
        self.returncode = -9


def test_interactsh_session_keeps_token_private_and_correlates_exact_id(tmp_path, monkeypatch):
    process_holder = {}

    def fake_popen(command, **_kwargs):
        process_holder["process"] = _FakeProcess(command)
        return process_holder["process"]

    monkeypatch.setattr("framework.ssrf.provider.shutil.which", lambda _name: "/usr/bin/interactsh-client")
    monkeypatch.setattr("framework.ssrf.provider.subprocess.Popen", fake_popen)
    monkeypatch.setattr("framework.ssrf.provider.tempfile.mkdtemp", lambda **_kwargs: str(tmp_path / "session"))
    (tmp_path / "session").mkdir()

    provider = InteractshOobProvider(server_url="oast.pro", token="local-secret-token")
    assert provider.registration_status() == OobProviderStatus.AVAILABLE
    token, url = provider.generate_canary(test_id="case-1")

    process = process_holder["process"]
    assert token == "abc123.correlation"
    assert url == "http://abc123.correlation.oast.pro"
    assert "local-secret-token" not in process.command
    config_path = process.command[process.command.index("-config") + 1]
    assert "local-secret-token" in Path(config_path).read_text(encoding="utf-8")
    assert stat.S_IMODE(os.stat(tmp_path / "session").st_mode) == 0o700
    assert stat.S_IMODE(os.stat(config_path).st_mode) == 0o600

    events = [
        {
            "protocol": "http",
            "unique-id": "abc123.correlation",
            "full-id": "abc123.correlation",
            "remote-address": "203.0.113.10",
            "timestamp": "2026-11-19T10:00:00Z",
            "raw-request": "GET /fetch?token=secret-value HTTP/1.1\r\nCookie: session=private\r\n",
        },
        {
            "protocol": "dns",
            "full-id": "unrelated.correlation",
            "remote-address": "203.0.113.11",
            "timestamp": "2026-11-19T10:00:00Z",
        },
    ]
    Path(process.output_path).write_text("".join(json.dumps(item) + "\n" for item in events), encoding="utf-8")

    interactions = provider.poll(token, timeout=0)
    assert len(interactions) == 1
    assert interactions[0].canary_token == token
    assert interactions[0].interaction_type == OobInteractionType.HTTP_INTERACTION
    assert interactions[0].observed_path == "/fetch?token=[REDACTED_BY_BB_AGENT]"
    assert interactions[0].bounded_headers == {}
    assert "secret-value" not in json.dumps(interactions[0].to_dict())
    provider.close()
    assert process.poll() == 0


def test_interactsh_unavailable_or_invalid_configuration_fails_closed(monkeypatch):
    monkeypatch.setattr("framework.ssrf.provider.shutil.which", lambda _name: None)
    provider = InteractshOobProvider(server_url="oast.pro")
    assert provider.registration_status() == OobProviderStatus.UNAVAILABLE

    invalid = InteractshOobProvider(server_url="http://oast.pro/path", token="secret")
    assert invalid.registration_status() == OobProviderStatus.CONFIG_REQUIRED


def test_pdcp_api_key_is_never_reused_as_interactsh_server_token(monkeypatch):
    monkeypatch.setenv("PDCP_API_KEY", "must-not-be-sent-to-oast")
    monkeypatch.delenv("INTERACTSH_TOKEN", raising=False)
    provider = InteractshOobProvider(server_url="oast.pro")
    assert provider.token is None


def test_interactsh_payload_must_belong_to_configured_server():
    assert InteractshOobProvider._payload_hostname("good-id.oast.pro", "oast.pro") == ("good-id", "good-id.oast.pro")
    assert InteractshOobProvider._payload_hostname("bad.example.net", "oast.pro") is None
    assert InteractshOobProvider._payload_hostname("good-id.oast.pro/path", "oast.pro") is None
