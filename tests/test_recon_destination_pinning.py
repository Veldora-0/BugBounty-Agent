"""Security regression tests for hostname resolution in active recon probes."""

from __future__ import annotations

import socket

import pytest

from framework.common.transport import resolve_public_destination_ips
from framework.recon.engine import ReconnaissanceEngine
from framework.scope.engine import ScopeEngine


def _in_scope_engine() -> ReconnaissanceEngine:
    scope = ScopeEngine({
        "program": {"name": "destination-pinning-test"},
        "targets": {"domains": ["example.com"]},
        "out_of_scope": {"domains": []},
    })
    return ReconnaissanceEngine(scope_engine=scope)


def _answer(ip: str, port: int = 443):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "::ffff:127.0.0.1"])
def test_resolver_rejects_prohibited_addresses(monkeypatch, ip):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [_answer(ip)])
    with pytest.raises(OSError, match="prohibited"):
        resolve_public_destination_ips("example.com", 443)


def test_resolver_rejects_mixed_public_and_private_answer_set(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [_answer("93.184.216.34"), _answer("192.168.1.10")],
    )
    with pytest.raises(OSError, match="prohibited"):
        resolve_public_destination_ips("example.com", 443)


def test_resolver_returns_numeric_addresses_and_caps_answer_count(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [_answer("93.184.216.34")])
    assert resolve_public_destination_ips("example.com", 443) == ["93.184.216.34"]

    too_many = [_answer(f"93.184.216.{i}") for i in range(1, 10)]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: too_many)
    with pytest.raises(OSError, match="more than 8"):
        resolve_public_destination_ips("example.com", 443)


def test_port_probe_connects_only_to_pinned_numeric_address(monkeypatch):
    calls = []

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [_answer("93.184.216.34")])
    monkeypatch.setattr(socket, "create_connection", lambda address, **kwargs: calls.append(address) or FakeSocket())

    observations = _in_scope_engine().probe_ports("example.com", [443])

    assert len(observations) == 1
    assert calls == [("93.184.216.34", 443)]


def test_port_probe_fails_closed_for_mixed_dns_answers(monkeypatch):
    calls = []
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [_answer("93.184.216.34"), _answer("127.0.0.1")],
    )
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: calls.append(args))

    assert _in_scope_engine().probe_ports("example.com", [443]) == []
    assert calls == []


def test_probe_ports_requires_scope_before_resolution(monkeypatch):
    calls = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: calls.append(args))

    assert ReconnaissanceEngine().probe_ports("example.com", [443]) == []
    assert calls == []
