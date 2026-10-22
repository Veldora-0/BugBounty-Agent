"""
Phase 18 Regression Tests: SSRF Transport, Destination & Byte-Budget Hardening.

Covers:
1. Alternate IP representation parsing and normalization (decimal scalars, hex scalars, octal scalars,
   dotted hex/octal, inet_aton multi-part, IPv4-mapped IPv6, and trailing dot resilience).
2. SSRF destination boundary evaluation for alternate notations, unspecified addresses (0.0.0.0, ::),
   loopback fixture port restrictions, and metadata endpoints.
3. Fail-closed behavior on mixed DNS resolution answers (DNS rebinding defenses).
4. Continuous network byte-budget accounting and enforcement across requests, redirects, and HTTP errors.
5. SsrfIntelligenceEngine byte counter exposure and lifecycle integration.
"""

from __future__ import annotations

import io
import ipaddress
import socket
import tempfile
import urllib.error
import urllib.request
from typing import Any, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from framework.common.transport import (
    PinnedHTTPConnection,
    PinnedHTTPSConnection,
    _is_loopback_ip_literal,
    parse_alternate_ip,
)
from framework.scope.engine import ScopeEngine
from framework.ssrf.engine import SsrfIntelligenceEngine
from framework.ssrf.provider import MockOobProvider
from framework.validation.engine import (
    SafeRedirectHandler,
    ScopeViolationError,
    SecurityValidationEngine,
    is_ssrf_prohibited_ip,
)
from framework.validation.policy import PolicyViolationError, SecurityTestPolicy
from framework.validation.request import ControlledRequest, ControlledResponse


def make_scope(
    urls: Optional[List[str]] = None,
    domains: Optional[List[str]] = None,
    out_urls: Optional[List[str]] = None,
) -> ScopeEngine:
    return ScopeEngine({
        "program": {"name": "Test"},
        "targets": {
            "urls": urls or [],
            "domains": domains or [],
        },
        "out_of_scope": {
            "urls": out_urls or [],
        },
    })


# ============================================================================
# 1. Alternate IP Representation Parsing
# ============================================================================

class TestAlternateIpParsing:
    """Verifies RFC / POSIX inet_aton alternate IP representation parsing."""

    def test_standard_dotted_decimal(self):
        assert parse_alternate_ip("127.0.0.1") == ipaddress.IPv4Address("127.0.0.1")
        assert parse_alternate_ip("10.0.0.1") == ipaddress.IPv4Address("10.0.0.1")
        assert parse_alternate_ip("8.8.8.8") == ipaddress.IPv4Address("8.8.8.8")

    def test_integer_scalar(self):
        # 127.0.0.1 == 2130706433
        assert parse_alternate_ip("2130706433") == ipaddress.IPv4Address("127.0.0.1")
        # 169.254.169.254 == 2852039166
        assert parse_alternate_ip("2852039166") == ipaddress.IPv4Address("169.254.169.254")
        # 0.0.0.0 == 0
        assert parse_alternate_ip("0") == ipaddress.IPv4Address("0.0.0.0")

    def test_hex_scalar(self):
        assert parse_alternate_ip("0x7f000001") == ipaddress.IPv4Address("127.0.0.1")
        assert parse_alternate_ip("0X7F000001") == ipaddress.IPv4Address("127.0.0.1")
        assert parse_alternate_ip("0xa9fea9fe") == ipaddress.IPv4Address("169.254.169.254")
        assert parse_alternate_ip("0x08080808") == ipaddress.IPv4Address("8.8.8.8")

    def test_octal_scalar(self):
        assert parse_alternate_ip("017700000001") == ipaddress.IPv4Address("127.0.0.1")

    def test_dotted_octal_and_hex(self):
        assert parse_alternate_ip("0177.0.0.1") == ipaddress.IPv4Address("127.0.0.1")
        assert parse_alternate_ip("0x7f.0.0.1") == ipaddress.IPv4Address("127.0.0.1")
        assert parse_alternate_ip("0x7f.0x0.0x0.0x1") == ipaddress.IPv4Address("127.0.0.1")
        assert parse_alternate_ip("0177.0.0.0x1") == ipaddress.IPv4Address("127.0.0.1")
        assert parse_alternate_ip("0251.0376.0251.0376") == ipaddress.IPv4Address("169.254.169.254")

    def test_inet_aton_multi_part(self):
        # 2 parts: 127.1 -> (127 << 24) | 1 = 127.0.0.1
        assert parse_alternate_ip("127.1") == ipaddress.IPv4Address("127.0.0.1")
        # 3 parts: 127.0.1 -> (127 << 24) | (0 << 16) | 1 = 127.0.0.1
        assert parse_alternate_ip("127.0.1") == ipaddress.IPv4Address("127.0.0.1")
        # 2 parts: 10.1 -> 10.0.0.1
        assert parse_alternate_ip("10.1") == ipaddress.IPv4Address("10.0.0.1")

    def test_ipv6_and_bracketed(self):
        assert parse_alternate_ip("::1") == ipaddress.IPv6Address("::1")
        assert parse_alternate_ip("[::1]") == ipaddress.IPv6Address("::1")
        assert parse_alternate_ip("::ffff:127.0.0.1") == ipaddress.IPv6Address("::ffff:127.0.0.1")
        assert parse_alternate_ip("[::ffff:127.0.0.1]") == ipaddress.IPv6Address("::ffff:127.0.0.1")
        # Alternate embedded IPv4 in IPv4-mapped IPv6
        assert parse_alternate_ip("[::ffff:0x7f000001]") == ipaddress.IPv6Address("::ffff:127.0.0.1")

    def test_trailing_dot_normalization(self):
        assert parse_alternate_ip("127.0.0.1.") == ipaddress.IPv4Address("127.0.0.1")

    def test_invalid_and_domain_names_return_none(self):
        assert parse_alternate_ip("example.com") is None
        assert parse_alternate_ip("localhost") is None
        assert parse_alternate_ip("sub.domain.co.uk") is None
        assert parse_alternate_ip("127.0.0.256") is None
        assert parse_alternate_ip("") is None
        assert parse_alternate_ip(None) is None


# ============================================================================
# 2. SSRF Prohibited IP Evaluation
# ============================================================================

class TestSsrfProhibitedIpEvaluation:
    """Verifies is_ssrf_prohibited_ip detects private, loopback, unspecified, and metadata IPs."""

    def test_unspecified_addresses(self):
        bad, reason = is_ssrf_prohibited_ip("0.0.0.0")
        assert bad is True
        bad, reason = is_ssrf_prohibited_ip("0")
        assert bad is True
        bad, reason = is_ssrf_prohibited_ip("::")
        assert bad is True

    def test_alternate_loopback(self):
        assert is_ssrf_prohibited_ip("0x7f000001")[0] is True
        assert is_ssrf_prohibited_ip("2130706433")[0] is True
        assert is_ssrf_prohibited_ip("0177.0.0.1")[0] is True
        assert is_ssrf_prohibited_ip("127.1")[0] is True

    def test_alternate_cloud_metadata(self):
        assert is_ssrf_prohibited_ip("0xa9fea9fe")[0] is True
        assert is_ssrf_prohibited_ip("2852039166")[0] is True
        assert is_ssrf_prohibited_ip("0251.0376.0251.0376")[0] is True

    def test_public_ips_permitted(self):
        assert is_ssrf_prohibited_ip("8.8.8.8")[0] is False
        assert is_ssrf_prohibited_ip("1.1.1.1")[0] is False
        assert is_ssrf_prohibited_ip("0x08080808")[0] is False


# ============================================================================
# 3. Transport Loopback Detection
# ============================================================================

class TestTransportLoopbackDetection:
    """Verifies Pinned connection classes recognize alternate loopback representations."""

    def test_is_loopback_ip_literal(self):
        assert _is_loopback_ip_literal("127.0.0.1") is True
        assert _is_loopback_ip_literal("0x7f000001") is True
        assert _is_loopback_ip_literal("2130706433") is True
        assert _is_loopback_ip_literal("0177.0.0.1") is True
        assert _is_loopback_ip_literal("127.1") is True
        assert _is_loopback_ip_literal("[::1]") is True
        assert _is_loopback_ip_literal("example.com") is False
        assert _is_loopback_ip_literal("8.8.8.8") is False

    def test_pinned_connection_normalizes_loopback(self):
        conn = PinnedHTTPConnection("0x7f000001", port=8080)
        assert conn.pinned_ips == ["127.0.0.1"]

        conn_https = PinnedHTTPSConnection("0177.0.0.1", port=8443)
        assert conn_https.pinned_ips == ["127.0.0.1"]


# ============================================================================
# 4. Scope Resolution & Anti-SSRF Destination Enforcement
# ============================================================================

class TestScopeResolutionDestinationEnforcement:
    """Verifies resolve_scope_ips enforces destination pinning and fails closed on mixed DNS."""

    def _setup_engine(self, scope_eng: ScopeEngine):
        tmp_dir = tempfile.mkdtemp()
        policy = SecurityTestPolicy(max_requests_per_program=20)
        eng = SecurityValidationEngine(program_dir=tmp_dir, scope_engine=scope_eng, policy=policy)
        return eng

    def test_alternate_loopback_without_fixture_port_fails_closed(self):
        scope_eng = make_scope(urls=["http://127.0.0.1:8080"])
        eng = self._setup_engine(scope_eng)
        # 0x7f000001 on unregistered port 8080
        with pytest.raises(ScopeViolationError, match="not an authorized local fixture port"):
            eng.resolve_scope_ips("http://0x7f000001:8080/")

        # 2130706433 on port 80
        with pytest.raises(ScopeViolationError, match="not an authorized local fixture port"):
            eng.resolve_scope_ips("http://2130706433/")

        # 127.1 on port 9000
        with pytest.raises(ScopeViolationError, match="not an authorized local fixture port"):
            eng.resolve_scope_ips("http://127.1:9000/")

    def test_alternate_loopback_with_authorized_fixture_port(self):
        scope_eng = make_scope(urls=["http://127.0.0.1:8080"])
        eng = self._setup_engine(scope_eng)
        eng.allow_fixture_port(8080)
        ips = eng.resolve_scope_ips("http://0x7f000001:8080/")
        assert ips == ["127.0.0.1"]

    def test_alternate_metadata_ip_blocked(self):
        scope_eng = make_scope(urls=["http://0xa9fea9fe"])
        eng = self._setup_engine(scope_eng)
        with pytest.raises(ScopeViolationError, match="prohibited address space"):
            eng.resolve_scope_ips("http://0xa9fea9fe/")

    def test_unspecified_address_blocked(self):
        scope_eng = make_scope(urls=["http://0.0.0.0"])
        eng = self._setup_engine(scope_eng)
        with pytest.raises(ScopeViolationError, match="prohibited address space"):
            eng.resolve_scope_ips("http://0.0.0.0/")

    def test_mixed_dns_resolution_fails_closed_on_private_answer(self):
        """DNS rebinding defense: if ANY candidate IP is private/loopback, the request fails closed."""
        scope_eng = make_scope(urls=["https://api.example.com"])
        eng = self._setup_engine(scope_eng)

        # Mock socket.getaddrinfo returning a public IP followed by a loopback IP
        mock_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ]
        with patch("socket.getaddrinfo", return_value=mock_addrinfo):
            with pytest.raises(ScopeViolationError, match="resolves to prohibited address 127.0.0.1"):
                eng.resolve_scope_ips("https://api.example.com/data")

    def test_mixed_dns_resolution_fails_closed_on_metadata_answer(self):
        scope_eng = make_scope(urls=["https://api.example.com"])
        eng = self._setup_engine(scope_eng)

        mock_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443)),
        ]
        with patch("socket.getaddrinfo", return_value=mock_addrinfo):
            with pytest.raises(ScopeViolationError, match="resolves to prohibited address 169.254.169.254"):
                eng.resolve_scope_ips("https://api.example.com/data")

    def test_pure_public_dns_resolution_permitted(self):
        scope_eng = make_scope(urls=["https://api.example.com"])
        eng = self._setup_engine(scope_eng)

        mock_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.35", 443)),
        ]
        with patch("socket.getaddrinfo", return_value=mock_addrinfo):
            ips = eng.resolve_scope_ips("https://api.example.com/data")
            assert ips == ["93.184.216.34", "93.184.216.35"]


# ============================================================================
# 5. Network Byte-Budget Accounting & Enforcement
# ============================================================================

class TestNetworkByteBudgetEnforcement:
    """Verifies continuous response-byte accounting across streaming reads, redirects, and limits."""

    def test_mock_hook_accounts_for_bytes_transferred(self):
        tmp_dir = tempfile.mkdtemp()
        scope_eng = make_scope(urls=["http://127.0.0.1:8080"])
        policy = SecurityTestPolicy(max_requests_per_program=10, max_total_bytes=1000)

        def mock_hook(req: ControlledRequest) -> ControlledResponse:
            body = "A" * 150
            return ControlledResponse(
                status_code=200,
                headers={"Content-Length": "150"},
                body=body,
                size_bytes=150,
                elapsed_seconds=0.01,
            )

        eng = SecurityValidationEngine(
            program_dir=tmp_dir,
            scope_engine=scope_eng,
            policy=policy,
            send_request_hook=mock_hook,
        )
        eng.allow_fixture_port(8080)

        req = ControlledRequest(url="http://127.0.0.1:8080/test", method="GET")
        eng.send_request(req)
        assert eng.total_bytes == 150
        assert eng.total_bytes_transferred == 150

        eng.send_request(req)
        assert eng.total_bytes == 300
        assert eng.total_bytes_transferred == 300

    def test_byte_budget_exhaustion_blocks_subsequent_requests(self):
        tmp_dir = tempfile.mkdtemp()
        scope_eng = make_scope(urls=["http://127.0.0.1:8080"])
        # 300 byte global budget
        policy = SecurityTestPolicy(max_requests_per_program=10, max_total_bytes=300)

        def mock_hook(req: ControlledRequest) -> ControlledResponse:
            return ControlledResponse(
                status_code=200,
                headers={},
                body="X" * 200,
                size_bytes=200,
                elapsed_seconds=0.01,
            )

        eng = SecurityValidationEngine(
            program_dir=tmp_dir,
            scope_engine=scope_eng,
            policy=policy,
            send_request_hook=mock_hook,
        )
        eng.allow_fixture_port(8080)

        req = ControlledRequest(url="http://127.0.0.1:8080/test", method="GET")
        eng.send_request(req)  # 200 bytes transferred

        # Second request exhausts the remaining 100 bytes of budget and pushes total to 400
        eng.send_request(req)

        # Third request must be blocked by PolicyViolationError
        with pytest.raises(PolicyViolationError, match="byte budget exhausted"):
            eng.send_request(req)

    def test_redirect_handler_enforces_byte_budget(self):
        tmp_dir = tempfile.mkdtemp()
        scope_eng = make_scope(urls=["http://127.0.0.1:8080"])
        policy = SecurityTestPolicy(max_requests_per_program=10, max_total_bytes=200)
        eng = SecurityValidationEngine(program_dir=tmp_dir, scope_engine=scope_eng, policy=policy)
        eng.allow_fixture_port(8080)

        # Pre-exhaust the byte budget
        eng.total_bytes_transferred = 250

        handler = SafeRedirectHandler(
            check_scope_fn=eng.resolve_scope_ips,
            original_url="http://127.0.0.1:8080/initial",
            engine=eng,
        )

        with pytest.raises(ScopeViolationError, match="Global byte budget exhausted during redirect"):
            handler.redirect_request(
                req=None,
                fp=None,
                code=302,
                msg="Found",
                headers={},
                newurl="http://127.0.0.1:8080/redirected",
            )

    def test_redirect_handler_enforces_request_budget(self):
        tmp_dir = tempfile.mkdtemp()
        scope_eng = make_scope(urls=["http://127.0.0.1:8080"])
        policy = SecurityTestPolicy(max_requests_per_program=3, max_total_bytes=10000)
        eng = SecurityValidationEngine(program_dir=tmp_dir, scope_engine=scope_eng, policy=policy)
        eng.allow_fixture_port(8080)

        # Set request count to limit
        eng.request_count = 3

        handler = SafeRedirectHandler(
            check_scope_fn=eng.resolve_scope_ips,
            original_url="http://127.0.0.1:8080/initial",
            engine=eng,
        )

        with pytest.raises(ScopeViolationError, match="Program request budget exhausted during redirect"):
            handler.redirect_request(
                req=None,
                fp=None,
                code=302,
                msg="Found",
                headers={},
                newurl="http://127.0.0.1:8080/redirected",
            )


# ============================================================================
# 6. SsrfIntelligenceEngine Byte Accounting Integration
# ============================================================================

class TestSsrfIntelligenceEngineByteCounters:
    """Verifies SsrfIntelligenceEngine surfaces total_bytes and total_bytes_transferred."""

    def test_engine_exposes_byte_counters(self):
        tmp_dir = tempfile.mkdtemp()
        scope_eng = make_scope(urls=["http://127.0.0.1:8080"])
        policy = SecurityTestPolicy(max_requests_per_program=10, max_total_bytes=5000)

        def mock_hook(req: ControlledRequest) -> ControlledResponse:
            return ControlledResponse(
                status_code=200,
                headers={},
                body="CANARY_RESPONSE",
                size_bytes=15,
                elapsed_seconds=0.01,
            )

        oob = MockOobProvider()
        engine = SsrfIntelligenceEngine(
            program_dir=tmp_dir,
            scope_engine=scope_eng,
            policy=policy,
            send_request_hook=mock_hook,
            oob_provider=oob,
        )
        engine.validation_engine.allow_fixture_port(8080)

        assert engine.total_bytes == 0
        assert engine.total_bytes_transferred == 0

        res = engine.run_evaluation(approve_all=True)
        assert "total_bytes_transferred" in res
        assert engine.total_bytes_transferred == res["total_bytes_transferred"]
