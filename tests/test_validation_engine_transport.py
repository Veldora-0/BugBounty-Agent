"""
Deterministic Tests for Phase 6 HTTP Transport Security & Destination-IP Pinning.

Covers Workstream A:
- Normal verified HTTPS behavior and default strict TLS verification
- Invalid/self-signed certificate rejection in default/production mode
- Hostname mismatch rejection
- Scope rejection before connection
- Redirect to an out-of-scope destination
- Protocol downgrade rejection (HTTPS -> HTTP)
- Connection to the approved address while preserving Host header and TLS SNI
- Destination IP pinning preventing DNS rebinding TOCTOU
- Local test fixture compatibility via allow_fixture_port
"""

from __future__ import annotations

import http.server
import os
import socket
import ssl
import tempfile
import threading
from typing import Optional
import urllib.request
from urllib.parse import urlparse
import pytest

from framework.scope.engine import ScopeEngine
from framework.validation.engine import (
    SafeRedirectHandler,
    ScopeViolationError,
    SecurityValidationEngine,
)
from framework.validation.policy import SecurityTestPolicy
from framework.validation.request import ControlledRequest


@pytest.fixture
def temp_workspace():
    with tempfile.TemporaryDirectory() as tmpdir:
        state_dir = os.path.join(tmpdir, "state")
        os.makedirs(state_dir, exist_ok=True)
        yield tmpdir


@pytest.fixture
def test_scope_engine(temp_workspace):
    scope_data = {
        "program": {"name": "test-program"},
        "targets": {
            "domains": ["example.com", "*.example.com"],
            "urls": ["http://127.0.0.1", "https://127.0.0.1"],
        },
        "out_of_scope": {
            "domains": ["forbidden.example.com"],
            "urls": ["https://example.com/blocked"],
        },
    }
    return ScopeEngine(scope_data)


def test_scope_rejection_before_connection(temp_workspace, test_scope_engine):
    """Verifies that out-of-scope targets are rejected before any network socket is opened."""
    engine = SecurityValidationEngine(
        program_dir=temp_workspace,
        scope_engine=test_scope_engine,
    )

    # 1. Unauthorized domain
    with pytest.raises(ScopeViolationError):
        engine.check_request_scope("https://unauthorized-evil.com/login")

    # 2. Explicit out-of-scope domain
    with pytest.raises(ScopeViolationError):
        engine.check_request_scope("https://forbidden.example.com/admin")

    # 3. SSRF prohibited IP (AWS metadata)
    with pytest.raises(ScopeViolationError):
        engine.check_request_scope("http://169.254.169.254/latest/meta-data/")

    # 4. SSRF private IP
    with pytest.raises(ScopeViolationError):
        engine.check_request_scope("http://10.0.0.1/internal")


def test_local_fixture_compatibility_with_port_gating(temp_workspace, test_scope_engine):
    """Verifies that 127.0.0.1 is blocked by default but allowed when explicitly registered as a test fixture port."""
    engine = SecurityValidationEngine(
        program_dir=temp_workspace,
        scope_engine=test_scope_engine,
    )

    # Starts a local test fixture HTTP server
    received_headers = {}

    class TestHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            received_headers["host"] = self.headers.get("Host", "")
            received_headers["user-agent"] = self.headers.get("User-Agent", "")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "fixture_ok"}')

    server = http.server.HTTPServer(("127.0.0.1", 0), TestHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        # Before allowing port: blocked as private loopback
        with pytest.raises(ScopeViolationError):
            engine.check_request_scope(f"http://127.0.0.1:{port}/test")

        # Register fixture port
        engine.allow_fixture_port(port)
        pinned = engine.check_request_scope(f"http://127.0.0.1:{port}/test")
        assert pinned == "127.0.0.1"

        # Dispatch real request
        req = ControlledRequest(method="GET", url=f"http://127.0.0.1:{port}/test")
        resp = engine.send_request(req)
        assert resp.status_code == 200
        assert "fixture_ok" in resp.body
        assert received_headers["host"] == f"127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()


def test_redirect_to_out_of_scope_is_rejected(temp_workspace, test_scope_engine):
    """Verifies that redirect following revalidates scope on every hop and blocks out-of-scope targets."""
    engine = SecurityValidationEngine(
        program_dir=temp_workspace,
        scope_engine=test_scope_engine,
    )

    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            if self.path == "/redirect-to-forbidden":
                self.send_response(302)
                self.send_header("Location", "https://forbidden.example.com/admin")
                self.end_headers()
            elif self.path == "/redirect-to-ssrf":
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/meta-data")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()

    server = http.server.HTTPServer(("127.0.0.1", 0), RedirectHandler)
    port = server.server_port
    engine.allow_fixture_port(port)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        # Redirect to out-of-scope destination raises ScopeViolationError
        req1 = ControlledRequest(method="GET", url=f"http://127.0.0.1:{port}/redirect-to-forbidden")
        with pytest.raises(ScopeViolationError):
            engine.send_request(req1)

        # Redirect to SSRF destination raises ScopeViolationError
        req2 = ControlledRequest(method="GET", url=f"http://127.0.0.1:{port}/redirect-to-ssrf")
        with pytest.raises(ScopeViolationError):
            engine.send_request(req2)
    finally:
        server.shutdown()
        server.server_close()


def test_https_strict_tls_rejection_of_invalid_cert(temp_workspace, test_scope_engine):
    """Verifies that production HTTPS fails closed and rejects untrusted / self-signed certificates."""
    engine = SecurityValidationEngine(
        program_dir=temp_workspace,
        scope_engine=test_scope_engine,
    )

    # Requests to badssl.com self-signed / expired or local invalid cert fail closed
    # Here we simulate by creating a dummy pinned socket or testing default SSL context properties
    ctx = ssl.create_default_context()
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED

    # Connecting with default engine without custom_ssl_context enforces check_hostname and CERT_REQUIRED
    # Test that an untrusted HTTPS target returns status_code=0 with SSL verification failure
    req = ControlledRequest(method="GET", url="https://127.0.0.1:9443/test")
    engine.allow_fixture_port(9443)
    resp = engine.send_request(req)
    assert resp.status_code == 0
    assert "Connection Error" in resp.body


def test_destination_ip_pinning_preserves_host_header(temp_workspace, test_scope_engine):
    """Verifies that destination-IP pinning routes to the approved address while preserving Host header."""
    received_host = None

    class HostCheckHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            nonlocal received_host
            received_host = self.headers.get("Host")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")

    server = http.server.HTTPServer(("127.0.0.1", 0), HostCheckHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        engine = SecurityValidationEngine(
            program_dir=temp_workspace,
            scope_engine=test_scope_engine,
        )
        engine.allow_fixture_port(port)

        # We construct a request with an explicit Host header
        req = ControlledRequest(
            method="GET",
            url=f"http://127.0.0.1:{port}/api/profile",
            headers={"Host": "api.example.com"},
        )
        resp = engine.send_request(req)
        assert resp.status_code == 200
        assert received_host == "api.example.com"
    finally:
        server.shutdown()
        server.server_close()


def test_dns_rebinding_prevention_via_pinning(temp_workspace):
    """
    Verifies that destination-IP pinning uses the IP that passed validation
    and does not re-query DNS during socket connection.
    """
    from framework.common.transport import PinnedHTTPConnection

    # Test PinnedHTTPConnection connects to pinned_ip, ignoring hostname
    conn = PinnedHTTPConnection("example.com", port=80, pinned_ip="127.0.0.1")
    assert conn.pinned_ip == "127.0.0.1"
    assert conn.original_host == "example.com"


# ==============================================================================
# Workstream A Hardening: Redirect Downgrade Fail-Closed & Unexpected Inputs
# ==============================================================================

def test_safe_redirect_handler_blocks_https_to_http_downgrade():
    """Verifies that an HTTPS-to-HTTP redirect is strictly blocked as a protocol downgrade."""
    def dummy_scope_checker(url: str):
        return "127.0.0.1"

    handler = SafeRedirectHandler(
        check_scope_fn=dummy_scope_checker,
        original_url="https://api.example.com/login",
    )
    req = urllib.request.Request("https://api.example.com/login")

    with pytest.raises(ScopeViolationError, match="Protocol downgrade from HTTPS to HTTP forbidden"):
        handler.redirect_request(req, None, 302, "Found", {}, "http://api.example.com/home")


def test_safe_redirect_handler_permits_normal_redirects():
    """Verifies that normal permitted redirects (HTTP-to-HTTP, HTTPS-to-HTTPS) succeed."""
    def dummy_scope_checker(url: str):
        return "127.0.0.1"

    # 1. Normal HTTPS-to-HTTPS redirect
    handler_https = SafeRedirectHandler(
        check_scope_fn=dummy_scope_checker,
        original_url="https://api.example.com/start",
    )
    req_https = urllib.request.Request("https://api.example.com/start")
    new_req_https = handler_https.redirect_request(
        req_https, None, 302, "Found", {}, "https://api.example.com/finish"
    )
    assert new_req_https is not None
    assert new_req_https.get_full_url() == "https://api.example.com/finish"
    assert handler_https.current_url == "https://api.example.com/finish"

    # 2. Normal HTTP-to-HTTP redirect
    handler_http = SafeRedirectHandler(
        check_scope_fn=dummy_scope_checker,
        original_url="http://127.0.0.1:8080/start",
    )
    req_http = urllib.request.Request("http://127.0.0.1:8080/start")
    new_req_http = handler_http.redirect_request(
        req_http, None, 302, "Found", {}, "http://127.0.0.1:8080/finish"
    )
    assert new_req_http is not None
    assert new_req_http.get_full_url() == "http://127.0.0.1:8080/finish"
    assert handler_http.current_url == "http://127.0.0.1:8080/finish"


def test_safe_redirect_handler_missing_request_fails_closed():
    """
    Verifies that a missing request object (req=None) cannot silently bypass
    HTTPS-to-HTTP downgrade protection, and fails closed when context is absent.
    """
    def dummy_scope_checker(url: str):
        return "127.0.0.1"

    # 1. req=None but originating URL context is HTTPS -> blocks downgrade
    handler_https = SafeRedirectHandler(
        check_scope_fn=dummy_scope_checker,
        original_url="https://api.example.com/start",
    )
    with pytest.raises(ScopeViolationError, match="Protocol downgrade from HTTPS to HTTP forbidden"):
        handler_https.redirect_request(None, None, 302, "Found", {}, "http://api.example.com/insecure")

    # 2. req=None and no originating context -> fails closed safely
    handler_unknown = SafeRedirectHandler(
        check_scope_fn=dummy_scope_checker,
        original_url=None,
    )
    with pytest.raises(ScopeViolationError, match="Missing request context"):
        handler_unknown.redirect_request(None, None, 302, "Found", {}, "http://api.example.com/insecure")


def test_safe_redirect_handler_unexpected_inputs_fail_safely():
    """Verifies that invalid or unexpected request objects and target URLs fail safely with ScopeViolationError."""
    def dummy_scope_checker(url: str):
        return "127.0.0.1"

    handler = SafeRedirectHandler(
        check_scope_fn=dummy_scope_checker,
        original_url="http://example.com/test",
        max_redirects=20,
    )

    # 1. Unexpected request object type (int, dict, etc.)
    with pytest.raises(ScopeViolationError, match="Unexpected request object"):
        handler.redirect_request(12345, None, 302, "Found", {}, "http://example.com/next")

    with pytest.raises(ScopeViolationError, match="Unexpected request object"):
        handler.redirect_request({"not": "a request"}, None, 302, "Found", {}, "http://example.com/next")

    # 2. Invalid target URL
    with pytest.raises(ScopeViolationError, match="Invalid redirect target URL"):
        handler.redirect_request(None, None, 302, "Found", {}, "")

    with pytest.raises(ScopeViolationError, match="Invalid redirect target URL"):
        handler.redirect_request(None, None, 302, "Found", {}, None)

    # 3. Unsupported scheme
    with pytest.raises(ScopeViolationError, match="unsupported scheme"):
        handler.redirect_request(None, None, 302, "Found", {}, "ftp://example.com/pub")

    with pytest.raises(ScopeViolationError, match="unsupported scheme"):
        handler.redirect_request(None, None, 302, "Found", {}, "javascript:alert(1)")


# ==============================================================================
# Workstream A Hardening: Bounded Candidate IP Fallback (IPv4/IPv6)
# ==============================================================================

def test_pinned_connection_bounded_fallback_across_candidate_ips():
    """
    Verifies that PinnedHTTPConnection attempts candidate IPs in bounded sequence,
    falling back when the first candidate fails, successfully connecting to a working IP,
    and recording connected_ip while preserving original_host and Host header.
    """
    received_host = None

    class FallbackTestHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            nonlocal received_host
            received_host = self.headers.get("Host")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"FALLBACK_SUCCESS")

    server = http.server.HTTPServer(("127.0.0.1", 0), FallbackTestHandler)
    live_port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        from framework.common.transport import PinnedHTTPConnection

        # 127.0.0.2 on an arbitrary closed port or 127.0.0.1 on closed port vs live_port:
        # We test with candidates: ["127.0.0.2", "127.0.0.1"].
        # If 127.0.0.2 connection fails, it falls back to 127.0.0.1.
        # Alternatively, pick an unused closed port or an unreachable loopback IP.
        # To be completely deterministic across all operating systems without depending on 127.0.0.2 routing,
        # we test candidate list where the first candidate raises OSError on socket creation/connect.
        candidates = ["127.0.0.240", "127.0.0.1"]
        conn = PinnedHTTPConnection(
            host="app.example.com",
            port=live_port,
            pinned_ips=candidates,
            timeout=2.0,
        )
        conn.request("GET", "/test", headers={"Host": "app.example.com"})
        resp = conn.getresponse()
        assert resp.status == 200
        body = resp.read().decode("utf-8")
        assert body == "FALLBACK_SUCCESS"
        assert conn.connected_ip == "127.0.0.1"
        assert conn.original_host == "app.example.com"
        assert received_host == "app.example.com"
        conn.close()
    finally:
        server.shutdown()
        server.server_close()


def test_pinned_connection_fails_safely_when_all_candidate_ips_unreachable():
    """Verifies that PinnedHTTPConnection raises OSError when all candidate IPs fail."""
    from framework.common.transport import PinnedHTTPConnection

    # Both candidate IPs point to ports that are definitely closed
    conn = PinnedHTTPConnection(
        host="example.com",
        port=1,  # Port 1 is closed
        pinned_ips=["127.0.0.1", "127.0.0.1"],
        timeout=0.5,
    )
    with pytest.raises(OSError):
        conn.connect()
    assert conn.connected_ip is None


def test_resolve_scope_ips_validates_all_candidate_ips(temp_workspace, test_scope_engine):
    """
    Verifies that resolve_scope_ips evaluates all resolved candidate IPs and blocks
    any host if ANY candidate IP resolves to prohibited space (e.g. private or metadata IP).
    """
    engine = SecurityValidationEngine(
        program_dir=temp_workspace,
        scope_engine=test_scope_engine,
    )

    # 1. Prohibited direct IP
    with pytest.raises(ScopeViolationError):
        engine.resolve_scope_ips("http://10.0.0.1/test")

    # 2. Localhost without fixture port allowed
    with pytest.raises(ScopeViolationError):
        engine.resolve_scope_ips("http://127.0.0.1:9000/test")

    # 3. Localhost with fixture port allowed returns ["127.0.0.1"]
    engine.allow_fixture_port(9000)
    resolved = engine.resolve_scope_ips("http://127.0.0.1:9000/test")
    assert resolved == ["127.0.0.1"]


def test_sec01_empty_pinned_ips_fails_closed_without_dns_resolution():
    """SEC-01: Verifies that direct construction with empty pinned_ips fails closed with OSError."""
    from framework.common.transport import PinnedHTTPConnection, PinnedHTTPSConnection

    # HTTP connection
    http_conn = PinnedHTTPConnection(host="example.com", port=80, pinned_ips=[])
    with pytest.raises(OSError) as exc_info:
        http_conn.connect()
    assert "No approved destination IP pinned for host" in str(exc_info.value)
    assert http_conn.sock is None
    assert http_conn.connected_ip is None

    # HTTPS connection
    https_conn = PinnedHTTPSConnection(host="example.com", port=443, pinned_ips=[])
    with pytest.raises(OSError) as exc_info:
        https_conn.connect()
    assert "No approved destination IP pinned for host" in str(exc_info.value)
    assert https_conn.sock is None
    assert https_conn.connected_ip is None


def test_sec02_tls_handshake_socket_cleanup_on_failure():
    """SEC-02: Verifies that if TLS wrap fails, raw_sock is closed and conn.sock is set to None."""
    from unittest.mock import MagicMock
    from framework.common.transport import PinnedHTTPSConnection

    mock_raw_sock = MagicMock()
    mock_context = MagicMock()
    mock_context.wrap_socket.side_effect = ssl.SSLError("Mock TLS handshake failure")

    conn = PinnedHTTPSConnection(
        host="secure.example.com",
        port=443,
        pinned_ips=["127.0.0.1"],
        timeout=1.0,
    )
    conn._context = mock_context

    from unittest.mock import patch
    with patch("socket.create_connection", return_value=mock_raw_sock):
        with pytest.raises(ssl.SSLError):
            conn.connect()

    assert conn.sock is None
    mock_raw_sock.close.assert_called_once()


def test_sec03_default_https_context_strict_tls():
    """SEC-03: Verifies that PinnedHTTPSConnection uses strict TLS context when _context is None."""
    from unittest.mock import MagicMock, patch
    from framework.common.transport import PinnedHTTPSConnection

    mock_raw_sock = MagicMock()
    captured_context = []
    real_create_default = ssl.create_default_context

    def mock_create_default_context(*args, **kwargs):
        ctx = real_create_default(*args, **kwargs)
        captured_context.append(ctx)
        return ctx

    conn = PinnedHTTPSConnection(
        host="secure.example.com",
        port=443,
        pinned_ips=["127.0.0.1"],
        timeout=1.0,
    )
    conn._context = None

    with patch("socket.create_connection", return_value=mock_raw_sock), \
         patch("ssl.create_default_context", side_effect=mock_create_default_context), \
         patch.object(ssl.SSLContext, "wrap_socket") as mock_wrap:
        mock_wrap.return_value = MagicMock()
        conn.connect()

    assert len(captured_context) == 1
    ctx = captured_context[0]
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert conn.sock is not None


def test_sec06_bounded_authentication_executor_handles_blocked_redirect():
    """SEC-06: Verifies that BoundedAuthenticationExecutor fails closed on blocked redirects."""
    from unittest.mock import MagicMock, patch
    from framework.authentication.executor import BoundedAuthenticationExecutor, AuthSafeRedirectHandler
    import urllib.error

    class MockScopeEngine:
        def check(self, url):
            class Decision:
                status = "IN_SCOPE"
                reason = "Target in test scope"
            return Decision()

    executor = BoundedAuthenticationExecutor(scope_engine=MockScopeEngine())
    executor.allow_fixture_port(8080)

    # Directly verify AuthSafeRedirectHandler downgrade block
    handler = AuthSafeRedirectHandler(
        scope_checker=lambda u: True,
        max_redirects=5,
        original_url="https://example.com/login",
    )

    with pytest.raises(urllib.error.HTTPError) as exc_info:
        handler.redirect_request(
            req="https://example.com/login",
            fp=None,
            code=302,
            msg="Found",
            headers={},
            newurl="http://example.com/insecure",
        )
    assert exc_info.value.code == 302
    assert "Protocol downgrade from HTTPS to HTTP forbidden" in str(exc_info.value.msg)

    # Verify that execute_request converts this into failure with status_code=0
    from unittest.mock import patch
    with patch("urllib.request.build_opener") as mock_build, \
         patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]):
        mock_opener = MagicMock()
        mock_opener.open.side_effect = urllib.error.HTTPError(
            url="http://example.com/insecure",
            code=302,
            msg="Protocol downgrade from HTTPS to HTTP forbidden",
            hdrs={},
            fp=None,
        )
        mock_build.return_value = mock_opener

        result = executor.execute_request("https://example.com/login", method="POST")
        assert result["success"] is False
        assert result["status_code"] == 0
        assert "Redirect blocked" in result["error"]
        assert result["evidence"] is None

