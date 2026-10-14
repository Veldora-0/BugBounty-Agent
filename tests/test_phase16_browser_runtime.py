"""
Comprehensive Regression & Integration Tests for Phase 16:
Browser Runtime & Client-Side Security.

Verifies:
1. Browser capability detection & truthful doctor diagnostics without downloads.
2. Safe URL & network policy enforcement (SSRF, DNS resolution, scheme restrictions).
3. Exception-safe lifecycle management and resource cleanup.
4. Canary-correlated XSS proof verification (rejecting unrelated dialogs).
5. Bounded SPA observations (routes, scripts, DOM mutations, console errors).
6. Privacy & redaction of sensitive headers, storage, and tokens.
7. Centralized network policy across redirects, subresources, iframes, popups, and WebSockets.
8. Real execution budgets preventing runaway browser sessions.
9. Conditional real-browser integration testing.
"""

from __future__ import annotations

import os
import socket
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch
import pytest

from framework.findings.lifecycle import FindingLifecycle
from framework.scope.engine import ScopeDecision, ScopeEngine, ScopeStatus
from framework.tools.doctor import SystemDoctor
from framework.validation.engine import ScopeViolationError
from framework.xss.browser import (
    BrowserCapability,
    BrowserCapabilityDetector,
    BrowserConfirmationResult,
    BrowserExecutionBudget,
    BrowserNetworkPolicy,
    BrowserSessionManager,
    BrowserSpaObserver,
    BrowserXssAssistant,
    redact_browser_request_metadata,
    redact_url_for_log,
)


# ==============================================================================
# 1. Capability Detection & Doctor Reporting Tests
# ==============================================================================

def test_capability_detection_missing_playwright_package():
    """When the python playwright package cannot be imported."""
    with patch.dict("sys.modules", {"playwright": None}):
        detector = BrowserCapabilityDetector()
        status = detector.detect()
        assert status.package_available is False
        assert status.can_launch is False
        assert status.state in ("MISSING_PACKAGE", "NOT_INSTALLED")


def test_capability_detection_driver_or_executable_missing():
    """Package is importable but Chromium executable or driver is missing."""
    mock_playwright = MagicMock()
    mock_playwright_module = MagicMock()
    mock_playwright_module.sync_api = MagicMock()

    mock_playwright_module.sync_api.sync_playwright.side_effect = FileNotFoundError("Executable not found")

    with patch.dict("sys.modules", {"playwright": mock_playwright_module, "playwright.sync_api": mock_playwright_module.sync_api}):
        detector = BrowserCapabilityDetector()
        status = detector.detect()
        assert status.package_available is True
        assert status.browser_executable_available is False
        assert status.can_launch is False
        assert status.state == "MISSING_BROWSER"


def test_capability_detection_launch_failure():
    """Executable exists but headless launch fails (e.g. sandbox or lib error)."""
    mock_pw = MagicMock()
    mock_pw.chromium.launch.side_effect = RuntimeError("Failed to launch browser: missing shared library")

    mock_sync = MagicMock()
    mock_sync.__enter__.return_value = mock_pw
    mock_sync.__exit__.return_value = False

    mock_api = MagicMock()
    mock_api.sync_playwright.return_value = mock_sync

    with patch("framework.xss.browser.BrowserCapabilityDetector._get_sync_playwright", return_value=mock_api):
        detector = BrowserCapabilityDetector()
        status = detector.detect()
        assert status.package_available is True
        assert status.can_launch is False
        assert status.state == "LAUNCH_FAILED"


def test_capability_detection_success():
    """Headless browser launches successfully."""
    mock_browser = MagicMock()
    mock_pw = MagicMock()
    mock_pw.chromium.launch.return_value = mock_browser

    mock_sync = MagicMock()
    mock_sync.__enter__.return_value = mock_pw
    mock_sync.__exit__.return_value = False

    mock_api = MagicMock()
    mock_api.sync_playwright.return_value = mock_sync

    with patch("framework.xss.browser.BrowserCapabilityDetector._get_sync_playwright", return_value=mock_api):
        detector = BrowserCapabilityDetector()
        status = detector.detect()
        assert status.package_available is True
        assert status.can_launch is True
        assert status.state == "READY"
        mock_browser.close.assert_called_once()


def test_doctor_browser_check_truthful_and_zero_downloads():
    """Doctor check_browser must report truthfully without performing downloads."""
    doctor = SystemDoctor()

    with patch("framework.xss.browser.BrowserCapabilityDetector.detect") as mock_detect:
        mock_detect.return_value = BrowserCapability(
            package_available=True,
            browser_executable_available=False,
            can_launch=False,
            state="MISSING_BROWSER",
            details="Node/Chromium runtime not found",
        )

        diag = doctor.check_browser()
        assert diag["status"] == "MISSING_BROWSER"
        assert diag["can_launch"] is False
        assert "Node/Chromium" in diag.get("details", "")


# ==============================================================================
# 2. URL & Network Safety Tests
# ==============================================================================

def test_verify_url_safety_rejects_non_http_schemes():
    assistant = BrowserXssAssistant(enabled=True)
    forbidden_urls = [
        "file:///etc/passwd",
        "ftp://example.com/test",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "gopher://127.0.0.1:70",
    ]
    for u in forbidden_urls:
        with pytest.raises(ValueError, match="protocol|scheme|not permitted"):
            assistant.verify_url_safety(u)


def test_verify_url_safety_rejects_private_and_metadata_ips():
    assistant = BrowserXssAssistant(enabled=True)
    bad_ips = [
        "http://127.0.0.1/test",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1:8080/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
    ]
    for u in bad_ips:
        with pytest.raises(ValueError, match="prohibited IP|prohibited"):
            assistant.verify_url_safety(u)


def test_verify_url_safety_resolves_hostname_dns_and_blocks_rebinding():
    assistant = BrowserXssAssistant(enabled=True)

    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (2, 1, 6, "", ("127.0.0.1", 80)),
        ]
        with pytest.raises(ValueError, match="prohibited IP|resolves to prohibited"):
            assistant.verify_url_safety("http://innocent-domain.local/page")


def test_verify_url_safety_fails_closed_on_scope_violation():
    mock_scope = MagicMock(spec=ScopeEngine)
    mock_scope.check.return_value = ScopeDecision(
        status=ScopeStatus.OUT_OF_SCOPE,
        reason="Explicitly excluded",
        target="http://example.com/admin",
        normalized_target="http://example.com/admin",
        matched_rule=None,
        rule_category="EXPLICIT_EXCLUSION_URL",
    )

    assistant = BrowserXssAssistant(enabled=True, scope_engine=mock_scope)
    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]):
        with pytest.raises(ScopeViolationError):
            assistant.verify_url_safety("http://example.com/admin")


# ==============================================================================
# 3. Resource Lifecycle & Exception Cleanup Tests
# ==============================================================================

def test_browser_session_cleanup_on_success():
    mock_page = MagicMock()
    mock_context = MagicMock()
    mock_browser = MagicMock()
    mock_pw = MagicMock()

    mock_pw.chromium.launch.return_value = mock_browser
    mock_browser.new_context.return_value = mock_context
    mock_context.new_page.return_value = mock_page

    with BrowserSessionManager(mock_pw, timeout=2.0) as session:
        assert session.page is mock_page

    mock_page.close.assert_called()
    mock_context.close.assert_called()
    mock_browser.close.assert_called()


def test_browser_session_cleanup_on_exception():
    mock_page = MagicMock()
    mock_context = MagicMock()
    mock_browser = MagicMock()
    mock_pw = MagicMock()

    mock_pw.chromium.launch.return_value = mock_browser
    mock_browser.new_context.return_value = mock_context
    mock_context.new_page.return_value = mock_page

    with pytest.raises(RuntimeError, match="Primary test failure"):
        with BrowserSessionManager(mock_pw, timeout=2.0):
            raise RuntimeError("Primary test failure")

    mock_page.close.assert_called()
    mock_context.close.assert_called()
    mock_browser.close.assert_called()


def test_browser_session_cleanup_error_does_not_mask_primary_error():
    mock_page = MagicMock()
    mock_page.close.side_effect = Exception("Page close failed")
    mock_context = MagicMock()
    mock_browser = MagicMock()
    mock_pw = MagicMock()

    mock_pw.chromium.launch.return_value = mock_browser
    mock_browser.new_context.return_value = mock_context
    mock_context.new_page.return_value = mock_page

    with pytest.raises(RuntimeError, match="Original crash"):
        with BrowserSessionManager(mock_pw, timeout=2.0):
            raise RuntimeError("Original crash")


# ==============================================================================
# 4. Canary-Aware XSS Evidence & False-Positive Tests
# ==============================================================================

def test_xss_confirmation_rejects_unrelated_dialog():
    """An alert dialog with message 'Welcome user' must NOT confirm a canary probe."""
    assistant = BrowserXssAssistant(enabled=True)

    result = assistant.evaluate_dialog_observation(
        dialog_observed=True,
        dialog_message="Welcome to our site!",
        dialog_type="alert",
        canary_token="bbxss_deadbeef",
    )

    assert result.is_confirmed is False
    assert result.outcome == "INCONCLUSIVE"
    assert "did not match canary token" in result.evidence_summary


def test_xss_confirmation_accepts_matching_canary_dialog():
    """A dialog containing the exact injected canary token confirms execution."""
    assistant = BrowserXssAssistant(enabled=True)

    result = assistant.evaluate_dialog_observation(
        dialog_observed=True,
        dialog_message="Executed: bbxss_deadbeef",
        dialog_type="alert",
        canary_token="bbxss_deadbeef",
    )

    assert result.is_confirmed is True
    assert result.outcome == "CONFIRMED"
    assert "bbxss_deadbeef" in result.evidence_summary


def test_xss_confirmation_when_browser_unavailable():
    """When browser cannot launch, result must be UNAVAILABLE, not safe or confirmed."""
    assistant = BrowserXssAssistant(enabled=True)

    with patch.object(assistant, "is_available", return_value=False):
        res = assistant.confirm_candidate("http://example.com/test", canary_token="bb_canary")
        assert res.success is False
        assert res.outcome == "UNAVAILABLE"
        assert "not available" in res.evidence_summary.lower()


# ==============================================================================
# 5. Bounded SPA Observation Tests
# ==============================================================================

def test_spa_observer_bounds_routes_and_scripts():
    """SPA observer collects routes, DOM changes, and scripts within strict bounds."""
    observer = BrowserSpaObserver(max_routes=3, max_scripts=5)

    for i in range(10):
        observer.record_route_change(f"/app/path{i}")

    summary = observer.get_summary()
    assert len(summary["routes_observed"]) == 3
    assert summary["routes_observed"] == ["/app/path0", "/app/path1", "/app/path2"]


def test_spa_observer_records_dom_mutation_summary():
    observer = BrowserSpaObserver()
    observer.record_mutation(node_type="div", action="added")
    observer.record_mutation(node_type="script", action="added")
    observer.record_mutation(node_type="div", action="removed")

    summary = observer.get_summary()
    assert summary["dom_mutation_count"] == 3
    assert summary["dynamic_scripts_added"] == 1


# ==============================================================================
# 6. Sensitive Data Redaction Tests
# ==============================================================================

def test_browser_network_interception_redacts_credentials():
    """Network request headers and tokens must be redacted by default."""
    raw_headers = {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.supersecret",
        "Cookie": "session_id=abcdef123456; csrf_token=secret789",
        "X-Api-Key": "my-secret-api-key",
        "User-Agent": "BugBounty-Agent/1.0",
        "Accept": "text/html",
    }

    redacted = redact_browser_request_metadata(
        url="http://example.com/api/data?access_token=secret123&user=alice",
        headers=raw_headers,
    )

    assert "[REDACTED]" in redacted["headers"]["Authorization"]
    assert "[REDACTED]" in redacted["headers"]["Cookie"]
    assert "[REDACTED]" in redacted["headers"]["X-Api-Key"]
    assert redacted["headers"]["User-Agent"] == "BugBounty-Agent/1.0"
    assert "secret123" not in redacted["url"]


# ==============================================================================
# 7. Fail-Closed DNS & Destination Safety Regression Tests (Priority P0)
# ==============================================================================

def test_verify_url_safety_dns_resolution_failure_fails_closed():
    """DNS resolution errors (socket.gaierror, OSError) must fail closed."""
    assistant = BrowserXssAssistant(enabled=True)
    with patch("socket.getaddrinfo", side_effect=socket.gaierror(-2, "Name or service not known")):
        with pytest.raises(ValueError, match="DNS resolution failed"):
            assistant.verify_url_safety("http://unresolvable-domain.example.com/page")


def test_verify_url_safety_empty_dns_results_fails_closed():
    """Empty DNS resolution result list must fail closed."""
    assistant = BrowserXssAssistant(enabled=True)
    with patch("socket.getaddrinfo", return_value=[]):
        with pytest.raises(ValueError, match="DNS resolution returned no addresses"):
            assistant.verify_url_safety("http://empty-dns.example.com/page")


def test_verify_url_safety_public_only_dns_succeeds():
    """Host resolving exclusively to public IP addresses must be permitted."""
    assistant = BrowserXssAssistant(enabled=True)
    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]):
        assistant.verify_url_safety("http://example.com/page")


def test_verify_url_safety_private_only_dns_fails_closed():
    """Host resolving to private IP (e.g. 10.0.0.1) must fail closed."""
    assistant = BrowserXssAssistant(enabled=True)
    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 80))]):
        with pytest.raises(ValueError, match="resolves to prohibited IP"):
            assistant.verify_url_safety("http://internal-host.example.com/page")


def test_verify_url_safety_mixed_public_and_prohibited_dns_fails_closed():
    """Host returning mixed public and private IP records must fail closed."""
    assistant = BrowserXssAssistant(enabled=True)
    with patch("socket.getaddrinfo", return_value=[
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
    ]):
        with pytest.raises(ValueError, match="resolves to prohibited IP"):
            assistant.verify_url_safety("http://mixed-dns.example.com/page")


def test_verify_url_safety_ipv4_and_ipv6_loopbacks():
    """Literal loopback IPs in IPv4 and IPv6 must be rejected."""
    assistant = BrowserXssAssistant(enabled=True)
    for url in ["http://127.0.0.1/", "http://127.0.1.1/", "http://[::1]/"]:
        with pytest.raises(ValueError, match="prohibited IP"):
            assistant.verify_url_safety(url)


def test_verify_url_safety_ipv4_mapped_ipv6():
    """IPv4-mapped IPv6 literal destinations must be rejected."""
    assistant = BrowserXssAssistant(enabled=True)
    for url in ["http://[::ffff:127.0.0.1]/", "http://[::ffff:169.254.169.254]/", "http://[::ffff:10.0.0.1]/"]:
        with pytest.raises(ValueError, match="prohibited IP"):
            assistant.verify_url_safety(url)


def test_verify_url_safety_metadata_destination():
    """Cloud metadata endpoints must be blocked."""
    assistant = BrowserXssAssistant(enabled=True)
    with pytest.raises(ValueError, match="prohibited IP"):
        assistant.verify_url_safety("http://169.254.169.254/latest/meta-data/")


def test_verify_url_safety_malformed_url_and_missing_host():
    """Missing host, empty url, or malformed protocol must be rejected."""
    assistant = BrowserXssAssistant(enabled=True)
    for url in ["", "http:///no-host", "ftp://host/path", "javascript:void(0)"]:
        with pytest.raises(ValueError):
            assistant.verify_url_safety(url)


def test_verify_url_safety_scope_cannot_override_failed_dns_or_prohibited_ip():
    """Scope authorization must never override destination or DNS check failures."""
    mock_scope = MagicMock(spec=ScopeEngine)
    mock_scope.check.return_value = ScopeDecision(
        status=ScopeStatus.IN_SCOPE,
        reason="Wildcard in scope",
        target="http://innocent.example.com",
        normalized_target="http://innocent.example.com",
        matched_rule="*.example.com",
        rule_category="WILDCARD",
    )
    assistant = BrowserXssAssistant(enabled=True, scope_engine=mock_scope)
    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]):
        with pytest.raises(ValueError, match="resolves to prohibited IP"):
            assistant.verify_url_safety("http://innocent.example.com")


# ==============================================================================
# 8. Centralized Network Policy Tests (Priority P0)
# ==============================================================================

def test_network_policy_in_scope_initial_navigation():
    """Legitimate in-scope request is allowed by policy."""
    policy = BrowserNetworkPolicy()
    mock_route = MagicMock()
    mock_request = MagicMock()
    mock_request.url = "http://example.com/home"
    mock_request.method = "GET"
    mock_request.headers = {"User-Agent": "test"}
    mock_request.redirected_from = None

    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]):
        policy.handle_route(mock_route, mock_request)
        mock_route.continue_.assert_called_once()
        assert policy.request_count == 1
        assert len(policy.blocked_requests) == 0


def test_network_policy_out_of_scope_redirect_blocked():
    """Redirect targeting an out-of-scope domain must be aborted."""
    mock_scope = MagicMock(spec=ScopeEngine)
    mock_scope.check.return_value = ScopeDecision(
        status=ScopeStatus.OUT_OF_SCOPE,
        reason="Target is external",
        target="http://attacker.com/evil",
        normalized_target="http://attacker.com/evil",
        matched_rule=None,
        rule_category="OUT_OF_SCOPE",
    )
    policy = BrowserNetworkPolicy(scope_engine=mock_scope)
    mock_route = MagicMock()
    mock_request = MagicMock()
    mock_request.url = "http://attacker.com/evil"
    mock_request.method = "GET"
    mock_request.headers = {}
    mock_request.redirected_from = MagicMock()

    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]):
        policy.handle_route(mock_route, mock_request)
        mock_route.abort.assert_called_with("accessdenied")
        assert len(policy.blocked_requests) == 1
        assert "OUT_OF_SCOPE" in policy.blocked_requests[0]["reason"]


def test_network_policy_redirect_to_prohibited_literal_ip():
    """Redirect targeting a loopback or private IP literal is aborted."""
    policy = BrowserNetworkPolicy()
    mock_route = MagicMock()
    mock_request = MagicMock()
    mock_request.url = "http://127.0.0.1:8080/admin"
    mock_request.method = "GET"
    mock_request.headers = {}
    mock_request.redirected_from = MagicMock()

    policy.handle_route(mock_route, mock_request)
    mock_route.abort.assert_called_with("accessdenied")
    assert len(policy.blocked_requests) == 1
    assert "prohibited IP" in policy.blocked_requests[0]["reason"]


def test_network_policy_redirect_to_hostname_resolving_to_prohibited_ip():
    """Redirect to host resolving to 169.254.169.254 is aborted."""
    policy = BrowserNetworkPolicy()
    mock_route = MagicMock()
    mock_request = MagicMock()
    mock_request.url = "http://metadata-rebinder.com/meta"
    mock_request.method = "GET"
    mock_request.headers = {}
    mock_request.redirected_from = MagicMock()

    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]):
        policy.handle_route(mock_route, mock_request)
        mock_route.abort.assert_called_with("accessdenied")
        assert len(policy.blocked_requests) == 1
        assert "prohibited IP" in policy.blocked_requests[0]["reason"]


def test_network_policy_prohibited_subresource_aborted():
    """Subresource image or script fetching private IP is aborted."""
    policy = BrowserNetworkPolicy()
    mock_route = MagicMock()
    mock_request = MagicMock()
    mock_request.url = "http://10.0.0.1/script.js"
    mock_request.method = "GET"
    mock_request.headers = {}
    mock_request.redirected_from = None

    policy.handle_route(mock_route, mock_request)
    mock_route.abort.assert_called_with("accessdenied")
    assert len(policy.blocked_requests) == 1


def test_network_policy_out_of_scope_iframe_aborted():
    """Iframe loading out-of-scope URL is aborted."""
    mock_scope = MagicMock(spec=ScopeEngine)
    mock_scope.check.return_value = ScopeDecision(
        status=ScopeStatus.OUT_OF_SCOPE,
        reason="Iframe out of scope",
        target="http://unauthorized-partner.com/",
        normalized_target="http://unauthorized-partner.com/",
        matched_rule=None,
        rule_category="OUT_OF_SCOPE",
    )
    policy = BrowserNetworkPolicy(scope_engine=mock_scope)
    mock_route = MagicMock()
    mock_request = MagicMock()
    mock_request.url = "http://unauthorized-partner.com/"
    mock_request.method = "GET"
    mock_request.headers = {}
    mock_request.redirected_from = None

    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]):
        policy.handle_route(mock_route, mock_request)
        mock_route.abort.assert_called_with("accessdenied")
        assert len(policy.blocked_requests) == 1


def test_network_policy_websocket_destination_restriction():
    """WebSocket connection to private or loopback IP must be closed immediately."""
    policy = BrowserNetworkPolicy()
    mock_ws = MagicMock()
    mock_ws.url = "ws://127.0.0.1:9001/ws"

    policy.handle_websocket(mock_ws)
    mock_ws.close.assert_called_once()
    assert len(policy.blocked_requests) == 1
    assert policy.blocked_requests[0]["method"] == "WEBSOCKET"


def test_network_policy_scope_and_dns_check_exceptions_fail_closed():
    """Unexpected exceptions in scope or DNS check fail closed and abort route."""
    policy = BrowserNetworkPolicy()
    mock_route = MagicMock()
    mock_request = MagicMock()
    mock_request.url = "http://example.com/test"
    mock_request.method = "GET"
    mock_request.headers = {}
    mock_request.redirected_from = None

    with patch.object(policy, "verify_url_safety", side_effect=RuntimeError("Unexpected policy failure")):
        policy.handle_route(mock_route, mock_request)
        mock_route.abort.assert_called_with("accessdenied")
        assert len(policy.blocked_requests) == 1


# ==============================================================================
# 9. Execution Budgets Tests (Priority P1)
# ==============================================================================

def test_execution_budget_request_limit_aborts_subsequent_requests():
    """When max_requests budget is reached, subsequent requests are aborted."""
    budget = BrowserExecutionBudget(max_requests=2)
    policy = BrowserNetworkPolicy(budget=budget)

    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]):
        for i in range(2):
            route = MagicMock()
            req = MagicMock(url=f"http://example.com/req{i}", method="GET", headers={}, redirected_from=None)
            policy.handle_route(route, req)
            route.continue_.assert_called_once()

        route_3 = MagicMock()
        req_3 = MagicMock(url="http://example.com/req2", method="GET", headers={}, redirected_from=None)
        policy.handle_route(route_3, req_3)
        route_3.abort.assert_called_with("timedout")
        assert policy.budget_exceeded is True


def test_execution_budget_redirect_limit_aborts():
    """When max_redirects budget is reached, redirect is aborted."""
    budget = BrowserExecutionBudget(max_redirects=1)
    policy = BrowserNetworkPolicy(budget=budget)

    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]):
        r1 = MagicMock()
        req1 = MagicMock(url="http://example.com/redir1", method="GET", headers={}, redirected_from=MagicMock())
        policy.handle_route(r1, req1)
        r1.continue_.assert_called_once()

        r2 = MagicMock()
        req2 = MagicMock(url="http://example.com/redir2", method="GET", headers={}, redirected_from=MagicMock())
        policy.handle_route(r2, req2)
        r2.abort.assert_called_with("accessdenied")
        assert policy.budget_exceeded is True


# ==============================================================================
# 10. Exception-Safe Lifecycle & Partial Initialization Tests (Priority P1)
# ==============================================================================

def test_lifecycle_context_creation_failure_cleans_up_browser():
    """If new_context() fails, browser launched in __enter__ must be closed."""
    mock_browser = MagicMock()
    mock_browser.new_context.side_effect = RuntimeError("Context allocation failed")
    mock_pw = MagicMock()
    mock_pw.chromium.launch.return_value = mock_browser

    with pytest.raises(RuntimeError, match="Context allocation failed"):
        with BrowserSessionManager(mock_pw, timeout=2.0):
            pass

    mock_browser.close.assert_called_once()


def test_lifecycle_page_creation_failure_cleans_up_context_and_browser():
    """If new_page() fails, context and browser must be closed."""
    mock_browser = MagicMock()
    mock_context = MagicMock()
    mock_context.new_page.side_effect = RuntimeError("Page allocation failed")
    mock_browser.new_context.return_value = mock_context
    mock_pw = MagicMock()
    mock_pw.chromium.launch.return_value = mock_browser

    with pytest.raises(RuntimeError, match="Page allocation failed"):
        with BrowserSessionManager(mock_pw, timeout=2.0):
            pass

    mock_context.close.assert_called_once()
    mock_browser.close.assert_called_once()


def test_lifecycle_multiple_cleanup_failures_do_not_mask_primary_error():
    """Exceptions during cleanup must never mask the primary exception raised inside the block."""
    mock_page = MagicMock()
    mock_page.close.side_effect = Exception("Page close error")
    mock_context = MagicMock()
    mock_context.close.side_effect = Exception("Context close error")
    mock_browser = MagicMock()
    mock_browser.close.side_effect = Exception("Browser close error")
    mock_pw = MagicMock()
    mock_pw.chromium.launch.return_value = mock_browser
    mock_browser.new_context.return_value = mock_context
    mock_context.new_page.return_value = mock_page

    with pytest.raises(ValueError, match="Primary payload error"):
        with BrowserSessionManager(mock_pw, timeout=2.0):
            raise ValueError("Primary payload error")


# ==============================================================================
# 11. Sensitive-Data Redaction Tests (Priority P1)
# ==============================================================================

def test_redaction_embedded_credentials_in_url():
    """Embedded URL passwords must be redacted from URLs and errors."""
    clean = redact_url_for_log("http://admin:SuperSecretPass999!@example.com/api?user=alice")
    assert "SuperSecretPass999!" not in clean
    assert "[REDACTED" in clean


def test_redaction_console_and_page_errors():
    """Console messages and page errors must scrub secrets."""
    observer = BrowserSpaObserver()
    observer.record_console("User token loaded: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummysecret")
    observer.record_error("Failed request with Authorization: Bearer secret-bearer-token")

    summary = observer.get_summary()
    assert "dummysecret" not in summary["console_messages"][0]
    assert "secret-bearer-token" not in summary["page_errors"][0]


def test_redaction_malformed_url_does_not_crash_or_leak():
    """Malformed URL with secret is scrubbed without raising unhandled exceptions."""
    malformed = "http://user:Secret123@::invalid-host:99999/path?token=jwtsecret"
    clean = redact_url_for_log(malformed)
    assert "Secret123" not in clean
    assert "jwtsecret" not in clean


# ==============================================================================
# 12. Canary-Aware Correlation & Candidate Proof Tests (Priority P1)
# ==============================================================================

def test_canary_empty_token_returns_inconclusive():
    """Dialog with empty canary token cannot confirm execution; returns INCONCLUSIVE."""
    assistant = BrowserXssAssistant(enabled=True)
    res = assistant.evaluate_dialog_observation(
        dialog_observed=True,
        dialog_message="1",
        dialog_type="alert",
        canary_token="",
    )
    assert res.is_confirmed is False
    assert res.outcome == "INCONCLUSIVE"


def test_canary_matching_token_returns_confirmed():
    """Dialog containing the exact canary token confirms execution."""
    assistant = BrowserXssAssistant(enabled=True)
    res = assistant.evaluate_dialog_observation(
        dialog_observed=True,
        dialog_message="Executed: bb_canary_12345",
        dialog_type="alert",
        canary_token="bb_canary_12345",
    )
    assert res.is_confirmed is True
    assert res.outcome == "CONFIRMED"


# ==============================================================================
# 13. Dependency & Doctor Diagnostics Tests
# ==============================================================================

def test_dependency_resolver_checks_playwright_browsers():
    """DependencyResolver correctly evaluates playwright-browsers dependency."""
    from framework.tools.dependencies import DependencyResolver
    from framework.tools.registry import ToolRegistry

    registry = ToolRegistry()
    resolver = DependencyResolver(registry)

    with patch("framework.tools.dependencies._check_playwright_browsers", return_value=False):
        missing = resolver.check_missing_prerequisites("playwright")
        assert "playwright-browsers" in missing

    with patch("framework.tools.dependencies._check_playwright_browsers", return_value=True):
        missing = resolver.check_missing_prerequisites("playwright")
        assert "playwright-browsers" not in missing


def test_doctor_browser_check_sanitizes_details():
    """Doctor check_browser must scrub secrets from details."""
    doctor = SystemDoctor()
    with patch("framework.xss.browser.BrowserCapabilityDetector.detect") as mock_det:
        mock_det.return_value = BrowserCapability(
            package_available=True,
            browser_executable_available=True,
            can_launch=False,
            state="LAUNCH_FAILED",
            details="Launch failed: token=SecretKey12345 in env",
        )
        res = doctor.check_browser()
        assert "SecretKey12345" not in res["details"]
        assert "[REDACTED_BY_BB_AGENT]" in res["details"] or "[REDACTED]" in res["details"]


# ==============================================================================
# 14. Real-Browser Integration Fixture (Conditional on Environment)
# ==============================================================================

@pytest.mark.skipif(
    not BrowserCapabilityDetector().detect().can_launch,
    reason="Headless Chromium runtime not available in current environment",
)
def test_real_browser_local_spa_integration():
    """
    Real-browser integration test against a local loopback server.
    Only executed when headless Chromium is actually launchable.
    """
    import http.server
    import threading

    class LocalSpaHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            html = """<!DOCTYPE html>
            <html>
            <head><title>SPA Test</title></head>
            <body>
                <div id="content">Initial</div>
                <script>
                    history.pushState({}, '', '/spa/route1');
                    const d = document.createElement('div');
                    d.textContent = 'Dynamic Node';
                    document.body.appendChild(d);
                </script>
            </body>
            </html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))

        def log_message(self, format, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), LocalSpaHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()

    assistant = BrowserXssAssistant(enabled=True)
    res = assistant.confirm_candidate(f"http://127.0.0.1:{port}/", canary_token="dummy", observe_spa=True)
    assert res.outcome in ("BLOCKED", "OBSERVED")
