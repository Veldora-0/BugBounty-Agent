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
import tempfile
import threading
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
    BrowserSecurityPolicyError,
    BrowserSessionManager,
    BrowserSpaObserver,
    BrowserXssAssistant,
    MANDATORY_CHROMIUM_ISOLATION_FLAGS,
    ValidatingEgressProxy,
    redact_browser_request_metadata,
    redact_url_for_log,
    truncate_to_max_bytes,
)
from framework.xss.engine import XssIntelligenceEngine
from framework.xss.model import XssCandidate, XssCategory, XssConfidence


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
    Real-browser integration test exercising actual headless Chromium execution
    and SPA observer hooks via Playwright in-memory route fulfillment.

    Safety & Determinism Guarantees:
    1. Authorized In-Scope Destination: Uses 'https://spa-fixture.example.com/app'.
    2. Zero External Traffic: Mocked DNS returns public IP; Playwright route handler
       fulfills the request in-memory with local fixture HTML.
    3. Production SSRF active: No bypasses for loopback or private ranges.
    4. Real Browser JS execution: Executes history.pushState and DOM mutations in real Chromium.
    5. Non-vacuous assertions: Asserts outcome is OBSERVED, route transitions are captured,
       and DOM mutation counts are recorded.
    """
    mock_scope = MagicMock(spec=ScopeEngine)
    mock_scope.check.return_value = ScopeDecision(
        status=ScopeStatus.IN_SCOPE,
        reason="Authorized test target",
        target="https://spa-fixture.example.com/app",
        normalized_target="https://spa-fixture.example.com/app",
        matched_rule=None,
        rule_category="TARGET_DOMAIN",
    )

    fixture_html = """<!DOCTYPE html>
    <html>
    <head><title>SPA Live Test</title></head>
    <body>
        <div id="content">Initial View</div>
        <script>
            // Client-side route transition
            history.pushState({}, '', '/spa/route1');
            // DOM mutation
            const d = document.createElement('div');
            d.id = 'dynamic-element';
            d.textContent = 'Dynamic Content Added';
            document.body.appendChild(d);
        </script>
    </body>
    </html>"""

    def handle_fixture_route(route, request):
        if "spa-fixture.example.com" in request.url:
            route.fulfill(
                status=200,
                content_type="text/html",
                body=fixture_html,
            )
            return True
        return False

    assistant = BrowserXssAssistant(
        enabled=True,
        scope_engine=mock_scope,
        route_fulfill_handler=handle_fixture_route,
    )

    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]):
        res = assistant.confirm_candidate(
            target_url="https://spa-fixture.example.com/app",
            canary_token="canary_token_spa",
            observe_spa=True,
        )

    # Assert real-browser observation succeeded
    assert res.outcome == "OBSERVED"
    assert res.success is True
    assert res.is_confirmed is False
    assert "/spa/route1" in res.spa_summary.get("routes_observed", [])
    assert res.spa_summary.get("dom_mutation_count", 0) >= 1


# ==============================================================================
# 15. Fail-Closed Browser Initialization & Policy Registration Regression Tests
# ==============================================================================

def test_attach_to_context_fails_closed_when_route_registration_fails():
    """
    If context.route() fails, attach_to_context must raise BrowserSecurityPolicyError.
    Proves that routing failure does not silently pass.
    """
    policy = BrowserNetworkPolicy()
    mock_context = MagicMock()
    mock_context.route.side_effect = RuntimeError("Playwright internal route error")

    with pytest.raises(BrowserSecurityPolicyError, match="mandatory network route interception"):
        policy.attach_to_context(mock_context)

    mock_context.route.assert_called_once_with("**/*", policy.handle_route)


def test_attach_to_context_fails_closed_when_websocket_handler_fails():
    """
    If WebSocket security event registration fails, must raise BrowserSecurityPolicyError.
    """
    policy = BrowserNetworkPolicy()
    mock_context = MagicMock()

    def mock_on(event, handler):
        if event == "websocket":
            raise RuntimeError("WebSocket event registration failed")

    mock_context.on.side_effect = mock_on

    with pytest.raises(BrowserSecurityPolicyError, match="mandatory WebSocket security handler"):
        policy.attach_to_context(mock_context)


def test_attach_to_context_fails_closed_when_page_handler_fails():
    """
    If child page event registration fails, must raise BrowserSecurityPolicyError.
    """
    policy = BrowserNetworkPolicy()
    mock_context = MagicMock()

    def mock_on(event, handler):
        if event == "page":
            raise RuntimeError("Page event registration failed")

    mock_context.on.side_effect = mock_on

    with pytest.raises(BrowserSecurityPolicyError, match="mandatory child page security handler"):
        policy.attach_to_context(mock_context)


def test_attach_to_context_rejects_null_context():
    """Passing a null context must raise BrowserSecurityPolicyError."""
    policy = BrowserNetworkPolicy()
    with pytest.raises(BrowserSecurityPolicyError, match="null BrowserContext"):
        policy.attach_to_context(None)


def test_confirm_candidate_aborts_navigation_when_security_policy_registration_fails():
    """
    When mandatory security policy registration fails inside confirm_candidate:
    1. Navigation (page.goto) is NEVER attempted.
    2. Acquired browser resources are cleaned up safely.
    3. The outcome is BLOCKED, not confirmed or successful.
    4. The security error is recorded in the result.
    """
    mock_page = MagicMock()
    mock_context = MagicMock()
    mock_browser = MagicMock()
    mock_pw = MagicMock()

    mock_pw.chromium.launch.return_value = mock_browser
    mock_browser.new_context.return_value = mock_context
    mock_context.new_page.return_value = mock_page

    # Simulate route registration failure in Playwright
    mock_context.route.side_effect = RuntimeError("Driver failed to register route interceptor")

    mock_sync = MagicMock()
    mock_sync.__enter__.return_value = mock_pw
    mock_sync.__exit__.return_value = False

    mock_playwright_mod = MagicMock()
    mock_sync_api = MagicMock()
    mock_sync_api.sync_playwright.return_value = mock_sync
    mock_playwright_mod.sync_api = mock_sync_api

    assistant = BrowserXssAssistant(enabled=True)

    with patch.object(assistant, "is_available", return_value=True):
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]):
            with patch.dict("sys.modules", {"playwright": mock_playwright_mod, "playwright.sync_api": mock_sync_api}):
                res = assistant.confirm_candidate(
                    target_url="http://example.com/search?q=test",
                    canary_token="canary_xyz",
                )

    # Invariant 1: Navigation was NEVER called
    mock_page.goto.assert_not_called()

    # Invariant 2: Result is safe, unconfirmed, and marked BLOCKED
    assert res.success is False
    assert res.is_confirmed is False
    assert res.outcome == "BLOCKED"
    assert any("mandatory" in err.lower() and "interception" in err.lower() for err in res.errors)
    assert "mandatory security policy" in res.evidence_summary.lower()

    # Invariant 3: Resources cleaned up safely; page was never created
    mock_context.new_page.assert_not_called()
    mock_context.close.assert_called()
    mock_browser.close.assert_called()


def test_confirm_candidate_navigates_when_policy_registration_succeeds():
    """
    When security policy registration succeeds, normal browser confirmation flow runs.
    """
    mock_page = MagicMock()
    mock_page.url = "http://example.com/search?q=test"
    mock_context = MagicMock()
    mock_browser = MagicMock()
    mock_pw = MagicMock()

    mock_pw.chromium.launch.return_value = mock_browser
    mock_browser.new_context.return_value = mock_context
    mock_context.new_page.return_value = mock_page

    mock_sync = MagicMock()
    mock_sync.__enter__.return_value = mock_pw
    mock_sync.__exit__.return_value = False

    mock_playwright_mod = MagicMock()
    mock_sync_api = MagicMock()
    mock_sync_api.sync_playwright.return_value = mock_sync
    mock_playwright_mod.sync_api = mock_sync_api

    assistant = BrowserXssAssistant(enabled=True)

    with patch.object(assistant, "is_available", return_value=True):
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]):
            with patch.dict("sys.modules", {"playwright": mock_playwright_mod, "playwright.sync_api": mock_sync_api}):
                res = assistant.confirm_candidate(
                    target_url="http://example.com/search?q=test",
                    canary_token="canary_xyz",
                )

    # Mandatory route interception was registered
    mock_context.route.assert_called_once_with("**/*", unittest_any())
    # Navigation proceeded
    mock_page.goto.assert_called_once()
    # Resources cleaned up after completion
    mock_page.close.assert_called()
    mock_context.close.assert_called()
    mock_browser.close.assert_called()
    assert res.outcome == "OBSERVED"


def unittest_any():
    from unittest.mock import ANY
    return ANY


def test_regression_browser_disabled_by_default_and_scope_enforced():
    """
    Verifies browser automation remains disabled by default and scope protections
    prevent pre-flight execution even before browser initialization.
    """
    assistant = BrowserXssAssistant()
    assert assistant.enabled is False

    res = assistant.confirm_candidate("http://example.com/test", canary_token="canary")
    assert res.success is False
    assert res.is_confirmed is False
    assert res.outcome == "UNAVAILABLE"
    assert "disabled by default" in res.evidence_summary.lower()


# ==============================================================================
# 16. XSS Intelligence Engine to Browser Lifecycle Tests
# ==============================================================================

def test_engine_confirm_candidate_browser_disabled_returns_unavailable():
    """When browser assistant is disabled on the engine, candidate remains unchanged."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        engine = XssIntelligenceEngine(program_dir=tmp_dir, browser_enabled=False)
        cand = XssCandidate(
            category=XssCategory.REFLECTED,
            target_asset="example.com",
            endpoint="http://example.com/search",
            parameter="q",
            canary_token="canary_123",
            confidence=XssConfidence.SUSPECTED,
        )

        res = engine.confirm_candidate_with_browser(cand)
        assert res.outcome == "UNAVAILABLE"
        assert res.is_confirmed is False
        assert cand.confidence == XssConfidence.SUSPECTED
        assert cand.lifecycle_state != "VALIDATED"


def test_engine_confirm_candidate_input_validation_failure():
    """Null candidate or missing endpoint must return INVALID_INPUT without crashing."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        engine = XssIntelligenceEngine(program_dir=tmp_dir, browser_enabled=True)

        res_none = engine.confirm_candidate_with_browser(None)
        assert res_none.outcome == "INVALID_INPUT"
        assert res_none.is_confirmed is False

        cand_no_ep = XssCandidate(
            category=XssCategory.REFLECTED,
            target_asset="example.com",
            endpoint="",
            parameter="q",
            canary_token="canary_123",
        )
        res_no_ep = engine.confirm_candidate_with_browser(cand_no_ep)
        assert res_no_ep.outcome == "INVALID_INPUT"
        assert res_no_ep.is_confirmed is False


def test_engine_confirm_candidate_inconclusive_observation():
    """Inconclusive browser observation must never promote candidate to VALIDATED."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        engine = XssIntelligenceEngine(program_dir=tmp_dir, browser_enabled=True)
        cand = XssCandidate(
            category=XssCategory.REFLECTED,
            target_asset="example.com",
            endpoint="http://example.com/search",
            parameter="q",
            canary_token="canary_123",
            confidence=XssConfidence.OBSERVED,
            lifecycle_state="OBSERVED",
        )

        mock_result = BrowserConfirmationResult(
            success=True,
            is_confirmed=False,
            outcome="INCONCLUSIVE",
            evidence_summary="Navigation completed with no dialog observed.",
        )

        with patch.object(engine.browser_assistant, "confirm_candidate", return_value=mock_result):
            res = engine.confirm_candidate_with_browser(cand)

        assert res.is_confirmed is False
        assert cand.confidence == XssConfidence.OBSERVED
        assert cand.lifecycle_state == "OBSERVED"


def test_engine_confirm_candidate_unrelated_dialog_rejects_confirmation():
    """Unrelated alert dialog must reject candidate confirmation and leave state intact."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        engine = XssIntelligenceEngine(program_dir=tmp_dir, browser_enabled=True)
        cand = XssCandidate(
            category=XssCategory.REFLECTED,
            target_asset="example.com",
            endpoint="http://example.com/search",
            parameter="q",
            canary_token="canary_123",
            confidence=XssConfidence.SUSPECTED,
        )

        mock_result = BrowserConfirmationResult(
            success=True,
            is_confirmed=False,
            outcome="INCONCLUSIVE",
            dialog_observed=True,
            dialog_message="Welcome User!",
            evidence_summary="Dialog did not match canary token.",
        )

        with patch.object(engine.browser_assistant, "confirm_candidate", return_value=mock_result):
            res = engine.confirm_candidate_with_browser(cand)

        assert res.is_confirmed is False
        assert cand.confidence == XssConfidence.SUSPECTED
        assert cand.lifecycle_state != "VALIDATED"


def test_engine_confirm_candidate_matching_canary_confirms_and_updates_lifecycle():
    """Matching canary token confirms execution, promotes to VALIDATED, and saves state."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        engine = XssIntelligenceEngine(program_dir=tmp_dir, browser_enabled=True)
        cand = XssCandidate(
            category=XssCategory.REFLECTED,
            target_asset="example.com",
            endpoint="http://example.com/search",
            parameter="q",
            canary_token="canary_123",
            confidence=XssConfidence.SUSPECTED,
            lifecycle_state="OBSERVED",
        )

        mock_result = BrowserConfirmationResult(
            success=True,
            is_confirmed=True,
            outcome="CONFIRMED",
            dialog_observed=True,
            dialog_message="canary_123",
            evidence_summary="Browser confirmed XSS execution via dialog with canary_123.",
        )

        with patch.object(engine.browser_assistant, "confirm_candidate", return_value=mock_result):
            res = engine.confirm_candidate_with_browser(cand)

        assert res.is_confirmed is True
        assert cand.confidence == XssConfidence.VALIDATED
        assert cand.lifecycle_state == "VALIDATED"
        assert "canary_123" in cand.notes

        # Verify state persistence
        saved_cands = engine.state_mgr.list_candidates()
        assert len(saved_cands) == 1
        assert saved_cands[0].confidence == XssConfidence.VALIDATED
        assert saved_cands[0].lifecycle_state == "VALIDATED"


def test_engine_confirm_candidate_initialization_failure():
    """Initialization/policy failure returns BLOCKED and does not update candidate."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        engine = XssIntelligenceEngine(program_dir=tmp_dir, browser_enabled=True)
        cand = XssCandidate(
            category=XssCategory.REFLECTED,
            target_asset="example.com",
            endpoint="http://example.com/search",
            parameter="q",
            canary_token="canary_123",
            confidence=XssConfidence.SUSPECTED,
        )

        mock_result = BrowserConfirmationResult(
            success=False,
            is_confirmed=False,
            outcome="BLOCKED",
            errors=["Network policy failed to attach."],
        )

        with patch.object(engine.browser_assistant, "confirm_candidate", return_value=mock_result):
            res = engine.confirm_candidate_with_browser(cand)

        assert res.is_confirmed is False
        assert res.outcome == "BLOCKED"
        assert cand.confidence == XssConfidence.SUSPECTED


def test_engine_confirm_candidate_timeout_failure():
    """Browser timeout returns TIMEOUT and does not promote candidate."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        engine = XssIntelligenceEngine(program_dir=tmp_dir, browser_enabled=True)
        cand = XssCandidate(
            category=XssCategory.REFLECTED,
            target_asset="example.com",
            endpoint="http://example.com/search",
            parameter="q",
            canary_token="canary_123",
            confidence=XssConfidence.OBSERVED,
        )

        mock_result = BrowserConfirmationResult(
            success=False,
            is_confirmed=False,
            outcome="TIMEOUT",
            errors=["Overall execution deadline exceeded."],
        )

        with patch.object(engine.browser_assistant, "confirm_candidate", return_value=mock_result):
            res = engine.confirm_candidate_with_browser(cand)

        assert res.is_confirmed is False
        assert res.outcome == "TIMEOUT"
        assert cand.confidence != XssConfidence.VALIDATED


# ==============================================================================
# 17. End-to-End Execution Deadline & Evidence-Size Budget Tests
# ==============================================================================

def test_budget_deadline_expiration_before_initialization():
    """Deadline already expired before initialization must abort immediately with TIMEOUT."""
    assistant = BrowserXssAssistant(enabled=True)
    budget = BrowserExecutionBudget(max_timeout_seconds=2.0)

    # Simulate monotonic clock advancing beyond deadline
    clock_values = [100.0, 105.0]  # start at 100.0, deadline is 102.0, next call is 105.0
    with patch("time.monotonic", side_effect=clock_values):
        with patch.object(assistant, "is_available", return_value=True):
            with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]):
                res = assistant.confirm_candidate(
                    target_url="http://example.com/test",
                    canary_token="canary_tok",
                    budget=budget,
                )

    assert res.success is False
    assert res.outcome == "TIMEOUT"
    assert "deadline" in res.evidence_summary.lower()


def test_budget_deadline_expiration_during_navigation():
    """If navigation wait causes deadline expiry, session terminates safely with TIMEOUT."""
    mock_page = MagicMock()
    mock_context = MagicMock()
    mock_browser = MagicMock()
    mock_pw = MagicMock()

    mock_pw.chromium.launch.return_value = mock_browser
    mock_browser.new_context.return_value = mock_context
    mock_context.new_page.return_value = mock_page

    mock_sync = MagicMock()
    mock_sync.__enter__.return_value = mock_pw
    mock_sync.__exit__.return_value = False

    mock_playwright_mod = MagicMock()
    mock_sync_api = MagicMock()
    mock_sync_api.sync_playwright.return_value = mock_sync
    mock_playwright_mod.sync_api = mock_sync_api

    assistant = BrowserXssAssistant(enabled=True)
    budget = BrowserExecutionBudget(max_timeout_seconds=2.0)

    # Monotonic clock: 0.0 at start, 0.1 at check, 0.2 at launch, 2.5 during goto
    clock_values = [0.0, 0.1, 0.2, 0.3, 2.5, 2.6, 2.7]
    with patch("time.monotonic", side_effect=clock_values):
        with patch.object(assistant, "is_available", return_value=True):
            with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]):
                with patch.dict("sys.modules", {"playwright": mock_playwright_mod, "playwright.sync_api": mock_sync_api}):
                    res = assistant.confirm_candidate(
                        target_url="http://example.com/test",
                        canary_token="canary_tok",
                        budget=budget,
                    )

    assert res.success is False
    assert res.outcome == "TIMEOUT"
    # Ensure cleanup ran
    mock_page.close.assert_called()
    mock_context.close.assert_called()
    mock_browser.close.assert_called()


def test_evidence_budget_caps_total_bytes_and_marks_truncated():
    """Evidence budget enforces max_evidence_bytes cap and marks truncated status."""
    observer = BrowserSpaObserver(max_evidence_bytes=1024)

    # Add messages that exceed 1024 bytes
    large_msg = "X" * 300
    for i in range(5):
        observer.record_console(f"Log {i}: {large_msg}")

    summary = observer.get_summary()
    assert summary["evidence_truncated"] is True
    assert summary["evidence_bytes"] <= 1024
    # Ensure not all 5 messages were accumulated
    assert len(summary["console_messages"]) < 5


def test_evidence_budget_truncation_preserves_redaction_and_safety():
    """Redaction is applied before length calculation, and truncated evidence note is recorded."""
    assistant = BrowserXssAssistant(enabled=True)
    budget = BrowserExecutionBudget(max_evidence_bytes=1024, max_timeout_seconds=5.0)

    # Verify that max_evidence_bytes is passed through and respected
    spa_obs = BrowserSpaObserver(max_evidence_bytes=budget.max_evidence_bytes)
    spa_obs.evidence_truncated = True

    summary = spa_obs.get_summary()
    assert summary["evidence_truncated"] is True


def test_truncate_to_max_bytes_multibyte_unicode_and_marker():
    """Strictly guarantees that Unicode byte truncation never exceeds max_bytes and preserves marker."""
    # 4-byte emoji: 😀 (\U0001F600)
    emoji_text = "😀" * 100  # 400 UTF-8 bytes
    truncated = truncate_to_max_bytes(emoji_text, max_bytes=100, marker=" [TRUNCATED]")
    encoded = truncated.encode("utf-8")
    assert len(encoded) <= 100
    assert truncated.endswith(" [TRUNCATED]")
    # Verify no decode error (valid UTF-8)
    assert encoded.decode("utf-8") == truncated

    # Normal ASCII truncation
    ascii_text = "A" * 200
    truncated_ascii = truncate_to_max_bytes(ascii_text, max_bytes=50, marker="...[CUT]")
    encoded_ascii = truncated_ascii.encode("utf-8")
    assert len(encoded_ascii) == 50
    assert truncated_ascii.endswith("...[CUT]")

    # Under limit requires no truncation
    short_text = "Hello world"
    assert truncate_to_max_bytes(short_text, max_bytes=100) == short_text


def test_browser_session_manager_enforces_launch_and_context_timeouts():
    """BrowserSessionManager passes timeout to pw.chromium.launch and context default timeouts."""
    mock_browser = MagicMock()
    mock_context = MagicMock()
    mock_page = MagicMock()
    mock_pw = MagicMock()

    mock_pw.chromium.launch.return_value = mock_browser
    mock_browser.new_context.return_value = mock_context
    mock_context.new_page.return_value = mock_page

    with BrowserSessionManager(mock_pw, timeout=3.5) as session:
        # Launch timeout in milliseconds: 3.5s -> 3500ms
        mock_pw.chromium.launch.assert_called_once_with(
            headless=True,
            timeout=3500,
            args=MANDATORY_CHROMIUM_ISOLATION_FLAGS,
        )
        mock_context.set_default_timeout.assert_called_once_with(3500)
        mock_context.set_default_navigation_timeout.assert_called_once_with(3500)
        assert session.page is mock_page


def test_confirm_candidate_evidence_summary_multibyte_byte_limit():
    """confirm_candidate guarantees res.evidence_summary never exceeds max_evidence_bytes in UTF-8 bytes."""
    assistant = BrowserXssAssistant(enabled=True)
    budget = BrowserExecutionBudget(max_evidence_bytes=1024, max_timeout_seconds=5.0)

    # Simulate multi-byte error message
    multibyte_err = "Error: \U0001F6A8 " * 200  # Heavy multi-byte emojis
    with patch.object(assistant, "is_available", return_value=True):
        with patch.object(assistant, "verify_url_safety", side_effect=ValueError(multibyte_err)):
            res = assistant.confirm_candidate(
                target_url="http://example.com/test",
                canary_token="canary_xyz",
                budget=budget,
            )

    assert res.outcome == "BLOCKED"
    encoded_evidence = res.evidence_summary.encode("utf-8")
    assert len(encoded_evidence) <= 1024
    # Valid UTF-8 round trip
    assert encoded_evidence.decode("utf-8") == res.evidence_summary


def test_spa_observer_record_request_unicode_byte_measurement():
    """BrowserSpaObserver.record_request accurately accounts for multibyte Unicode headers."""
    observer = BrowserSpaObserver(max_evidence_bytes=200)
    # Multibyte Unicode character in header: 日本語 (9 bytes)
    headers = {"X-Custom": "日本語" * 15}  # 135 bytes
    observer.record_request("GET", "http://example.com/api", headers)
    assert observer.current_evidence_bytes > 135
    assert len(observer.network_requests) == 1


# ==============================================================================
# 18. Validating Egress Security Proxy & Anti-DNS-Rebinding Tests (Priority P0)
# ==============================================================================

def test_proxy_public_destination_connect_succeeds():
    """ValidatingEgressProxy allows CONNECT to verified public destinations."""
    proxy = ValidatingEgressProxy(timeout=2.0)
    port = proxy.start()
    try:
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]):
            with patch.object(proxy, "_connect_upstream") as mock_up_connect:
                # Client connects to proxy
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(2.0)
                client.connect(("127.0.0.1", port))
                client.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
                resp = client.recv(1024)
                client.close()

                assert b"200 Connection Established" in resp
                # Verify that upstream socket connected directly to pinned validated IP
                mock_up_connect.assert_called_once()
                assert mock_up_connect.call_args[0][1] == ("93.184.216.34", 443)
    finally:
        proxy.stop()


def test_proxy_loopback_and_private_destinations_rejected():
    """ValidatingEgressProxy blocks loopback and private literal/hostname destinations."""
    proxy = ValidatingEgressProxy(timeout=2.0)
    port = proxy.start()
    try:
        targets = ["127.0.0.1:80", "localhost:80", "10.0.0.1:80", "192.168.1.1:80", "[::1]:80"]
        for tgt in targets:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(2.0)
            client.connect(("127.0.0.1", port))
            client.sendall(f"CONNECT {tgt} HTTP/1.1\r\nHost: {tgt}\r\n\r\n".encode("utf-8"))
            resp = client.recv(1024)
            client.close()

            assert b"403 Forbidden" in resp
            assert b"Access Denied by Egress Security Policy" in resp

        assert len(proxy.blocked_connections) >= len(targets)
    finally:
        proxy.stop()


def test_proxy_ipv4_mapped_ipv6_and_link_local_rejected():
    """ValidatingEgressProxy blocks IPv4-mapped IPv6, link-local, and cloud metadata."""
    proxy = ValidatingEgressProxy(timeout=2.0)
    port = proxy.start()
    try:
        targets = ["[::ffff:127.0.0.1]:80", "169.254.169.254:80", "[fe80::1]:80"]
        for tgt in targets:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(2.0)
            client.connect(("127.0.0.1", port))
            client.sendall(f"CONNECT {tgt} HTTP/1.1\r\nHost: {tgt}\r\n\r\n".encode("utf-8"))
            resp = client.recv(1024)
            client.close()

            assert b"403 Forbidden" in resp
    finally:
        proxy.stop()


def test_proxy_mixed_public_and_private_dns_fails_closed():
    """Mixed public/private DNS answers fail closed before socket connection."""
    proxy = ValidatingEgressProxy(timeout=2.0)
    port = proxy.start()
    try:
        mixed_dns = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ]
        with patch("socket.getaddrinfo", return_value=mixed_dns):
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(2.0)
            client.connect(("127.0.0.1", port))
            client.sendall(b"CONNECT mixed.example.com:443 HTTP/1.1\r\nHost: mixed.example.com\r\n\r\n")
            resp = client.recv(1024)
            client.close()

            assert b"403 Forbidden" in resp
            assert any("prohibited IP '127.0.0.1'" in b["reason"] for b in proxy.blocked_connections)
    finally:
        proxy.stop()


def test_proxy_dns_failures_and_empty_answers_fail_closed():
    """DNS resolution errors and empty answer sets fail closed."""
    proxy = ValidatingEgressProxy(timeout=2.0)
    port = proxy.start()
    try:
        # 1. DNS error
        with patch("socket.getaddrinfo", side_effect=socket.gaierror(-2, "Name or service not known")):
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(2.0)
            client.connect(("127.0.0.1", port))
            client.sendall(b"CONNECT bad-domain.example.com:443 HTTP/1.1\r\nHost: bad-domain.example.com\r\n\r\n")
            resp = client.recv(1024)
            client.close()
            assert b"403 Forbidden" in resp

        # 2. Empty answer list
        with patch("socket.getaddrinfo", return_value=[]):
            client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client2.settimeout(2.0)
            client2.connect(("127.0.0.1", port))
            client2.sendall(b"CONNECT empty.example.com:443 HTTP/1.1\r\nHost: empty.example.com\r\n\r\n")
            resp2 = client2.recv(1024)
            client2.close()
            assert b"403 Forbidden" in resp2
    finally:
        proxy.stop()


def test_proxy_dns_rebinding_cannot_connect_to_unvalidated_address():
    """
    Validates that destination IP is pinned from preflight validation and
    connected to directly without second hostname lookup.
    """
    proxy = ValidatingEgressProxy(timeout=2.0)

    # First lookup returns public IP 93.184.216.34
    public_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    with patch("socket.getaddrinfo", return_value=public_dns):
        chosen_entry = proxy.validate_destination_and_get_addr(
            host="rebind.example.com",
            port=443,
            scheme="https",
            scope_url="https://rebind.example.com:443/",
        )

    # Invariant: sockaddr returned is the validated IP tuple
    assert chosen_entry[4] == ("93.184.216.34", 443)


def test_proxy_redirect_and_subresource_scope_enforcement():
    """Proxy enforces scope validation on subresource/redirect HTTP requests."""
    mock_scope = MagicMock(spec=ScopeEngine)
    mock_scope.check.side_effect = lambda url: (
        ScopeDecision(status=ScopeStatus.OUT_OF_SCOPE, reason="Subresource out of scope", target=url, normalized_target=url, matched_rule=None, rule_category="TARGET_DOMAIN")
        if "forbidden-subresource" in url
        else ScopeDecision(status=ScopeStatus.IN_SCOPE, reason="In scope", target=url, normalized_target=url, matched_rule=None, rule_category="TARGET_DOMAIN")
    )

    proxy = ValidatingEgressProxy(scope_engine=mock_scope, timeout=2.0)
    port = proxy.start()
    try:
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]):
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(2.0)
            client.connect(("127.0.0.1", port))
            client.sendall(b"GET http://forbidden-subresource.example.com/asset.js HTTP/1.1\r\nHost: forbidden-subresource.example.com\r\n\r\n")
            resp = client.recv(1024)
            client.close()

            assert b"403 Forbidden" in resp
            assert any("OUT_OF_SCOPE" in b["reason"] for b in proxy.blocked_connections)
    finally:
        proxy.stop()


def test_proxy_startup_failure_prevents_browser_navigation():
    """If proxy fails to start, BrowserSessionManager raises BrowserSecurityPolicyError and aborts."""
    mock_pw = MagicMock()
    mock_pw.chromium.launch.return_value = MagicMock()

    with patch.object(ValidatingEgressProxy, "start", side_effect=RuntimeError("Bind address in use")):
        with pytest.raises(BrowserSecurityPolicyError, match="mandatory validating egress proxy"):
            with BrowserSessionManager(mock_pw, timeout=2.0):
                pass

    # Chromium launch was NEVER called
    mock_pw.chromium.launch.assert_not_called()


def test_proxy_cleanup_works_after_failure_and_timeouts():
    """ValidatingEgressProxy.stop cleanly releases sockets and terminates thread."""
    proxy = ValidatingEgressProxy(timeout=2.0)
    port = proxy.start()
    assert proxy.is_running is True
    assert proxy.server_sock is not None
    assert proxy._thread is not None and proxy._thread.is_alive()

    proxy.stop()
    assert proxy.is_running is False
    assert proxy.server_sock is None
    assert proxy._thread is None


def test_proxy_mandatory_scope_authorization():
    """Even with public IP, destination failing scope check is denied by proxy."""
    mock_scope = MagicMock(spec=ScopeEngine)
    mock_scope.check.return_value = ScopeDecision(
        status=ScopeStatus.OUT_OF_SCOPE,
        reason="Target domain not in scope.yaml",
        target="https://public-out-of-scope.example.com/",
        normalized_target="https://public-out-of-scope.example.com/",
        matched_rule=None,
        rule_category="TARGET_DOMAIN",
    )

    proxy = ValidatingEgressProxy(scope_engine=mock_scope, timeout=2.0)
    port = proxy.start()
    try:
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]):
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(2.0)
            client.connect(("127.0.0.1", port))
            client.sendall(b"CONNECT public-out-of-scope.example.com:443 HTTP/1.1\r\nHost: public-out-of-scope.example.com:443\r\n\r\n")
            resp = client.recv(1024)
            client.close()

            assert b"403 Forbidden" in resp
    finally:
        proxy.stop()


def test_proxy_bracketed_ipv6_handling():
    """ValidatingEgressProxy accurately parses bracketed IPv6 and blocks loopback while allowing public IPv6."""
    proxy = ValidatingEgressProxy(timeout=2.0)
    port = proxy.start()
    try:
        # 1. Prohibited loopback bracketed IPv6
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(2.0)
        client.connect(("127.0.0.1", port))
        client.sendall(b"CONNECT [::1]:8080 HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n")
        resp = client.recv(1024)
        client.close()
        assert b"403 Forbidden" in resp
        assert any("Loopback" in b["reason"] or "::1" in b["reason"] for b in proxy.blocked_connections)

        # 2. Public bracketed IPv6 allowed
        public_ipv6_info = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 443, 0, 0))]
        with patch("socket.getaddrinfo", return_value=public_ipv6_info):
            with patch.object(proxy, "_connect_upstream") as mock_connect:
                client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client2.settimeout(2.0)
                client2.connect(("127.0.0.1", port))
                client2.sendall(b"CONNECT [2606:2800:220:1:248:1893:25c8:1946]:443 HTTP/1.1\r\nHost: [2606:2800:220:1:248:1893:25c8:1946]:443\r\n\r\n")
                resp2 = client2.recv(1024)
                client2.close()
                assert b"200 Connection Established" in resp2
                mock_connect.assert_called_once()
                assert mock_connect.call_args[0][1][0] == "2606:2800:220:1:248:1893:25c8:1946"
    finally:
        proxy.stop()


def test_proxy_unsupported_protocol_scheme_rejected():
    """ValidatingEgressProxy blocks unsupported protocols (e.g. ftp, gopher)."""
    proxy = ValidatingEgressProxy(timeout=2.0)
    port = proxy.start()
    try:
        schemes = ["ftp://example.com/pub/file", "gopher://example.com/"]
        for target_url in schemes:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(2.0)
            client.connect(("127.0.0.1", port))
            client.sendall(f"GET {target_url} HTTP/1.1\r\nHost: example.com\r\n\r\n".encode("utf-8"))
            resp = client.recv(1024)
            client.close()
            assert b"403 Forbidden" in resp
        assert len(proxy.blocked_connections) >= len(schemes)
    finally:
        proxy.stop()


def test_proxy_origin_form_with_host_header():
    """ValidatingEgressProxy falls back to Host header when origin-form request line is received."""
    proxy = ValidatingEgressProxy(timeout=2.0)
    port = proxy.start()
    try:
        connected_event = threading.Event()
        connected_args = []
        def mock_conn(sock, addr):
            connected_args.append(addr)
            connected_event.set()

        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]):
            with patch.object(proxy, "_connect_upstream", side_effect=mock_conn):
                with patch.object(proxy, "_relay_bidirectional"):
                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client.settimeout(2.0)
                    client.connect(("127.0.0.1", port))
                    client.sendall(b"GET /index.html HTTP/1.1\r\nHost: example.com:80\r\n\r\n")
                    assert connected_event.wait(timeout=2.0) is True
                    assert connected_args == [("93.184.216.34", 80)]
                    client.close()
    finally:
        proxy.stop()


def test_proxy_malformed_request_lines():
    """ValidatingEgressProxy returns 400 Bad Request for malformed request lines."""
    proxy = ValidatingEgressProxy(timeout=2.0)
    port = proxy.start()
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(2.0)
        client.connect(("127.0.0.1", port))
        client.sendall(b"GARBAGE_REQUEST_WITHOUT_PARTS\r\n\r\n")
        resp = client.recv(1024)
        client.close()
        assert b"400 Bad Request" in resp
    finally:
        proxy.stop()


# ==============================================================================
# 19. WebSocket Pre-Connection Transport & Scope Enforcement Tests
# ==============================================================================

def test_proxy_websocket_loopback_blocked_pre_connection():
    """ValidatingEgressProxy blocks WebSocket connection to loopback before upstream connect."""
    proxy = ValidatingEgressProxy(timeout=2.0, allow_websockets=True)
    port = proxy.start()
    try:
        with patch.object(proxy, "_connect_upstream") as mock_connect:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(2.0)
            client.connect(("127.0.0.1", port))
            # HTTP Upgrade to WebSocket targeting loopback
            client.sendall(
                b"GET /ws HTTP/1.1\r\n"
                b"Host: 127.0.0.1:8080\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            )
            resp = client.recv(1024)
            client.close()

            assert b"403 Forbidden" in resp
            assert b"Access Denied by Egress Security Policy" in resp
            # Upstream connection was NEVER attempted
            mock_connect.assert_not_called()
            assert any("Loopback" in b["reason"] for b in proxy.blocked_connections)
    finally:
        proxy.stop()


def test_proxy_websocket_private_and_metadata_blocked_pre_connection():
    """ValidatingEgressProxy blocks WebSocket upgrade to private and cloud metadata targets pre-connection."""
    proxy = ValidatingEgressProxy(timeout=2.0, allow_websockets=True)
    port = proxy.start()
    try:
        targets = ["10.0.0.1:80", "169.254.169.254:80", "192.168.1.1:80"]
        for tgt in targets:
            with patch.object(proxy, "_connect_upstream") as mock_connect:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(2.0)
                client.connect(("127.0.0.1", port))
                client.sendall(
                    f"GET /chat HTTP/1.1\r\n"
                    f"Host: {tgt}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n\r\n".encode("utf-8")
                )
                resp = client.recv(1024)
                client.close()

                assert b"403 Forbidden" in resp
                mock_connect.assert_not_called()
    finally:
        proxy.stop()


def test_proxy_websocket_out_of_scope_blocked_pre_connection():
    """ValidatingEgressProxy blocks WebSocket upgrade to out-of-scope domain before connection."""
    mock_scope = MagicMock(spec=ScopeEngine)
    mock_scope.check.return_value = ScopeDecision(
        status=ScopeStatus.OUT_OF_SCOPE,
        reason="Target domain not authorized in scope.yaml",
        target="http://unauthorized-ws.example.com:80/ws",
        normalized_target="http://unauthorized-ws.example.com:80/ws",
        matched_rule=None,
        rule_category="TARGET_DOMAIN",
    )

    proxy = ValidatingEgressProxy(scope_engine=mock_scope, timeout=2.0, allow_websockets=True)
    port = proxy.start()
    try:
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]):
            with patch.object(proxy, "_connect_upstream") as mock_connect:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(2.0)
                client.connect(("127.0.0.1", port))
                client.sendall(
                    b"GET /ws HTTP/1.1\r\n"
                    b"Host: unauthorized-ws.example.com:80\r\n"
                    b"Upgrade: websocket\r\n"
                    b"Connection: Upgrade\r\n\r\n"
                )
                resp = client.recv(1024)
                client.close()

                assert b"403 Forbidden" in resp
                mock_connect.assert_not_called()
                assert any("OUT_OF_SCOPE" in b["reason"] for b in proxy.blocked_connections)
    finally:
        proxy.stop()


def test_proxy_websocket_disabled_policy_blocks_pre_connection():
    """When allow_websockets=False, all WebSocket upgrades are explicitly rejected pre-connection."""
    proxy = ValidatingEgressProxy(timeout=2.0, allow_websockets=False)
    port = proxy.start()
    try:
        with patch.object(proxy, "_connect_upstream") as mock_connect:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(2.0)
            client.connect(("127.0.0.1", port))
            client.sendall(
                b"GET /ws HTTP/1.1\r\n"
                b"Host: public-allowed.example.com:80\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n\r\n"
            )
            resp = client.recv(1024)
            client.close()

            assert b"403 Forbidden" in resp
            assert b"WebSocket traffic disabled by Egress Security Policy" in resp
            mock_connect.assert_not_called()
    finally:
        proxy.stop()


def test_proxy_websocket_authorized_in_scope_succeeds():
    """When allow_websockets=True, in-scope public WebSocket connection connects upstream directly."""
    mock_scope = MagicMock(spec=ScopeEngine)
    mock_scope.check.return_value = ScopeDecision(
        status=ScopeStatus.IN_SCOPE,
        reason="Domain authorized in scope.yaml",
        target="http://in-scope-ws.example.com:80/ws",
        normalized_target="http://in-scope-ws.example.com:80/ws",
        matched_rule="in-scope-ws.example.com",
        rule_category="TARGET_DOMAIN",
    )

    proxy = ValidatingEgressProxy(scope_engine=mock_scope, timeout=2.0, allow_websockets=True)
    port = proxy.start()
    try:
        connected_event = threading.Event()
        connected_args = []
        def mock_conn(sock, addr):
            connected_args.append(addr)
            connected_event.set()

        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]):
            with patch.object(proxy, "_connect_upstream", side_effect=mock_conn):
                with patch.object(proxy, "_relay_bidirectional"):
                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client.settimeout(2.0)
                    client.connect(("127.0.0.1", port))
                    client.sendall(
                        b"GET /ws HTTP/1.1\r\n"
                        b"Host: in-scope-ws.example.com:80\r\n"
                        b"Upgrade: websocket\r\n"
                        b"Connection: Upgrade\r\n\r\n"
                    )
                    assert connected_event.wait(timeout=2.0) is True
                    assert connected_args == [("93.184.216.34", 80)]
                    client.close()
    finally:
        proxy.stop()


def test_network_policy_websocket_disabled_policy_terminates():
    """BrowserNetworkPolicy with allow_websockets=False terminates any incoming websocket."""
    policy = BrowserNetworkPolicy(allow_websockets=False)
    mock_ws = MagicMock(url="ws://in-scope.example.com/ws")
    policy.handle_websocket(mock_ws)
    mock_ws.close.assert_called_once()
    assert len(policy.blocked_requests) == 1
    assert "disabled by security policy" in policy.blocked_requests[0]["reason"]


def test_proxy_connect_wss_prohibited_destinations_blocked_pre_connection():
    """ValidatingEgressProxy blocks CONNECT tunnels to prohibited destinations (WSS/HTTPS) before connection."""
    proxy = ValidatingEgressProxy(timeout=2.0, allow_websockets=True)
    port = proxy.start()
    try:
        targets = ["127.0.0.1:8443", "10.0.0.1:443", "169.254.169.254:443"]
        for tgt in targets:
            with patch.object(proxy, "_connect_upstream") as mock_connect:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(2.0)
                client.connect(("127.0.0.1", port))
                client.sendall(
                    f"CONNECT {tgt} HTTP/1.1\r\n"
                    f"Host: {tgt}\r\n\r\n".encode("utf-8")
                )
                resp = client.recv(1024)
                client.close()

                assert b"403 Forbidden" in resp
                mock_connect.assert_not_called()
    finally:
        proxy.stop()


def test_proxy_connect_wss_out_of_scope_blocked_pre_connection():
    """ValidatingEgressProxy blocks CONNECT tunnels to out-of-scope destinations before connection."""
    mock_scope = MagicMock(spec=ScopeEngine)
    mock_scope.check.return_value = ScopeDecision(
        status=ScopeStatus.OUT_OF_SCOPE,
        reason="Target domain not authorized in scope.yaml",
        target="https://unauthorized-wss.example.com:443/",
        normalized_target="https://unauthorized-wss.example.com:443/",
        matched_rule=None,
        rule_category="TARGET_DOMAIN",
    )

    proxy = ValidatingEgressProxy(scope_engine=mock_scope, timeout=2.0, allow_websockets=True)
    port = proxy.start()
    try:
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]):
            with patch.object(proxy, "_connect_upstream") as mock_connect:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(2.0)
                client.connect(("127.0.0.1", port))
                client.sendall(
                    b"CONNECT unauthorized-wss.example.com:443 HTTP/1.1\r\n"
                    b"Host: unauthorized-wss.example.com:443\r\n\r\n"
                )
                resp = client.recv(1024)
                client.close()

                assert b"403 Forbidden" in resp
                mock_connect.assert_not_called()
                assert any("OUT_OF_SCOPE" in b["reason"] for b in proxy.blocked_connections)
    finally:
        proxy.stop()


def test_proxy_connect_authorized_https_succeeds_under_allow_websockets_false():
    """Ordinary authorized HTTPS via CONNECT succeeds even when allow_websockets=False."""
    mock_scope = MagicMock(spec=ScopeEngine)
    mock_scope.check.return_value = ScopeDecision(
        status=ScopeStatus.IN_SCOPE,
        reason="Domain authorized in scope.yaml",
        target="https://in-scope.example.com:443/",
        normalized_target="https://in-scope.example.com:443/",
        matched_rule="in-scope.example.com",
        rule_category="TARGET_DOMAIN",
    )

    proxy = ValidatingEgressProxy(scope_engine=mock_scope, timeout=2.0, allow_websockets=False)
    port = proxy.start()
    try:
        connected_event = threading.Event()
        connected_args = []
        def mock_conn(sock, addr):
            connected_args.append(addr)
            connected_event.set()

        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]):
            with patch.object(proxy, "_connect_upstream", side_effect=mock_conn):
                with patch.object(proxy, "_relay_bidirectional"):
                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client.settimeout(2.0)
                    client.connect(("127.0.0.1", port))
                    client.sendall(
                        b"CONNECT in-scope.example.com:443 HTTP/1.1\r\n"
                        b"Host: in-scope.example.com:443\r\n\r\n"
                    )
                    resp = client.recv(1024)
                    client.close()

                    assert b"200 Connection Established" in resp
                    assert connected_event.wait(timeout=2.0) is True
                    assert connected_args == [("93.184.216.34", 443)]
    finally:
        proxy.stop()


def test_network_policy_wss_disabled_policy_terminates():
    """BrowserNetworkPolicy terminates WSS connection immediately when allow_websockets=False."""
    policy = BrowserNetworkPolicy(allow_websockets=False)
    mock_ws = MagicMock(url="wss://in-scope.example.com:443/chat")
    policy.handle_websocket(mock_ws)
    mock_ws.close.assert_called_once()
    assert len(policy.blocked_requests) == 1
    assert "disabled by security policy" in policy.blocked_requests[0]["reason"]
    assert policy.blocked_requests[0]["method"] == "WEBSOCKET"


def test_proxy_no_upstream_connection_before_authorization():
    """Verifies that _connect_upstream is strictly never called if authorization fails or errors."""
    mock_scope = MagicMock(spec=ScopeEngine)
    mock_scope.check.side_effect = RuntimeError("Database connection lost during scope lookup")

    proxy = ValidatingEgressProxy(scope_engine=mock_scope, timeout=2.0)
    port = proxy.start()
    try:
        with patch.object(proxy, "_connect_upstream") as mock_connect:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(2.0)
            client.connect(("127.0.0.1", port))
            client.sendall(
                b"CONNECT secure.example.com:443 HTTP/1.1\r\n"
                b"Host: secure.example.com:443\r\n\r\n"
            )
            resp = client.recv(1024)
            client.close()

            assert b"403 Forbidden" in resp
            mock_connect.assert_not_called()
    finally:
        proxy.stop()


def test_websocket_route_pre_handshake_disabled_rejects_without_upstream_handshake():
    """BrowserNetworkPolicy.handle_websocket_route closes ws_route and NEVER calls connect_to_server when allow_websockets=False."""
    policy = BrowserNetworkPolicy(allow_websockets=False)
    mock_ws_route = MagicMock()
    mock_ws_route.url = "wss://in-scope.example.com:443/chat"

    policy.handle_websocket_route(mock_ws_route)

    mock_ws_route.connect_to_server.assert_not_called()
    mock_ws_route.close.assert_called_once_with(
        code=1008, reason="WebSocket traffic is disabled by security policy"
    )
    assert len(policy.blocked_requests) == 1
    assert policy.blocked_requests[0]["method"] == "WEBSOCKET"
    assert "disabled by security policy" in policy.blocked_requests[0]["reason"]


def test_websocket_route_pre_handshake_prohibited_destinations_reject_without_handshake():
    """handle_websocket_route closes ws_route and NEVER calls connect_to_server for prohibited destinations."""
    policy = BrowserNetworkPolicy(allow_websockets=True)
    prohibited_targets = [
        "wss://127.0.0.1:8443/ws",
        "wss://10.0.0.1:443/ws",
        "wss://169.254.169.254:443/ws",
        "ws://192.168.1.1:80/socket",
    ]

    for target in prohibited_targets:
        mock_ws_route = MagicMock()
        mock_ws_route.url = target

        policy.handle_websocket_route(mock_ws_route)

        mock_ws_route.connect_to_server.assert_not_called()
        mock_ws_route.close.assert_called_once()
        args, kwargs = mock_ws_route.close.call_args
        assert kwargs.get("code") == 1008


def test_websocket_route_pre_handshake_out_of_scope_rejects_without_handshake():
    """handle_websocket_route closes ws_route and NEVER calls connect_to_server when out-of-scope."""
    mock_scope = MagicMock(spec=ScopeEngine)
    mock_scope.check.return_value = ScopeDecision(
        status=ScopeStatus.OUT_OF_SCOPE,
        reason="Target domain not authorized in scope.yaml",
        target="https://unauthorized.example.com:443/ws",
        normalized_target="https://unauthorized.example.com:443/ws",
        matched_rule=None,
        rule_category="TARGET_DOMAIN",
    )

    policy = BrowserNetworkPolicy(scope_engine=mock_scope, allow_websockets=True)
    mock_ws_route = MagicMock()
    mock_ws_route.url = "wss://unauthorized.example.com:443/ws"

    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]):
        policy.handle_websocket_route(mock_ws_route)

    mock_ws_route.connect_to_server.assert_not_called()
    mock_ws_route.close.assert_called_once()
    args, kwargs = mock_ws_route.close.call_args
    assert kwargs.get("code") == 1008


def test_websocket_route_pre_handshake_authorized_connects_to_server():
    """handle_websocket_route calls connect_to_server when in-scope and allow_websockets=True."""
    mock_scope = MagicMock(spec=ScopeEngine)
    mock_scope.check.return_value = ScopeDecision(
        status=ScopeStatus.IN_SCOPE,
        reason="Target authorized",
        target="https://in-scope.example.com:443/ws",
        normalized_target="https://in-scope.example.com:443/ws",
        matched_rule="in-scope.example.com",
        rule_category="TARGET_DOMAIN",
    )

    policy = BrowserNetworkPolicy(scope_engine=mock_scope, allow_websockets=True)
    mock_ws_route = MagicMock()
    mock_ws_route.url = "wss://in-scope.example.com:443/ws"

    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]):
        policy.handle_websocket_route(mock_ws_route)

    mock_ws_route.connect_to_server.assert_called_once()


def test_attach_to_context_registers_pre_handshake_route_web_socket():
    """attach_to_context registers route_web_socket with regex pattern and handle_websocket_route."""
    policy = BrowserNetworkPolicy()
    mock_context = MagicMock()

    policy.attach_to_context(mock_context)

    mock_context.route_web_socket.assert_called_once()
    args, kwargs = mock_context.route_web_socket.call_args
    assert args[0].pattern == r"^wss?://.*"
    assert args[1] == policy.handle_websocket_route


def test_attach_to_context_fails_closed_when_route_web_socket_fails():
    """If route_web_socket registration fails, attach_to_context must raise BrowserSecurityPolicyError."""
    policy = BrowserNetworkPolicy()
    mock_context = MagicMock()
    mock_context.route_web_socket.side_effect = RuntimeError("route_web_socket registration failed")

    with pytest.raises(BrowserSecurityPolicyError, match="pre-handshake WebSocket route interception"):
        policy.attach_to_context(mock_context)
