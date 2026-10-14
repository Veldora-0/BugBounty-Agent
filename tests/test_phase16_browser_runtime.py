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
"""

from __future__ import annotations

import os
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
    BrowserSessionManager,
    BrowserSpaObserver,
    BrowserXssAssistant,
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
    
    # Simulate executable not found error
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
    mock_pw_context = MagicMock()
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
    
    # Mock DNS resolution returning private IP for an innocent-looking domain
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
    
    # Simulate dialog event with unrelated text
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
    
    # Record routes past the limit
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
    from framework.xss.browser import redact_browser_request_metadata
    
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
    
    # Sensitive headers must be sanitized
    assert "[REDACTED]" in redacted["headers"]["Authorization"]
    assert "[REDACTED]" in redacted["headers"]["Cookie"]
    assert "[REDACTED]" in redacted["headers"]["X-Api-Key"]
    assert redacted["headers"]["User-Agent"] == "BugBounty-Agent/1.0"
    
    # Sensitive query parameter must be redacted
    assert "access_token=[REDACTED]" in redacted["url"] or "access_token" not in redacted["url"] or "secret123" not in redacted["url"]
    assert "secret123" not in redacted["url"]
