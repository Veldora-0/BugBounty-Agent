"""
Browser-Assisted Confirmation & Client-Side Runtime for BugBounty-Agent.

Provides an isolated, headless Playwright confirmation layer strictly disabled
by default. Enforces strict anti-SSRF pre-checks, DNS resolution checks,
subresource route interception, exception-safe resource lifecycle cleanup,
canary-correlated XSS proof verification, bounded SPA observations, and
comprehensive credential/token redaction.
"""

from __future__ import annotations

import logging
import os
import re
import socket
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from framework.common.evidence import sanitize_sensitive_data
from framework.findings.lifecycle import FindingLifecycle
from framework.scope.engine import ScopeEngine, ScopeStatus
from framework.validation.engine import ScopeViolationError, is_ssrf_prohibited_ip


logger = logging.getLogger(__name__)


# ==============================================================================
# 1. Capability Detection & Status
# ==============================================================================

class BrowserCapability:
    """Represents the operational availability of headless browser automation."""

    def __init__(
        self,
        package_available: bool = False,
        browser_executable_available: bool = False,
        can_launch: bool = False,
        state: str = "NOT_INSTALLED",
        details: str = "",
    ):
        self.package_available = package_available
        self.browser_executable_available = browser_executable_available
        self.can_launch = can_launch
        self.state = state  # READY, MISSING_PACKAGE, MISSING_BROWSER, LAUNCH_FAILED, NOT_INSTALLED
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_available": self.package_available,
            "browser_executable_available": self.browser_executable_available,
            "can_launch": self.can_launch,
            "state": self.state,
            "details": self.details,
        }


class BrowserCapabilityDetector:
    """
    Truthfully inspects browser automation capability without initiating downloads,
    installations, or exposing sensitive environment secrets.
    """

    @staticmethod
    def _get_sync_playwright():
        try:
            import playwright.sync_api as sync_api
            return sync_api
        except ImportError:
            return None

    def detect(self) -> BrowserCapability:
        """Inspects package, executable, driver, and launchability."""
        api = self._get_sync_playwright()
        if api is None:
            return BrowserCapability(
                package_available=False,
                browser_executable_available=False,
                can_launch=False,
                state="MISSING_PACKAGE",
                details="Playwright Python package is not installed.",
            )

        try:
            with api.sync_playwright() as p:
                try:
                    exec_path = p.chromium.executable_path
                    if not exec_path or not os.path.exists(exec_path):
                        return BrowserCapability(
                            package_available=True,
                            browser_executable_available=False,
                            can_launch=False,
                            state="MISSING_BROWSER",
                            details="Chromium browser binary is not installed.",
                        )
                except Exception as e:
                    return BrowserCapability(
                        package_available=True,
                        browser_executable_available=False,
                        can_launch=False,
                        state="MISSING_BROWSER",
                        details=f"Chromium executable check failed: {type(e).__name__}",
                    )

                # Dry-launch headless browser to verify shared libraries and sandbox
                try:
                    browser = p.chromium.launch(headless=True)
                    browser.close()
                    return BrowserCapability(
                        package_available=True,
                        browser_executable_available=True,
                        can_launch=True,
                        state="READY",
                        details="Headless Chromium verified and ready.",
                    )
                except Exception as launch_err:
                    return BrowserCapability(
                        package_available=True,
                        browser_executable_available=True,
                        can_launch=False,
                        state="LAUNCH_FAILED",
                        details=f"Headless launch failed: {type(launch_err).__name__}",
                    )
        except FileNotFoundError as fnf:
            # E.g. Missing /usr/bin/node driver on Linux/Kali
            return BrowserCapability(
                package_available=True,
                browser_executable_available=False,
                can_launch=False,
                state="MISSING_BROWSER",
                details=f"Browser driver executable not found: {type(fnf).__name__}",
            )
        except Exception as ex:
            return BrowserCapability(
                package_available=True,
                browser_executable_available=False,
                can_launch=False,
                state="LAUNCH_FAILED",
                details=f"Driver initialization failed: {type(ex).__name__}",
            )


# ==============================================================================
# 2. Privacy & Credential Redaction
# ==============================================================================

SENSITIVE_PARAM_NAMES = {
    "token", "access_token", "api_key", "apikey", "key", "secret",
    "password", "pass", "pwd", "auth", "session", "jwt", "bearer",
}

SENSITIVE_HEADER_NAMES = {
    "authorization", "cookie", "set-cookie", "x-api-key", "api-key",
    "proxy-authorization", "token", "x-csrf-token", "x-xsrf-token",
}


def redact_browser_request_metadata(url: str, headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Sanitizes URL query parameters and request headers to prevent persisting
    raw authentication credentials or secrets.
    """
    # 1. Redact headers
    redacted_headers: Dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADER_NAMES:
            redacted_headers[k] = "[REDACTED]"
        else:
            redacted_headers[k] = v

    # 2. Redact sensitive query parameters
    try:
        parsed = urlparse(url)
        if parsed.query:
            query_items = parse_qsl(parsed.query, keep_blank_values=True)
            new_query = []
            for qk, qv in query_items:
                if qk.lower() in SENSITIVE_PARAM_NAMES:
                    new_query.append((qk, "[REDACTED]"))
                else:
                    new_query.append((qk, qv))
            new_url = urlunparse(parsed._replace(query=urlencode(new_query)))
        else:
            new_url = url
    except Exception:
        new_url = url

    return {
        "url": new_url,
        "headers": redacted_headers,
    }


# ==============================================================================
# 3. Exception-Safe Resource Lifecycle Manager
# ==============================================================================

class BrowserSessionManager:
    """
    Guarantees strict, exception-safe cleanup of Page, BrowserContext, and Browser
    resources even during navigation timeouts, worker aborts, or runtime crashes.
    """

    def __init__(self, playwright_instance, timeout: float = 5.0):
        self.pw = playwright_instance
        self.timeout = max(1.0, float(timeout))
        self.browser = None
        self.context = None
        self.page = None

    def __enter__(self) -> BrowserSessionManager:
        self.browser = self.pw.chromium.launch(headless=True)
        self.context = self.browser.new_context(
            ignore_https_errors=True,
            java_script_enabled=True,
        )
        self.page = self.context.new_page()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        cleanup_errors: List[Exception] = []
        if self.page:
            try:
                self.page.close()
            except Exception as e:
                cleanup_errors.append(e)
        if self.context:
            try:
                self.context.close()
            except Exception as e:
                cleanup_errors.append(e)
        if self.browser:
            try:
                self.browser.close()
            except Exception as e:
                cleanup_errors.append(e)

        # Never mask the primary exception if one occurred
        if exc_type is not None:
            return False

        if cleanup_errors:
            raise cleanup_errors[0]

        return False


# ==============================================================================
# 4. Bounded SPA Observer
# ==============================================================================

class BrowserSpaObserver:
    """
    Collects bounded client-side routing, DOM mutation summaries, dynamic scripts,
    and network requests for modern Single-Page Applications (SPAs).
    """

    def __init__(
        self,
        max_routes: int = 10,
        max_scripts: int = 20,
        max_requests: int = 50,
        max_console: int = 20,
    ):
        self.max_routes = max_routes
        self.max_scripts = max_scripts
        self.max_requests = max_requests
        self.max_console = max_console

        self.routes_observed: List[str] = []
        self.dynamic_scripts: List[Dict[str, Any]] = []
        self.network_requests: List[Dict[str, Any]] = []
        self.console_messages: List[str] = []
        self.page_errors: List[str] = []
        self.dom_mutation_count: int = 0
        self.dynamic_scripts_added: int = 0

    def record_route_change(self, route_url: str) -> None:
        if len(self.routes_observed) < self.max_routes:
            if route_url not in self.routes_observed:
                self.routes_observed.append(route_url)

    def record_mutation(self, node_type: str, action: str = "added") -> None:
        self.dom_mutation_count += 1
        if node_type.lower() == "script" and action == "added":
            self.dynamic_scripts_added += 1

    def record_script(self, src: Optional[str] = None, length: int = 0) -> None:
        if len(self.dynamic_scripts) < self.max_scripts:
            self.dynamic_scripts.append({
                "src": src or "inline",
                "length": length,
            })

    def record_request(self, method: str, url: str, headers: Dict[str, str]) -> None:
        if len(self.network_requests) < self.max_requests:
            redacted = redact_browser_request_metadata(url, headers)
            self.network_requests.append({
                "method": method,
                "url": redacted["url"],
                "headers": redacted["headers"],
            })

    def record_console(self, text: str) -> None:
        if len(self.console_messages) < self.max_console:
            self.console_messages.append(text)

    def record_error(self, err_text: str) -> None:
        if len(self.page_errors) < self.max_console:
            self.page_errors.append(err_text)

    def get_summary(self) -> Dict[str, Any]:
        return {
            "routes_observed": list(self.routes_observed),
            "dom_mutation_count": self.dom_mutation_count,
            "dynamic_scripts_added": self.dynamic_scripts_added,
            "dynamic_scripts": list(self.dynamic_scripts),
            "network_requests_count": len(self.network_requests),
            "console_messages": list(self.console_messages),
            "page_errors": list(self.page_errors),
        }


# ==============================================================================
# 5. Confirmation Result & Assistant
# ==============================================================================

class BrowserConfirmationResult:
    """Outcome of browser-assisted verification and SPA observation."""

    def __init__(
        self,
        success: bool = False,
        is_confirmed: bool = False,
        outcome: str = "INCONCLUSIVE",  # CONFIRMED, INCONCLUSIVE, UNAVAILABLE, BLOCKED, TIMEOUT, OBSERVED
        dialog_observed: bool = False,
        dialog_message: Optional[str] = None,
        dialog_type: Optional[str] = None,
        console_messages: Optional[List[str]] = None,
        errors: Optional[List[str]] = None,
        spa_summary: Optional[Dict[str, Any]] = None,
        evidence_summary: str = "",
    ):
        self.success = success
        self.is_confirmed = is_confirmed
        self.outcome = outcome
        self.dialog_observed = dialog_observed
        self.dialog_message = dialog_message
        self.dialog_type = dialog_type
        self.console_messages = console_messages or []
        self.errors = errors or []
        self.spa_summary = spa_summary or {}
        self.evidence_summary = evidence_summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "is_confirmed": self.is_confirmed,
            "outcome": self.outcome,
            "dialog_observed": self.dialog_observed,
            "dialog_message": self.dialog_message,
            "dialog_type": self.dialog_type,
            "console_messages": self.console_messages,
            "errors": self.errors,
            "spa_summary": self.spa_summary,
            "evidence_summary": self.evidence_summary,
        }


class BrowserXssAssistant:
    """
    Modular headless browser confirmation and client-side security engine.
    Strictly opt-in; enforces fail-closed network safety, DNS verification,
    request interception, and canary-correlated evidence verification.
    """

    def __init__(
        self,
        enabled: bool = False,
        timeout: float = 5.0,
        scope_validator: Optional[Callable[[str], None]] = None,
        scope_engine: Optional[ScopeEngine] = None,
        detector: Optional[BrowserCapabilityDetector] = None,
    ):
        self.enabled = bool(enabled)
        self.timeout = max(1.0, min(15.0, float(timeout)))
        self.scope_validator = scope_validator
        self.scope_engine = scope_engine
        self.detector = detector or BrowserCapabilityDetector()

    def is_available(self) -> bool:
        """Verifies if headless browser is executable and ready."""
        cap = self.detector.detect()
        return cap.can_launch

    def is_playwright_available(self) -> bool:
        """Backwards compatibility check for package presence."""
        cap = self.detector.detect()
        return cap.package_available

    def verify_url_safety(self, url: str) -> None:
        """
        Enforces strict anti-SSRF, DNS resolution safety, scheme restrictions,
        and scope authorization before browser navigation.
        """
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"Browser navigation blocked: protocol '{scheme}' not permitted. Only HTTP/HTTPS allowed.")

        host = (parsed.hostname or "").lower()
        if not host:
            raise ValueError(f"Browser navigation blocked: invalid hostname in '{url}'.")

        port = parsed.port or (443 if scheme == "https" else 80)

        # 1. Check literal IP addresses directly
        prohibited, reason = is_ssrf_prohibited_ip(host)
        if prohibited:
            raise ValueError(f"Browser navigation blocked: target '{host}' is in prohibited IP range ({reason}).")

        # 2. Resolve DNS hostnames to verify destination IPs (Anti-SSRF & Rebinding Protection)
        try:
            addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            resolved_ips = {item[4][0] for item in addr_info}
            for rip in resolved_ips:
                bad_ip, ip_reason = is_ssrf_prohibited_ip(rip)
                if bad_ip:
                    raise ValueError(
                        f"Browser navigation blocked: hostname '{host}' resolves to prohibited IP '{rip}' ({ip_reason})."
                    )
        except (socket.gaierror, OSError) as e:
            # Re-raise if resolution specifically failed due to our own check
            if "Browser navigation blocked" in str(e):
                raise
            # In offline or mock environments, if host cannot resolve, allow if scope validator passes

        # 3. Enforce Scope authorization
        if self.scope_engine:
            decision = self.scope_engine.check(url)
            if decision.status != ScopeStatus.IN_SCOPE:
                raise ScopeViolationError(
                    f"Browser navigation target '{url}' is OUT_OF_SCOPE: {decision.reason} (matched rule: {decision.matched_rule})"
                )

        if self.scope_validator:
            self.scope_validator(url)

    def evaluate_dialog_observation(
        self,
        dialog_observed: bool,
        dialog_message: Optional[str],
        dialog_type: Optional[str],
        canary_token: str,
    ) -> BrowserConfirmationResult:
        """
        Correlates observed browser dialogs with injected canary tokens to prevent
        attributing unrelated application alerts or notifications to candidate XSS probes.
        """
        if not dialog_observed:
            return BrowserConfirmationResult(
                success=True,
                is_confirmed=False,
                outcome="OBSERVED",
                dialog_observed=False,
                evidence_summary="Browser completed navigation without script dialog trigger.",
            )

        msg = dialog_message or ""
        token = canary_token.strip()

        # Strict canary match: token must be present in the alert message
        if token and token in msg:
            summary = (
                f"Browser confirmed XSS execution via dialog ({dialog_type}): "
                f"dialog message contained injected canary token '{token}'."
            )
            return BrowserConfirmationResult(
                success=True,
                is_confirmed=True,
                outcome="CONFIRMED",
                dialog_observed=True,
                dialog_message=dialog_message,
                dialog_type=dialog_type,
                evidence_summary=summary,
            )

        # Unrelated dialog observed
        summary = (
            f"Browser observed script dialog ({dialog_type}: '{msg}') but message "
            f"did not match canary token '{token}'; rejected as unverified false positive."
        )
        return BrowserConfirmationResult(
            success=True,
            is_confirmed=False,
            outcome="INCONCLUSIVE",
            dialog_observed=True,
            dialog_message=dialog_message,
            dialog_type=dialog_type,
            evidence_summary=summary,
        )

    def confirm_candidate(
        self,
        target_url: str,
        canary_token: str,
        observe_spa: bool = False,
    ) -> BrowserConfirmationResult:
        """
        Navigates to candidate target URL in an isolated, headless Playwright session.
        Applies route interception, bounded SPA observation, and canary verification.
        """
        if not self.enabled:
            return BrowserConfirmationResult(
                success=False,
                is_confirmed=False,
                outcome="UNAVAILABLE",
                evidence_summary="Browser confirmation is disabled by default.",
            )

        if not self.is_available():
            return BrowserConfirmationResult(
                success=False,
                is_confirmed=False,
                outcome="UNAVAILABLE",
                evidence_summary="Headless browser runtime is not available in the current environment.",
            )

        # 1. Pre-flight URL & Scope Validation
        try:
            self.verify_url_safety(target_url)
        except Exception as e:
            return BrowserConfirmationResult(
                success=False,
                is_confirmed=False,
                outcome="BLOCKED",
                errors=[f"Safety check failed: {str(e)}"],
                evidence_summary=f"Pre-flight safety validation blocked navigation: {str(e)}",
            )

        # 2. Execution in Managed Headless Session
        spa_observer = BrowserSpaObserver()
        dialog_events: List[Dict[str, str]] = []

        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as pw:
                with BrowserSessionManager(pw, timeout=self.timeout) as session:
                    page = session.page

                    # Register safe dialog handler
                    def on_dialog(dialog):
                        dialog_events.append({
                            "type": dialog.type,
                            "message": dialog.message,
                        })
                        try:
                            dialog.dismiss()
                        except Exception:
                            pass

                    def on_console(msg):
                        spa_observer.record_console(f"[{msg.type}] {msg.text}")

                    def on_page_error(err):
                        spa_observer.record_error(str(err))

                    # Request interception: apply safety policies to all subresources and redirects
                    def handle_route(route, request):
                        req_url = request.url
                        try:
                            self.verify_url_safety(req_url)
                            spa_observer.record_request(request.method, req_url, request.headers)
                            route.continue_()
                        except Exception as route_err:
                            route.abort("accessdenied")

                    page.on("dialog", on_dialog)
                    page.on("console", on_console)
                    page.on("pageerror", on_page_error)
                    page.route("**/*", handle_route)

                    # Bounded navigation
                    page.goto(
                        target_url,
                        timeout=int(self.timeout * 1000),
                        wait_until="domcontentloaded",
                    )
                    page.wait_for_timeout(500)

                    # Capture initial client-side route
                    spa_observer.record_route_change(page.url)

            # Analyze findings
            has_dialog = len(dialog_events) > 0
            d_msg = dialog_events[0]["message"] if has_dialog else None
            d_typ = dialog_events[0]["type"] if has_dialog else None

            eval_res = self.evaluate_dialog_observation(
                dialog_observed=has_dialog,
                dialog_message=d_msg,
                dialog_type=d_typ,
                canary_token=canary_token,
            )
            eval_res.spa_summary = spa_observer.get_summary()
            eval_res.console_messages = spa_observer.console_messages
            eval_res.errors = spa_observer.page_errors
            return eval_res

        except Exception as e:
            err_msg = str(e)
            outcome = "TIMEOUT" if "timeout" in err_msg.lower() else "INCONCLUSIVE"
            return BrowserConfirmationResult(
                success=False,
                is_confirmed=False,
                outcome=outcome,
                errors=[err_msg],
                spa_summary=spa_observer.get_summary(),
                evidence_summary=f"Browser execution exception ({outcome}): {err_msg}",
            )
