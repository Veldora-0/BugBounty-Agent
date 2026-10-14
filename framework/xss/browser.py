"""
Browser-Assisted Confirmation & Client-Side Runtime for BugBounty-Agent.

Provides an isolated, headless Playwright confirmation layer strictly disabled
by default. Enforces centralized fail-closed anti-SSRF pre-checks, DNS resolution
validation, subresource/redirect route interception, exception-safe resource lifecycle
cleanup, canary-correlated XSS proof verification, bounded SPA observations, and
comprehensive credential/token redaction.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
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
        self.details = sanitize_sensitive_data(details)

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
    "code", "refresh_token", "client_secret",
}

SENSITIVE_HEADER_NAMES = {
    "authorization", "cookie", "set-cookie", "x-api-key", "api-key",
    "proxy-authorization", "token", "x-csrf-token", "x-xsrf-token",
    "session", "proxy-authenticate",
}


def redact_url_for_log(url: str) -> str:
    """
    Sanitizes URL by stripping embedded user credentials, redacting sensitive
    query parameters, and applying global sensitive-pattern scrubbing.
    """
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc
        if "@" in netloc:
            userinfo, hostport = netloc.split("@", 1)
            if ":" in userinfo:
                user, _ = userinfo.split(":", 1)
                netloc = f"{user}:[REDACTED]@{hostport}"
            else:
                netloc = f"[REDACTED]@{hostport}"

        new_query = ""
        if parsed.query:
            query_items = parse_qsl(parsed.query, keep_blank_values=True)
            sanitized_items = []
            for qk, qv in query_items:
                if qk.lower() in SENSITIVE_PARAM_NAMES:
                    sanitized_items.append((qk, "[REDACTED]"))
                else:
                    sanitized_items.append((qk, qv))
            new_query = urlencode(sanitized_items)

        redacted = urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, new_query, parsed.fragment))
        return sanitize_sensitive_data(redacted)
    except Exception:
        return sanitize_sensitive_data(url)


def redact_browser_request_metadata(url: str, headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Sanitizes URL credentials, query parameters, and request headers to prevent
    persisting raw authentication credentials or tokens.
    """
    redacted_headers: Dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADER_NAMES:
            redacted_headers[k] = "[REDACTED]"
        else:
            redacted_headers[k] = sanitize_sensitive_data(v)

    clean_url = redact_url_for_log(url)
    return {
        "url": clean_url,
        "headers": redacted_headers,
    }


# ==============================================================================
# 3. Execution Budgets
# ==============================================================================

class BrowserExecutionBudget:
    """
    Defines operational boundaries for headless execution to prevent resource
    exhaustion, unbounded crawling, or long-running runaway sessions.
    """

    def __init__(
        self,
        max_timeout_seconds: float = 5.0,
        max_redirects: int = 5,
        max_requests: int = 50,
        max_routes: int = 10,
        max_console_messages: int = 20,
        max_page_errors: int = 20,
        max_evidence_bytes: int = 65536,
    ):
        self.max_timeout_seconds = max(1.0, min(15.0, float(max_timeout_seconds)))
        self.max_redirects = max(0, int(max_redirects))
        self.max_requests = max(1, int(max_requests))
        self.max_routes = max(1, int(max_routes))
        self.max_console_messages = max(0, int(max_console_messages))
        self.max_page_errors = max(0, int(max_page_errors))
        self.max_evidence_bytes = max(1024, int(max_evidence_bytes))


# ==============================================================================
# 4. Centralized Network Policy & Destination Safety
# ==============================================================================

class BrowserNetworkPolicy:
    """
    Centralized network safety policy for headless browser sessions.
    Enforces fail-closed DNS resolution, anti-SSRF protections, scheme restrictions,
    request interception, redirect bounds, and scope authorization across all frames,
    popups, and subresources.
    """

    def __init__(
        self,
        scope_engine: Optional[ScopeEngine] = None,
        scope_validator: Optional[Callable[[str], None]] = None,
        budget: Optional[BrowserExecutionBudget] = None,
        observer: Optional[BrowserSpaObserver] = None,
    ):
        self.scope_engine = scope_engine
        self.scope_validator = scope_validator
        self.budget = budget or BrowserExecutionBudget()
        self.observer = observer

        self.request_count: int = 0
        self.redirect_count: int = 0
        self.blocked_requests: List[Dict[str, Any]] = []
        self.budget_exceeded: bool = False

    @staticmethod
    def verify_destination_and_scope(
        url: str,
        scope_engine: Optional[ScopeEngine] = None,
        scope_validator: Optional[Callable[[str], None]] = None,
    ) -> None:
        """
        Validates destination safety fail-closed:
        1. Scheme must be HTTP, HTTPS, WS, or WSS.
        2. Hostname must be present and valid.
        3. Literal IPs checked against SSRF prohibitions (IPv4/IPv6 private/loopback/metadata).
        4. Hostnames resolved via DNS; all resolved IPs checked against SSRF prohibitions.
           DNS errors or empty resolution fail closed.
        5. Scope authorization verified via ScopeEngine / scope_validator. Scope cannot
           override a failed destination or DNS check.
        """
        if not url:
            raise ValueError("Browser navigation blocked: empty or missing destination URL.")

        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValueError(f"Browser navigation blocked: malformed destination URL: {type(e).__name__}") from e

        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https", "ws", "wss"):
            clean_url = redact_url_for_log(url)
            raise ValueError(
                f"Browser navigation blocked: protocol '{scheme}' in '{clean_url}' is not permitted. Only HTTP/HTTPS/WS/WSS allowed."
            )

        host = (parsed.hostname or "").lower().strip("[]")
        if not host:
            clean_url = redact_url_for_log(url)
            raise ValueError(f"Browser navigation blocked: invalid or missing hostname in '{clean_url}'.")

        # 1. Literal IP verification
        is_bad_literal, literal_reason = is_ssrf_prohibited_ip(host)
        if is_bad_literal:
            raise ValueError(f"Browser navigation blocked: target '{host}' is in prohibited IP range ({literal_reason}).")

        # 2. Hostname DNS Resolution (Anti-SSRF & DNS Validation)
        # Determine whether host is a literal IP address
        is_literal_ip = False
        try:
            ipaddress.ip_address(host)
            is_literal_ip = True
        except ValueError:
            is_literal_ip = False

        if not is_literal_ip:
            port = parsed.port or (443 if scheme in ("https", "wss") else 80)
            try:
                addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            except (socket.gaierror, OSError) as e:
                # Fail closed on DNS resolution errors
                raise ValueError(f"Browser navigation blocked: DNS resolution failed for host '{host}': {type(e).__name__}") from e

            if not addr_info:
                # Fail closed on empty DNS resolution
                raise ValueError(f"Browser navigation blocked: DNS resolution returned no addresses for host '{host}'.")

            resolved_ips = {item[4][0] for item in addr_info}
            for rip in resolved_ips:
                bad_ip, ip_reason = is_ssrf_prohibited_ip(rip)
                if bad_ip:
                    # Fail closed if ANY resolved address is prohibited (including mixed public/private)
                    raise ValueError(
                        f"Browser navigation blocked: hostname '{host}' resolves to prohibited IP '{rip}' ({ip_reason})."
                    )

        # 3. Scope Authorization Check
        scope_check_url = url
        if scheme in ("ws", "wss"):
            scope_scheme = "https" if scheme == "wss" else "http"
            scope_check_url = urlunparse(parsed._replace(scheme=scope_scheme))

        if scope_engine:
            decision = scope_engine.check(scope_check_url)
            if decision.status != ScopeStatus.IN_SCOPE:
                clean_url = redact_url_for_log(url)
                raise ScopeViolationError(
                    f"Browser navigation target '{clean_url}' is OUT_OF_SCOPE: {decision.reason} (matched rule: {decision.matched_rule})"
                )

        if scope_validator:
            scope_validator(scope_check_url)

    def verify_url_safety(self, url: str) -> None:
        """Instance helper using policy's configured scope engine and validator."""
        self.verify_destination_and_scope(
            url=url,
            scope_engine=self.scope_engine,
            scope_validator=self.scope_validator,
        )

    def record_blocked(self, url: str, method: str, reason: str) -> None:
        """Records a blocked network request or connection for auditing."""
        self.blocked_requests.append({
            "url": redact_url_for_log(url),
            "method": method,
            "reason": sanitize_sensitive_data(reason),
        })

    def handle_route(self, route: Any, request: Any) -> None:
        """
        Route interception handler invoked for every browser request, iframe,
        subresource, worker, and redirect.
        """
        req_url = getattr(request, "url", "")
        method = getattr(request, "method", "GET")
        headers = getattr(request, "headers", {})

        # Budget check: request count
        if self.request_count >= self.budget.max_requests:
            self.budget_exceeded = True
            self.record_blocked(req_url, method, "Execution budget exceeded: maximum requests reached.")
            try:
                route.abort("timedout")
            except Exception:
                pass
            return

        # Budget check: redirect count
        if getattr(request, "redirected_from", None) is not None:
            self.redirect_count += 1
            if self.redirect_count > self.budget.max_redirects:
                self.budget_exceeded = True
                self.record_blocked(req_url, method, "Execution budget exceeded: maximum redirects reached.")
                try:
                    route.abort("accessdenied")
                except Exception:
                    pass
                return

        # Verify destination safety and scope
        try:
            self.verify_url_safety(req_url)
        except Exception as e:
            self.record_blocked(req_url, method, str(e))
            try:
                route.abort("accessdenied")
            except Exception:
                pass
            return

        self.request_count += 1
        if self.observer:
            self.observer.record_request(method, req_url, headers)

        try:
            route.continue_()
        except Exception:
            try:
                route.abort("failed")
            except Exception:
                pass

    def handle_websocket(self, ws: Any) -> None:
        """Inspects WebSocket connections and closes prohibited/out-of-scope targets."""
        ws_url = getattr(ws, "url", "")
        try:
            self.verify_url_safety(ws_url)
        except Exception as e:
            self.record_blocked(ws_url, "WEBSOCKET", str(e))
            try:
                ws.close()
            except Exception:
                pass

    def attach_to_context(self, context: Any) -> None:
        """Registers network interception and WebSocket handlers on a BrowserContext."""
        try:
            context.route("**/*", self.handle_route)
        except Exception:
            pass

        try:
            context.on("websocket", self.handle_websocket)
        except Exception:
            pass

        try:
            context.on("page", lambda p: self._attach_to_page(p))
        except Exception:
            pass

    def _attach_to_page(self, page: Any) -> None:
        """Ensures popup and newly created child pages inherit websocket listeners."""
        try:
            page.on("websocket", self.handle_websocket)
        except Exception:
            pass


# ==============================================================================
# 5. Exception-Safe Resource Lifecycle Manager
# ==============================================================================

class BrowserSessionManager:
    """
    Guarantees strict, exception-safe cleanup of Page, BrowserContext, and Browser
    resources even during initialization failures, navigation timeouts, worker aborts,
    or runtime crashes.
    """

    def __init__(self, playwright_instance, timeout: float = 5.0):
        self.pw = playwright_instance
        self.timeout = max(1.0, min(15.0, float(timeout)))
        self.browser = None
        self.context = None
        self.page = None

    def _cleanup_resources(self) -> List[Exception]:
        """Closes allocated browser resources in reverse order, suppressing secondary errors."""
        cleanup_errors: List[Exception] = []

        if self.page:
            try:
                self.page.close()
            except Exception as e:
                cleanup_errors.append(e)
            finally:
                self.page = None

        if self.context:
            try:
                self.context.close()
            except Exception as e:
                cleanup_errors.append(e)
            finally:
                self.context = None

        if self.browser:
            try:
                self.browser.close()
            except Exception as e:
                cleanup_errors.append(e)
            finally:
                self.browser = None

        return cleanup_errors

    def __enter__(self) -> BrowserSessionManager:
        try:
            self.browser = self.pw.chromium.launch(headless=True)
            try:
                # Service workers blocked to prevent unintercepted network requests
                self.context = self.browser.new_context(
                    ignore_https_errors=True,
                    java_script_enabled=True,
                    service_workers="block",
                )
            except (TypeError, Exception):
                self.context = self.browser.new_context(
                    ignore_https_errors=True,
                    java_script_enabled=True,
                )
            self.page = self.context.new_page()
            return self
        except Exception:
            self._cleanup_resources()
            raise

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        cleanup_errors = self._cleanup_resources()

        # Never mask the primary exception if one occurred
        if exc_type is not None:
            return False

        if cleanup_errors:
            raise cleanup_errors[0]

        return False


# ==============================================================================
# 6. Bounded SPA Observer
# ==============================================================================

class BrowserSpaObserver:
    """
    Collects bounded client-side routing, DOM mutation summaries, dynamic scripts,
    and network requests for modern Single-Page Applications (SPAs).
    All stored data is strictly sanitized and capped to prevent memory leaks
    or sensitive token persistence.
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
        clean_route = redact_url_for_log(route_url)
        if len(self.routes_observed) < self.max_routes:
            if clean_route not in self.routes_observed:
                self.routes_observed.append(clean_route)

    def record_mutation(self, node_type: str, action: str = "added") -> None:
        self.dom_mutation_count += 1
        if node_type.lower() == "script" and action == "added":
            self.dynamic_scripts_added += 1

    def record_script(self, src: Optional[str] = None, length: int = 0) -> None:
        if len(self.dynamic_scripts) < self.max_scripts:
            clean_src = redact_url_for_log(src) if src else "inline"
            self.dynamic_scripts.append({
                "src": clean_src,
                "length": max(0, int(length)),
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
            clean_text = sanitize_sensitive_data(text)
            self.console_messages.append(clean_text)

    def record_error(self, err_text: str) -> None:
        if len(self.page_errors) < self.max_console:
            clean_err = sanitize_sensitive_data(err_text)
            self.page_errors.append(clean_err)

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
# 7. Confirmation Result & Assistant
# ==============================================================================

class BrowserConfirmationResult:
    """Outcome of browser-assisted verification and SPA observation."""

    def __init__(
        self,
        success: bool = False,
        is_confirmed: bool = False,
        outcome: str = "INCONCLUSIVE",  # CONFIRMED, INCONCLUSIVE, UNAVAILABLE, BLOCKED, TIMEOUT, OBSERVED, BUDGET_EXCEEDED
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
        self.dialog_message = sanitize_sensitive_data(dialog_message) if dialog_message else None
        self.dialog_type = dialog_type
        self.console_messages = [sanitize_sensitive_data(m) for m in (console_messages or [])]
        self.errors = [sanitize_sensitive_data(e) for e in (errors or [])]
        self.spa_summary = spa_summary or {}
        self.evidence_summary = sanitize_sensitive_data(evidence_summary)

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
        BrowserNetworkPolicy.verify_destination_and_scope(
            url=url,
            scope_engine=self.scope_engine,
            scope_validator=self.scope_validator,
        )

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
        token = canary_token.strip() if canary_token else ""

        # Empty canary cannot confirm execution
        if not token:
            summary = (
                f"Browser observed dialog ({dialog_type}: '{msg}') but no canary token was "
                "provided; cannot attribute execution to candidate. Result is INCONCLUSIVE."
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

        # Strict canary match: token must be present in the alert message
        if token in msg:
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
        budget: Optional[BrowserExecutionBudget] = None,
    ) -> BrowserConfirmationResult:
        """
        Navigates to candidate target URL in an isolated, headless Playwright session.
        Applies centralized network policy, bounded execution budgets, route interception,
        bounded SPA observation, and canary verification.
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
            sanitized_err = sanitize_sensitive_data(str(e))
            return BrowserConfirmationResult(
                success=False,
                is_confirmed=False,
                outcome="BLOCKED",
                errors=[f"Safety check failed: {sanitized_err}"],
                evidence_summary=f"Pre-flight safety validation blocked navigation: {sanitized_err}",
            )

        # 2. Execution Setup
        exec_budget = budget or BrowserExecutionBudget(max_timeout_seconds=self.timeout)
        spa_observer = BrowserSpaObserver(
            max_routes=exec_budget.max_routes,
            max_console=exec_budget.max_console_messages,
            max_requests=exec_budget.max_requests,
        )
        policy = BrowserNetworkPolicy(
            scope_engine=self.scope_engine,
            scope_validator=self.scope_validator,
            budget=exec_budget,
            observer=spa_observer,
        )
        dialog_events: List[Dict[str, str]] = []

        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as pw:
                with BrowserSessionManager(pw, timeout=self.timeout) as session:
                    context = session.context
                    page = session.page

                    # Attach centralized network safety policy to context
                    policy.attach_to_context(context)

                    # Dialog handler
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

                    page.on("dialog", on_dialog)
                    page.on("console", on_console)
                    page.on("pageerror", on_page_error)

                    # Instrument SPA hooks if enabled
                    if observe_spa:
                        spa_init_script = """
                        (() => {
                            try {
                                const origPush = history.pushState;
                                history.pushState = function() {
                                    try { window.__bb_spa_route && window.__bb_spa_route(arguments[2] ? String(arguments[2]) : location.href); } catch(e){}
                                    return origPush.apply(this, arguments);
                                };
                                const origReplace = history.replaceState;
                                history.replaceState = function() {
                                    try { window.__bb_spa_route && window.__bb_spa_route(arguments[2] ? String(arguments[2]) : location.href); } catch(e){}
                                    return origReplace.apply(this, arguments);
                                };
                                window.addEventListener('hashchange', () => {
                                    try { window.__bb_spa_route && window.__bb_spa_route(location.href); } catch(e){}
                                });
                                const observer = new MutationObserver((mutations) => {
                                    for (const m of mutations) {
                                        if (m.addedNodes) {
                                            for (const n of m.addedNodes) {
                                                if (n.nodeName) {
                                                    const isScript = n.nodeName.toLowerCase() === 'script';
                                                    const src = isScript ? (n.src || '') : '';
                                                    window.__bb_spa_mutation && window.__bb_spa_mutation(n.nodeName, 'added', src);
                                                }
                                            }
                                        }
                                    }
                                });
                                observer.observe(document.documentElement || document, { childList: true, subtree: true });
                            } catch(e){}
                        })();
                        """
                        try:
                            page.add_init_script(spa_init_script)
                            page.expose_binding(
                                "__bb_spa_route",
                                lambda source, route: spa_observer.record_route_change(str(route)),
                            )
                            page.expose_binding(
                                "__bb_spa_mutation",
                                lambda source, node_name, action, src: (
                                    spa_observer.record_mutation(str(node_name), str(action)),
                                    spa_observer.record_script(str(src) if src else None, len(str(src))) if str(node_name).lower() == "script" else None,
                                ),
                            )
                        except Exception:
                            pass

                    # Bounded navigation
                    page.goto(
                        target_url,
                        timeout=int(exec_budget.max_timeout_seconds * 1000),
                        wait_until="domcontentloaded",
                    )
                    page.wait_for_timeout(500)

                    # Capture initial client-side route
                    spa_observer.record_route_change(page.url)

            if policy.budget_exceeded:
                return BrowserConfirmationResult(
                    success=False,
                    is_confirmed=False,
                    outcome="BUDGET_EXCEEDED",
                    errors=["Execution budget exceeded during navigation or subresource processing."],
                    spa_summary=spa_observer.get_summary(),
                    evidence_summary="Browser execution stopped: operational execution budget exceeded.",
                )

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
            err_msg = sanitize_sensitive_data(str(e))
            outcome = "TIMEOUT" if "timeout" in err_msg.lower() else "INCONCLUSIVE"
            return BrowserConfirmationResult(
                success=False,
                is_confirmed=False,
                outcome=outcome,
                errors=[err_msg],
                spa_summary=spa_observer.get_summary(),
                evidence_summary=f"Browser execution exception ({outcome}): {err_msg}",
            )
