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
import select
import socket
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from framework.common.evidence import sanitize_sensitive_data
from framework.findings.lifecycle import FindingLifecycle
from framework.scope.engine import ScopeEngine, ScopeStatus
from framework.validation.engine import ScopeViolationError, is_ssrf_prohibited_ip


logger = logging.getLogger(__name__)


class BrowserSecurityPolicyError(RuntimeError):
    """Raised when mandatory browser network security controls fail to register or initialize."""
    pass


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

    def detect(self, browser_type: str = "chromium") -> BrowserCapability:
        """Inspects package, executable, driver, and launchability for chromium or firefox."""
        api = self._get_sync_playwright()
        if api is None:
            return BrowserCapability(
                package_available=False,
                browser_executable_available=False,
                can_launch=False,
                state="MISSING_PACKAGE",
                details="Playwright Python package is not installed.",
            )

        btype = (browser_type or "chromium").lower().strip()
        if btype not in ("chromium", "firefox"):
            return BrowserCapability(
                package_available=True,
                browser_executable_available=False,
                can_launch=False,
                state="UNSUPPORTED_BROWSER",
                details=f"Unsupported browser type: {btype}. Supported types: chromium, firefox.",
            )

        try:
            with api.sync_playwright() as p:
                b_driver = p.firefox if btype == "firefox" else p.chromium
                b_name = "Firefox" if btype == "firefox" else "Chromium"
                try:
                    exec_path = b_driver.executable_path
                    if not exec_path or not os.path.exists(exec_path):
                        return BrowserCapability(
                            package_available=True,
                            browser_executable_available=False,
                            can_launch=False,
                            state="MISSING_BROWSER",
                            details=f"{b_name} browser binary is not installed.",
                        )
                except Exception as e:
                    return BrowserCapability(
                        package_available=True,
                        browser_executable_available=False,
                        can_launch=False,
                        state="MISSING_BROWSER",
                        details=f"{b_name} executable check failed: {type(e).__name__}",
                    )

                # Dry-launch headless browser to verify shared libraries and sandbox
                try:
                    browser = b_driver.launch(headless=True, timeout=5000)
                    browser.close()
                    return BrowserCapability(
                        package_available=True,
                        browser_executable_available=True,
                        can_launch=True,
                        state="READY",
                        details=f"Headless {b_name} verified and ready.",
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


def truncate_to_max_bytes(text: str, max_bytes: int, marker: str = " [EVIDENCE TRUNCATED]") -> str:
    """
    Truncates a Unicode string so its UTF-8 encoded byte size strictly does not exceed max_bytes.
    If truncation is necessary, preserves the provided marker at the end within the byte limit.
    """
    if not text:
        return ""
    max_bytes = max(16, int(max_bytes))
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text

    marker_bytes = marker.encode("utf-8", errors="replace")
    if len(marker_bytes) >= max_bytes:
        return encoded[:max_bytes].decode("utf-8", errors="ignore")

    budget_for_text = max_bytes - len(marker_bytes)
    truncated_prefix = encoded[:budget_for_text].decode("utf-8", errors="ignore")
    return truncated_prefix + marker


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
        route_fulfill_handler: Optional[Callable[[Any, Any], bool]] = None,
        allow_websockets: bool = True,
    ):
        self.scope_engine = scope_engine
        self.scope_validator = scope_validator
        self.budget = budget or BrowserExecutionBudget()
        self.observer = observer
        self.route_fulfill_handler = route_fulfill_handler
        self.allow_websockets = bool(allow_websockets)

        self.request_count: int = 0
        self.redirect_count: int = 0
        self.blocked_requests: List[Dict[str, Any]] = []
        self.budget_exceeded: bool = False
        self._attached_contexts: Set[int] = set()

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

        if self.route_fulfill_handler:
            try:
                handled = self.route_fulfill_handler(route, request)
                if handled:
                    return
            except Exception:
                pass

        try:
            route.continue_()
        except Exception:
            try:
                route.abort("failed")
            except Exception:
                pass

    def handle_websocket(self, ws: Any) -> None:
        """
        Inspects WebSocket connections and terminates prohibited/out-of-scope targets.

        SECURITY BOUNDARY & TIMING NOTE:
        In Playwright/CDP, context.on("websocket") is an asynchronous post-handshake event
        fired after the browser network stack has already initiated the WebSocket handshake.
        It cannot prevent the initial transport connection from being established.

        TRANSPORT ENFORCEMENT & TLS TUNNEL BOUNDARIES:
        1. Pre-connection destination safety, anti-SSRF, and scope verification for ALL
           traffic (including HTTP, HTTPS, WS, and WSS via CONNECT) is enforced at the
           transport layer by ValidatingEgressProxy before any upstream TCP socket is opened.
        2. Prohibited IPs and out-of-scope destinations are strictly blocked pre-connection
           for both plain WS and encrypted WSS (via CONNECT tunnel rejection).
        3. Cleartext WebSocket (ws://) requests with 'Upgrade: websocket' are selectively
           blocked pre-connection by ValidatingEgressProxy when allow_websockets=False.
        4. Encrypted WebSocket (wss://) requests traverse an end-to-end encrypted TLS CONNECT
           tunnel. Because ValidatingEgressProxy acts as a non-MITM blind tunnel, it cannot
           distinguish inside-tunnel WSS handshakes from standard HTTPS GET/POST requests
           without breaking TLS integrity. Therefore, selective disabling of WSS within an
           authorized, in-scope TLS tunnel (allow_websockets=False) is enforced at this layer
           by immediately closing the socket upon creation, while normal HTTPS is preserved.
        """
        ws_url = getattr(ws, "url", "")
        try:
            if not self.allow_websockets:
                raise ValueError("WebSocket traffic is disabled by security policy")
            self.verify_url_safety(ws_url)
        except Exception as e:
            self.record_blocked(ws_url, "WEBSOCKET", str(e))
            try:
                ws.close()
            except Exception:
                pass

    def handle_websocket_route(self, ws_route: Any) -> None:
        """
        Pre-handshake WebSocket interception handler via Playwright's BrowserContext.route_web_socket.

        PRE-HANDSHAKE ENFORCEMENT GUARANTEE:
        Playwright routes WebSockets at the browser engine level before any network handshake
        reaches the upstream server. By default, routed WebSockets do NOT connect to the server
        unless ws_route.connect_to_server() is explicitly called.

        - If allow_websockets=False: records violation and calls ws_route.close(code=1008);
          the WebSocket handshake is strictly prevented from reaching the upstream server.
        - If allow_websockets=True: validates destination IP and scope against SSRF rules.
          If invalid/out-of-scope, rejects with ws_route.close(code=1008); if authorized,
          calls ws_route.connect_to_server() which proceeds through ValidatingEgressProxy.
        """
        ws_url = getattr(ws_route, "url", "")
        if not self.allow_websockets:
            self.record_blocked(ws_url, "WEBSOCKET", "WebSocket traffic is disabled by security policy")
            try:
                ws_route.close(code=1008, reason="WebSocket traffic is disabled by security policy")
            except Exception:
                pass
            return

        try:
            self.verify_url_safety(ws_url)
        except Exception as e:
            self.record_blocked(ws_url, "WEBSOCKET", str(e))
            try:
                ws_route.close(code=1008, reason=str(e))
            except Exception:
                pass
            return

        try:
            ws_route.connect_to_server()
        except Exception as e:
            self.record_blocked(ws_url, "WEBSOCKET", f"Upstream WebSocket connection failed: {e}")
            try:
                ws_route.close(code=1011, reason="Upstream connection failed")
            except Exception:
                pass

    def attach_to_context(self, context: Any) -> None:
        """
        Registers mandatory network interception and WebSocket security handlers on a BrowserContext.

        Fails closed: if mandatory route interception or security handlers fail to register,
        raises BrowserSecurityPolicyError to prevent unintercepted network requests.
        """
        if context is None:
            raise BrowserSecurityPolicyError("Cannot attach network policy to null BrowserContext.")

        ctx_id = id(context)
        if ctx_id in self._attached_contexts:
            return

        try:
            context.route("**/*", self.handle_route)
        except Exception as e:
            raise BrowserSecurityPolicyError(
                f"Failed to register mandatory network route interception: {type(e).__name__}: {e}"
            ) from e

        # Pre-handshake WebSocket routing (Playwright route_web_socket)
        if hasattr(context, "route_web_socket"):
            try:
                context.route_web_socket(re.compile(r"^wss?://.*"), self.handle_websocket_route)
            except Exception as e:
                raise BrowserSecurityPolicyError(
                    f"Failed to register mandatory pre-handshake WebSocket route interception: {type(e).__name__}: {e}"
                ) from e

        try:
            context.on("websocket", self.handle_websocket)
        except Exception as e:
            raise BrowserSecurityPolicyError(
                f"Failed to register mandatory WebSocket security handler: {type(e).__name__}: {e}"
            ) from e

        try:
            context.on("page", lambda p: self._attach_to_page(p))
        except Exception as e:
            raise BrowserSecurityPolicyError(
                f"Failed to register mandatory child page security handler: {type(e).__name__}: {e}"
            ) from e

        self._attached_contexts.add(ctx_id)

    def _attach_to_page(self, page: Any) -> None:
        """Ensures popup and newly created child pages inherit websocket listeners."""
        try:
            page.on("websocket", self.handle_websocket)
        except Exception:
            pass


# ==============================================================================
# 5. Local Validating Egress Security Proxy (Anti-DNS-Rebinding)
# ==============================================================================

MANDATORY_CHROMIUM_ISOLATION_FLAGS: List[str] = [
    "--proxy-bypass-list=<-loopback>",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-domain-reliability",
    "--disable-sync",
    "--disable-breakpad",
    "--dns-prefetch-disable",
    "--no-default-browser-check",
    "--no-pings",
]


class ValidatingEgressProxy:
    """
    Local validating HTTP/CONNECT forward proxy for headless browser execution.
    Eliminates the DNS TOCTOU rebinding window by resolving and validating
    destination IPs before connection, and connecting strictly to the validated IP.

    SECURITY ARCHITECTURE & BOUNDARIES:
    - Pre-Connection Validation: Verifies destination host, IP, anti-SSRF prohibitions,
      and ScopeEngine authorization before establishing ANY upstream socket connection.
    - Prohibited/Out-of-Scope Blocking: CONNECT tunnels and HTTP requests to prohibited
      or out-of-scope destinations are rejected immediately with HTTP 403 before any
      upstream connection is attempted.
    - Plain WebSocket (ws://): Detected via 'Upgrade: websocket' headers and blocked
      pre-connection when allow_websockets=False.
    - Encrypted WebSocket (wss://) & HTTPS: Validated and IP-pinned at the CONNECT layer.
      Because non-MITM forward proxies cannot decrypt inside-tunnel traffic, selective protocol
      filtering of WSS within authorized tunnels is handled by BrowserNetworkPolicy,
      preserving standard authorized HTTPS traffic.
    """

    def __init__(
        self,
        scope_engine: Optional[ScopeEngine] = None,
        scope_validator: Optional[Callable[[str], None]] = None,
        timeout: float = 5.0,
        allow_websockets: bool = True,
    ):
        self.scope_engine = scope_engine
        self.scope_validator = scope_validator
        self.timeout = max(1.0, min(15.0, float(timeout)))
        self.allow_websockets = bool(allow_websockets)
        self.server_sock: Optional[socket.socket] = None
        self.port: int = 0
        self.is_running: bool = False
        self._thread: Optional[threading.Thread] = None
        self._client_sockets: Set[socket.socket] = set()
        self._lock = threading.Lock()
        self.blocked_connections: List[Dict[str, Any]] = []

    def start(self) -> int:
        """Starts the validating forward proxy on 127.0.0.1 with an OS-assigned ephemeral port."""
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind(("127.0.0.1", 0))
            self.server_sock.listen(64)
            self.server_sock.settimeout(0.5)
            self.port = self.server_sock.getsockname()[1]
            self.is_running = True
            self._thread = threading.Thread(target=self._accept_loop, daemon=True, name="ValidatingEgressProxy")
            self._thread.start()
            return self.port
        except Exception as e:
            self.stop()
            raise RuntimeError(f"Failed to start ValidatingEgressProxy: {e}") from e

    def stop(self) -> None:
        """Stops the proxy and cleanly closes all active sockets."""
        self.is_running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
            self.server_sock = None

        with self._lock:
            for s in list(self._client_sockets):
                try:
                    s.close()
                except Exception:
                    pass
            self._client_sockets.clear()

        if self._thread:
            if self._thread.is_alive():
                self._thread.join(timeout=2.0)
            self._thread = None

    def _connect_upstream(self, sock: socket.socket, sockaddr: Any) -> None:
        """Connects the upstream socket to the pinned, validated IP tuple."""
        sock.connect(sockaddr)

    def record_blocked(self, url: str, method: str, reason: str) -> None:
        """Records a blocked network connection for auditing."""
        self.blocked_connections.append({
            "url": redact_url_for_log(url),
            "method": method,
            "reason": sanitize_sensitive_data(reason),
        })

    def validate_destination_and_get_addr(
        self, host: str, port: int, scheme: str, scope_url: str
    ) -> Any:
        """
        Validates the destination fail-closed:
        1. Scheme check (HTTP/HTTPS/WS/WSS only).
        2. Literal IP check (prohibits private/loopback/metadata/link-local/IPv4-mapped-IPv6).
        3. DNS resolution via socket.getaddrinfo.
        4. Validates EVERY resolved IP; fails closed on any prohibited address (including mixed public/private).
        5. Scope validation via scope_engine and scope_validator.
        6. Returns the validated address entry for direct socket connection (no re-resolution).
        """
        if not host:
            raise ValueError("Missing or empty destination host.")

        clean_scheme = (scheme or "").lower()
        if clean_scheme not in ("http", "https", "ws", "wss"):
            raise ValueError(f"Prohibited scheme: '{clean_scheme}'")

        # 1. Literal IP check
        is_bad_literal, literal_reason = is_ssrf_prohibited_ip(host)
        if is_bad_literal:
            raise ValueError(f"Prohibited destination IP: {literal_reason}")

        try:
            ipaddress.ip_address(host)
            is_literal_ip = True
        except ValueError:
            is_literal_ip = False

        if is_literal_ip:
            try:
                addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            except Exception as e:
                raise ValueError(f"Address parsing failed for IP '{host}': {e}") from e
        else:
            try:
                addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            except (socket.gaierror, OSError) as e:
                raise ValueError(f"DNS resolution failed for '{host}': {e}") from e

            if not addr_info:
                raise ValueError(f"DNS resolution returned no addresses for '{host}'")

            for entry in addr_info:
                resolved_ip = entry[4][0]
                bad_ip, ip_reason = is_ssrf_prohibited_ip(resolved_ip)
                if bad_ip:
                    raise ValueError(f"Destination '{host}' resolves to prohibited IP '{resolved_ip}' ({ip_reason})")

        # 2. Scope check
        scope_check_url = scope_url
        if clean_scheme in ("ws", "wss"):
            norm_scheme = "https" if clean_scheme == "wss" else "http"
            scope_check_url = urlunparse(urlparse(scope_url)._replace(scheme=norm_scheme))

        if self.scope_engine:
            decision = self.scope_engine.check(scope_check_url)
            if decision.status != ScopeStatus.IN_SCOPE:
                raise ScopeViolationError(
                    f"Destination '{scope_url}' is OUT_OF_SCOPE: {decision.reason}"
                )

        if self.scope_validator:
            self.scope_validator(scope_check_url)

        return addr_info[0]

    def _accept_loop(self) -> None:
        while self.is_running and self.server_sock:
            try:
                client_sock, client_addr = self.server_sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            with self._lock:
                self._client_sockets.add(client_sock)

            t = threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True)
            t.start()

    def _handle_client(self, client_sock: socket.socket) -> None:
        upstream_sock: Optional[socket.socket] = None
        try:
            client_sock.settimeout(self.timeout)
            raw_data = b""
            while b"\r\n\r\n" not in raw_data and len(raw_data) < 65536 and self.is_running:
                try:
                    chunk = client_sock.recv(4096)
                except (socket.timeout, OSError):
                    break
                if not chunk:
                    break
                raw_data += chunk

            if not raw_data:
                return

            header_end = raw_data.find(b"\r\n\r\n")
            if header_end == -1:
                client_sock.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                return

            header_bytes = raw_data[:header_end]
            body_prefix = raw_data[header_end + 4:]

            lines = header_bytes.split(b"\r\n")
            request_line = lines[0].decode("utf-8", errors="replace")
            parts = request_line.split(" ")
            if len(parts) < 3:
                client_sock.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                return

            method, target_uri, proto = parts[0].upper(), parts[1], parts[2]

            if method == "CONNECT":
                target_str = target_uri.strip()
                if target_str.startswith("["):
                    if "]:" in target_str:
                        host_part, port_str = target_str.split("]:", 1)
                        host = host_part.lstrip("[")
                        try:
                            port = int(port_str)
                        except ValueError:
                            port = 443
                    else:
                        host = target_str.strip("[]")
                        port = 443
                elif ":" in target_str:
                    host_part, port_str = target_str.rsplit(":", 1)
                    host = host_part
                    try:
                        port = int(port_str)
                    except ValueError:
                        port = 443
                else:
                    host = target_str
                    port = 443
                scheme = "https"
                scope_url = f"https://{host}:{port}/"
            else:
                parsed = urlparse(target_uri)
                host = parsed.hostname or ""
                scheme = (parsed.scheme or "http").lower()
                port = parsed.port or (443 if scheme == "https" else 80)
                if not host:
                    for line in lines[1:]:
                        if line.lower().startswith(b"host:"):
                            host_hdr = line.split(b":", 1)[1].decode("utf-8", errors="replace").strip()
                            if host_hdr.startswith("["):
                                if "]:" in host_hdr:
                                    h_part, p_part = host_hdr.split("]:", 1)
                                    host = h_part.lstrip("[")
                                    try:
                                        port = int(p_part)
                                    except ValueError:
                                        pass
                                else:
                                    host = host_hdr.strip("[]")
                            elif ":" in host_hdr:
                                h_part, p_part = host_hdr.rsplit(":", 1)
                                host = h_part
                                try:
                                    port = int(p_part)
                                except ValueError:
                                    pass
                            else:
                                host = host_hdr
                            break
                is_websocket_upgrade = False
                for line in lines[1:]:
                    line_lower = line.lower()
                    if line_lower.startswith(b"upgrade:") and b"websocket" in line_lower:
                        is_websocket_upgrade = True
                        break

                if is_websocket_upgrade or scheme in ("ws", "wss"):
                    is_ws = True
                    scheme = "wss" if (scheme == "wss" or port == 443) else "ws"
                else:
                    is_ws = False

                path_part = parsed.path or "/"
                if parsed.query:
                    path_part += f"?{parsed.query}"

                if is_ws:
                    scope_url = f"{scheme}://{host}:{port}{path_part}"
                    if not self.allow_websockets:
                        self.record_blocked(scope_url, "WEBSOCKET", "WebSocket traffic disabled by security policy")
                        client_sock.sendall(
                            b"HTTP/1.1 403 Forbidden\r\n"
                            b"Content-Type: text/plain\r\n"
                            b"Connection: close\r\n\r\n"
                            b"WebSocket traffic disabled by Egress Security Policy\r\n"
                        )
                        return
                else:
                    scope_url = target_uri if (parsed.scheme and parsed.netloc) else f"{scheme}://{host}:{port}{path_part}"

            try:
                validated_entry = self.validate_destination_and_get_addr(host, port, scheme, scope_url)
            except Exception as e:
                self.record_blocked(scope_url, method, str(e))
                client_sock.sendall(
                    b"HTTP/1.1 403 Forbidden\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Connection: close\r\n\r\n"
                    b"Access Denied by Egress Security Policy\r\n"
                )
                return

            family, socktype, proto_num, canonname, sockaddr = validated_entry
            upstream_sock = socket.socket(family, socktype, proto_num)
            upstream_sock.settimeout(self.timeout)

            # Direct connection to the pinned IP tuple (NO TOCTOU re-resolution)
            self._connect_upstream(upstream_sock, sockaddr)

            if method == "CONNECT":
                client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                self._relay_bidirectional(client_sock, upstream_sock)
            else:
                path = parsed.path or "/"
                if parsed.query:
                    path += f"?{parsed.query}"
                new_request_line = f"{method} {path} {proto}\r\n"
                headers_rest = b"\r\n".join(lines[1:])
                forward_bytes = new_request_line.encode("utf-8") + headers_rest + b"\r\n\r\n" + body_prefix
                upstream_sock.sendall(forward_bytes)
                self._relay_bidirectional(client_sock, upstream_sock)

        except Exception:
            pass
        finally:
            with self._lock:
                self._client_sockets.discard(client_sock)
            try:
                client_sock.close()
            except Exception:
                pass
            if upstream_sock:
                try:
                    upstream_sock.close()
                except Exception:
                    pass

    def _relay_bidirectional(self, s1: socket.socket, s2: socket.socket) -> None:
        sockets = [s1, s2]
        while self.is_running:
            try:
                readable, _, exceptional = select.select(sockets, [], sockets, 0.5)
            except Exception:
                break
            if exceptional:
                break
            if not readable:
                continue
            for s in readable:
                other = s2 if s is s1 else s1
                try:
                    data = s.recv(16384)
                    if not data:
                        return
                    other.sendall(data)
                except Exception:
                    return


# ==============================================================================
# 6. Exception-Safe Resource Lifecycle Manager
# ==============================================================================

class BrowserSessionManager:
    """
    Guarantees strict, exception-safe cleanup of Page, BrowserContext, and Browser
    resources even during initialization failures, navigation timeouts, worker aborts,
    or runtime crashes.
    """

    def __init__(
        self,
        playwright_instance,
        timeout: float = 5.0,
        scope_engine: Optional[ScopeEngine] = None,
        scope_validator: Optional[Callable[[str], None]] = None,
        enable_egress_proxy: bool = True,
        allow_websockets: bool = True,
        network_policy: Optional[BrowserNetworkPolicy] = None,
        browser_type: str = "chromium",
    ):
        self.pw = playwright_instance
        self.timeout = max(1.0, min(15.0, float(timeout)))
        self.scope_engine = scope_engine
        self.scope_validator = scope_validator
        self.enable_egress_proxy = bool(enable_egress_proxy)
        self.allow_websockets = bool(allow_websockets)
        self.network_policy = network_policy
        self.browser_type = (browser_type or "chromium").lower().strip()
        self.browser = None
        self.context = None
        self.page = None
        self.proxy: Optional[ValidatingEgressProxy] = None

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

        if self.proxy:
            try:
                self.proxy.stop()
            except Exception as e:
                cleanup_errors.append(e)
            finally:
                self.proxy = None

        return cleanup_errors

    def __enter__(self) -> BrowserSessionManager:
        try:
            proxy_config = None
            launch_args: List[str] = []
            if self.enable_egress_proxy:
                try:
                    self.proxy = ValidatingEgressProxy(
                        scope_engine=self.scope_engine,
                        scope_validator=self.scope_validator,
                        timeout=self.timeout,
                        allow_websockets=self.allow_websockets,
                    )
                    proxy_port = self.proxy.start()
                    proxy_config = {
                        "server": f"http://127.0.0.1:{proxy_port}",
                        "bypass": "<-loopback>",
                    }
                    if self.browser_type != "firefox":
                        launch_args.extend(MANDATORY_CHROMIUM_ISOLATION_FLAGS)
                except Exception as e:
                    raise BrowserSecurityPolicyError(
                        f"Failed to initialize mandatory validating egress proxy: {type(e).__name__}: {e}"
                    ) from e

            launch_timeout_ms = max(500, int(self.timeout * 1000))
            if self.browser_type == "firefox":
                self.browser = self.pw.firefox.launch(
                    headless=True,
                    timeout=launch_timeout_ms,
                    proxy=proxy_config,
                )
            else:
                self.browser = self.pw.chromium.launch(
                    headless=True,
                    timeout=launch_timeout_ms,
                    args=launch_args if launch_args else None,
                )
            context_kwargs: Dict[str, Any] = {
                "ignore_https_errors": True,
                "java_script_enabled": True,
            }
            if proxy_config:
                context_kwargs["proxy"] = proxy_config

            try:
                # Service workers blocked to prevent unintercepted network requests
                self.context = self.browser.new_context(
                    service_workers="block",
                    **context_kwargs,
                )
            except (TypeError, Exception):
                self.context = self.browser.new_context(
                    **context_kwargs,
                )
            try:
                self.context.set_default_timeout(launch_timeout_ms)
                self.context.set_default_navigation_timeout(launch_timeout_ms)
            except Exception:
                pass
            if self.network_policy:
                self.network_policy.attach_to_context(self.context)
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
        max_evidence_bytes: int = 65536,
    ):
        self.max_routes = max_routes
        self.max_scripts = max_scripts
        self.max_requests = max_requests
        self.max_console = max_console
        self.max_evidence_bytes = max(1024, int(max_evidence_bytes))

        self.current_evidence_bytes: int = 0
        self.evidence_truncated: bool = False
        self.routes_observed: List[str] = []
        self.dynamic_scripts: List[Dict[str, Any]] = []
        self.network_requests: List[Dict[str, Any]] = []
        self.console_messages: List[str] = []
        self.page_errors: List[str] = []
        self.dom_mutation_count: int = 0
        self.dynamic_scripts_added: int = 0

    def _would_exceed(self, added_bytes: int) -> bool:
        if self.current_evidence_bytes + added_bytes > self.max_evidence_bytes:
            self.evidence_truncated = True
            return True
        return False

    def record_route_change(self, route_url: str) -> None:
        clean_route = redact_url_for_log(route_url)
        byte_len = len(clean_route.encode("utf-8", errors="replace"))
        if self._would_exceed(byte_len):
            return
        if len(self.routes_observed) < self.max_routes:
            if clean_route not in self.routes_observed:
                self.routes_observed.append(clean_route)
                self.current_evidence_bytes += byte_len

    def record_mutation(self, node_type: str, action: str = "added") -> None:
        self.dom_mutation_count += 1
        if node_type.lower() == "script" and action == "added":
            self.dynamic_scripts_added += 1

    def record_script(self, src: Optional[str] = None, length: int = 0) -> None:
        clean_src = redact_url_for_log(src) if src else "inline"
        byte_len = len(clean_src.encode("utf-8", errors="replace")) + 16
        if self._would_exceed(byte_len):
            return
        if len(self.dynamic_scripts) < self.max_scripts:
            self.dynamic_scripts.append({
                "src": clean_src,
                "length": max(0, int(length)),
            })
            self.current_evidence_bytes += byte_len

    def record_request(self, method: str, url: str, headers: Dict[str, str]) -> None:
        redacted = redact_browser_request_metadata(url, headers)
        raw_repr = f"{method} {redacted['url']} " + " ".join(f"{k}:{v}" for k, v in redacted["headers"].items())
        byte_len = len(raw_repr.encode("utf-8", errors="replace"))
        if self._would_exceed(byte_len):
            return
        if len(self.network_requests) < self.max_requests:
            self.network_requests.append({
                "method": method,
                "url": redacted["url"],
                "headers": redacted["headers"],
            })
            self.current_evidence_bytes += byte_len

    def record_console(self, text: str) -> None:
        clean_text = sanitize_sensitive_data(text)
        byte_len = len(clean_text.encode("utf-8", errors="replace"))
        if self._would_exceed(byte_len):
            return
        if len(self.console_messages) < self.max_console:
            self.console_messages.append(clean_text)
            self.current_evidence_bytes += byte_len

    def record_error(self, err_text: str) -> None:
        clean_err = sanitize_sensitive_data(err_text)
        byte_len = len(clean_err.encode("utf-8", errors="replace"))
        if self._would_exceed(byte_len):
            return
        if len(self.page_errors) < self.max_console:
            self.page_errors.append(clean_err)
            self.current_evidence_bytes += byte_len

    def get_summary(self) -> Dict[str, Any]:
        return {
            "routes_observed": list(self.routes_observed),
            "dom_mutation_count": self.dom_mutation_count,
            "dynamic_scripts_added": self.dynamic_scripts_added,
            "dynamic_scripts": list(self.dynamic_scripts),
            "network_requests_count": len(self.network_requests),
            "console_messages": list(self.console_messages),
            "page_errors": list(self.page_errors),
            "evidence_bytes": self.current_evidence_bytes,
            "evidence_truncated": self.evidence_truncated,
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
        route_fulfill_handler: Optional[Callable[[Any, Any], bool]] = None,
        enable_egress_proxy: bool = True,
        allow_websockets: bool = True,
        browser_type: str = "chromium",
    ):
        self.enabled = bool(enabled)
        self.timeout = max(1.0, min(15.0, float(timeout)))
        self.scope_validator = scope_validator
        self.scope_engine = scope_engine
        self.detector = detector or BrowserCapabilityDetector()
        self.route_fulfill_handler = route_fulfill_handler
        self.enable_egress_proxy = bool(enable_egress_proxy)
        self.allow_websockets = bool(allow_websockets)
        self.browser_type = (browser_type or "chromium").lower().strip()

    def is_available(self) -> bool:
        """Verifies if headless browser is executable and ready."""
        cap = self.detector.detect(self.browser_type)
        return cap.can_launch

    def is_playwright_available(self) -> bool:
        """Backwards compatibility check for package presence."""
        cap = self.detector.detect(self.browser_type)
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

        exec_budget = budget or BrowserExecutionBudget(max_timeout_seconds=self.timeout)

        # 1. Pre-flight URL & Scope Validation
        try:
            self.verify_url_safety(target_url)
        except Exception as e:
            sanitized_err = sanitize_sensitive_data(str(e))
            evidence = truncate_to_max_bytes(
                f"Pre-flight safety validation blocked navigation: {sanitized_err}",
                exec_budget.max_evidence_bytes,
                marker=f" [EVIDENCE TRUNCATED: max_evidence_bytes ({exec_budget.max_evidence_bytes}) reached]",
            )
            return BrowserConfirmationResult(
                success=False,
                is_confirmed=False,
                outcome="BLOCKED",
                errors=[f"Safety check failed: {sanitized_err}"],
                evidence_summary=evidence,
            )

        # 2. Execution Setup
        start_mono = time.monotonic()
        deadline = start_mono + exec_budget.max_timeout_seconds

        def remaining_budget_ms() -> int:
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError(f"Overall browser execution deadline of {exec_budget.max_timeout_seconds:.1f}s exceeded.")
            return max(100, int(rem * 1000))

        spa_observer = BrowserSpaObserver(
            max_routes=exec_budget.max_routes,
            max_console=exec_budget.max_console_messages,
            max_requests=exec_budget.max_requests,
            max_evidence_bytes=exec_budget.max_evidence_bytes,
        )
        policy = BrowserNetworkPolicy(
            scope_engine=self.scope_engine,
            scope_validator=self.scope_validator,
            budget=exec_budget,
            observer=spa_observer,
            route_fulfill_handler=self.route_fulfill_handler,
            allow_websockets=self.allow_websockets,
        )
        dialog_events: List[Dict[str, str]] = []

        try:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Overall browser execution deadline of {exec_budget.max_timeout_seconds:.1f}s exceeded prior to initialization.")

            from playwright.sync_api import sync_playwright

            with sync_playwright() as pw:
                rem_session_timeout = max(0.5, deadline - time.monotonic())
                with BrowserSessionManager(
                    pw,
                    timeout=rem_session_timeout,
                    scope_engine=self.scope_engine,
                    scope_validator=self.scope_validator,
                    enable_egress_proxy=self.enable_egress_proxy,
                    allow_websockets=self.allow_websockets,
                    network_policy=policy,
                    browser_type=self.browser_type,
                ) as session:
                    context = session.context
                    page = session.page

                    # Centralized network safety policy attached prior to page creation;
                    # idempotent call guarantees coverage even for custom session callers
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
                    nav_timeout_ms = remaining_budget_ms()
                    page.goto(
                        target_url,
                        timeout=nav_timeout_ms,
                        wait_until="domcontentloaded",
                    )

                    # Bounded wait
                    rem_wait_ms = int((deadline - time.monotonic()) * 1000)
                    if rem_wait_ms <= 0:
                        raise TimeoutError(f"Overall browser execution deadline of {exec_budget.max_timeout_seconds:.1f}s exceeded during navigation.")
                    wait_ms = min(500, rem_wait_ms)
                    page.wait_for_timeout(wait_ms)

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

            # Check deadline before final evaluation
            if time.monotonic() > deadline:
                raise TimeoutError(f"Overall browser execution deadline of {exec_budget.max_timeout_seconds:.1f}s exceeded after session teardown.")

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
            if spa_observer.evidence_truncated:
                eval_res.evidence_summary = truncate_to_max_bytes(
                    eval_res.evidence_summary,
                    exec_budget.max_evidence_bytes,
                    marker=f" [EVIDENCE TRUNCATED: max_evidence_bytes ({exec_budget.max_evidence_bytes}) reached]",
                )
            else:
                eval_res.evidence_summary = truncate_to_max_bytes(
                    eval_res.evidence_summary,
                    exec_budget.max_evidence_bytes,
                    marker="",
                )
            return eval_res

        except Exception as e:
            err_msg = sanitize_sensitive_data(str(e))
            if isinstance(e, BrowserSecurityPolicyError):
                outcome = "BLOCKED"
                evidence = f"Browser execution blocked: mandatory security policy initialization failed: {err_msg}"
            elif "timeout" in err_msg.lower() or isinstance(e, TimeoutError):
                outcome = "TIMEOUT"
                evidence = f"Browser execution exception (TIMEOUT): {err_msg}"
            else:
                outcome = "INCONCLUSIVE"
                evidence = f"Browser execution exception ({outcome}): {err_msg}"

            if spa_observer.evidence_truncated:
                evidence = truncate_to_max_bytes(
                    evidence,
                    exec_budget.max_evidence_bytes,
                    marker=f" [EVIDENCE TRUNCATED: max_evidence_bytes ({exec_budget.max_evidence_bytes}) reached]",
                )
            else:
                evidence = truncate_to_max_bytes(
                    evidence,
                    exec_budget.max_evidence_bytes,
                    marker="",
                )

            return BrowserConfirmationResult(
                success=False,
                is_confirmed=False,
                outcome=outcome,
                errors=[err_msg],
                spa_summary=spa_observer.get_summary(),
                evidence_summary=evidence,
            )
