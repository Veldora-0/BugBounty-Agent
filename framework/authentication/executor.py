"""
Bounded Request Executor for Authentication Security Testing (Phase 14.1).

Enforces strict timeout caps, response size limits, anti-SSRF protections,
redirect scope re-verification, and rate limiting using standard library urllib.
Zero external dependencies; completely isolated from third-party engines.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import os
import socket
import ssl
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request

from framework.authentication.evidence import AuthenticationEvidenceManager
from framework.scope.engine import ScopeDecision, ScopeEngine, ScopeStatus


# Prohibited IP ranges for SSRF prevention
PROHIBITED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local / Cloud metadata (AWS, GCP, Azure)
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),   # Carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),     # Multicast
    ipaddress.ip_network("240.0.0.0/4"),     # Reserved
    ipaddress.ip_network("::1/128"),         # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),        # IPv6 unique-local
    ipaddress.ip_network("fe80::/10"),       # IPv6 link-local
]


def is_ssrf_prohibited_host(host: str) -> Tuple[bool, str]:
    """
    Checks if a hostname or IP address resolves to prohibited private, loopback,
    link-local, cloud metadata, or reserved networks.
    """
    clean_host = host.strip().lower()
    if not clean_host:
        return True, "Empty host"

    # Direct name checks
    if clean_host in ("localhost", "metadata.google.internal", "instance-data"):
        return True, f"Prohibited hostname: {clean_host}"

    try:
        ip_obj = ipaddress.ip_address(clean_host)
        is_ip = True
    except ValueError:
        ip_obj = None
        is_ip = False

    if is_ip and ip_obj is not None:
        for net in PROHIBITED_IP_NETWORKS:
            if ip_obj in net:
                return True, f"IP {clean_host} in prohibited network {net}"
        return False, ""

    # Hostname resolution check
    try:
        addr_info = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _, _, _, _, sockaddr in addr_info:
            resolved_ip_str = sockaddr[0]
            try:
                resolved_ip = ipaddress.ip_address(resolved_ip_str)
                for net in PROHIBITED_IP_NETWORKS:
                    if resolved_ip in net:
                        return True, f"Host {clean_host} resolves to prohibited IP {resolved_ip_str} ({net})"
            except ValueError:
                pass
    except (socket.gaierror, OSError):
        # If unresolvable, let socket open attempt fail naturally
        pass

    return False, ""


class AuthSafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    HTTP redirect handler that enforces scope and anti-SSRF policies on each redirection hop.
    """

    def __init__(self, scope_checker: Callable[[str], bool], max_redirects: int = 5):
        super().__init__()
        self.scope_checker = scope_checker
        self.max_redirects = max_redirects
        self.redirect_count = 0

    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Optional[urllib.request.Request]:
        self.redirect_count += 1
        if self.redirect_count > self.max_redirects:
            raise urllib.error.HTTPError(newurl, code, f"Exceeded maximum redirects ({self.max_redirects})", headers, fp)

        # Enforce scope check on target redirect URL
        if not self.scope_checker(newurl):
            raise urllib.error.HTTPError(newurl, code, f"Redirect target '{newurl}' is OUT_OF_SCOPE", headers, fp)

        # Enforce anti-SSRF on redirect host
        parsed = urllib.parse.urlparse(newurl)
        host = parsed.hostname or ""
        prohibited, reason = is_ssrf_prohibited_host(host)
        if prohibited:
            raise urllib.error.HTTPError(newurl, code, f"Redirect target host '{host}' is prohibited ({reason})", headers, fp)

        return super().redirect_request(req, fp, code, msg, headers, newurl)


class BoundedAuthenticationExecutor:
    """
    Dispatches safe, bounded HTTP requests with strict timeouts, response size limits,
    anti-SSRF boundary enforcement, redirect validation, and credential sanitization.
    """

    def __init__(
        self,
        scope_engine: Optional[ScopeEngine] = None,
        timeout: float = 8.0,
        max_response_bytes: int = 100 * 1024,  # 100 KB
        delay_seconds: float = 0.1,
        max_requests_per_endpoint: int = 5,
    ) -> None:
        self.scope_engine = scope_engine
        self.timeout = min(timeout, 10.0)  # capped at 10s
        self.max_response_bytes = max_response_bytes
        self.delay_seconds = delay_seconds
        self.max_requests_per_endpoint = max_requests_per_endpoint
        self.endpoint_counts: Dict[str, int] = {}
        self.total_requests = 0

    def check_scope(self, url: str) -> bool:
        """Evaluates whether URL is strictly in-scope."""
        if not self.scope_engine:
            return False
        decision = self.scope_engine.check(url)
        return decision.status == ScopeStatus.IN_SCOPE

    def execute_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes | str] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Executes a controlled HTTP request with safety enforcement.
        Returns a sanitized result dictionary containing status_code, body, and evidence.
        """
        method = method.upper()
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""

        # Scope verification
        if not self.check_scope(url):
            reason = "No scope engine configured" if not self.scope_engine else self.scope_engine.check(url).reason
            return {
                "success": False,
                "error": f"Target '{url}' is OUT_OF_SCOPE: {reason}",
                "status_code": 0,
                "body": "",
                "evidence": None,
            }

        # Anti-SSRF verification
        prohibited, reason = is_ssrf_prohibited_host(host)
        if prohibited:
            return {
                "success": False,
                "error": f"Target host '{host}' prohibited: {reason}",
                "status_code": 0,
                "body": "",
                "evidence": None,
            }

        # Endpoint budget check
        ep_key = f"{method} {parsed.path or '/'}"
        count = self.endpoint_counts.get(ep_key, 0)
        if count >= self.max_requests_per_endpoint:
            return {
                "success": False,
                "error": f"Request budget exhausted for {ep_key} ({count}/{self.max_requests_per_endpoint})",
                "status_code": 0,
                "body": "",
                "evidence": None,
            }

        # Dry run: log planned request and return without socket creation
        if dry_run:
            req_summary = f"{method} {url}"
            sanitized_req = AuthenticationEvidenceManager.sanitize(req_summary)
            return {
                "success": True,
                "status_code": 200,
                "body": "[DRY_RUN_NO_TRAFFIC]",
                "dry_run": True,
                "request_summary": sanitized_req,
                "evidence": None,
            }

        # Prepare request object
        req_headers = {
            "User-Agent": "BugBounty-Agent/1.1 (Authentication Security Engine)",
            "Accept": "application/json, text/html, */*",
        }
        if headers:
            req_headers.update(headers)

        payload_bytes: Optional[bytes] = None
        if data is not None:
            if isinstance(data, str):
                payload_bytes = data.encode("utf-8")
            else:
                payload_bytes = data

        req = urllib.request.Request(
            url,
            data=payload_bytes,
            headers=req_headers,
            method=method,
        )

        # Build SSL context
        ctx: Optional[ssl.SSLContext] = None
        if url.startswith("https://"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        redirect_handler = AuthSafeRedirectHandler(self.check_scope)
        handlers: List[Any] = [redirect_handler]
        if ctx:
            handlers.append(urllib.request.HTTPSHandler(context=ctx))

        opener = urllib.request.build_opener(*handlers)

        # Rate limiting delay
        if self.delay_seconds > 0:
            time.sleep(self.delay_seconds)

        self.endpoint_counts[ep_key] = count + 1
        self.total_requests += 1

        start_time = time.time()
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                elapsed = time.time() - start_time
                status_code = resp.status
                resp_headers = dict(resp.headers)
                raw_body = resp.read(self.max_response_bytes)
                body_str = raw_body.decode("utf-8", errors="replace")

                evidence = AuthenticationEvidenceManager.record_evidence(
                    endpoint=parsed.path or "/",
                    method=method,
                    status_code=status_code,
                    request_summary=f"{method} {url}\n{json.dumps(req_headers)}",
                    response_summary=f"HTTP/1.1 {status_code}\n{body_str[:500]}",
                    auth_state_before="UNVALIDATED",
                    auth_state_after="EVALUATED",
                )

                return {
                    "success": True,
                    "status_code": status_code,
                    "headers": resp_headers,
                    "body": body_str,
                    "elapsed_seconds": elapsed,
                    "evidence": evidence,
                }
        except urllib.error.HTTPError as he:
            elapsed = time.time() - start_time
            err_body = he.read(self.max_response_bytes).decode("utf-8", errors="replace") if hasattr(he, "read") else ""
            evidence = AuthenticationEvidenceManager.record_evidence(
                endpoint=parsed.path or "/",
                method=method,
                status_code=he.code,
                request_summary=f"{method} {url}",
                response_summary=f"HTTP/1.1 {he.code}\n{err_body[:500]}",
                auth_state_before="UNVALIDATED",
                auth_state_after="EVALUATED",
            )
            return {
                "success": True,
                "status_code": he.code,
                "headers": dict(he.headers) if hasattr(he, "headers") else {},
                "body": err_body,
                "elapsed_seconds": elapsed,
                "evidence": evidence,
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "status_code": 0,
                "body": "",
                "evidence": None,
            }
