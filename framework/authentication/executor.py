"""
Bounded Request Executor for Authentication Security Testing (Phase 14.1).

Enforces strict timeout caps, response size limits, anti-SSRF protections,
redirect scope re-verification, and rate limiting using standard library urllib.
Zero external dependencies; completely isolated from third-party engines.
"""

from __future__ import annotations

from datetime import datetime, timezone
import http.client
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
    ipaddress.ip_network("::ffff:0:0/96"),   # IPv4-mapped IPv6 block
]


def check_single_ip_prohibited(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
    """Evaluates whether an IP address (with IPv4-mapped IPv6 unmapping) is in prohibited networks."""
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        unmapped = ip_obj.ipv4_mapped
        for net in PROHIBITED_IP_NETWORKS:
            try:
                if unmapped in net:
                    return True, f"IPv4-mapped IP {ip_obj} ({unmapped}) in prohibited network {net}"
            except TypeError:
                continue
    for net in PROHIBITED_IP_NETWORKS:
        try:
            if ip_obj in net:
                return True, f"IP {ip_obj} in prohibited network {net}"
        except TypeError:
            continue
    return False, ""


def is_ssrf_prohibited_host(host: str) -> Tuple[bool, str]:
    """
    Checks if a hostname or IP address resolves to prohibited private, loopback,
    link-local, cloud metadata, or reserved networks.
    """
    clean_host = host.strip().lower()
    if not clean_host:
        return True, "Empty host"

    # Direct name checks and cloud metadata
    metadata_hosts = {
        "localhost",
        "metadata.google.internal",
        "instance-data",
        "169.254.169.254",
        "169.254.169.123",
    }
    if clean_host in metadata_hosts or clean_host.endswith(".metadata.google.internal"):
        return True, f"Prohibited hostname: {clean_host}"

    try:
        ip_obj = ipaddress.ip_address(clean_host)
        return check_single_ip_prohibited(ip_obj)
    except ValueError:
        pass

    # Hostname resolution check
    try:
        addr_info = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _, _, _, _, sockaddr in addr_info:
            resolved_ip_str = sockaddr[0]
            try:
                resolved_ip = ipaddress.ip_address(resolved_ip_str)
                prohibited, reason = check_single_ip_prohibited(resolved_ip)
                if prohibited:
                    return True, f"Host {clean_host} resolves to prohibited IP {resolved_ip_str}: {reason}"
            except ValueError:
                pass
    except (socket.gaierror, OSError):
        # If unresolvable, let socket open attempt fail naturally
        pass

    return False, ""


class PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection with destination-IP pinning to prevent DNS rebinding."""

    def __init__(self, host: str, port: Optional[int] = None, pinned_ip: Optional[str] = None, **kwargs: Any) -> None:
        self.pinned_ip = pinned_ip
        if ":" in host and not host.startswith("["):
            self.original_host = host.split(":")[0]
        else:
            self.original_host = host
        super().__init__(host, port, **kwargs)

    def connect(self) -> None:
        target_ip = self.pinned_ip if self.pinned_ip else self.host
        self.sock = socket.create_connection(
            (target_ip, self.port),
            self.timeout,
            self.source_address,
        )


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection with destination-IP pinning, retaining SNI and certificate verification."""

    def __init__(self, host: str, port: Optional[int] = None, pinned_ip: Optional[str] = None, **kwargs: Any) -> None:
        self.pinned_ip = pinned_ip
        if ":" in host and not host.startswith("["):
            self.original_host = host.split(":")[0]
        else:
            self.original_host = host
        super().__init__(host, port, **kwargs)

    def connect(self) -> None:
        target_ip = self.pinned_ip if self.pinned_ip else self.host
        raw_sock = socket.create_connection(
            (target_ip, self.port),
            self.timeout,
            self.source_address,
        )
        server_hostname = self.original_host or self.host
        if ":" in server_hostname and not server_hostname.startswith("["):
            server_hostname = server_hostname.split(":")[0]

        if self._context:
            self.sock = self._context.wrap_socket(
                raw_sock,
                server_hostname=server_hostname,
            )
        else:
            self.sock = raw_sock


class PinnedHTTPHandler(urllib.request.HTTPHandler):
    """Handler routing HTTP requests through PinnedHTTPConnection."""

    def __init__(self, ip_map: Dict[str, str], debuglevel: int = 0) -> None:
        super().__init__(debuglevel=debuglevel)
        self.ip_map = ip_map

    def http_open(self, req: urllib.request.Request) -> Any:
        def connection_factory(host: str, **kwargs: Any) -> http.client.HTTPConnection:
            clean_host = host.split(":")[0] if ":" in host and not host.startswith("[") else host
            pinned_ip = self.ip_map.get(clean_host.lower())
            return PinnedHTTPConnection(host, pinned_ip=pinned_ip, **kwargs)
        return self.do_open(connection_factory, req)


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """Handler routing HTTPS requests through PinnedHTTPSConnection."""

    def __init__(
        self,
        ip_map: Dict[str, str],
        context: Optional[ssl.SSLContext] = None,
        debuglevel: int = 0,
        check_hostname: Optional[bool] = None,
    ) -> None:
        super().__init__(debuglevel=debuglevel, context=context, check_hostname=check_hostname)
        self.ip_map = ip_map

    def https_open(self, req: urllib.request.Request) -> Any:
        def connection_factory(host: str, **kwargs: Any) -> http.client.HTTPSConnection:
            clean_host = host.split(":")[0] if ":" in host and not host.startswith("[") else host
            pinned_ip = self.ip_map.get(clean_host.lower())
            return PinnedHTTPSConnection(host, pinned_ip=pinned_ip, context=self._context, check_hostname=self._check_hostname, **kwargs)
        return self.do_open(connection_factory, req)


class AuthSafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    HTTP redirect handler that enforces scope, anti-SSRF policies, protocol downgrade prevention,
    and destination-IP pinning on each redirection hop.
    """

    def __init__(self, scope_checker: Callable[[str], bool], ip_map: Optional[Dict[str, str]] = None, max_redirects: int = 5):
        super().__init__()
        self.scope_checker = scope_checker
        self.ip_map = ip_map if ip_map is not None else {}
        self.max_redirects = max_redirects
        self.redirect_count = 0

    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Optional[urllib.request.Request]:
        self.redirect_count += 1
        if self.redirect_count > self.max_redirects:
            raise urllib.error.HTTPError(newurl, code, f"Exceeded maximum redirects ({self.max_redirects})", headers, fp)

        # Validate URL scheme
        parsed_new = urllib.parse.urlparse(newurl)
        new_scheme = (parsed_new.scheme or "").lower()
        if new_scheme not in ("http", "https"):
            raise urllib.error.HTTPError(newurl, code, f"Redirect to unsupported scheme: {new_scheme}", headers, fp)

        # Prevent protocol downgrade (HTTPS -> HTTP)
        orig_scheme = urllib.parse.urlparse(req.get_full_url()).scheme.lower()
        if orig_scheme == "https" and new_scheme == "http":
            raise urllib.error.HTTPError(newurl, code, "Protocol downgrade from HTTPS to HTTP forbidden", headers, fp)

        # Enforce anti-SSRF on redirect host and pin IP
        host = (parsed_new.hostname or "").lower()
        port = parsed_new.port or (443 if new_scheme == "https" else 80)
        prohibited, reason = is_ssrf_prohibited_host(host)
        if prohibited:
            raise urllib.error.HTTPError(newurl, code, f"Redirect target host '{host}' is prohibited ({reason})", headers, fp)

        # Enforce scope check on target redirect URL
        if not self.scope_checker(newurl):
            raise urllib.error.HTTPError(newurl, code, f"Redirect target '{newurl}' is OUT_OF_SCOPE", headers, fp)

        # Resolve redirect destination to pin IP
        try:
            addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            candidate_ips = [sa[0] for _, _, _, _, sa in addr_info]
            for c_ip in candidate_ips:
                try:
                    ip_obj = ipaddress.ip_address(c_ip)
                    is_prohib, p_reason = check_single_ip_prohibited(ip_obj)
                    if is_prohib:
                        raise urllib.error.HTTPError(newurl, code, f"Redirect destination IP '{c_ip}' is prohibited: {p_reason}", headers, fp)
                except ValueError:
                    pass
            if candidate_ips:
                self.ip_map[host] = candidate_ips[0]
        except urllib.error.HTTPError:
            raise
        except Exception:
            # If resolution fails, let request open fail naturally
            pass

        return super().redirect_request(req, fp, code, msg, headers, newurl)


class BoundedAuthenticationExecutor:
    """
    Dispatches safe, bounded HTTP requests with strict timeouts, response size limits,
    anti-SSRF boundary enforcement, redirect validation, TLS certificate verification,
    destination-IP pinning, safe proxy bypassing, and credential sanitization.
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

        # Dry run: strictly zero socket connections, zero DNS resolution
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

        parsed = urllib.parse.urlparse(url)
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower()
        port = parsed.port or (443 if scheme == "https" else 80)

        # Validate scheme
        if scheme not in ("http", "https"):
            return {
                "success": False,
                "error": f"Unsupported scheme: {scheme}",
                "status_code": 0,
                "body": "",
                "evidence": None,
            }

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

        # Pre-resolve destination IP to pin connection and prevent DNS rebinding
        ip_map: Dict[str, str] = {}
        try:
            addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            candidate_ips = [sa[0] for _, _, _, _, sa in addr_info]
            if not candidate_ips:
                return {
                    "success": False,
                    "error": f"Could not resolve host '{host}'",
                    "status_code": 0,
                    "body": "",
                    "evidence": None,
                }
            for c_ip in candidate_ips:
                try:
                    ip_obj = ipaddress.ip_address(c_ip)
                    is_prohib, p_reason = check_single_ip_prohibited(ip_obj)
                    if is_prohib:
                        return {
                            "success": False,
                            "error": f"Target host '{host}' resolved to prohibited IP '{c_ip}': {p_reason}",
                            "status_code": 0,
                            "body": "",
                            "evidence": None,
                        }
                except ValueError:
                    pass
            ip_map[host] = candidate_ips[0]
        except (socket.gaierror, OSError) as e:
            return {
                "success": False,
                "error": f"DNS resolution failed for '{host}': {e}",
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

        # Prepare request headers including explicit Host
        host_header = f"{host}:{port}" if (scheme == "http" and port != 80) or (scheme == "https" and port != 443) else host
        req_headers = {
            "Host": host_header,
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

        # Build secure SSL context enforcing strict TLS verification
        ctx: Optional[ssl.SSLContext] = None
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ca_bundle = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
            if ca_bundle and os.path.isfile(ca_bundle):
                ctx.load_verify_locations(cafile=ca_bundle)

        redirect_handler = AuthSafeRedirectHandler(self.check_scope, ip_map=ip_map, max_redirects=5)
        proxy_handler = urllib.request.ProxyHandler({})  # Bypass unvetted ambient environment proxies
        handlers: List[Any] = [proxy_handler, redirect_handler]
        if scheme == "https":
            handlers.append(PinnedHTTPSHandler(ip_map=ip_map, context=ctx))
        else:
            handlers.append(PinnedHTTPHandler(ip_map=ip_map))

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
        except (ssl.SSLError, ssl.CertificateError) as se:
            evidence = AuthenticationEvidenceManager.record_evidence(
                endpoint=parsed.path or "/",
                method=method,
                status_code=0,
                request_summary=f"{method} {url}",
                response_summary=f"TLS verification failed: {se}",
                auth_state_before="UNVALIDATED",
                auth_state_after="TLS_ERROR",
            )
            return {
                "success": False,
                "error": f"TLS verification failed: {se}",
                "status_code": 0,
                "body": "",
                "evidence": evidence,
            }
        except urllib.error.URLError as ue:
            if isinstance(ue.reason, (ssl.SSLError, ssl.CertificateError)) or "certificate" in str(ue.reason).lower() or "ssl" in str(ue.reason).lower():
                evidence = AuthenticationEvidenceManager.record_evidence(
                    endpoint=parsed.path or "/",
                    method=method,
                    status_code=0,
                    request_summary=f"{method} {url}",
                    response_summary=f"TLS verification failed: {ue.reason}",
                    auth_state_before="UNVALIDATED",
                    auth_state_after="TLS_ERROR",
                )
                return {
                    "success": False,
                    "error": f"TLS verification failed: {ue.reason}",
                    "status_code": 0,
                    "body": "",
                    "evidence": evidence,
                }
            return {
                "success": False,
                "error": f"URL error: {ue.reason}",
                "status_code": 0,
                "body": "",
                "evidence": None,
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "status_code": 0,
                "body": "",
                "evidence": None,
            }

