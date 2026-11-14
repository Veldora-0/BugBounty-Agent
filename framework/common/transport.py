"""
Safe HTTP Transport and Destination-IP Pinning for BugBounty-Agent.

Provides PinnedHTTPConnection, PinnedHTTPSConnection, PinnedHTTPHandler,
and PinnedHTTPSHandler to eliminate DNS rebinding (TOCTOU) while maintaining
TLS SNI, certificate chain verification, Host header preservation, and
bounded fallback across verified candidate IPv4 and IPv6 addresses.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union
import urllib.request


def parse_alternate_ip(host_or_ip: str) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    """
    Parses an IP address from standard or alternate representations.
    Supports:
    - Standard IPv4 dotted decimal ('127.0.0.1')
    - Standard IPv6 and bracketed IPv6 ('::1', '[::1]', '::ffff:127.0.0.1')
    - Single integer scalar IPv4 in decimal, hex, or octal ('2130706433', '0x7f000001', '017700000001')
    - Dotted IPv4 with hex, octal, or mixed parts ('0x7f.0.0.1', '0177.0.0.1', '0177.0.0.0x1')
    - 2-part and 3-part inet_aton notation ('127.1' -> '127.0.0.1', '127.0.1' -> '127.0.0.1')
    - Bracketed or mapped IPv6 with alternate embedded IPv4 ('[::ffff:0x7f000001]')

    Returns an ipaddress.IPv4Address or ipaddress.IPv6Address, or None if the input is a domain name or invalid.
    """
    if not host_or_ip or not isinstance(host_or_ip, str):
        return None

    clean = host_or_ip.strip().strip("[]").rstrip(".")
    if not clean:
        return None

    # Check direct standard representation
    try:
        return ipaddress.ip_address(clean)
    except ValueError:
        pass

    # Check IPv4-mapped IPv6 with alternate IPv4 representation
    lower_clean = clean.lower()
    if lower_clean.startswith("::ffff:"):
        sub = lower_clean[7:]
        parsed_sub = parse_alternate_ip(sub)
        if isinstance(parsed_sub, ipaddress.IPv4Address):
            return ipaddress.IPv6Address(f"::ffff:{parsed_sub}")
        return None

    # If it contains colons, it cannot be IPv4 alternate notation
    if ":" in clean:
        return None

    parts = clean.split(".")
    if 1 <= len(parts) <= 4:
        try:
            int_parts: List[int] = []
            for p in parts:
                p_str = p.strip()
                if not p_str:
                    return None
                if p_str.lower().startswith("0x"):
                    val = int(p_str, 16)
                elif p_str.startswith("0") and len(p_str) > 1:
                    val = int(p_str, 8)
                else:
                    val = int(p_str, 10)
                if val < 0:
                    return None
                int_parts.append(val)

            if len(int_parts) == 1:
                if int_parts[0] <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(int_parts[0])
            elif len(int_parts) == 2:
                if int_parts[0] <= 255 and int_parts[1] <= 0xFFFFFF:
                    val = (int_parts[0] << 24) | int_parts[1]
                    return ipaddress.IPv4Address(val)
            elif len(int_parts) == 3:
                if int_parts[0] <= 255 and int_parts[1] <= 255 and int_parts[2] <= 0xFFFF:
                    val = (int_parts[0] << 24) | (int_parts[1] << 16) | int_parts[2]
                    return ipaddress.IPv4Address(val)
            elif len(int_parts) == 4:
                if all(p <= 255 for p in int_parts):
                    val = (int_parts[0] << 24) | (int_parts[1] << 16) | (int_parts[2] << 8) | int_parts[3]
                    return ipaddress.IPv4Address(val)
        except (ValueError, OverflowError):
            pass

    return None


def _is_loopback_ip_literal(host: str) -> bool:
    """Returns True only if host is an explicit IP literal representing a loopback address."""
    clean = host.split(":")[0] if ":" in host and not host.startswith("[") else host
    clean = clean.strip("[]")
    alt = parse_alternate_ip(clean)
    if alt is not None:
        return alt.is_loopback
    return False


class PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection with bounded destination-IP pinning and fallback to prevent DNS rebinding."""

    def __init__(
        self,
        host: str,
        port: Optional[int] = None,
        pinned_ip: Optional[str] = None,
        pinned_ips: Optional[Sequence[str]] = None,
        max_fallback_attempts: int = 5,
        **kwargs: Any,
    ) -> None:
        if ":" in host and not host.startswith("["):
            self.original_host = host.split(":")[0]
        else:
            self.original_host = host

        if pinned_ips:
            self.pinned_ips: List[str] = list(pinned_ips)[:max_fallback_attempts]
        elif pinned_ip:
            self.pinned_ips = [pinned_ip]
        elif _is_loopback_ip_literal(self.original_host):
            alt = parse_alternate_ip(self.original_host)
            self.pinned_ips = [str(alt) if alt else self.original_host]
        else:
            self.pinned_ips = []

        self.pinned_ip = self.pinned_ips[0] if self.pinned_ips else pinned_ip
        self.max_fallback_attempts = max_fallback_attempts
        self.connected_ip: Optional[str] = None

        super().__init__(host, port, **kwargs)

    def connect(self) -> None:
        # SEC-01: Fail closed if no approved pinned destination IPs exist (zero DNS fallback)
        if not self.pinned_ips:
            raise OSError(
                f"No approved destination IP pinned for host '{self.original_host}': unpinned DNS resolution forbidden"
            )

        last_err: Optional[OSError] = None

        for ip in self.pinned_ips:
            try:
                self.sock = socket.create_connection(
                    (ip, self.port),
                    self.timeout,
                    self.source_address,
                )
                self.connected_ip = ip
                return
            except OSError as e:
                last_err = e

        self.sock = None
        if last_err:
            raise last_err
        raise OSError(f"Failed to connect to any resolved IP for {self.host}")


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection with bounded destination-IP pinning and fallback, retaining SNI and certificate verification."""

    def __init__(
        self,
        host: str,
        port: Optional[int] = None,
        pinned_ip: Optional[str] = None,
        pinned_ips: Optional[Sequence[str]] = None,
        max_fallback_attempts: int = 5,
        **kwargs: Any,
    ) -> None:
        if ":" in host and not host.startswith("["):
            self.original_host = host.split(":")[0]
        else:
            self.original_host = host

        if pinned_ips:
            self.pinned_ips: List[str] = list(pinned_ips)[:max_fallback_attempts]
        elif pinned_ip:
            self.pinned_ips = [pinned_ip]
        elif _is_loopback_ip_literal(self.original_host):
            alt = parse_alternate_ip(self.original_host)
            self.pinned_ips = [str(alt) if alt else self.original_host]
        else:
            self.pinned_ips = []

        self.pinned_ip = self.pinned_ips[0] if self.pinned_ips else pinned_ip
        self.max_fallback_attempts = max_fallback_attempts
        self.connected_ip: Optional[str] = None

        super().__init__(host, port, **kwargs)

    def connect(self) -> None:
        # SEC-01: Fail closed if no approved pinned destination IPs exist (zero DNS fallback)
        if not self.pinned_ips:
            raise OSError(
                f"No approved destination IP pinned for host '{self.original_host}': unpinned DNS resolution forbidden"
            )

        last_err: Optional[OSError] = None
        raw_sock: Optional[socket.socket] = None

        for ip in self.pinned_ips:
            try:
                raw_sock = socket.create_connection(
                    (ip, self.port),
                    self.timeout,
                    self.source_address,
                )
                self.connected_ip = ip
                break
            except OSError as e:
                last_err = e

        if raw_sock is None:
            self.sock = None
            if last_err:
                raise last_err
            raise OSError(f"Failed to connect to any resolved IP for {self.host}")

        server_hostname = self.original_host or self.host
        if ":" in server_hostname and not server_hostname.startswith("["):
            server_hostname = server_hostname.split(":")[0]

        # SEC-03: Never silently fall back to unencrypted socket if context omitted
        ctx = self._context
        if ctx is None:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

        # SEC-02: Wrap in TLS and ensure raw_sock cleanup on failure
        try:
            self.sock = ctx.wrap_socket(
                raw_sock,
                server_hostname=server_hostname,
            )
        except Exception:
            self.sock = None
            try:
                raw_sock.close()
            except Exception:
                pass
            raise


class PinnedHTTPHandler(urllib.request.HTTPHandler):
    """Handler routing HTTP requests through PinnedHTTPConnection with bounded fallback."""

    def __init__(self, ip_map: Dict[str, Union[str, Sequence[str]]], debuglevel: int = 0) -> None:
        super().__init__(debuglevel=debuglevel)
        self.ip_map = ip_map

    def http_open(self, req: urllib.request.Request) -> Any:
        def connection_factory(host: str, **kwargs: Any) -> http.client.HTTPConnection:
            clean_host = host.split(":")[0] if ":" in host and not host.startswith("[") else host
            entry = self.ip_map.get(clean_host.lower())
            if isinstance(entry, (list, tuple)):
                pinned_ips = list(entry)
            elif isinstance(entry, str):
                pinned_ips = [entry] if entry else []
            else:
                pinned_ips = []
            pinned_ip = pinned_ips[0] if pinned_ips else None
            return PinnedHTTPConnection(host, pinned_ip=pinned_ip, pinned_ips=pinned_ips, **kwargs)
        return self.do_open(connection_factory, req)


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """Handler routing HTTPS requests through PinnedHTTPSConnection with bounded fallback."""

    def __init__(
        self,
        ip_map: Dict[str, Union[str, Sequence[str]]],
        context: Optional[ssl.SSLContext] = None,
        debuglevel: int = 0,
        check_hostname: Optional[bool] = None,
    ) -> None:
        super().__init__(debuglevel=debuglevel, context=context, check_hostname=check_hostname)
        self.ip_map = ip_map

    def https_open(self, req: urllib.request.Request) -> Any:
        def connection_factory(host: str, **kwargs: Any) -> http.client.HTTPSConnection:
            clean_host = host.split(":")[0] if ":" in host and not host.startswith("[") else host
            entry = self.ip_map.get(clean_host.lower())
            if isinstance(entry, (list, tuple)):
                pinned_ips = list(entry)
            elif isinstance(entry, str):
                pinned_ips = [entry] if entry else []
            else:
                pinned_ips = []
            pinned_ip = pinned_ips[0] if pinned_ips else None
            return PinnedHTTPSConnection(
                host,
                pinned_ip=pinned_ip,
                pinned_ips=pinned_ips,
                context=self._context,
                check_hostname=self._check_hostname,
                **kwargs,
            )
        return self.do_open(connection_factory, req)


# Comprehensive IP ranges for SSRF prevention
PRIVATE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / Cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # Carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),   # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"), # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),    # Multicast
    ipaddress.ip_network("240.0.0.0/4"),    # Reserved
    ipaddress.ip_network("::1/128"),        # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),       # IPv6 unique-local
    ipaddress.ip_network("fe80::/10"),      # IPv6 link-local
]


def is_ssrf_prohibited_ip(ip_input: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> Tuple[bool, str]:
    """
    Evaluates whether an IP address belongs to private, loopback, link-local,
    reserved, or IPv4-mapped private address space.
    """
    if isinstance(ip_input, str):
        ip_obj = parse_alternate_ip(ip_input)
        if ip_obj is None:
            try:
                ip_obj = ipaddress.ip_address(ip_input)
            except ValueError:
                return False, ""
    else:
        ip_obj = ip_input

    # Check unspecified address (0.0.0.0 or ::)
    if ip_obj.is_unspecified:
        return True, "Unspecified address range"

    # Check IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        mapped = ip_obj.ipv4_mapped
        is_bad, reason = is_ssrf_prohibited_ip(mapped)
        if is_bad:
            return True, f"IPv4-mapped {mapped} is prohibited ({reason})"

    if ip_obj.is_loopback:
        return True, "Loopback address range"
    if ip_obj.is_private:
        return True, "Private address range"
    if ip_obj.is_link_local:
        return True, "Link-local address range"
    if ip_obj.is_reserved:
        return True, "Reserved address range"
    if ip_obj.is_multicast:
        return True, "Multicast address range"

    for net in PRIVATE_NETWORKS:
        if ip_obj in net:
            return True, f"Matched forbidden network {net}"

    return False, ""


class ScopeViolationError(ValueError):
    """Raised when a request target falls outside authorized scope."""
    pass


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    HTTP redirect handler that enforces scope, anti-SSRF policies, protocol downgrade prevention,
    request limits, global byte budget ceilings, and destination-IP pinning on each redirection hop.
    """

    def __init__(
        self,
        check_scope_fn: Callable[[str], Any],
        ip_map: Optional[Dict[str, Any]] = None,
        max_redirects: int = 5,
        original_url: Optional[str] = None,
        engine: Optional[Any] = None,
    ):
        super().__init__()
        self.check_scope_fn = check_scope_fn
        self.ip_map = ip_map if ip_map is not None else {}
        self.max_redirects = max_redirects
        self.redirect_count = 0
        self.current_url = original_url
        self.engine = engine

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        from urllib.parse import urlparse

        self.redirect_count += 1
        if self.redirect_count > self.max_redirects:
            raise ScopeViolationError(f"Too many redirects (exceeded maximum of {self.max_redirects})")

        # Validate URL input
        if not newurl or not isinstance(newurl, str):
            raise ScopeViolationError(f"Invalid redirect target URL: {newurl}")

        parsed_new = urlparse(newurl)
        new_scheme = (parsed_new.scheme or "").lower()
        if new_scheme not in ("http", "https"):
            raise ScopeViolationError(f"Redirect to unsupported scheme: {new_scheme}")

        # Determine original scheme for protocol downgrade verification
        orig_url = None
        if req is not None:
            if hasattr(req, "get_full_url"):
                orig_url = req.get_full_url()
            elif isinstance(req, str):
                orig_url = req
            else:
                raise ScopeViolationError(f"Unexpected request object type in redirect handler: {type(req).__name__}")
        elif self.current_url:
            orig_url = self.current_url

        if not orig_url:
            raise ScopeViolationError("Missing request context in redirect handler: protocol downgrade cannot be verified")

        orig_scheme = urlparse(orig_url).scheme.lower()
        if orig_scheme == "https" and new_scheme == "http":
            raise ScopeViolationError("Protocol downgrade from HTTPS to HTTP forbidden")

        # Request count and byte budget enforcement during redirect hop
        if self.engine is not None:
            if hasattr(self.engine, "request_count") and hasattr(self.engine, "policy"):
                max_reqs = getattr(self.engine.policy, "max_requests_per_program", 200)
                if self.engine.request_count >= max_reqs:
                    raise ScopeViolationError(
                        f"Program request budget exhausted during redirect ({self.engine.request_count}/{max_reqs})"
                    )
                self.engine.request_count += 1

            if hasattr(self.engine, "total_bytes_transferred") and hasattr(self.engine, "policy"):
                max_bytes = getattr(self.engine.policy, "max_total_bytes", 10 * 1024 * 1024)
                effective_transferred = max(
                    getattr(self.engine, "total_bytes_transferred", 0),
                    getattr(self.engine, "total_bytes", 0),
                )
                if effective_transferred >= max_bytes:
                    raise ScopeViolationError(
                        f"Global byte budget exhausted during redirect ({effective_transferred}/{max_bytes})"
                    )

        # Revalidate redirect destination against scope and anti-SSRF rules; obtain pinned IP(s)
        pinned = self.check_scope_fn(newurl)
        new_host = (parsed_new.hostname or "").lower()
        if new_host and pinned:
            self.ip_map[new_host] = pinned

        # Track current URL for subsequent redirect hops
        self.current_url = newurl

        if req is None or isinstance(req, str):
            return urllib.request.Request(newurl)

        return super().redirect_request(req, fp, code, msg, headers, newurl)


def safe_fetch_url(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[Union[str, bytes]] = None,
    timeout: float = 5.0,
    max_bytes: Optional[int] = None,
    scope_engine: Optional[Any] = None,
    custom_ssl_context: Optional[ssl.SSLContext] = None,
    max_redirects: int = 5,
) -> Optional[Dict[str, Any]]:
    """
    Executes a bounded, secure HTTP/HTTPS request through pinned transport.
    Validates scope, blocks SSRF to private/loopback/metadata destinations,
    validates redirects, prevents protocol downgrade, and enforces strict TLS verification.
    """
    import os
    from urllib.parse import urlparse

    if not url or not isinstance(url, str):
        return None

    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return None

    host = (parsed.hostname or "").lower()
    if not host:
        return None

    port = parsed.port or (443 if scheme == "https" else 80)

    # Fail closed if scope_engine is provided and target is not in scope
    if scope_engine is not None:
        dec = scope_engine.check(url)
        if getattr(dec, "status", None) != "IN_SCOPE":
            return None

    # Anti-SSRF hostname checks
    metadata_hosts = {
        "localhost",
        "169.254.169.254",
        "instance-data",
        "metadata.google.internal",
    }
    if host in metadata_hosts or host.endswith(".metadata.google.internal"):
        return None

    alt_ip = parse_alternate_ip(host)
    if alt_ip is not None:
        bad, _ = is_ssrf_prohibited_ip(alt_ip)
        if bad:
            return None
        pinned_ips = [str(alt_ip)]
    else:
        try:
            addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            candidate_ips: List[str] = []
            for _, _, _, _, sa in addr_info:
                c_ip = sa[0]
                if c_ip not in candidate_ips:
                    candidate_ips.append(c_ip)
            for c_ip in candidate_ips:
                cand_obj = parse_alternate_ip(c_ip) or ipaddress.ip_address(c_ip)
                bad, _ = is_ssrf_prohibited_ip(cand_obj)
                if bad:
                    return None
            pinned_ips = candidate_ips
        except (socket.gaierror, OSError):
            return None

    if not pinned_ips:
        return None

    ip_map: Dict[str, Any] = {host: pinned_ips}

    def check_scope_redirect(new_url: str) -> List[str]:
        if scope_engine is not None:
            r_dec = scope_engine.check(new_url)
            if getattr(r_dec, "status", None) != "IN_SCOPE":
                raise ScopeViolationError(f"Redirect target '{new_url}' is OUT_OF_SCOPE")
        r_p = urlparse(new_url)
        r_h = (r_p.hostname or "").lower()
        r_pt = r_p.port or (443 if r_p.scheme == "https" else 80)
        if r_h in metadata_hosts or r_h.endswith(".metadata.google.internal"):
            raise ScopeViolationError(f"Redirect target '{r_h}' is prohibited")
        r_alt = parse_alternate_ip(r_h)
        if r_alt is not None:
            r_bad, r_reason = is_ssrf_prohibited_ip(r_alt)
            if r_bad:
                raise ScopeViolationError(f"Redirect host '{r_h}' prohibited: {r_reason}")
            return [str(r_alt)]
        r_ai = socket.getaddrinfo(r_h, r_pt, socket.AF_UNSPEC, socket.SOCK_STREAM)
        r_cands: List[str] = []
        for _, _, _, _, r_sa in r_ai:
            if r_sa[0] not in r_cands:
                r_cands.append(r_sa[0])
        for r_ci in r_cands:
            r_co = parse_alternate_ip(r_ci) or ipaddress.ip_address(r_ci)
            r_bad, r_reason = is_ssrf_prohibited_ip(r_co)
            if r_bad:
                raise ScopeViolationError(f"Redirect host '{r_h}' resolves to prohibited {r_ci}")
        return r_cands

    req_headers = dict(headers or {})
    host_hdr = f"{host}:{port}" if (scheme == "http" and port != 80) or (scheme == "https" and port != 443) else host
    if "Host" not in req_headers and "host" not in req_headers:
        req_headers["Host"] = host_hdr

    payload_bytes = None
    if body is not None:
        payload_bytes = body.encode("utf-8") if isinstance(body, str) else body

    req = urllib.request.Request(
        url,
        data=payload_bytes,
        headers=req_headers,
        method=method.upper(),
    )

    ctx: Optional[ssl.SSLContext] = None
    if scheme == "https":
        if custom_ssl_context:
            ctx = custom_ssl_context
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ca_bundle = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
            if ca_bundle and os.path.isfile(ca_bundle):
                ctx.load_verify_locations(cafile=ca_bundle)

    redirect_handler = SafeRedirectHandler(
        check_scope_fn=check_scope_redirect,
        ip_map=ip_map,
        max_redirects=max_redirects,
        original_url=url,
    )
    http_handler = PinnedHTTPHandler(ip_map=ip_map)
    https_handler = PinnedHTTPSHandler(ip_map=ip_map, context=ctx, check_hostname=True if ctx else None)
    # urllib otherwise imports HTTP(S)_PROXY from the process environment. An
    # ambient proxy can resolve the destination independently of our pinned IP
    # map, so target traffic must connect directly through the vetted handlers.
    proxy_handler = urllib.request.ProxyHandler({})
    opener = urllib.request.build_opener(proxy_handler, redirect_handler, http_handler, https_handler)

    try:
        with opener.open(req, timeout=timeout) as resp:
            final_url = resp.geturl()
            if scope_engine is not None:
                dec = scope_engine.check(final_url)
                if getattr(dec, "status", None) != "IN_SCOPE":
                    return None
            status = resp.status
            res_headers = dict(resp.headers)
            raw = resp.read(max_bytes) if max_bytes is not None else resp.read()
            body_text = raw.decode("utf-8", errors="ignore")
            return {
                "status_code": status,
                "headers": res_headers,
                "body": body_text,
                "raw_bytes": raw,
                "final_url": final_url,
            }
    except Exception:
        return None
