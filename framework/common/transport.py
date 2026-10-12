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
from typing import Any, Dict, List, Optional, Sequence, Union
import urllib.request


def _is_loopback_ip_literal(host: str) -> bool:
    """Returns True only if host is an explicit IP literal representing a loopback address."""
    clean = host.split(":")[0] if ":" in host and not host.startswith("[") else host
    clean = clean.strip("[]")
    try:
        ip = ipaddress.ip_address(clean)
        return ip.is_loopback
    except ValueError:
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
            self.pinned_ips = [self.original_host]
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
            self.pinned_ips = [self.original_host]
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
