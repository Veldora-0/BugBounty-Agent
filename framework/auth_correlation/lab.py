"""
Phase 21: LocalAuthCorrelationLab & Dedicated SimulationTransport.

Provides an isolated, in-process deterministic HTTP simulation server on loopback,
paired with SimulationTransport featuring hop-by-hop redirect isolation.
Strictly communicates with numeric 127.0.0.1:<lab_port> and rejects all external traffic.
"""

from __future__ import annotations

import http.client
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import threading
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

from framework.validation.request import ControlledRequest, ControlledResponse


class SecurityBoundaryViolationError(Exception):
    """Raised when SimulationTransport encounters non-loopback hosts, arbitrary ports, or redirect leaks."""
    pass


class SimulationTransport:
    """
    Dedicated simulation-only HTTP client with hop-by-hop redirect isolation.
    Communicates strictly with numeric 127.0.0.1 on the exact active lab port.
    Rejects localhost, IPv6 loopback, arbitrary ports, external hosts, and redirect leaks.
    """
    MAX_REDIRECT_HOPS = 3

    def __init__(self, lab_port: int, timeout: float = 5.0, allow_redirects: bool = True):
        if isinstance(lab_port, bool) or not isinstance(lab_port, int) or lab_port <= 0 or lab_port > 65535:
            raise SecurityBoundaryViolationError("Invalid lab port parameter")
        self.lab_port = lab_port
        self.timeout = timeout
        self.allow_redirects = allow_redirects

    def validate_target_url(self, url: str) -> None:
        """Validates target at every hop before dispatching network packets."""
        parsed = urlparse(url)
        # 1. Require HTTP scheme strictly
        if parsed.scheme != "http":
            raise SecurityBoundaryViolationError("SimulationTransport requires strictly 'http' scheme")
        # 2. Require exact numeric 127.0.0.1 (rejects localhost, ::1, domain names)
        if parsed.hostname != "127.0.0.1":
            raise SecurityBoundaryViolationError(
                "SimulationTransport rejected target host. "
                "Only exact numeric '127.0.0.1' is permitted. "
                "'localhost', IPv6 loopback, and external hosts are strictly prohibited."
            )
        # 3. Require exact active lab port
        if parsed.port != self.lab_port:
            raise SecurityBoundaryViolationError(
                f"SimulationTransport rejected port. "
                f"Target port must strictly match active lab port {self.lab_port}."
            )

    def _raw_dispatch(self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> Tuple[int, Dict[str, str], bytes]:
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        conn = http.client.HTTPConnection("127.0.0.1", self.lab_port, timeout=self.timeout)
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            resp_headers = {k: v for k, v in resp.getheaders()}
            resp_bytes = resp.read()
            return resp.status, resp_headers, resp_bytes
        finally:
            conn.close()

    def send_request(self, request_or_method: Any, url: Optional[str] = None, **kwargs) -> ControlledResponse:
        """Dispatches request with hop-by-hop redirect verification up to 3 hops."""
        if isinstance(request_or_method, ControlledRequest):
            req = request_or_method
            current_method = req.method
            current_url = req.url
            headers = dict(req.headers)
            body = req.build_body_bytes()
        else:
            current_method = str(request_or_method)
            current_url = str(url)
            headers = kwargs.get("headers", {})
            body = kwargs.get("body")

        hops = 0
        while True:
            if current_url.startswith("/"):
                current_url = f"http://127.0.0.1:{self.lab_port}{current_url}"
            self.validate_target_url(current_url)
            status, resp_headers, resp_bytes = self._raw_dispatch(current_method, current_url, headers, body)

            # Redirect handling
            if status in (301, 302, 303, 307, 308) and self.allow_redirects:
                hops += 1
                if hops > self.MAX_REDIRECT_HOPS:
                    raise SecurityBoundaryViolationError("SimulationTransport exceeded maximum redirect hop limit")

                location = resp_headers.get("Location") or resp_headers.get("location")
                if not location:
                    return ControlledResponse(status_code=status, headers=resp_headers, body=resp_bytes)

                redirect_url = urljoin(current_url, location)
                # Hop-by-hop destination validation BEFORE next request
                self.validate_target_url(redirect_url)

                current_url = redirect_url
                if status in (301, 302, 303) and current_method != "HEAD":
                    current_method = "GET"
                    body = None
                continue

            return ControlledResponse(status_code=status, headers=resp_headers, body=resp_bytes)

    execute_request = send_request


class _LabRequestHandler(BaseHTTPRequestHandler):
    """Deterministic HTTP handler simulating all 6 Phase 21 lab scenarios."""

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Suppress console logging during test runs

    def do_GET(self) -> None:
        self._handle_request("GET")

    def do_POST(self) -> None:
        self._handle_request("POST")

    def do_HEAD(self) -> None:
        self._handle_request("HEAD")

    def _handle_request(self, method: str) -> None:
        path = self.path
        auth_header = self.headers.get("Authorization", "")

        # ----------------------------------------------------------------------
        # API v1 routes for preflight health gating and candidate discovery
        # ----------------------------------------------------------------------
        if path.startswith("/api/v1/"):
            if auth_header:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "ok", "user": "authorized", "tenant_id": "tenant_a"}')
                return
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Unauthorized"}')
                return

        # ----------------------------------------------------------------------
        # SCEN-01: Expired session false-negative prevention
        # ----------------------------------------------------------------------
        if path.startswith("/scen01/profile"):
            if "expired_token_b" in auth_header:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Session token expired"}')
                return
            elif "valid_token_a" in auth_header:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"user_id": "usr_a", "role": "USER", "name": "Alice"}')
                return
            else:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b'{"error": "Unauthorized"}')
                return

        # ----------------------------------------------------------------------
        # SCEN-02: Post-logout resource persistence
        # ----------------------------------------------------------------------
        if path.startswith("/scen02/invoices/101"):
            # Target server continues accepting revoked token!
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"invoice_id": "101", "amount": 450.00, "customer": "Alice Corp"}')
            return

        # ----------------------------------------------------------------------
        # SCEN-03: Post-password-change invalidation failure
        # ----------------------------------------------------------------------
        if path.startswith("/scen03/user/settings"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"settings_id": "set_99", "email": "bob@corp.local", "api_enabled": true}')
            return

        # ----------------------------------------------------------------------
        # SCEN-04: Pre-MFA sensitive data exposure
        # ----------------------------------------------------------------------
        if path.startswith("/scen04/profile"):
            if "pre_mfa_token" in auth_header:
                # Exposes protected user data without MFA challenge!
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"user_id": "usr_pre_mfa", "ssn": "123-45-6789", "role": "FINANCE_ADMIN"}')
                return
            elif "fully_auth_token" in auth_header:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"user_id": "usr_pre_mfa", "ssn": "123-45-6789", "role": "FINANCE_ADMIN"}')
                return

        # ----------------------------------------------------------------------
        # SCEN-05: Multi-tenant route desynchronization
        # ----------------------------------------------------------------------
        if path.startswith("/scen05/tenants/"):
            # Route: /scen05/tenants/{tenant_id}/invoices/101
            # Accepts Tenant A's token when querying Tenant B!
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b'{"tenant_id": "tenant_b", "invoice": 101, "total": 12500.00}')
            return

        # ----------------------------------------------------------------------
        # SCEN-06: Multi-tenant header desync with cache hit
        # ----------------------------------------------------------------------
        if path.startswith("/scen06/data"):
            if "_bb_cb=" in path:
                # Cache-busted request hits true backend: 403 Forbidden!
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b'{"error": "Forbidden: cross-tenant access denied"}')
                return
            else:
                # Normal request returns cached 200 OK from proxy
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("CF-Cache-Status", "HIT")
                self.send_header("Age", "120")
                self.end_headers()
                self.wfile.write(b'{"tenant_id": "tenant_b", "data": "cached_report"}')
                return

        # Default redirect for testing redirect hop limits
        if path.startswith("/redirect/hop/"):
            hop_num = int(path.split("/")[-1])
            if hop_num < 5:
                self.send_response(302)
                self.send_header("Location", f"/redirect/hop/{hop_num + 1}")
                self.end_headers()
                return
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Redirect finished")
                return

        if path == "/redirect/external":
            self.send_response(302)
            self.send_header("Location", "https://attacker.evil.local/steal")
            self.end_headers()
            return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b'{"error": "Not Found"}')


class LocalAuthCorrelationLab:
    """In-process simulation lab hosting deterministic test scenarios on 127.0.0.1."""

    SCENARIOS: List[str] = [
        "SCEN-01: Valid Resource vs Public Landing Soft-404 Differential",
        "SCEN-02: Mode A Observation Post-Revocation Valid Baseline Persistence",
        "SCEN-03: Mode B Differential Session Revocation Resource Probe",
        "SCEN-04: Pre-MFA Partially Authenticated Privilege Escalation",
        "SCEN-05: Multi-Tenant Route Path Cross-Channel Desynchronization",
        "SCEN-06: Multi-Tenant Header Desync with Cache-Busting Validation",
    ]

    @classmethod
    def list_scenarios(cls) -> List[str]:
        """Returns the list of deterministic scenarios supported by the lab."""
        return list(cls.SCENARIOS)

    def __init__(self):
        self.server: Optional[HTTPServer] = None
        self.port: int = 0
        self.thread: Optional[threading.Thread] = None

    def start(self) -> int:
        """Starts HTTP server on loopback with ephemeral port."""
        self.server = HTTPServer(("127.0.0.1", 0), _LabRequestHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self.port

    def stop(self) -> None:
        """Stops server and closes sockets cleanly."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self.thread:
            self.thread.join(timeout=2.0)
            self.thread = None

    def get_transport(self) -> SimulationTransport:
        """Instantiates dedicated SimulationTransport bound strictly to this lab."""
        if self.port == 0:
            raise RuntimeError("Lab must be started before retrieving transport")
        return SimulationTransport(lab_port=self.port)
