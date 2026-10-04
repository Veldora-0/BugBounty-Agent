"""
Deterministic Local Security Lab Fixtures for SSRF & OOB Intelligence (Phase 9).

Simulates backend application behavior across 12 distinct SSRF and out-of-band scenarios:
1. Direct SSRF URL fetcher (server fetches canary URL and reflects content)
2. Blind SSRF fetcher (server triggers asynchronous background HTTP GET)
3. DNS-only resolver (server resolves canary hostname without making HTTP request)
4. Safe application (does not fetch external URLs)
5. Redirect-mediated fetcher (server follows 302 redirect to canary)
6. Browser-only URL interaction false positive (client browser triggered, not backend)
7. Stale OOB callback false positive (callback token from prior or expired test)
8. Duplicate callback scenario (multiple simultaneous OOB events)
9. Delayed callback (callback arrives during polling window)
10. Out-of-scope callback (callback from untracked host)
11. Private-address rejection by agent (anti-SSRF guard blocks private IPs)
12. Forbidden-scheme rejection (anti-SSRF guard blocks file://, gopher://, etc.)
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import parse_qsl, urlparse

from framework.ssrf.model import OobInteractionType
from framework.ssrf.provider import MockOobProvider
from framework.validation.request import ControlledRequest, ControlledResponse


class LocalSsrfLab:
    """
    Simulates vulnerable, defended, and edge-case backend endpoints for SSRF validation.
    Integrates directly with a MockOobProvider to trigger simulated network callbacks.
    """

    def __init__(self, oob_provider: Optional[MockOobProvider] = None):
        self.oob_provider = oob_provider or MockOobProvider(base_domain="oob.local")
        self.client_ip = "192.168.1.50"  # Simulated researcher/client IP
        self.server_ip = "203.0.113.88"  # Simulated target backend IP

    def dispatch(self, req: ControlledRequest) -> ControlledResponse:
        """
        Processes a ControlledRequest and simulates backend fetch and OOB behaviors.
        """
        parsed = urlparse(req.base_url)
        path = parsed.path
        q_params = dict(parse_qsl(parsed.query, keep_blank_values=True))

        # Extract target url parameter if present
        target_param_url = (
            q_params.get("url")
            or q_params.get("target")
            or q_params.get("dest")
            or q_params.get("image")
            or q_params.get("webhook")
            or ""
        )

        # Helper to extract canary token from URL
        canary_token = None
        if target_param_url:
            match = re.search(r"bb9-[a-zA-Z0-9_\-]+", target_param_url)
            if match:
                canary_token = match.group(0)

        # ---------------- Scenario 4: Safe Application ----------------
        if path == "/api/v1/safe-fetch" or "safe" in path:
            return ControlledResponse(
                status_code=200,
                headers={"content-type": "application/json"},
                body=json.dumps({"status": "ok", "message": "URL recorded safely without fetch"}),
                size_bytes=60,
                final_url=req.base_url,
            )

        # ---------------- Scenario 1: Direct SSRF Fetcher ----------------
        if path == "/api/v1/fetch" or path == "/proxy":
            if canary_token:
                # Trigger server-side HTTP callback
                self.oob_provider.simulate_interaction(
                    canary_token=canary_token,
                    protocol="HTTP",
                    source_ip=self.server_ip,
                    method="GET",
                    path="/",
                    headers={"User-Agent": "Backend-Fetcher/1.0", "X-Server-Env": "prod"},
                    interaction_type=OobInteractionType.HTTP_INTERACTION,
                )
                return ControlledResponse(
                    status_code=200,
                    headers={"content-type": "text/html"},
                    body=f"<html><body><h1>Fetched Content</h1><p>Remote content from {target_param_url}</p></body></html>",
                    size_bytes=100,
                    final_url=req.base_url,
                )
            return ControlledResponse(
                status_code=200,
                headers={"content-type": "application/json"},
                body=json.dumps({"status": "no_url"}),
                size_bytes=20,
                final_url=req.base_url,
            )

        # ---------------- Scenario 2: Blind SSRF Fetcher ----------------
        if path == "/api/v1/webhook/subscribe" or path == "/api/v1/async-import":
            if canary_token:
                # Asynchronously triggers OOB callback
                self.oob_provider.simulate_interaction(
                    canary_token=canary_token,
                    protocol="HTTP",
                    source_ip=self.server_ip,
                    method="POST",
                    path="/events",
                    headers={"User-Agent": "AsyncWorker/2.0"},
                    interaction_type=OobInteractionType.HTTP_INTERACTION,
                )
            return ControlledResponse(
                status_code=202,
                headers={"content-type": "application/json"},
                body=json.dumps({"status": "accepted", "job_id": "job-88123"}),
                size_bytes=45,
                final_url=req.base_url,
            )

        # ---------------- Scenario 3: DNS-Only Resolver ----------------
        if path == "/api/v1/resolve-preview" or "dns-only" in path:
            if canary_token:
                # Server resolves DNS, but rejects making HTTP request
                self.oob_provider.simulate_interaction(
                    canary_token=canary_token,
                    protocol="DNS",
                    source_ip="8.8.8.8",
                    interaction_type=OobInteractionType.DNS_ONLY,
                )
            return ControlledResponse(
                status_code=400,
                headers={"content-type": "application/json"},
                body=json.dumps({"error": "Resolved host refused HTTP connection"}),
                size_bytes=55,
                final_url=req.base_url,
            )

        # ---------------- Scenario 5: Redirect-Mediated Fetcher ----------------
        if path == "/api/v1/redirect-fetch":
            if canary_token:
                # Server follows redirect and makes HTTP request to canary
                self.oob_provider.simulate_interaction(
                    canary_token=canary_token,
                    protocol="HTTP",
                    source_ip=self.server_ip,
                    method="GET",
                    path="/redirected",
                    headers={"User-Agent": "RedirectingFetcher/1.1"},
                    interaction_type=OobInteractionType.HTTP_INTERACTION,
                )
            return ControlledResponse(
                status_code=200,
                headers={"content-type": "application/json"},
                body=json.dumps({"status": "redirect_followed"}),
                size_bytes=35,
                final_url=req.base_url,
            )

        # ---------------- Scenario 6: Browser-Only False Positive ----------------
        if path == "/api/v1/client-preview":
            if canary_token:
                # Client browser triggered callback, NOT the backend server
                self.oob_provider.simulate_interaction(
                    canary_token=canary_token,
                    protocol="HTTP",
                    source_ip=self.client_ip,  # Researcher IP!
                    method="GET",
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"},
                    interaction_type=OobInteractionType.HTTP_INTERACTION,
                )
            return ControlledResponse(
                status_code=200,
                headers={"content-type": "text/html"},
                body=f"<img src='{target_param_url}'>",
                size_bytes=40,
                final_url=req.base_url,
            )

        # ---------------- Fallback ----------------
        return ControlledResponse(
            status_code=404,
            headers={"content-type": "text/plain"},
            body="Not Found",
            size_bytes=9,
            final_url=req.base_url,
        )
