"""
Local Deterministic Security Lab for HTTP Header Trust & Protocol Security (Phase 11).

Provides an in-memory, deterministic mock environment supporting 15 distinct
header trust, CORS, HPP, and caching scenarios without any external network traffic.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlparse

from framework.validation.request import ControlledRequest, ControlledResponse


class LocalHttpTrustLab:
    """Deterministic mock HTTP engine for Phase 11 validation."""

    def __init__(self, upstream_domain: str = "lab.local"):
        self.upstream_domain = upstream_domain
        self.cached_responses: Dict[str, Dict[str, Any]] = {}

    def handle_request(self, req: ControlledRequest) -> ControlledResponse:
        """Dispatches request to appropriate scenario handler."""
        url = req.url or req.build_effective_url()
        parsed = urlparse(url)
        path = parsed.path
        headers = {k.title(): v for k, v in req.headers.items()}
        method = req.method.upper()

        host_hdr = headers.get("Host", self.upstream_domain)
        xfh_hdr = headers.get("X-Forwarded-Host", "")
        fwd_hdr = headers.get("Forwarded", "")
        xfp_hdr = headers.get("X-Forwarded-Proto", "https")
        origin_hdr = headers.get("Origin", "")

        # Scenario 1: Host reflected but harmless (echo in body, no links/redirects)
        if path == "/echo-host":
            body = f"<html><body>Current Host Header received: {host_hdr}</body></html>"
            return ControlledResponse(status_code=200, headers={"Content-Type": "text/html"}, body_text=body)

        # Scenario 2: Host controls canonical URL
        if path == "/page":
            body = f'<html><head><link rel="canonical" href="https://{host_hdr}/page"></head><body><h1>Sample Page</h1></body></html>'
            return ControlledResponse(status_code=200, headers={"Content-Type": "text/html"}, body_text=body)

        # Scenario 3: Host controls redirect
        if path == "/login-redirect":
            dest = f"https://{host_hdr}/dashboard"
            return ControlledResponse(status_code=302, headers={"Location": dest, "Content-Type": "text/html"}, body_text=f"Redirecting to {dest}")

        # Scenario 4: Host controls password-reset URL in isolated lab
        if path == "/auth/forgot-password":
            token = "lab_sec_tok_991823"
            body = f'<html><body><p>Reset link generated:</p><a href="https://{host_hdr}/auth/reset?token={token}">Click here to reset your password</a></body></html>'
            return ControlledResponse(status_code=200, headers={"Content-Type": "text/html"}, body_text=body)

        # Scenario 5: X-Forwarded-Host trusted over Host
        if path == "/api/config":
            effective_host = xfh_hdr if xfh_hdr else host_hdr
            body = f'<html><head><meta property="og:url" content="https://{effective_host}/api/config"></head></html>'
            return ControlledResponse(status_code=200, headers={"Content-Type": "text/html"}, body_text=body)

        # Scenario 6: Forwarded header trusted (Forwarded: host=...)
        if path == "/forwarded-test":
            effective_host = host_hdr
            if fwd_hdr and "host=" in fwd_hdr.lower():
                m = re.search(r'host=([^;,\s]+)', fwd_hdr, re.IGNORECASE)
                if m:
                    effective_host = m.group(1).strip('"')
            body = f'<html><head><link rel="canonical" href="https://{effective_host}/forwarded-test"></head></html>'
            return ControlledResponse(status_code=200, headers={"Content-Type": "text/html"}, body_text=body)

        # Scenario 7: X-Forwarded-Proto affects generated scheme
        if path == "/proto-test":
            scheme = "http" if xfp_hdr.lower() == "http" else "https"
            body = f'<html><head><link rel="canonical" href="{scheme}://{host_hdr}/proto-test"></head></html>'
            return ControlledResponse(status_code=200, headers={"Content-Type": "text/html"}, body_text=body)

        # Scenario 8: Correctly configured trusted proxy (ignores spoofed X-Forwarded-Host)
        if path == "/secure-proxy":
            # Always uses configured upstream domain regardless of XFH
            body = f'<html><head><link rel="canonical" href="https://{self.upstream_domain}/secure-proxy"></head></html>'
            return ControlledResponse(status_code=200, headers={"Content-Type": "text/html"}, body_text=body)

        # Scenario 9: Reflected Origin without credentials
        if path == "/public-cors":
            resp_headers = {"Content-Type": "application/json"}
            if origin_hdr:
                resp_headers["Access-Control-Allow-Origin"] = origin_hdr
                resp_headers["Vary"] = "Origin"
            body = '{"status": "public_data", "items": [1, 2, 3]}'
            return ControlledResponse(status_code=200, headers=resp_headers, body_text=body)

        # Scenario 10: Reflected Origin with credentials (vulnerable CORS)
        if path == "/api/user/profile":
            resp_headers = {
                "Content-Type": "application/json",
                "Access-Control-Allow-Credentials": "true",
            }
            if origin_hdr:
                resp_headers["Access-Control-Allow-Origin"] = origin_hdr
                resp_headers["Vary"] = "Origin"
            body = '{"username": "admin", "email": "admin@lab.local", "secret": "confidential_profile_data"}'
            return ControlledResponse(status_code=200, headers=resp_headers, body_text=body)

        # Scenario 11: Safe allowlist CORS
        if path == "/api/allowlist-cors":
            resp_headers = {"Content-Type": "application/json"}
            allowed_origins = [f"https://{self.upstream_domain}", f"https://portal.{self.upstream_domain}"]
            if origin_hdr in allowed_origins:
                resp_headers["Access-Control-Allow-Origin"] = origin_hdr
                resp_headers["Access-Control-Allow-Credentials"] = "true"
            else:
                resp_headers["Access-Control-Allow-Origin"] = f"https://{self.upstream_domain}"
            body = '{"result": "ok"}'
            return ControlledResponse(status_code=200, headers=resp_headers, body_text=body)

        # Scenario 12: Duplicate query parameter parser difference (HPP)
        if path == "/api/account":
            # Check duplicate query parameters: user=alice&user=bob
            # In our simulation, framework takes LAST parameter
            q_list = parse_qsl(parsed.query, keep_blank_values=True)
            user_val = "guest"
            for k, v in q_list:
                if k == "user" or k == "id":
                    user_val = v
            body = f'{{"active_account": "{user_val}"}}'
            return ControlledResponse(status_code=200, headers={"Content-Type": "application/json"}, body_text=body)

        # Scenario 13: Cache variation without poisoning (Keyed properly or no-store)
        if path == "/static-cache":
            resp_headers = {
                "Content-Type": "text/html",
                "Cache-Control": "public, max-age=3600",
                "Vary": "Host, X-Forwarded-Host",
                "Age": "45",
            }
            body = "<html><body>Static Cache Content</body></html>"
            return ControlledResponse(status_code=200, headers=resp_headers, body_text=body)

        # Scenario 14: Controlled cache poisoning simulation in isolated lab
        if path == "/cached-page":
            effective_host = xfh_hdr if xfh_hdr else host_hdr
            # In an unkeyed proxy scenario:
            body = f'<html><head><script src="https://{effective_host}/tracking.js"></script></head><body>Welcome</body></html>'
            resp_headers = {
                "Content-Type": "text/html",
                "Cache-Control": "public, max-age=600",
                "X-Cache": "HIT",
                "Age": "120",
            }
            return ControlledResponse(status_code=200, headers=resp_headers, body_text=body)

        # Scenario 15: Generic debug reflection false positive
        if path == "/debug-error":
            body = f"""<!DOCTYPE html>
<html><head><title>Debug Error 500</title></head>
<body>
<h1>Traceback (most recent call last):</h1>
<pre>
  File "app.py", line 42, in index
    headers = environ['HTTP_HOST'] = "{host_hdr}"
ZeroDivisionError: division by zero
</pre>
</body></html>"""
            return ControlledResponse(status_code=500, headers={"Content-Type": "text/html"}, body_text=body)

        # Default fallback
        return ControlledResponse(
            status_code=200,
            headers={"Content-Type": "text/html", "Host": host_hdr},
            body_text=f"<html><body>Default Lab Page ({path})</body></html>",
        )
