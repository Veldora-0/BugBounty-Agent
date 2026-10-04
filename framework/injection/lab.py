"""
Deterministic Local Security Lab for Injection Testing (Phase 10).

Provides 15 offline, deterministic simulation scenarios covering:
- SQL (boolean SQLi, parameterized safe query, error false positive, unstable response)
- NoSQL (query operator differential, safe typed validation)
- SSTI (harmless expression evaluation, literal-safe template rendering)
- Command Injection (candidate modeling, safe argument handling)
- Operational anomalies (WAF challenge, rate limiting, caching, timing jitter, generic 500)

Never contacts external networks or runs live destructive attacks.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlparse

from framework.validation.request import ControlledRequest, ControlledResponse


class LocalInjectionLab:
    """Mock HTTP simulation handler for 15 injection scenarios."""

    def __init__(self):
        self._nonce_counter = 0

    def handle_request(self, request: ControlledRequest) -> ControlledResponse:
        url = request.url
        parsed = urlparse(url)
        path = parsed.path
        qsl = dict(parse_qsl(parsed.query, keep_blank_values=True))

        # 1. SQL Injection: Vulnerable Boolean SQLi (/api/items)
        if "/api/items" in path and not "/safe-" in path:
            val = qsl.get("id", "1")
            if "'" in val and not "OR" in val:
                # Syntax error trigger
                return ControlledResponse(
                    status_code=500,
                    headers={"Content-Type": "application/json"},
                    body=b'{"error": "You have an error in your SQL syntax near \'"\' at line 1"}',
                    request_method=request.method,
                    request_url=request.url,
                )
            if "OR 1=1" in val or "' OR '1'='1" in val or val == "1":
                # True condition -> item found
                return ControlledResponse(
                    status_code=200,
                    headers={"Content-Type": "application/json"},
                    body=b'{"item_id": 1, "name": "Standard Industrial Widget", "price": 99.95, "in_stock": true}',
                    request_method=request.method,
                    request_url=request.url,
                )
            if "OR 1=2" in val or "' OR '1'='2" in val:
                # False condition -> empty/not found
                return ControlledResponse(
                    status_code=404,
                    headers={"Content-Type": "application/json"},
                    body=b'{"error": "Item not found"}',
                    request_method=request.method,
                    request_url=request.url,
                )
            if "SLEEP(1)" in val:
                # Bounded timing simulation
                resp = ControlledResponse(
                    status_code=200,
                    headers={"Content-Type": "application/json"},
                    body=b'{"item_id": 1, "delayed": true}',
                    request_method=request.method,
                    request_url=request.url,
                )
                setattr(resp, "duration_seconds", 1.05)
                return resp
            return ControlledResponse(status_code=200, headers={}, body=b'{"item_id": 1}', request_method=request.method, request_url=request.url)

        # 2. SQL: Safe Parameterized Query (/api/safe-items)
        if "/api/safe-items" in path:
            val = qsl.get("id", "1")
            if val == "1":
                return ControlledResponse(status_code=200, headers={}, body=b'{"item_id": 1, "name": "Safe Widget"}', request_method=request.method, request_url=request.url)
            # Parameter treated strictly as literal string lookup -> returns 404 without syntax error
            return ControlledResponse(status_code=404, headers={}, body=b'{"error": "Item not found"}', request_method=request.method, request_url=request.url)

        # 3. SQL Error False Positive (/api/search)
        if "/api/search" in path:
            q = qsl.get("q", "test")
            # Returns normal search page even with quote
            return ControlledResponse(
                status_code=200,
                headers={"Content-Type": "text/html"},
                body=f"<html><body><h2>Search Results</h2><p>No results found matching query: {q}</p></body></html>".encode("utf-8"),
                request_method=request.method,
                request_url=request.url,
            )

        # 4. Unstable Dynamic Response (/api/unstable-status)
        if "/api/unstable-status" in path:
            self._nonce_counter += 1
            body = f'{{"status": "ok", "nonce": "token_{self._nonce_counter}", "timestamp": {time.time()}}}'.encode("utf-8")
            return ControlledResponse(status_code=200, headers={}, body=body, request_method=request.method, request_url=request.url)

        # 5. NoSQL: Vulnerable Query Operator (/api/users)
        if "/api/users" in path and not "/safe-" in path:
            # Query parameter operator e.g. user[$ne]=__bb_nonexistent__
            if any("[$ne]" in k for k in qsl.keys()):
                # Returns collection expansion
                return ControlledResponse(
                    status_code=200,
                    headers={"Content-Type": "application/json"},
                    body=b'[{"user": "admin", "role": "admin"}, {"user": "guest", "role": "viewer"}]',
                    request_method=request.method,
                    request_url=request.url,
                )
            if any("[$eq]" in k for k in qsl.keys()):
                return ControlledResponse(status_code=404, headers={}, body=b'{"error": "User not found"}', request_method=request.method, request_url=request.url)
            return ControlledResponse(status_code=200, headers={}, body=b'{"user": "admin", "role": "admin"}', request_method=request.method, request_url=request.url)

        # 6. NoSQL: Safe Typed Validation (/api/safe-users)
        if "/api/safe-users" in path:
            if any("[$" in k for k in qsl.keys()):
                return ControlledResponse(
                    status_code=400,
                    headers={"Content-Type": "application/json"},
                    body=b'{"error": "Invalid parameter type: string expected"}',
                    request_method=request.method,
                    request_url=request.url,
                )
            return ControlledResponse(status_code=200, headers={}, body=b'{"user": "admin"}', request_method=request.method, request_url=request.url)

        # 7. SSTI: Vulnerable Expression Evaluation (/render)
        if "/render" in path and not "-safe" in path:
            tpl = qsl.get("template", "Hello World")
            if "{{7*7}}" in tpl:
                rendered = tpl.replace("{{7*7}}", "49")
            elif "${7*7}" in tpl:
                rendered = tpl.replace("${7*7}", "49")
            else:
                rendered = tpl
            return ControlledResponse(
                status_code=200,
                headers={"Content-Type": "text/html"},
                body=f"<html><body>{rendered}</body></html>".encode("utf-8"),
                request_method=request.method,
                request_url=request.url,
            )

        # 8. SSTI: Literal-Safe Template Rendering (/render-safe)
        if "/render-safe" in path:
            tpl = qsl.get("template", "Hello World")
            # Escapes or outputs literally without evaluating
            return ControlledResponse(
                status_code=200,
                headers={"Content-Type": "text/html"},
                body=f"<html><body>{tpl}</body></html>".encode("utf-8"),
                request_method=request.method,
                request_url=request.url,
            )

        # 9. Command Injection Candidate (/api/convert)
        if "/api/convert" in path and not "-safe" in path:
            f = qsl.get("file", "doc.pdf")
            return ControlledResponse(
                status_code=200,
                headers={"Content-Type": "application/json"},
                body=f'{{"status": "converted", "file": "{f}", "size": 1024}}'.encode("utf-8"),
                request_method=request.method,
                request_url=request.url,
            )

        # 10. Safe Command Argument Handling (/api/convert-safe)
        if "/api/convert-safe" in path:
            f = qsl.get("file", "doc.pdf")
            if any(ch in f for ch in (";", "|", "&", "`", "$", "(", ")")):
                return ControlledResponse(
                    status_code=400,
                    headers={"Content-Type": "application/json"},
                    body=b'{"error": "Disallowed characters in filename"}',
                    request_method=request.method,
                    request_url=request.url,
                )
            return ControlledResponse(status_code=200, headers={}, body=b'{"status": "converted"}', request_method=request.method, request_url=request.url)

        # 11. WAF False Positive (/waf-protected)
        if "/waf-protected" in path:
            return ControlledResponse(
                status_code=403,
                headers={"Server": "cloudflare", "Content-Type": "text/html"},
                body=b"<html><head><title>Attention Required! | Cloudflare</title></head><body>Please complete security check</body></html>",
                request_method=request.method,
                request_url=request.url,
            )

        # 12. Rate-Limit Response (/rate-limited)
        if "/rate-limited" in path:
            return ControlledResponse(
                status_code=429,
                headers={"Retry-After": "60"},
                body=b'{"error": "Too Many Requests"}',
                request_method=request.method,
                request_url=request.url,
            )

        # 13. Caching Variation (/cached-page)
        if "/cached-page" in path:
            return ControlledResponse(
                status_code=304,
                headers={"ETag": '"123456"', "Cache-Control": "max-age=3600"},
                body=b"",
                request_method=request.method,
                request_url=request.url,
            )

        # 14. Timing Jitter (/jitter-endpoint)
        if "/jitter-endpoint" in path:
            resp = ControlledResponse(
                status_code=200,
                headers={},
                body=b'{"status": "ok"}',
                request_method=request.method,
                request_url=request.url,
            )
            setattr(resp, "duration_seconds", 0.08)
            return resp

        # 15. Generic 500 Error (/crash-generic)
        if "/crash-generic" in path:
            return ControlledResponse(
                status_code=500,
                headers={"Content-Type": "application/json"},
                body=b'{"error": "Unhandled runtime NullPointerException in ApplicationServlet"}',
                request_method=request.method,
                request_url=request.url,
            )

        # Default fallback
        return ControlledResponse(
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body=b"OK",
            request_method=request.method,
            request_url=request.url,
        )
