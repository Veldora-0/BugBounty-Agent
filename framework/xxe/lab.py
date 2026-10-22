"""
Local XXE Test Lab for Deterministic Verification (Phase 18).

Simulates server-side XML parser behaviors without requiring live target applications
or external network infrastructure:
1. REFLECTION: Vulnerable parser that resolves and reflects synthetic internal entities.
2. SECURE_REJECT: Hardened parser with DTD processing disabled (safe default).
3. PARSER_ERROR: Application reporting XML syntax or parsing failures.
4. BLIND_OOB: Server resolving external SYSTEM DTD identifiers via mock callback.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlparse

from framework.validation.request import ControlledRequest, ControlledResponse


class LocalXxeLab:
    """Deterministic local lab simulating XML parser responses."""

    def __init__(self, mode: str = "reflection", reflect_element: str = "url"):
        # Modes: "reflection", "secure_reject", "parser_error", "blind_oob"
        self.mode = mode.lower().strip()
        self.reflect_element = reflect_element.lower().strip()
        self.received_requests: list[ControlledRequest] = []

    def create_handler_hook(self) -> Callable[[ControlledRequest], ControlledResponse]:
        """Returns a callable compatible with SecurityValidationEngine send_request_hook."""
        def hook(req: ControlledRequest) -> ControlledResponse:
            self.received_requests.append(req)
            body = req.body or ""

            # Check if payload contains disallowed destructive/sensitive targets
            for forbidden in ("file://", "/etc/passwd", "/etc/hosts", "win.ini", "169.254.169.254"):
                if forbidden in body.lower():
                    return ControlledResponse(
                        status_code=403,
                        headers={"Content-Type": "text/plain"},
                        body=f"Forbidden target blocked: {forbidden}",
                        size_bytes=len(forbidden) + 26,
                        elapsed_seconds=0.01,
                    )

            if self.mode == "secure_reject":
                # Hardened XML parser disallowing DTDs
                if "<!DOCTYPE" in body.upper() or "<!ENTITY" in body.upper():
                    return ControlledResponse(
                        status_code=400,
                        headers={"Content-Type": "text/plain"},
                        body="XML parsing error: DOCTYPE declarations are prohibited on this endpoint.",
                        size_bytes=72,
                        elapsed_seconds=0.01,
                    )
                return ControlledResponse(
                    status_code=200,
                    headers={"Content-Type": "application/xml"},
                    body='<?xml version="1.0"?><response><status>OK</status></response>',
                    size_bytes=60,
                    elapsed_seconds=0.01,
                )

            elif self.mode == "parser_error":
                return ControlledResponse(
                    status_code=400,
                    headers={"Content-Type": "text/plain"},
                    body="XML syntax error: Entity expansion or DTD syntax failed on line 2.",
                    size_bytes=66,
                    elapsed_seconds=0.01,
                )

            elif self.mode == "blind_oob":
                # Matches external DTD SYSTEM url and simulates server fetching it
                match = re.search(r'SYSTEM\s+["\']([^"\']+)["\']', body, re.IGNORECASE)
                oob_url = match.group(1) if match else None
                return ControlledResponse(
                    status_code=200,
                    headers={"Content-Type": "application/xml"},
                    body=f'<?xml version="1.0"?><response><status>PROCESSED_OOB</status><target>{oob_url or ""}</target></response>',
                    size_bytes=100,
                    elapsed_seconds=0.05,
                )

            else:
                # Default: "reflection" - extracts internal entity and reflects its value
                entity_match = re.search(r'<!ENTITY\s+([a-zA-Z0-9_\-]+)\s+["\']([^"\']+)["\']', body)
                entity_name = entity_match.group(1) if entity_match else None
                entity_val = entity_match.group(2) if entity_match else None

                # Check if &entity_name; is referenced in the XML
                reflected_text = "default_value"
                if entity_name and entity_val and f"&{entity_name};" in body:
                    reflected_text = entity_val

                resp_body = f'<?xml version="1.0" encoding="UTF-8"?><result><output>{reflected_text}</output></result>'
                return ControlledResponse(
                    status_code=200,
                    headers={"Content-Type": "application/xml"},
                    body=resp_body,
                    size_bytes=len(resp_body),
                    elapsed_seconds=0.02,
                )

        return hook
