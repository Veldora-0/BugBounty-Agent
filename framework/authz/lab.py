"""
Deterministic Local Security Lab Fixtures for Authorization & Access Control.

Simulates genuine HTTP application authorization behaviors across 8 distinct scenarios:
1. Horizontal IDOR (BOLA)
2. Vertical Privilege Escalation
3. Tenant Isolation Failure
4. Correct Access Control Enforcement
5. Soft-404 False-Positive Response
6. Generic HTTP 200 Denial Message
7. Unauthenticated Protected Resource
8. Intentionally Public Resource
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, Optional
from urllib.parse import parse_qsl, urlparse

from framework.validation.request import ControlledRequest, ControlledResponse


class LocalAuthzLab:
    """
    Simulates a vulnerable and defended backend web application for authorization testing.
    Can be used as a ControlledRequest dispatch hook for deterministic offline testing.
    """

    def __init__(self):
        # Database records
        self.documents = {
            "101": {"id": "101", "owner": "user_a", "tenant": "tenant_a", "title": "Secret Strategy User A"},
            "102": {"id": "102", "owner": "user_b", "tenant": "tenant_a", "title": "Private Document User B"},
        }
        self.invoices = {
            "inv-001": {"id": "inv-001", "owner": "user_a", "tenant": "tenant_a", "amount": 1500},
            "inv-002": {"id": "inv-002", "owner": "user_b", "tenant": "tenant_b", "amount": 9200},
        }

    def dispatch(self, req: ControlledRequest) -> ControlledResponse:
        """Simulates application routing and access control decisions."""
        parsed = urlparse(req.base_url)
        path = parsed.path
        auth_header = req.headers.get("Authorization", "")
        cookie_header = req.headers.get("Cookie", "")

        # Infer principal from headers or tokens
        principal_id = "ANONYMOUS"
        role = "ANONYMOUS"
        tenant_id = None

        if "user_a" in auth_header or "user_a" in cookie_header:
            principal_id = "user_a"
            role = "USER"
            tenant_id = "tenant_a"
        elif "user_b" in auth_header or "user_b" in cookie_header:
            principal_id = "user_b"
            role = "USER"
            tenant_id = "tenant_b"
        elif "admin" in auth_header or "admin" in cookie_header:
            principal_id = "admin_user"
            role = "ADMIN"
            tenant_id = "tenant_a"

        # ---------------- Scenario 8: Public Resource ----------------
        if path == "/public/terms" or path == "/about":
            return ControlledResponse(
                status_code=200,
                headers={"content-type": "text/html"},
                body="<html><body><h1>Terms of Service</h1><p>Public terms.</p></body></html>",
                size_bytes=80,
                final_url=req.base_url,
            )

        # ---------------- Scenario 7: Unauthenticated Protected Resource ----------------
        if path == "/api/v1/profile":
            if principal_id == "ANONYMOUS":
                # VULNERABLE: Leaks profile even when unauthenticated!
                return ControlledResponse(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    body=json.dumps({"user": "user_a", "email": "user_a@example.com", "private_notes": "my_secrets"}),
                    size_bytes=75,
                    final_url=req.base_url,
                )
            return ControlledResponse(
                status_code=200,
                headers={"content-type": "application/json"},
                body=json.dumps({"user": principal_id, "status": "authenticated"}),
                size_bytes=50,
                final_url=req.base_url,
            )

        # ---------------- Scenario 2: Vertical Privilege Escalation ----------------
        if path.startswith("/admin/users"):
            if role == "ADMIN":
                return ControlledResponse(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    body=json.dumps({"admin_access": True, "users": ["user_a", "user_b", "admin"]}),
                    size_bytes=60,
                    final_url=req.base_url,
                )
            elif role == "USER":
                # VULNERABLE: normal user gets admin data!
                return ControlledResponse(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    body=json.dumps({"admin_access": True, "users": ["user_a", "user_b", "admin"]}),
                    size_bytes=60,
                    final_url=req.base_url,
                )
            else:
                return ControlledResponse(
                    status_code=401,
                    headers={"content-type": "text/plain"},
                    body="Authentication required.",
                    size_bytes=25,
                    final_url=req.base_url,
                )

        # ---------------- Scenario 1 & 4 & 5 & 6: Documents (/api/v1/documents/{id}) ----------------
        if path.startswith("/api/v1/documents/"):
            doc_id = path.split("/")[-1]

            # Invalid document
            if doc_id not in self.documents:
                return ControlledResponse(
                    status_code=404,
                    headers={"content-type": "application/json"},
                    body=json.dumps({"error": "Document not found"}),
                    size_bytes=35,
                    final_url=req.base_url,
                )

            doc = self.documents[doc_id]

            # Special fixture: correctly defended endpoint
            if "defended" in req.base_url:
                if doc["owner"] != principal_id and role != "ADMIN":
                    return ControlledResponse(
                        status_code=403,
                        headers={"content-type": "application/json"},
                        body=json.dumps({"error": "Forbidden: You are not the owner"}),
                        size_bytes=45,
                        final_url=req.base_url,
                    )
                return ControlledResponse(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    body=json.dumps(doc),
                    size_bytes=100,
                    final_url=req.base_url,
                )

            # Special fixture: Generic 200 Denial Page
            if "generic-denial" in req.base_url:
                if doc["owner"] != principal_id:
                    return ControlledResponse(
                        status_code=200,
                        headers={"content-type": "text/html"},
                        body="<html><body><h1>Access Denied</h1><p>You do not have permission to view this.</p></body></html>",
                        size_bytes=90,
                        final_url=req.base_url,
                    )

            # Special fixture: Soft-404 Response
            if "soft-404" in req.base_url:
                if doc["owner"] != principal_id:
                    return ControlledResponse(
                        status_code=200,
                        headers={"content-type": "text/html"},
                        body="<html><body><h1>Page Not Found</h1><p>Record does not exist.</p></body></html>",
                        size_bytes=80,
                        final_url=req.base_url,
                    )

            # Default: VULNERABLE Horizontal BOLA/IDOR
            return ControlledResponse(
                status_code=200,
                headers={"content-type": "application/json"},
                body=json.dumps(doc),
                size_bytes=100,
                final_url=req.base_url,
            )

        # ---------------- Scenario 3: Tenant Isolation (/api/v1/invoices/{id}) ----------------
        if path.startswith("/api/v1/invoices/"):
            inv_id = path.split("/")[-1]
            if inv_id not in self.invoices:
                return ControlledResponse(
                    status_code=404,
                    headers={"content-type": "application/json"},
                    body=json.dumps({"error": "Invoice not found"}),
                    size_bytes=35,
                    final_url=req.base_url,
                )

            inv = self.invoices[inv_id]

            # Cross-tenant breach simulation
            return ControlledResponse(
                status_code=200,
                headers={"content-type": "application/json"},
                body=json.dumps(inv),
                size_bytes=90,
                final_url=req.base_url,
            )

        # Fallback
        return ControlledResponse(
            status_code=404,
            headers={"content-type": "text/plain"},
            body="Not found",
            size_bytes=10,
            final_url=req.base_url,
        )
