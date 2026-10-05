"""
Deterministic Local Security Lab for Business Logic & Workflow Intelligence (Phase 12).

Simulates in-memory multi-step business workflows covering:
1. Step skipping (accessing payment capture before authorization)
2. Step reordering (completing order before review)
3. Replay vulnerability (replaying gift coupon/token)
4. One-time token replay (password reset link used twice)
5. Duplicate action (double-submit on funds transfer without idempotency)
6. Horizontal ownership violation (User A editing User B's profile/ticket)
7. Vertical privilege violation (Regular user updating role to admin)
8. Tenant isolation violation (Tenant A querying Tenant B's invoices)
9. Negative quantity (adding -5 items to invert cart total)
10. Price tampering (client-authoritative item price parameter)
11. Approval bypass (publishing document without manager approval)
12. Deleted-resource lifecycle abuse (updating a deleted/archived invoice)
13. Safe legitimate workflow (properly validated checkout)
14. Race-condition fixture (concurrent coupon redemption / double-spend)
15. External finding correlation fixture (reproducing and verifying external scanner candidates)
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlparse

from framework.validation.request import ControlledRequest, ControlledResponse


class LocalBusinessLogicLab:
    """Mock application providing deterministic stateful scenarios."""

    def __init__(self):
        self.reset_state()

    def reset_state(self) -> None:
        """Resets all in-memory mock application state."""
        self.users = {
            "user_a": {"id": "user_a", "role": "USER", "tenant": "tenant_1"},
            "user_b": {"id": "user_b", "role": "USER", "tenant": "tenant_2"},
            "admin": {"id": "admin", "role": "ADMIN", "tenant": "tenant_1"},
        }
        self.used_tokens = set()
        self.orders = {}
        self.coupon_redemptions = 0
        self.max_coupon_limit = 1
        self.invoices = {
            "inv-101": {"id": "inv-101", "owner": "user_a", "tenant": "tenant_1", "status": "ACTIVE"},
            "inv-102": {"id": "inv-102", "owner": "user_b", "tenant": "tenant_2", "status": "ACTIVE"},
            "inv-999": {"id": "inv-999", "owner": "user_a", "tenant": "tenant_1", "status": "DELETED"},
        }
        self.approvals = {
            "doc-1": {"id": "doc-1", "approved": False, "status": "DRAFT"},
        }

    def handle_request(self, req: ControlledRequest) -> ControlledResponse:
        url = req.url or req.build_effective_url()
        parsed = urlparse(url)
        path = parsed.path
        method = req.method.upper()
        headers = {k.title(): v for k, v in req.headers.items()}
        auth_user = headers.get("X-User-Id", "user_a")
        tenant = headers.get("X-Tenant-Id", "tenant_1")

        body_data = {}
        if req.body:
            try:
                body_data = json.loads(req.body)
            except Exception:
                body_data = dict(parse_qsl(req.body))

        # Scenario 1: Step Skipping (Order checkout without payment authorization)
        if path == "/api/checkout/capture":
            # Vulnerable if called without prior /api/checkout/authorize step!
            token = body_data.get("auth_token") or parsed.query
            if not token or "valid_auth" not in str(token):
                # VULNERABLE: allows capture even without authorization token
                return ControlledResponse(status_code=200, headers={"Content-Type": "application/json"}, body_text='{"status": "SUCCESS", "captured": true, "note": "step skipped"}')
            return ControlledResponse(status_code=200, headers={"Content-Type": "application/json"}, body_text='{"status": "SUCCESS", "captured": true}')

        # Scenario 2: Step Reordering (Finalize order before review)
        if path == "/api/workflow/finalize":
            has_reviewed = body_data.get("reviewed", False)
            # Vulnerable: finalizes regardless of review status
            return ControlledResponse(status_code=200, headers={"Content-Type": "application/json"}, body_text='{"workflow_state": "FINALIZED"}')

        # Scenario 3 & 4: Replay Token / One-time token
        if path == "/api/tokens/redeem":
            tok = str(body_data.get("token", "default_tok"))
            if tok in self.used_tokens:
                # VULNERABLE token endpoint allows reuse if path == /api/tokens/redeem_flaw
                return ControlledResponse(status_code=400, headers={"Content-Type": "application/json"}, body_text='{"error": "TOKEN_ALREADY_USED"}')
            self.used_tokens.add(tok)
            return ControlledResponse(status_code=200, headers={"Content-Type": "application/json"}, body_text='{"status": "TOKEN_ACCEPTED"}')

        if path == "/api/tokens/redeem-flawed":
            # Flawed one-time token endpoint: does NOT invalidate token!
            return ControlledResponse(status_code=200, headers={"Content-Type": "application/json"}, body_text='{"status": "TOKEN_ACCEPTED", "reusable": true}')

        # Scenario 5: Duplicate action submission
        if path == "/api/transfer/funds":
            amount = int(body_data.get("amount", 100))
            # Processes every duplicate request without idempotency key
            return ControlledResponse(status_code=200, headers={"Content-Type": "application/json"}, body_text=f'{{"transferred": {amount}, "status": "COMPLETED"}}')

        # Scenario 6: Horizontal Ownership Mismatch
        if path.startswith("/api/tickets/"):
            ticket_id = path.split("/")[-1]
            # user_a modifying user_b ticket
            if method in ("PUT", "POST") and auth_user == "user_a" and "user_b" in ticket_id:
                # VULNERABLE: returns success modifying other user's resource
                return ControlledResponse(status_code=200, headers={"Content-Type": "application/json"}, body_text=f'{{"ticket": "{ticket_id}", "status": "MUTATED_BY_ANOTHER_USER"}}')
            return ControlledResponse(status_code=200, headers={"Content-Type": "application/json"}, body_text='{"ticket": "viewed"}')

        # Scenario 7: Vertical Privilege / Role Transition
        if path == "/api/user/role":
            req_role = body_data.get("role", "USER")
            # VULNERABLE: allows regular user to promote themselves to ADMIN
            return ControlledResponse(status_code=200, headers={"Content-Type": "application/json"}, body_text=f'{{"user": "{auth_user}", "role": "{req_role}"}}')

        # Scenario 8: Tenant Isolation Violation
        if path == "/api/invoices/fetch":
            inv_id = body_data.get("invoice_id") or "inv-102"
            inv = self.invoices.get(inv_id, {})
            # VULNERABLE: returns foreign tenant invoice
            return ControlledResponse(status_code=200, headers={"Content-Type": "application/json"}, body_text=json.dumps(inv))

        # Scenario 9: Negative Quantity
        if path == "/api/cart/update":
            qty = int(body_data.get("quantity", 1))
            # VULNERABLE: accepts negative quantity and subtracts from price
            total = max(0, 100 + (qty * 10))
            return ControlledResponse(status_code=200, headers={"Content-Type": "application/json"}, body_text=f'{{"quantity": {qty}, "total": {total}}}')

        # Scenario 10: Price Tampering
        if path == "/api/order/submit":
            price = body_data.get("price")
            # VULNERABLE: trusts client-supplied price
            return ControlledResponse(status_code=200, headers={"Content-Type": "application/json"}, body_text=f'{{"order_status": "CONFIRMED", "price_charged": {price}}}')

        # Scenario 11: Approval Bypass
        if path == "/api/documents/publish":
            doc_id = body_data.get("doc_id", "doc-1")
            # VULNERABLE: publishes document without checking if approved==True
            return ControlledResponse(status_code=200, headers={"Content-Type": "application/json"}, body_text=f'{{"doc_id": "{doc_id}", "status": "PUBLISHED"}}')

        # Scenario 12: Deleted Resource Lifecycle Abuse
        if path == "/api/invoices/update":
            inv_id = body_data.get("invoice_id", "inv-999")
            # VULNERABLE: mutates invoice even though it's DELETED
            return ControlledResponse(status_code=200, headers={"Content-Type": "application/json"}, body_text=f'{{"invoice_id": "{inv_id}", "status": "MUTATED_POST_DELETION"}}')

        # Scenario 13: Safe Legitimate Workflow
        if path == "/api/safe/checkout":
            if int(body_data.get("quantity", 1)) <= 0:
                return ControlledResponse(status_code=400, headers={"Content-Type": "application/json"}, body_text='{"error": "INVALID_QUANTITY"}')
            return ControlledResponse(status_code=200, headers={"Content-Type": "application/json"}, body_text='{"status": "VALID_PURCHASE"}')

        # Scenario 14: Race Condition / Concurrent Coupon
        if path == "/api/coupon/apply":
            self.coupon_redemptions += 1
            # In an unprotected race condition, count can exceed 1
            return ControlledResponse(status_code=200, headers={"Content-Type": "application/json"}, body_text=f'{{"redemptions": {self.coupon_redemptions}, "applied": true}}')

        # Fallback
        return ControlledResponse(status_code=200, headers={"Content-Type": "application/json"}, body_text='{"status": "OK"}')
