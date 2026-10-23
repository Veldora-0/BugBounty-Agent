"""
Deterministic Local Security Lab for Race Conditions & Distributed Workflows.

Runs an in-memory HTTP service on an ephemeral loopback port serving 8 deterministic
concurrency scenarios covering vulnerable race conditions, check-then-act gaps,
proper mutex/rate-limiting controls, and distributed workflow desynchronization.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
import json
import logging
import socket
import threading
import time
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlparse

from framework.scope.engine import ScopeEngine


class ConcurrencyLabHandler(BaseHTTPRequestHandler):
    """HTTP request handler for deterministic concurrency test scenarios."""

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress standard HTTP server logging to keep test output clean."""
        pass

    def _read_body(self) -> Dict[str, Any]:
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len <= 0:
            return {}
        raw = self.rfile.read(content_len).decode("utf-8", errors="replace")
        try:
            return json.loads(raw)
        except Exception:
            return dict(parse_qsl(raw))

    def _send_json(self, status_code: int, data: Dict[str, Any]) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        server: LocalConcurrencyLabServer = self.server  # type: ignore
        body = self._read_body()

        # Scenario 1: Coupon Double Spend (Vulnerable TOCTOU)
        if path == "/scenario/coupon-race":
            # Check-then-act gap: read limit before updating
            current_redemptions = server.coupon_redemptions
            time.sleep(0.04)  # Simulate DB query / asynchronous gap
            if current_redemptions < 1:
                server.coupon_redemptions += 1
                self._send_json(200, {
                    "status": "APPLIED",
                    "coupon": "PROMO-50",
                    "redemptions": server.coupon_redemptions,
                })
            else:
                self._send_json(400, {"error": "COUPON_ALREADY_USED", "redemptions": server.coupon_redemptions})
            return

        # Scenario 2: Balance Transfer Overdraw (Vulnerable TOCTOU)
        if path == "/scenario/balance-transfer":
            amount = float(body.get("amount", 100.0))
            current_balance = server.account_balance
            time.sleep(0.04)  # Gap between balance check and debit
            if current_balance >= amount:
                server.account_balance -= amount
                self._send_json(200, {
                    "status": "TRANSFERRED",
                    "amount": amount,
                    "remaining_balance": server.account_balance,
                })
            else:
                self._send_json(400, {"error": "INSUFFICIENT_FUNDS", "balance": server.account_balance})
            return

        # Scenario 3: Voting Limit Overrun (Vulnerable LIMIT_OVERRUN)
        if path == "/scenario/voting-limit":
            current_votes = server.voting_count
            time.sleep(0.04)  # Gap between quota check and vote registration
            if current_votes < 1:
                server.voting_count += 1
                self._send_json(200, {"status": "VOTE_RECORDED", "total_votes": server.voting_count})
            else:
                self._send_json(429, {"error": "DAILY_VOTE_LIMIT_REACHED", "total_votes": server.voting_count})
            return

        # Scenario 4: Idempotency Key Cache Race (Vulnerable IDEMPOTENCY_BYPASS)
        if path == "/scenario/idempotency-race":
            key = self.headers.get("Idempotency-Key") or body.get("idempotency_key", "default_key")
            time.sleep(0.04)  # Gap before writing key to distributed store
            if key not in server.cached_idempotency_keys:
                server.cached_idempotency_keys.add(key)
                server.order_count += 1
                self._send_json(200, {"status": "ORDER_CREATED", "order_id": f"ORD-{server.order_count}"})
            else:
                self._send_json(200, {"status": "DUPLICATE_ORDER_IGNORED", "idempotent": True})
            return

        # Scenario 5: Mutex Protected Endpoint (Safe: returns 409 Conflict on collision)
        if path == "/scenario/mutex-safe":
            acquired = server.mutex_lock.acquire(blocking=False)
            if not acquired:
                self._send_json(409, {"error": "RESOURCE_LOCKED", "message": "Concurrent modification conflict"})
                return
            try:
                time.sleep(0.03)  # Hold lock briefly
                server.safe_mutex_counter += 1
                self._send_json(200, {"status": "SUCCESS", "counter": server.safe_mutex_counter})
            finally:
                server.mutex_lock.release()
            return

        # Scenario 6: Rate Limiting Protected (Safe: returns 429 Too Many Requests)
        if path == "/scenario/rate-limit-safe":
            with server.rate_limit_lock:
                server.rate_limit_hits += 1
                if server.rate_limit_hits > 1:
                    self._send_json(429, {"error": "TOO_MANY_REQUESTS", "retry_after": 5})
                    return
            self._send_json(200, {"status": "ALLOWED"})
            return

        # Scenario 7: Inconclusive Timeout
        if path == "/scenario/timeout-inconclusive":
            # Simulate upstream gateway timeout
            time.sleep(0.05)
            self._send_json(504, {"error": "GATEWAY_TIMEOUT", "message": "Backend worker pool busy"})
            return

        # Scenario 8: Distributed Workflow Partial Desynchronization
        if path == "/scenario/distributed-desync":
            # Step 1: Debit funds
            server.distributed_step1_committed = True
            time.sleep(0.04)
            # Step 2: Fails unexpectedly and fails to compensate Step 1!
            server.distributed_step2_committed = False
            self._send_json(500, {
                "error": "STEP2_FAILED",
                "inconsistent_state": True,
                "details": "Step 1 committed but Step 2 failed without rollback compensation",
            })
            return

        # Fallback
        self._send_json(404, {"error": "NOT_FOUND"})

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        server: LocalConcurrencyLabServer = self.server  # type: ignore

        if path == "/state/status":
            self._send_json(200, {
                "coupon_redemptions": server.coupon_redemptions,
                "account_balance": server.account_balance,
                "voting_count": server.voting_count,
                "order_count": server.order_count,
                "safe_mutex_counter": server.safe_mutex_counter,
                "distributed_step1_committed": server.distributed_step1_committed,
                "distributed_step2_committed": server.distributed_step2_committed,
            })
            return

        self._send_json(404, {"error": "NOT_FOUND"})


class LocalConcurrencyLabServer(ThreadingHTTPServer):
    """ThreadingHTTPServer holding stateful in-memory scenario counters."""

    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self.reset_state()

    def reset_state(self) -> None:
        self.coupon_redemptions = 0
        self.account_balance = 100.0
        self.voting_count = 0
        self.order_count = 0
        self.cached_idempotency_keys = set()
        self.mutex_lock = threading.Lock()
        self.safe_mutex_counter = 0
        self.rate_limit_lock = threading.Lock()
        self.rate_limit_hits = 0
        self.distributed_step1_committed = False
        self.distributed_step2_committed = False


class LocalConcurrencyLab:
    """Manages lifecycle of ephemeral local HTTP concurrency testing lab."""

    def __init__(self):
        self.server: Optional[LocalConcurrencyLabServer] = None
        self.thread: Optional[threading.Thread] = None
        self.port: int = 0
        self.base_url: str = ""

    def start(self) -> str:
        """Starts background HTTP server on ephemeral loopback port."""
        self.server = LocalConcurrencyLabServer(("127.0.0.1", 0), ConcurrencyLabHandler)
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"

        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True, name="bb-concurrency-lab")
        self.thread.start()
        return self.base_url

    def stop(self) -> None:
        """Stops and cleans up the background HTTP server."""
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass
            self.server = None
        if self.thread:
            self.thread.join(timeout=2.0)
            self.thread = None

    def reset_state(self) -> None:
        """Resets all in-memory mock scenario state."""
        if self.server:
            self.server.reset_state()

    @classmethod
    def get_scope_engine(cls, port: int) -> ScopeEngine:
        """Constructs ScopeEngine explicitly authorizing only this lab port."""
        return ScopeEngine({
            "program": {"name": "local-concurrency-lab"},
            "targets": {
                "domains": ["127.0.0.1", "localhost"],
                "urls": [f"http://127.0.0.1:{port}/", f"http://localhost:{port}/"],
            },
        })
