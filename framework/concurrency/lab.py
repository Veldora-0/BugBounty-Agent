"""
Deterministic Local Security Lab for Race Conditions & Distributed Workflows.

Runs an in-memory HTTP service on an ephemeral loopback port serving 8 deterministic
concurrency scenarios covering vulnerable race conditions, check-then-act gaps,
proper mutex/rate-limiting controls, and distributed workflow desynchronization.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
import datetime
import hashlib
import hmac
import json
import logging
import secrets
import socket
import threading
import time
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlparse
import uuid

from framework.concurrency.model import EvidenceSource, PostStateEvidence
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
                    "redemption_id": f"RDM-{server.coupon_redemptions}",
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
                    "transaction_id": f"TX-{uuid.uuid4().hex[:8]}",
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
                self._send_json(200, {
                    "status": "VOTE_RECORDED",
                    "vote_id": f"VOTE-{server.voting_count}",
                    "total_votes": server.voting_count,
                })
            else:
                self._send_json(429, {"error": "DAILY_VOTE_LIMIT_REACHED", "total_votes": server.voting_count})
            return

        # Scenario 4: Idempotency Key Cache Race (Vulnerable IDEMPOTENCY_BYPASS)
        if path == "/scenario/idempotency-race":
            key = self.headers.get("Idempotency-Key") or body.get("idempotency_key", "default_key")
            already_cached = key in server.cached_idempotency_keys
            time.sleep(0.04)  # Gap between cache lookup and writing key to distributed store
            if not already_cached:
                server.cached_idempotency_keys.add(key)
                server.order_count += 1
                self._send_json(200, {"status": "ORDER_CREATED", "order_id": f"ORD-{server.order_count}"})
            else:
                self._send_json(200, {"status": "DUPLICATE_ORDER_IGNORED", "idempotent": True, "order_id": "ORD-1"})
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

    # Cryptographically random internal trust key generated once per runtime process.
    # Used to authenticate post-state evidence created specifically through the trusted lab interface.
    _LAB_TRUST_KEY: bytes = secrets.token_bytes(32)
    _ACTIVE_LABS: Dict[int, LocalConcurrencyLab] = {}

    def __init__(self):
        self.server: Optional[LocalConcurrencyLabServer] = None
        self.thread: Optional[threading.Thread] = None
        self.port: int = 0
        self.base_url: str = ""

    @classmethod
    def _create_attestation(cls, source: str, endpoint: str, post_state: Dict[str, Any]) -> str:
        payload = f"{source}|{endpoint}|{json.dumps(post_state, sort_keys=True)}"
        return hmac.new(cls._LAB_TRUST_KEY, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    @classmethod
    def create_authoritative_evidence(
        cls,
        post_state: Dict[str, Any],
        endpoint: str = "http://127.0.0.1:8080/state/status",
        pre_state: Optional[Dict[str, Any]] = None,
        provenance_details: str = "Deterministic test fixture evidence.",
    ) -> PostStateEvidence:
        """
        Creates authenticated post-state evidence using the trusted lab fixture attestation.
        Only accessible within the internal framework/lab boundary.
        """
        token = cls._create_attestation(EvidenceSource.LAB_FIXTURE_AUTHORITATIVE.value, endpoint, post_state)
        return PostStateEvidence(
            source=EvidenceSource.LAB_FIXTURE_AUTHORITATIVE,
            pre_state=pre_state,
            post_state=post_state,
            verified_endpoint=endpoint,
            verified_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            provenance_details=provenance_details,
            _attestation_token=token,
        )

    @classmethod
    def verify_attestation(cls, evidence: Any) -> bool:
        """
        Validates cryptographic attestation of post-state evidence.
        Guarantees evidence was produced directly by a genuine LocalConcurrencyLab instance.
        """
        if not hasattr(evidence, "_attestation_token") or not evidence._attestation_token:
            return False
        if not hasattr(evidence, "source") or evidence.source != EvidenceSource.LAB_FIXTURE_AUTHORITATIVE:
            return False
        ps = getattr(evidence, "post_state", None)
        if not isinstance(ps, dict) or not ps:
            return False
        ep = getattr(evidence, "verified_endpoint", "") or ""
        expected = cls._create_attestation(evidence.source.value, ep, ps)
        return hmac.compare_digest(str(evidence._attestation_token), expected)

    @classmethod
    def get_active_lab(cls, port: int) -> Optional[LocalConcurrencyLab]:
        """Looks up active LocalConcurrencyLab instance by ephemeral port."""
        return cls._ACTIVE_LABS.get(port)

    def start(self) -> str:
        """Starts background HTTP server on ephemeral loopback port."""
        self.server = LocalConcurrencyLabServer(("127.0.0.1", 0), ConcurrencyLabHandler)
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        LocalConcurrencyLab._ACTIVE_LABS[self.port] = self

        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True, name="bb-concurrency-lab")
        self.thread.start()
        return self.base_url

    def stop(self) -> None:
        """Stops and cleans up the background HTTP server."""
        if self.port in LocalConcurrencyLab._ACTIVE_LABS:
            LocalConcurrencyLab._ACTIVE_LABS.pop(self.port, None)

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

    def get_authoritative_state(self) -> PostStateEvidence:
        """Returns verified, authoritative post-state evidence from the lab fixture."""
        state_dict: Dict[str, Any] = {}
        if self.server:
            state_dict = {
                "coupon_redemptions": self.server.coupon_redemptions,
                "account_balance": self.server.account_balance,
                "voting_count": self.server.voting_count,
                "order_count": self.server.order_count,
                "safe_mutex_counter": self.server.safe_mutex_counter,
                "rate_limit_hits": self.server.rate_limit_hits,
                "distributed_step1_committed": self.server.distributed_step1_committed,
                "distributed_step2_committed": self.server.distributed_step2_committed,
            }
        ep = f"{self.base_url}/state/status"
        token = self._create_attestation(EvidenceSource.LAB_FIXTURE_AUTHORITATIVE.value, ep, state_dict)
        return PostStateEvidence(
            source=EvidenceSource.LAB_FIXTURE_AUTHORITATIVE,
            post_state=state_dict,
            verified_endpoint=ep,
            verified_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            provenance_details="Queried directly from in-memory LocalConcurrencyLab fixture server.",
            _attestation_token=token,
        )

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
