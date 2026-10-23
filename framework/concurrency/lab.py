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

from framework.concurrency.model import (
    CURRENT_EVIDENCE_SCHEMA_VERSION,
    EvidenceEnvelope,
    EvidenceSource,
    PostStateEvidence,
    canonical_serialize_envelope,
)
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
                time.sleep(0.04)  # Hold lock briefly
                server.safe_mutex_counter += 1
                self._send_json(200, {"status": "SUCCESS", "counter": server.safe_mutex_counter})
            finally:
                try:
                    server.mutex_lock.release()
                except RuntimeError:
                    pass
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
        self.mutex_lock = threading.Lock()
        self.rate_limit_lock = threading.Lock()
        super().__init__(server_address, RequestHandlerClass)
        self.reset_state()

    def reset_state(self) -> None:
        self.coupon_redemptions = 0
        self.account_balance = 100.0
        self.voting_count = 0
        self.order_count = 0
        self.cached_idempotency_keys = set()
        self.safe_mutex_counter = 0
        self.rate_limit_lock = threading.Lock()
        self.rate_limit_hits = 0
        self.distributed_step1_committed = False
        self.distributed_step2_committed = False


class LocalConcurrencyLab:
    """Manages lifecycle of ephemeral local HTTP concurrency testing lab."""

    # Cryptographically random internal trust key generated once per runtime process.
    # Used strictly to authenticate post-state evidence created from genuine LocalConcurrencyLab observations.
    _LAB_TRUST_KEY: bytes = secrets.token_bytes(32)
    _ACTIVE_LABS: Dict[int, LocalConcurrencyLab] = {}

    def __init__(self):
        self.server: Optional[LocalConcurrencyLabServer] = None
        self.thread: Optional[threading.Thread] = None
        self.port: int = 0
        self.base_url: str = ""
        self._active_observations: Dict[str, Dict[str, Any]] = {}
        self._obs_lock = threading.Lock()

    def _read_server_state(self) -> Dict[str, Any]:
        """Reads in-memory state directly from the active LocalConcurrencyLabServer."""
        if not self.server:
            return {}
        return {
            "coupon_redemptions": int(self.server.coupon_redemptions),
            "account_balance": float(self.server.account_balance),
            "voting_count": int(self.server.voting_count),
            "order_count": int(self.server.order_count),
            "safe_mutex_counter": int(self.server.safe_mutex_counter),
            "rate_limit_hits": int(self.server.rate_limit_hits),
            "distributed_step1_committed": bool(self.server.distributed_step1_committed),
            "distributed_step2_committed": bool(self.server.distributed_step2_committed),
        }

    def start_observation(self, observation_id: str) -> None:
        """Captures initial pre-state baseline directly from server for a specific test run."""
        with self._obs_lock:
            self._active_observations[observation_id] = {
                "pre_state": self._read_server_state(),
                "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }

    def complete_observation(self, observation_id: str) -> PostStateEvidence:
        """
        Completes the observation session for observation_id.
        Collects post-state directly from the running server, computes deltas against
        the pre-state baseline, constructs a canonical EvidenceEnvelope, and signs it.
        """
        with self._obs_lock:
            obs = self._active_observations.pop(observation_id, None)
            pre_state = obs["pre_state"] if obs else None

        post_state = self._read_server_state()
        ep = f"{self.base_url}/state/status"

        delta_metrics: Dict[str, Any] = {}
        if pre_state and post_state:
            for k in ("coupon_redemptions", "voting_count", "order_count", "safe_mutex_counter", "rate_limit_hits"):
                if k in pre_state and k in post_state:
                    delta_metrics[k] = post_state[k] - pre_state[k]
            if "account_balance" in pre_state and "account_balance" in post_state:
                delta_metrics["balance_delta"] = post_state["account_balance"] - pre_state["account_balance"]

        envelope = EvidenceEnvelope(
            schema_version=CURRENT_EVIDENCE_SCHEMA_VERSION,
            observation_id=observation_id,
            source=EvidenceSource.LAB_FIXTURE_AUTHORITATIVE.value,
            endpoint=ep,
            verified_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            pre_state=pre_state,
            post_state=post_state,
            delta_metrics=delta_metrics,
            provenance_details="Captured directly from in-memory LocalConcurrencyLab fixture server.",
        )
        token = self._sign_envelope(envelope)
        return PostStateEvidence(
            source=EvidenceSource.LAB_FIXTURE_AUTHORITATIVE,
            schema_version=envelope.schema_version,
            observation_id=envelope.observation_id,
            pre_state=envelope.pre_state,
            post_state=envelope.post_state,
            delta_metrics=envelope.delta_metrics,
            verified_endpoint=envelope.endpoint,
            verified_at=envelope.verified_at,
            provenance_details=envelope.provenance_details,
            _attestation_token=token,
        )

    def capture_evidence(self, observation_id: Optional[str] = None) -> PostStateEvidence:
        """Convenience method to complete an observation and capture signed authoritative evidence."""
        obs_id = observation_id or str(uuid.uuid4())
        return self.complete_observation(obs_id)

    @classmethod
    def _sign_envelope(cls, envelope: EvidenceEnvelope) -> str:
        raw = canonical_serialize_envelope(envelope.to_canonical_dict())
        return hmac.new(cls._LAB_TRUST_KEY, raw, hashlib.sha256).hexdigest()

    @classmethod
    def verify_attestation(cls, evidence: Any, expected_observation_id: Optional[str] = None) -> bool:
        """
        Validates cryptographic attestation over the complete evidence envelope.
        Guarantees evidence was produced directly by a genuine LocalConcurrencyLab instance
        and has not been altered in any decision-relevant field.
        """
        token = getattr(evidence, "_attestation_token", None)
        if not token or not isinstance(token, str) or len(token) != 64:
            return False

        source = getattr(evidence, "source", None)
        if source != EvidenceSource.LAB_FIXTURE_AUTHORITATIVE:
            return False

        schema_version = getattr(evidence, "schema_version", None)
        if schema_version != CURRENT_EVIDENCE_SCHEMA_VERSION:
            return False

        obs_id = getattr(evidence, "observation_id", None)
        if not obs_id or not isinstance(obs_id, str):
            return False
        if expected_observation_id and obs_id != expected_observation_id:
            return False

        ep = getattr(evidence, "verified_endpoint", "") or ""
        if not ep or not isinstance(ep, str):
            return False

        # Endpoint validation: must correspond to an active lab server
        parsed = urlparse(ep)
        port = parsed.port
        if not port or port not in cls._ACTIVE_LABS:
            return False
        if parsed.hostname not in ("127.0.0.1", "localhost"):
            return False

        ps = getattr(evidence, "post_state", None)
        if not isinstance(ps, dict) or not ps:
            return False

        pre = getattr(evidence, "pre_state", None)
        if pre is not None and not isinstance(pre, dict):
            return False

        delta_m = getattr(evidence, "delta_metrics", {})
        if not isinstance(delta_m, dict):
            return False

        envelope_dict = {
            "delta_metrics": delta_m,
            "endpoint": ep,
            "observation_id": obs_id,
            "post_state": ps,
            "pre_state": pre or {},
            "provenance_details": getattr(evidence, "provenance_details", "") or "",
            "schema_version": schema_version,
            "source": source.value if isinstance(source, EvidenceSource) else str(source),
            "verified_at": getattr(evidence, "verified_at", "") or "",
        }

        try:
            canonical_bytes = canonical_serialize_envelope(envelope_dict)
            expected_token = hmac.new(cls._LAB_TRUST_KEY, canonical_bytes, hashlib.sha256).hexdigest()
            return hmac.compare_digest(token, expected_token)
        except Exception:
            return False

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

    def get_authoritative_state(self, observation_id: Optional[str] = None) -> PostStateEvidence:
        """Returns verified, authoritative post-state evidence from the lab fixture."""
        obs_id = observation_id or str(uuid.uuid4())
        return self.complete_observation(obs_id)

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
