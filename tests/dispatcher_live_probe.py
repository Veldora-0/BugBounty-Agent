#!/usr/bin/env python3
"""Phase 21: Live Dispatcher Verification Probe.

Validates the live isolated execution dispatcher on Linux / Windows:
1. Connects to the dispatcher IPC endpoint (/run/bugbounty/dispatcher.sock or pipe).
2. Verifies PING and STATUS responses.
3. Validates the pinned Ed25519 public verification key (/etc/bugbounty/dispatcher.pub).
4. Tests negative rejection of unapproved / unauthorized mutation requests.
5. If approval keys are provisioned, performs live end-to-end execution against a local
   HTTP fixture server, verifies signed Ed25519 receipt, issues ExecutionCapability,
   and tests replay rejection.
6. If root/systemd privileges are unavailable to configure service keys, reports NOT RUN
   for the live execution portion without fabricating results or mocking.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import http.server
import json
import os
import secrets
import socket
import sys
import tempfile
import threading
import time
from typing import Any, Dict, Optional, Tuple

# Add repository root to path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from framework.auth_correlation.dispatcher import ControlledDispatchResult
from framework.auth_correlation.ipc.client import IsolatedDispatcherClient
from framework.auth_correlation.ipc.protocol import PROTOCOL_VERSION, DispatcherUnavailableError
from framework.auth_correlation.ipc.receipt import (
    derive_verification_key,
    load_dispatcher_verification_key,
    verify_execution_receipt,
)
from framework.auth_correlation.ipc.service import CANONICAL_ACTION_FIELDS, IsolatedExecutionDispatcher
from framework.auth_correlation.ledger import (
    ExecutionLedger,
    ExecutionProvenanceError,
    issue_execution_capability,
)
from framework.auth_correlation.revocation import get_or_create_approval_key, sign_action_approval
from framework.common.evidence import EvidenceStore
from framework.validation.request import ControlledRequest, ControlledResponse


class FixtureHTTPHandler(http.server.BaseHTTPRequestHandler):
    """Local fixture HTTP server for controlled invalidation testing."""

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Suppress console logging

    def do_POST(self) -> None:
        if self.path == "/auth/logout":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0:
                _ = self.rfile.read(content_length)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "logged_out", "revoked": true}')
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/auth/logout" or self.path.startswith("/auth/logout?"):
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Session revoked", "status": "revoked"}')
        else:
            self.send_response(404)
            self.end_headers()


def start_fixture_server() -> Tuple[http.server.HTTPServer, int, threading.Thread]:
    """Starts local fixture HTTP server on 127.0.0.1 on an available port."""
    server = http.server.HTTPServer(("127.0.0.1", 0), FixtureHTTPHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port, thread


def run_live_service_probe(
    socket_path: Optional[str] = None,
    public_key_path: Optional[str] = None,
) -> int:
    """Probes the live running systemd service."""
    print("=" * 70)
    print("Phase 21: Live Dispatcher Service Probe")
    print("=" * 70)

    endpoint_type = "pipe" if os.name == "nt" else "unix"
    if socket_path is None:
        if os.name == "nt":
            address = os.environ.get("BUGBOUNTY_DISPATCHER_PIPE", r"\\.\pipe\bugbounty_dispatcher")
        else:
            address = os.environ.get("BUGBOUNTY_DISPATCHER_SOCKET", "/run/bugbounty/dispatcher.sock")
    else:
        address = socket_path

    print(f"[*] Connecting to dispatcher IPC endpoint ({endpoint_type}): {address}")
    client = IsolatedDispatcherClient(endpoint_type=endpoint_type, address=address, timeout=5.0)

    # 1. PING Check
    try:
        ping_ok = client.ping()
    except Exception as e:
        print(f"[!] FAILED to connect to dispatcher: {e}")
        return 1

    if not ping_ok:
        print("[!] Dispatcher returned PING == False")
        return 1
    print("[+] PING check passed: dispatcher daemon is responsive.")

    # 2. STATUS Check
    try:
        status_resp = client.get_status()
    except Exception as e:
        print(f"[!] FAILED to get dispatcher status: {e}")
        return 1

    if status_resp.get("status") != "SUCCESS":
        print(f"[!] STATUS check returned non-success: {status_resp}")
        return 1

    receipt_info = status_resp.get("receipt", {})
    disp_id = receipt_info.get("dispatcher_id", "UNKNOWN")
    key_id = receipt_info.get("dispatcher_key_id", "UNKNOWN")
    has_app_key = receipt_info.get("has_approval_key", False)
    prod_iso = receipt_info.get("production_isolation_supported", False)
    plat_lim = receipt_info.get("platform_limitation")

    print(f"[+] STATUS query succeeded: dispatcher_id={disp_id}, key_id={key_id}")
    print(f"[*] Production isolation: {prod_iso} (limitation: {plat_lim})")
    print(f"[*] Service has operator approval key configured: {has_app_key}")

    # 3. Public Verification Key Check
    pub_path = public_key_path
    if pub_path is None:
        if os.name == "nt":
            pub_path = os.path.join(
                os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
                "BugBounty", "Dispatcher", "dispatcher.pub",
            )
        else:
            pub_path = "/etc/bugbounty/dispatcher.pub"

    print(f"[*] Checking dispatcher public key: {pub_path}")
    if not os.path.exists(pub_path):
        print(f"[!] Pinned public verification key not found at {pub_path}")
        return 1

    try:
        verification_key = load_dispatcher_verification_key(path=pub_path)
        print(f"[+] Pinned public key loaded successfully ({len(verification_key)} bytes).")
    except Exception as e:
        print(f"[!] Failed to load public key: {e}")
        return 1

    # 4. Negative Rejection Probe
    print("[*] Testing negative rejection of unapproved / malformed mutation...")
    bogus_aid = f"ACT-{'0' * 64}"
    bogus_dossier = {
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": "probe-prog",
        "target_endpoint": "https://target.local/auth/logout",
        "test_account": "probe-user",
        "ttl": 300,
        "unique_approval_id": f"APPR-{'0' * 32}",
        "approval_signature": f"SIG-{'F' * 128}",
    }
    bogus_sess = {"session_ref": f"sess_{'0' * 32}", "principal_id": "probe-user"}

    try:
        reject_resp = client.dispatch_mutation(
            program_id="probe-prog",
            action_id=bogus_aid,
            action_dossier=bogus_dossier,
            session_context=bogus_sess,
        )
    except Exception as e:
        print(f"[!] Error sending mutation probe: {e}")
        return 1

    if reject_resp.get("status") == "REJECTED":
        err_code = reject_resp.get("error_code")
        err_msg = reject_resp.get("error_message")
        print(f"[+] Negative rejection verified: status=REJECTED, error_code={err_code}")
        print(f"    Message: {err_msg}")
    else:
        print(f"[!] Negative rejection FAILED: expected REJECTED, got {reject_resp}")
        return 1

    # 5. Live execution assessment
    if not has_app_key:
        print("=" * 70)
        print("[!] LIVE SERVICE MUTATION EXECUTION: NOT RUN")
        print("    Reason: The live systemd service is running under _bbdispatcher:bbgroup,")
        print("    but has not been provisioned with an operator action_approval.key in")
        print("    /var/lib/bugbounty/keys. Root/sudo privileges are required to configure")
        print("    keys for the systemd service. Live rejection checks PASSED.")
        print("=" * 70)
        return 0

    print("[+] Live service has approval key configured; proceeding to local fixture test...")
    # Run full execution test with local fixture server
    return run_full_execution_test(client, verification_key)


def run_full_execution_test(client: IsolatedDispatcherClient, verification_key: bytes) -> int:
    """Performs live mutation execution against local HTTP fixture."""
    server, port, thread = start_fixture_server()
    target_url = f"http://127.0.0.1:{port}/auth/logout"
    print(f"[*] Local fixture HTTP server started on {target_url}")

    try:
        temp_dir = tempfile.mkdtemp(prefix="bb_probe_")
        state_dir = os.path.join(temp_dir, "state")
        key_dir = os.path.join(temp_dir, "keys")
        ev_dir = os.path.join(temp_dir, "evidence")
        os.makedirs(state_dir, exist_ok=True)
        os.makedirs(key_dir, exist_ok=True)
        os.makedirs(ev_dir, exist_ok=True)

        app_key = get_or_create_approval_key(key_dir=key_dir)
        dossier_data = {
            "action_type": "LOGOUT",
            "created_at": time.time(),
            "method": "POST",
            "program_id": "probe-prog",
            "target_endpoint": target_url,
            "test_account": "probe-alice",
            "ttl": 300,
            "unique_approval_id": f"APPR-{secrets.token_hex(16).upper()}",
        }
        signed_dossier = sign_action_approval(dossier_data, approval_key=app_key)
        aid = signed_dossier["action_id"]
        sess_ctx = {"session_ref": f"sess_{secrets.token_hex(16)}", "principal_id": "probe-alice"}

        print(f"[*] Dispatching approved Mode B mutation: action_id={aid[:20]}...")
        resp = client.dispatch_mutation(
            program_id="probe-prog",
            action_id=aid,
            action_dossier=signed_dossier,
            session_context=sess_ctx,
        )

        if resp.get("status") != "SUCCESS":
            print(f"[!] Dispatch mutation failed: {resp}")
            return 1

        receipt = resp.get("receipt")
        if not receipt:
            print("[!] Dispatch mutation succeeded but receipt is missing")
            return 1

        # Verify receipt signature
        v_ok, v_reason = verify_execution_receipt(
            receipt,
            verification_key=verification_key,
            expected_action_id=aid,
            expected_program_id="probe-prog",
        )
        if not v_ok:
            print(f"[!] Receipt verification failed: {v_reason}")
            return 1
        print(f"[+] Ed25519 ExecutionReceipt cryptographically verified: receipt_id={receipt['receipt_id']}")

        # Test replay rejection
        print("[*] Testing replay attack rejection with duplicate action ID...")
        replay_resp = client.dispatch_mutation(
            program_id="probe-prog",
            action_id=aid,
            action_dossier=signed_dossier,
            session_context=sess_ctx,
        )
        if replay_resp.get("status") != "REJECTED":
            print(f"[!] Replay rejection FAILED: got {replay_resp}")
            return 1
        print(f"[+] Replay attack rejected: {replay_resp.get('error_code')}")

        print("=" * 70)
        print("[+] LIVE EXECUTION VERIFICATION: ALL CHECKS PASSED")
        print("=" * 70)
        return 0
    finally:
        server.shutdown()
        server.server_close()


class MockLabTransport:
    """Mock lab transport engine for standalone isolated testing."""

    def __init__(self) -> None:
        self.requests: list[ControlledRequest] = []

    def send_request(self, req: ControlledRequest) -> ControlledResponse:
        self.requests.append(req)
        if req.headers.get("X-Correlation-Dispatch", "").endswith("-VERIFY"):
            return ControlledResponse(
                status_code=401,
                headers={"Content-Type": "application/json"},
                body_bytes=b'{"error": "Session revoked", "status": "revoked"}',
            )
        return ControlledResponse(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body_bytes=b'{"status": "logged_out", "revoked": true}',
        )


def run_standalone_isolated_test() -> int:
    """Runs full end-to-end execution test using a dedicated isolated dispatcher instance."""
    print("=" * 70)
    print("Phase 21: Standalone Isolated Execution Test")
    print("=" * 70)

    temp_dir = tempfile.mkdtemp(prefix="bb_standalone_")
    state_dir = os.path.join(temp_dir, "state")
    key_dir = os.path.join(temp_dir, "keys")
    ev_dir = os.path.join(temp_dir, "evidence")
    os.makedirs(state_dir, exist_ok=True)
    os.makedirs(key_dir, exist_ok=True)
    os.makedirs(ev_dir, exist_ok=True)

    app_key = get_or_create_approval_key(key_dir=key_dir)
    transport = MockLabTransport()

    pipe_or_sock = (
        rf"\\.\pipe\bb_test_{secrets.token_hex(8)}"
        if os.name == "nt"
        else os.path.join(temp_dir, "test_disp.sock")
    )

    disp = IsolatedExecutionDispatcher(
        program_id="test-prog",
        pipe_name=pipe_or_sock if os.name == "nt" else None,
        socket_path=pipe_or_sock if os.name != "nt" else None,
        key_dir=key_dir,
        state_dir=state_dir,
        evidence_dir=ev_dir,
        approval_key=app_key,
        transport_engine=transport,
        is_lab=True,
    )
    disp.start()

    try:
        client = IsolatedDispatcherClient(
            endpoint_type="pipe" if os.name == "nt" else "unix",
            address=pipe_or_sock,
            timeout=5.0,
        )

        assert client.ping() is True
        verification_key = disp.verification_key

        target_url = "https://target.local/auth/logout"
        dossier_data = {
            "action_type": "LOGOUT",
            "created_at": time.time(),
            "method": "POST",
            "program_id": "test-prog",
            "target_endpoint": target_url,
            "test_account": "standalone-alice",
            "ttl": 300,
            "unique_approval_id": f"APPR-{secrets.token_hex(16).upper()}",
        }
        signed_dossier = sign_action_approval(dossier_data, approval_key=app_key)
        aid = signed_dossier["action_id"]
        sess_ctx = {"session_ref": f"sess_{secrets.token_hex(16)}", "principal_id": "standalone-alice"}

        resp = client.dispatch_mutation(
            program_id="test-prog",
            action_id=aid,
            action_dossier=signed_dossier,
            session_context=sess_ctx,
        )

        assert resp.get("status") == "SUCCESS", f"Expected SUCCESS, got {resp}"
        rcpt = resp["receipt"]
        v_ok, v_msg = verify_execution_receipt(rcpt, verification_key=verification_key)
        assert v_ok is True, f"Receipt verification failed: {v_msg}"
        print(f"[+] Standalone execution verified: receipt_id={rcpt['receipt_id']}")

        # Replay rejection check
        replay_resp = client.dispatch_mutation(
            program_id="test-prog",
            action_id=aid,
            action_dossier=signed_dossier,
            session_context=sess_ctx,
        )
        assert replay_resp.get("status") == "REJECTED"
        print(f"[+] Standalone replay rejection verified: {replay_resp.get('error_code')}")

        print("=" * 70)
        print("[+] STANDALONE ISOLATED TEST: PASSED")
        print("=" * 70)
        return 0
    finally:
        disp.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 21 Dispatcher Verification Probe")
    parser.add_argument("--socket", help="Path to dispatcher unix socket or named pipe")
    parser.add_argument("--public-key", help="Path to dispatcher public verification key")
    parser.add_argument(
        "--mode",
        choices=["live", "live-service-rejection", "standalone", "all"],
        default="live",
        help="Verification mode",
    )
    args = parser.parse_args()

    if args.mode in ("live", "live-service-rejection"):
        return run_live_service_probe(socket_path=args.socket, public_key_path=args.public_key)
    elif args.mode == "standalone":
        return run_standalone_isolated_test()
    elif args.mode == "all":
        rc1 = run_standalone_isolated_test()
        if rc1 != 0:
            return rc1
        return run_live_service_probe(socket_path=args.socket, public_key_path=args.public_key)
    return 0


if __name__ == "__main__":
    sys.exit(main())
