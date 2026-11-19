#!/usr/bin/env python3
"""Phase 21: Live Dispatcher Verification Probe.

Validates the live isolated execution dispatcher on Linux / Windows:
1. Connects to the dispatcher IPC endpoint (/run/bugbounty/dispatcher.sock or pipe).
2. Verifies PING and STATUS responses.
3. Validates the pinned Ed25519 public verification key (/etc/bugbounty/dispatcher.pub).
4. Tests negative rejection of unapproved / unauthorized mutation requests.
5. Reports positive systemd execution as NOT RUN: production dispatch correctly blocks
   loopback fixtures, and this probe has no independently owned authorized endpoint.
6. The standalone mode exercises success and replay rejection with an isolated mock transport;
   it is not evidence of successful execution through the installed systemd service.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
import secrets
import sys
import tempfile
import time
from typing import Optional

# Add repository root to path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from framework.auth_correlation.ipc.client import IsolatedDispatcherClient
from framework.auth_correlation.ipc.protocol import PROTOCOL_VERSION
from framework.auth_correlation.ipc.receipt import (
    load_dispatcher_verification_key,
    verify_execution_receipt,
)
from framework.auth_correlation.ipc.service import IsolatedExecutionDispatcher
from framework.auth_correlation.revocation import get_or_create_approval_key, sign_action_approval
from framework.validation.request import ControlledRequest, ControlledResponse


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
    program_id = receipt_info.get("program_id")
    has_app_key = receipt_info.get("has_approval_key", False)
    has_scope_engine = receipt_info.get("has_scope_engine", False)
    production_ready = receipt_info.get("production_dispatch_ready", False)
    prod_iso = receipt_info.get("production_isolation_supported", False)
    plat_lim = receipt_info.get("platform_limitation")

    if not isinstance(program_id, str) or not program_id:
        print("[!] STATUS response does not identify the dispatcher program binding.")
        return 1

    print(f"[+] STATUS query succeeded: dispatcher_id={disp_id}, key_id={key_id}, program_id={program_id}")
    print(f"[*] Production isolation: {prod_iso} (limitation: {plat_lim})")
    print(f"[*] Service has operator approval key configured: {has_app_key}")
    print(f"[*] Service has configured program scope: {has_scope_engine}")
    print(f"[*] Production dispatch ready: {production_ready}")

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
        "action_id": bogus_aid,
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": program_id,
        "target_endpoint": "https://target.local/auth/logout",
        "test_account": "probe-user",
        "ttl": 300,
        "unique_approval_id": f"APPR-{'0' * 32}",
        "approval_signature": f"SIG-{'F' * 128}",
    }
    bogus_sess = {"session_ref": f"sess_{'0' * 32}", "principal_id": "probe-user"}

    try:
        reject_resp = client.dispatch_mutation(
            program_id=program_id,
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

    print("=" * 70)
    print("[!] LIVE SYSTEMD SUCCESSFUL MUTATION: NOT RUN")
    if not has_app_key or not has_scope_engine or not production_ready:
        print("    Reason: the installed service is not fully configured with both a protected")
        print("    operator key and a trusted program scope. Configure it before controlled dispatch.")
    else:
        print("    Reason: this probe has no independently authorized test endpoint. Production")
        print("    dispatch forbids loopback, so it must not reuse a local fixture as a live test.")
    print("    Negative rejection checks PASSED; standalone success is separately simulated.")
    print("=" * 70)
    return 0


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
