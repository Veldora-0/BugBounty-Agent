#!/usr/bin/env python3
"""Exercise and verify one approved action through the installed Linux dispatcher.

The execution mode sends exactly one POST and one follow-up GET to a researcher-owned
HTTPS acceptance endpoint. It then retries the same single-use approval and requires
the service to reject that replay without sending another request.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from framework.auth_correlation.ipc.client import IsolatedDispatcherClient
from framework.auth_correlation.ipc.config import load_scope_engine
from framework.auth_correlation.ipc.receipt import (
    load_dispatcher_verification_key,
    verify_execution_receipt,
)
from framework.auth_correlation.revocation import sign_action_approval
from framework.common.transport import safe_fetch_url


SOCKET_PATH = "/run/bugbounty/dispatcher.sock"
STATE_DIR = Path("/var/lib/bugbounty/state")
EVIDENCE_DIR = Path("/var/lib/bugbounty/evidence")
APPROVAL_FILES = {
    "consumed_approvals.json",
    "consumed_approvals.lock",
    "consumed_nonces.json",
    "consumed_nonces.lock",
}


def _load_result(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Acceptance result must be a regular, non-symlink file")
    with path.open("r", encoding="utf-8") as stream:
        result = json.load(stream)
    if not isinstance(result, dict):
        raise ValueError("Acceptance result has an invalid schema")
    return result


def _check_endpoint(endpoint: str) -> None:
    parsed = urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Acceptance endpoint must be an absolute HTTPS URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Endpoint must not contain credentials, query parameters, or a fragment")
    if parsed.port not in (None, 443):
        raise ValueError("Acceptance endpoint must use standard HTTPS port 443")
    if parsed.hostname.lower().endswith((".localhost", ".local", ".internal", ".test", ".invalid")):
        raise ValueError("Acceptance endpoint must use a public DNS hostname")


def _load_approval_key(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Approval key must be a regular, non-symlink file")
    info = path.stat()
    if info.st_mode & 0o077:
        raise ValueError("Operator test key must be private to its owner (mode 0600)")
    key = path.read_bytes()
    if len(key) != 32:
        raise ValueError("Operator test key must contain exactly 32 bytes")
    return key


def _load_fixture_token(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Fixture token must be a regular, non-symlink file")
    if path.stat().st_mode & 0o077:
        raise ValueError("Fixture token must be private to its owner (mode 0600)")
    token = path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"AUD08-[a-f0-9]{32}", token):
        raise ValueError("Fixture token has an invalid format")
    return token


def execute(args: argparse.Namespace) -> None:
    endpoint = args.endpoint
    _check_endpoint(endpoint)
    key = _load_approval_key(Path(args.approval_key))
    fixture_token = _load_fixture_token(Path(args.fixture_token_file))
    scope = load_scope_engine(args.scope_file)
    if not scope.is_in_scope(endpoint):
        raise ValueError("Acceptance endpoint is not in the temporary dispatcher scope")

    client = IsolatedDispatcherClient(endpoint_type="unix", address=SOCKET_PATH, timeout=20.0)
    status = client.get_status()
    service = status.get("receipt") or {}
    if (
        status.get("status") != "SUCCESS"
        or service.get("is_lab") is not False
        or service.get("production_dispatch_ready") is not True
        or service.get("program_id") != args.program_id
    ):
        raise ValueError("Installed service is not production-ready for the temporary program")

    principal = "aud08-acceptance"
    dossier = sign_action_approval(
        {
            "action_type": "LOGOUT",
            "created_at": time.time(),
            "method": "POST",
            "program_id": args.program_id,
            "target_endpoint": endpoint,
            "test_account": principal,
            "ttl": 180,
            "unique_approval_id": f"APPR-AUD08-{secrets.token_hex(12).upper()}",
        },
        approval_key=key,
    )
    session_ref = f"sess_{secrets.token_hex(16)}"
    session = {
        "session_ref": session_ref,
        "principal_id": principal,
        "volatile_headers": {"Authorization": f"Bearer {fixture_token}"},
    }
    action_nonce = f"NONCE-{secrets.token_hex(16).upper()}"
    replay_nonce = f"NONCE-{secrets.token_hex(16).upper()}"

    response = client.dispatch_mutation(
        program_id=args.program_id,
        action_id=dossier["action_id"],
        action_dossier=dossier,
        session_context=session,
        nonce=action_nonce,
    )
    if response.get("status") != "SUCCESS" or not isinstance(response.get("receipt"), dict):
        raise ValueError(
            "Approved service action failed: "
            f"{response.get('error_code')}: {response.get('error_message')}"
        )

    receipt = response["receipt"]
    verification_key = load_dispatcher_verification_key(args.public_key)
    valid, reason = verify_execution_receipt(
        receipt,
        verification_key,
        expected_action_id=dossier["action_id"],
        expected_nonce=action_nonce,
        expected_program_id=args.program_id,
    )
    if not valid:
        raise ValueError(f"Service receipt did not verify: {reason}")
    if receipt.get("target_endpoint") != endpoint or receipt.get("dispatch_op_id") is None:
        raise ValueError("Receipt is not bound to this endpoint and dispatch")

    mutation = receipt.get("mutation_evidence") or {}
    verification = receipt.get("verification_evidence") or {}
    if mutation.get("status_code", 0) not in range(200, 300):
        raise ValueError("Receipt does not show a successful acceptance POST")
    if verification.get("status_code") not in (401, 403):
        raise ValueError("Receipt does not show the acceptance session rejected on follow-up GET")
    if verification.get("invalidation_result") != "REVOKED":
        raise ValueError("Receipt does not record verified revocation")

    replay = client.dispatch_mutation(
        program_id=args.program_id,
        action_id=dossier["action_id"],
        action_dossier=dossier,
        session_context=session,
        nonce=replay_nonce,
    )
    if (
        replay.get("status") != "REJECTED"
        or replay.get("error_code") != "APPROVAL_CONSUMPTION_FAILED"
        or replay.get("receipt") is not None
    ):
        raise ValueError("Single-use approval replay was not rejected as expected")
    if not re.search(r"already been consumed|replay rejected", replay.get("error_message", ""), re.I):
        raise ValueError("Replay rejection did not identify the consumed approval")

    result = {
        "version": 1,
        "program_id": args.program_id,
        "endpoint": endpoint,
        "action_id": dossier["action_id"],
        "action_nonce": action_nonce,
        "replay_nonce": replay_nonce,
        "session_ref": session_ref,
        "receipt": receipt,
        "replay_status": replay["status"],
        "replay_error_code": replay["error_code"],
    }
    output = Path(args.result_file)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(output, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")

    print("PASS: installed non-lab dispatcher completed one approved POST + revocation GET.")
    print(f"PASS: Ed25519 receipt verified for action {dossier['action_id']}.")
    print("PASS: single-use approval replay was rejected before a second transport call.")
    print("Evidence records are being checked independently by the root acceptance wrapper.")


def preflight(args: argparse.Namespace) -> None:
    endpoint = args.endpoint
    _check_endpoint(endpoint)
    fixture_token = _load_fixture_token(Path(args.fixture_token_file))
    scope = load_scope_engine(args.scope_file)
    if not scope.is_in_scope(endpoint):
        raise ValueError("Acceptance endpoint is not in the temporary dispatcher scope")
    health = safe_fetch_url(
        endpoint,
        method="GET",
        headers={"X-AUD08-Health": fixture_token},
        timeout=10.0,
        max_bytes=1024,
        scope_engine=scope,
    )
    if health is None:
        raise ValueError(
            "Safe-transport preflight failed before dispatcher state or approval consumption; "
            "check Kali direct outbound TCP/443, DNS, TLS trust, and Cloudflare tunnel availability"
        )
    if health.get("status_code") != 204:
        raise ValueError(f"Acceptance fixture health preflight returned HTTP {health.get('status_code')}, expected 204")
    print("PASS: scope-checked pinned HTTPS transport reached the temporary fixture before dispatcher state changes.")


def verify(args: argparse.Namespace) -> None:
    from framework.common.evidence import EvidenceStore

    result = _load_result(Path(args.result_file))
    receipt = result.get("receipt")
    if not isinstance(receipt, dict):
        raise ValueError("Acceptance result has no signed dispatcher receipt")
    if result.get("program_id") != args.program_id or result.get("endpoint") != args.endpoint:
        raise ValueError("Acceptance result is bound to a different program or endpoint")
    key = load_dispatcher_verification_key(args.public_key)
    valid, reason = verify_execution_receipt(
        receipt,
        key,
        expected_action_id=result.get("action_id"),
        expected_nonce=result.get("action_nonce"),
        expected_program_id=args.program_id,
    )
    if not valid:
        raise ValueError(f"Receipt verification failed: {reason}")
    if result.get("replay_status") != "REJECTED" or result.get("replay_error_code") != "APPROVAL_CONSUMPTION_FAILED":
        raise ValueError("Acceptance result does not prove single-use replay rejection")

    store = EvidenceStore(args.evidence_dir)
    descriptors = []
    for field in ("mutation_evidence", "verification_evidence"):
        expected = receipt.get(field)
        if not isinstance(expected, dict):
            raise ValueError(f"Receipt is missing {field}")
        evidence = store.get_evidence(expected.get("evidence_id"))
        if not evidence:
            raise ValueError(f"Receipt evidence {expected.get('evidence_id')} is not readable from disk")
        for key_name in ("request_sha256", "response_sha256"):
            if evidence.get(key_name) != expected.get(key_name):
                raise ValueError(f"Persisted {field} {key_name} does not match the signed receipt")
        metadata = evidence.get("metadata") or {}
        for key_name, expected_value in {
            "action_id": result.get("action_id"),
            "dispatch_op_id": receipt.get("dispatch_op_id"),
            "session_ref": receipt.get("session_ref"),
            "program_id": args.program_id,
            "capture_source": "CONTROLLED_TRANSPORT_DISPATCH",
            "evidence_class": "CONTROLLED_TRANSPORT_DISPATCH",
        }.items():
            if metadata.get(key_name) != expected_value:
                raise ValueError(f"Persisted {field} metadata {key_name} does not match the receipt")
        descriptors.append(evidence)

    state = Path(args.state_dir)
    approvals_path = state / "consumed_approvals.json"
    nonces_path = state / "consumed_nonces.json"
    for path in (approvals_path, nonces_path):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Expected dispatcher security state is missing or unsafe: {path.name}")
    approvals = json.loads(approvals_path.read_text(encoding="utf-8"))
    nonces = json.loads(nonces_path.read_text(encoding="utf-8"))
    consumed = approvals.get("consumed", {})
    entry = consumed.get(result.get("action_id")) if isinstance(consumed, dict) else None
    if not isinstance(entry, dict) or entry.get("dispatch_op_id") != receipt.get("dispatch_op_id"):
        raise ValueError("Consumed approval state is not bound to the signed receipt")
    if entry.get("program_id") != args.program_id or entry.get("target_endpoint") != args.endpoint:
        raise ValueError("Consumed approval state is not bound to the temporary program and endpoint")
    nonce_values = nonces.get("nonces") if isinstance(nonces, dict) else None
    expected_nonces = {result.get("action_nonce"), result.get("replay_nonce")}
    if not isinstance(nonce_values, list) or not expected_nonces.issubset(set(nonce_values)):
        raise ValueError("Dispatcher nonce state does not record action and replay attempts")

    evidence_names = set(os.listdir(args.evidence_dir))
    expected_evidence_names = set()
    for evidence in descriptors:
        for name_field in ("capture_path", "meta_path"):
            evidence_path = Path(evidence[name_field])
            if evidence_path.parent.resolve() != Path(args.evidence_dir).resolve():
                raise ValueError("EvidenceStore returned a path outside the protected evidence directory")
            expected_evidence_names.add(evidence_path.name)
    if evidence_names != expected_evidence_names:
        raise ValueError("Protected evidence directory contains unexpected files; preserving it for review")

    state_names = set(os.listdir(args.state_dir))
    if not state_names.issubset(APPROVAL_FILES) or not {approvals_path.name, nonces_path.name}.issubset(state_names):
        raise ValueError("Dispatcher state directory contains unexpected files; preserving it for review")

    result["_verified_evidence_paths"] = [
        {"capture_path": e["capture_path"], "meta_path": e["meta_path"]} for e in descriptors
    ]
    result["_verified_state_names"] = sorted(state_names)
    output = Path(args.result_file)
    output.unlink()
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")

    print("PASS: signed receipt verified against the installed service public key.")
    print("PASS: both signed evidence records were independently read from disk and matched by digest.")
    print("PASS: approval consumption and both request nonces are present in protected dispatcher state.")
    print("PASS: only the two expected evidence records were created.")


def cleanup(args: argparse.Namespace) -> None:
    result_path = Path(args.result_file)
    if not result_path.exists():
        raise ValueError("No independently verified result file; preserving protected dispatcher artifacts")
    result = _load_result(result_path)
    paths = result.get("_verified_evidence_paths")
    if not isinstance(paths, list) or len(paths) != 2:
        raise ValueError("Evidence paths were not verified; preserving protected dispatcher artifacts")

    expected_evidence_names = set()
    for record in paths:
        if not isinstance(record, dict) or set(record) != {"capture_path", "meta_path"}:
            raise ValueError("Malformed evidence cleanup record")
        for raw_path in record.values():
            path = Path(raw_path)
            if path.parent.resolve() != Path(args.evidence_dir).resolve():
                raise ValueError("Refusing to remove evidence outside the service evidence directory")
            if path.is_symlink() or not path.is_file():
                raise ValueError("Evidence cleanup target is missing or unsafe")
            expected_evidence_names.add(path.name)

    evidence_root = Path(args.evidence_dir)
    if set(os.listdir(evidence_root)) != expected_evidence_names:
        raise ValueError("Evidence directory changed since verification; preserving all files")

    state_root = Path(args.state_dir)
    actual_state_names = set(os.listdir(state_root))
    if not actual_state_names.issubset(APPROVAL_FILES):
        raise ValueError("Dispatcher state changed since verification; preserving all files")
    if actual_state_names != set(result.get("_verified_state_names", [])):
        raise ValueError("Dispatcher state file set changed since verification; preserving all files")
    state_paths = []
    for name in actual_state_names:
        path = state_root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Dispatcher state cleanup target is missing or unsafe")
        state_paths.append(path)

    for record in paths:
        for raw_path in record.values():
            Path(raw_path).unlink()
    for path in state_paths:
        path.unlink()
    result_path.unlink()
    print("PASS: removed only verified AUD-08 fixture evidence and state; service signing key/state directories were preserved.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("execute")
    run_parser.add_argument("--program-id", required=True)
    run_parser.add_argument("--endpoint", required=True)
    run_parser.add_argument("--scope-file", required=True)
    run_parser.add_argument("--approval-key", required=True)
    run_parser.add_argument("--fixture-token-file", required=True)
    run_parser.add_argument("--public-key", default="/etc/bugbounty/dispatcher.pub")
    run_parser.add_argument("--result-file", required=True)
    run_parser.set_defaults(func=execute)

    preflight_parser = subparsers.add_parser("preflight")
    preflight_parser.add_argument("--endpoint", required=True)
    preflight_parser.add_argument("--scope-file", required=True)
    preflight_parser.add_argument("--fixture-token-file", required=True)
    preflight_parser.set_defaults(func=preflight)

    for command in ("verify", "cleanup"):
        cmd_parser = subparsers.add_parser(command)
        cmd_parser.add_argument("--program-id", required=True)
        cmd_parser.add_argument("--endpoint", required=True)
        cmd_parser.add_argument("--public-key", default="/etc/bugbounty/dispatcher.pub")
        cmd_parser.add_argument("--result-file", required=True)
        cmd_parser.add_argument("--state-dir", default=str(STATE_DIR))
        cmd_parser.add_argument("--evidence-dir", default=str(EVIDENCE_DIR))
        cmd_parser.set_defaults(func=verify if command == "verify" else cleanup)

    args = parser.parse_args()
    try:
        args.func(args)
        return 0
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
