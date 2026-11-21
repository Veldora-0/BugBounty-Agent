"""Regression tests for durable, fail-closed Phase 21 dispatcher state."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import secrets
import threading
import time

import pytest

from framework.auth_correlation.ipc.protocol import PROTOCOL_VERSION
from framework.auth_correlation.ipc.service import IsolatedExecutionDispatcher
from framework.auth_correlation.dispatcher import ControlledDispatchWorkflow
from framework.auth_correlation.ipc.receipt import derive_verification_key, sign_execution_receipt
from framework.auth_correlation.model import ApprovalSecurityError, CorrelatedSessionContext
from framework.auth_correlation.revocation import sign_action_approval
from framework.validation.request import ControlledRequest, ControlledResponse


def _signed_dossier(key: bytes, approval_suffix: str) -> dict:
    dossier = {
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": "state-test-program",
        "target_endpoint": "https://authorized.example/logout",
        "test_account": "alice",
        "ttl": 300,
        "unique_approval_id": f"appr_state_{approval_suffix}",
    }
    return sign_action_approval(dossier, approval_key=key)


def _request(dossier: dict, nonce: str) -> dict:
    return {
        "version": PROTOCOL_VERSION,
        "request_id": f"REQ-{secrets.token_hex(16).upper()}",
        "nonce": nonce,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "action": "DISPATCH_MUTATION",
        "payload": {
            "program_id": "state-test-program",
            "action_id": dossier["action_id"],
            "action_dossier": dossier,
            "session_context": {
                "session_ref": f"sess_{'0' * 32}",
                "principal_id": "alice",
            },
        },
    }


@pytest.mark.parametrize(
    "contents",
    [
        b"{malformed-json",
        b'{"consumed": {}}',
        b'{"version": 2, "consumed": {}}',
        b'{"version": 1, "consumed": []}',
        b'{"version": 1, "consumed": {"ACT-' + b"0" * 64 + b'": []}}',
    ],
)
def test_corrupt_approval_registry_is_not_replaced(tmp_path, contents):
    key = secrets.token_bytes(32)
    dispatcher = IsolatedExecutionDispatcher(
        program_id="state-test-program",
        key_dir=str(tmp_path / "keys"),
        state_dir=str(tmp_path / "state"),
        evidence_dir=str(tmp_path / "evidence"),
        approval_key=key,
        is_lab=True,
    )
    path = dispatcher._get_consumed_registry_path()
    with open(path, "wb") as registry:
        registry.write(contents)

    dossier = _signed_dossier(key, "approval")
    with pytest.raises(ValueError, match="Consumed approvals registry corrupted"):
        dispatcher._atomically_consume_approval(
            dossier["action_id"],
            dossier,
            {"principal_id": "alice", "session_ref": f"sess_{'0' * 32}"},
            "DISP-OP-test",
        )

    with open(path, "rb") as registry:
        assert registry.read() == contents


@pytest.mark.parametrize(
    "contents",
    [
        b"{malformed-json",
        b'{"nonces": []}',
        b'{"version": 2, "nonces": []}',
        b'{"version": 1, "nonces": "not-a-list"}',
        b'{"version": 1, "nonces": ["not-a-nonce"]}',
    ],
)
def test_corrupt_nonce_registry_fails_closed_without_replacement(tmp_path, contents):
    dispatcher = IsolatedExecutionDispatcher(
        program_id="state-test-program",
        key_dir=str(tmp_path / "keys"),
        state_dir=str(tmp_path / "state"),
        evidence_dir=str(tmp_path / "evidence"),
        approval_key=secrets.token_bytes(32),
        is_lab=True,
    )
    path = dispatcher._get_nonces_path()
    with open(path, "wb") as registry:
        registry.write(contents)

    with pytest.raises(ValueError, match="nonce registry"):
        dispatcher._reserve_nonce(f"NONCE-{'1' * 32}")

    with open(path, "rb") as registry:
        assert registry.read() == contents


def test_nonce_reservation_survives_restart_and_does_not_evict_old_nonces(tmp_path):
    first = IsolatedExecutionDispatcher(
        program_id="state-test-program",
        key_dir=str(tmp_path / "keys"),
        state_dir=str(tmp_path / "state"),
        evidence_dir=str(tmp_path / "evidence"),
        approval_key=secrets.token_bytes(32),
        is_lab=True,
    )
    existing = [f"NONCE-{value:032X}" for value in range(10000)]
    with open(first._get_nonces_path(), "w", encoding="utf-8") as registry:
        json.dump({"version": 1, "nonces": existing}, registry)

    new_nonce = f"NONCE-{'F' * 32}"
    first._reserve_nonce(new_nonce)
    with open(first._get_nonces_path(), "r", encoding="utf-8") as registry:
        saved = json.load(registry)
    assert len(saved["nonces"]) == 10001
    assert saved["nonces"][0] == existing[0]

    restarted = IsolatedExecutionDispatcher(
        program_id="state-test-program",
        key_dir=str(tmp_path / "keys"),
        state_dir=str(tmp_path / "state"),
        evidence_dir=str(tmp_path / "evidence"),
        approval_key=secrets.token_bytes(32),
        is_lab=True,
    )
    with pytest.raises(ValueError, match="already been consumed"):
        restarted._reserve_nonce(existing[0])


class _ConcurrentTransport:
    def __init__(self):
        self.mutation_entered = threading.Event()
        self.release_mutation = threading.Event()
        self.mutation_count = 0
        self._lock = threading.Lock()

    def send_request(self, request: ControlledRequest) -> ControlledResponse:
        dispatch = request.headers.get("X-Correlation-Dispatch", "")
        if dispatch.endswith("-VERIFY"):
            return ControlledResponse(401, {"content-type": "text/plain"}, b"expired")

        with self._lock:
            self.mutation_count += 1
        self.mutation_entered.set()
        if not self.release_mutation.wait(timeout=3):
            raise TimeoutError("test did not release mutation transport")
        return ControlledResponse(
            200,
            {"content-type": "application/json"},
            b'{"status":"logged_out","revoked":true}',
        )


def test_concurrent_requests_cannot_mutate_with_same_nonce(tmp_path):
    approval_key = secrets.token_bytes(32)
    transport = _ConcurrentTransport()
    dispatcher = IsolatedExecutionDispatcher(
        program_id="state-test-program",
        key_dir=str(tmp_path / "keys"),
        state_dir=str(tmp_path / "state"),
        evidence_dir=str(tmp_path / "evidence"),
        approval_key=approval_key,
        transport_engine=transport,
        is_lab=True,
    )
    nonce = f"NONCE-{'A' * 32}"
    request_one = _request(_signed_dossier(approval_key, "first"), nonce)
    request_two = _request(_signed_dossier(approval_key, "second"), nonce)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(dispatcher.handle_request, request_one)
        assert transport.mutation_entered.wait(timeout=2)
        second = pool.submit(dispatcher.handle_request, request_two)
        time.sleep(0.1)
        transport.release_mutation.set()
        responses = [first.result(timeout=3), second.result(timeout=3)]

    assert transport.mutation_count == 1
    assert sorted(response["status"] for response in responses) == ["REJECTED", "SUCCESS"]
    replay = next(response for response in responses if response["status"] == "REJECTED")
    assert replay["error_code"] == "NONCE_REPLAY_DETECTED"


class _WritableStoreWithoutRetrieval:
    def is_writable(self) -> bool:
        return True


class _RecordingDispatcherClient:
    def __init__(self):
        self.dispatch_count = 0

    def ping(self) -> bool:
        return True

    def dispatch_mutation(self, *args, **kwargs):
        self.dispatch_count += 1
        return {"status": "ERROR", "error_code": "UNEXPECTED_TEST_DISPATCH"}


def test_writable_evidence_store_without_retrieval_fails_before_dispatch(tmp_path):
    app_key = secrets.token_bytes(32)
    dossier = _signed_dossier(app_key, "no-retrieval")
    client = _RecordingDispatcherClient()
    workflow = ControlledDispatchWorkflow(
        program_id="state-test-program",
        state_dir=str(tmp_path / "state"),
        evidence_store=_WritableStoreWithoutRetrieval(),
        transport_engine=object(),
        scope_engine=type("Scope", (), {"is_in_scope": lambda self, _: True})(),
        approval_key=app_key,
        dispatcher_client=client,
        dispatcher_verification_key=secrets.token_bytes(32),
    )

    with pytest.raises(ApprovalSecurityError, match="must implement get_evidence"):
        workflow.execute(
            CorrelatedSessionContext(f"sess_{'0' * 32}", "alice"),
            dossier["action_id"],
            dossier,
        )

    assert client.dispatch_count == 0


def test_custom_evidence_store_digest_mismatch_fails_closed(tmp_path):
    app_key = secrets.token_bytes(32)
    dossier = _signed_dossier(app_key, "bad-digest")
    signing_key = secrets.token_bytes(32)
    mut_id = "EVID-000000000001"
    ver_id = "EVID-000000000002"
    receipt = {
        "version": 1,
        "receipt_id": "RCPT-" + "1" * 32,
        "dispatcher_id": "DISPATCHER-TEST",
        "dispatcher_key_id": "KEY-DISPATCHER-ED25519-V1",
        "dispatch_op_id": "DISP-OP-" + "2" * 64,
        "action_id": dossier["action_id"],
        "action_dossier_digest": dossier["action_id"][4:],
        "approval_id": dossier["unique_approval_id"],
        "request_nonce": "",
        "execution_id": "EXEC-" + "3" * 32,
        "program_id": "state-test-program",
        "principal_id": "alice",
        "session_ref": f"sess_{'0' * 32}",
        "target_endpoint": dossier["target_endpoint"],
        "http_method": "POST",
        "action_type": "LOGOUT",
        "scope_decision": "ALLOWED",
        "execution_outcome": "REVOCATION_VERIFIED",
        "mutation_evidence": {
            "evidence_id": mut_id,
            "request_sha256": "a" * 64,
            "response_sha256": "b" * 64,
            "status_code": 200,
            "timestamp": "2026-11-21T00:00:00Z",
        },
        "verification_evidence": {
            "evidence_id": ver_id,
            "invalidation_result": "REVOKED",
            "request_sha256": "c" * 64,
            "response_sha256": "d" * 64,
            "status_code": 401,
            "timestamp": "2026-11-21T00:00:01Z",
            "verification_method": "POST_MUTATION_PROBE_CONFIRMED_401",
        },
        "consumption_token": secrets.token_hex(32),
        "issued_at": "2026-11-21T00:00:01Z",
    }

    class SignedClient:
        def ping(self):
            return True

        def dispatch_mutation(self, *args, nonce=None, **kwargs):
            receipt["request_nonce"] = nonce
            receipt["signature"] = sign_execution_receipt(receipt, signing_key)
            return {"status": "SUCCESS", "receipt": receipt}

    class MismatchingEvidenceStore:
        def is_writable(self):
            return True

        def get_evidence(self, evidence_id):
            return {
                "evidence_id": evidence_id,
                "request_sha256": "f" * 64,
                "response_sha256": "e" * 64,
            }

    workflow = ControlledDispatchWorkflow(
        program_id="state-test-program",
        state_dir=str(tmp_path / "state"),
        evidence_store=MismatchingEvidenceStore(),
        transport_engine=object(),
        scope_engine=type("Scope", (), {"is_in_scope": lambda self, _: True})(),
        approval_key=app_key,
        dispatcher_client=SignedClient(),
        dispatcher_verification_key=derive_verification_key(signing_key),
    )

    with pytest.raises(ApprovalSecurityError, match="on-disk digests do not match receipt digests"):
        workflow.execute(
            CorrelatedSessionContext(f"sess_{'0' * 32}", "alice"),
            dossier["action_id"],
            dossier,
        )
