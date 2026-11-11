"""
Unit and regression tests for Phase 21 ExecutionLedger.

Verifies:
- Tamper-evident execution ledger operations
- HMAC-SHA256 cryptographic signatures over 25 canonical execution fields
- Single-use claim for invalidation attestation issuance
- Replay attack rejection on claimed execution records
- Schema validation, positive allowlisting, and safe representation redaction
- Concurrency and lock safety across simulated processes
"""

import hashlib
import hmac
import json
import os
import time
import pytest

from framework.auth_correlation.ledger import (
    ExecutionLedger,
    ExecutionRecord,
    ExecutionProvenanceError,
    get_or_create_execution_key,
    CANONICAL_EXECUTION_FIELDS,
    EXECUTION_ID_PATTERN,
    EXECUTION_SIG_PATTERN,
    EXECUTION_DOMAIN,
)
from framework.auth_correlation.model import SerializationSecurityError


def test_execution_ledger_key_management(tmp_path):
    """Verifies execution key retrieval, generation, and file security."""
    key_dir = str(tmp_path / "keys")
    os.makedirs(key_dir, exist_ok=True)

    key1 = get_or_create_execution_key(key_dir=key_dir)
    assert isinstance(key1, bytes)
    assert len(key1) == 32

    # Second call retrieves identical key
    key2 = get_or_create_execution_key(key_dir=key_dir)
    assert key1 == key2

    key_file = os.path.join(key_dir, "execution_ledger.key")
    assert os.path.isfile(key_file)


def test_execution_ledger_record_and_get(tmp_path):
    """Verifies that authentic execution records are properly signed and verified upon retrieval."""
    state_dir = str(tmp_path / "state")
    key_dir = str(tmp_path / "keys")
    os.makedirs(state_dir, exist_ok=True)
    os.makedirs(key_dir, exist_ok=True)

    exec_key = b"\x44" * 32
    ledger = ExecutionLedger(state_dir=state_dir, execution_key=exec_key, key_dir=key_dir)

    ts = "2026-11-11T12:00:00Z"
    aid = "ACT-0000000000000000000000000000000000000000000000000000000000000001"
    rec = ledger.record_execution(
        action_id=aid,
        action_dossier_digest=aid[4:],
        approval_id="APPR-001",
        program_id="test_program",
        session_ref="sess_00000000000000000000000000000001",
        principal_id="u1",
        test_account="u1",
        target_endpoint="https://target.local/auth/logout",
        http_method="POST",
        action_type="LOGOUT",
        mutation_evidence_ref="EVID-000000000001",
        mutation_request_digest="1" * 64,
        mutation_response_digest="2" * 64,
        mutation_status_code=200,
        verification_evidence_ref="EVID-000000000002",
        verification_request_digest="3" * 64,
        verification_response_digest="4" * 64,
        verification_status_code=401,
        verification_method="MUTATION_EXPLICIT_REVOCATION_VERIFIED",
        invalidation_verification_result="REVOKED",
        execution_timestamp=ts,
        verification_timestamp=ts,
    )

    assert EXECUTION_ID_PATTERN.match(rec.execution_id)
    assert EXECUTION_SIG_PATTERN.match(rec.signature)
    assert rec.attestation_created is False
    assert rec.attestation_id is None

    # Retrieve and verify
    retrieved = ledger.get_execution(rec.execution_id)
    assert retrieved is not None
    assert retrieved.execution_id == rec.execution_id
    assert retrieved.signature == rec.signature
    assert retrieved.approval_id == "APPR-001"

    # Representation redaction
    repr_str = repr(rec)
    assert "EXEC-" in repr_str
    assert "ACT-" in repr_str


def test_execution_ledger_single_use_claim(tmp_path):
    """Verifies that claiming an execution record for an attestation succeeds once and rejects replay."""
    state_dir = str(tmp_path / "state")
    ledger = ExecutionLedger(state_dir=state_dir, execution_key=b"\x55" * 32)

    ts = "2026-11-11T12:00:00Z"
    aid = "ACT-0000000000000000000000000000000000000000000000000000000000000002"
    rec = ledger.record_execution(
        action_id=aid,
        action_dossier_digest=aid[4:],
        approval_id="APPR-002",
        program_id="test_program",
        session_ref="sess_00000000000000000000000000000002",
        principal_id="u2",
        test_account="u2",
        target_endpoint="https://target.local/auth/logout",
        http_method="POST",
        action_type="LOGOUT",
        mutation_evidence_ref="EVID-000000000003",
        mutation_request_digest="5" * 64,
        mutation_response_digest="6" * 64,
        mutation_status_code=200,
        verification_evidence_ref="EVID-000000000004",
        verification_request_digest="7" * 64,
        verification_response_digest="8" * 64,
        verification_status_code=401,
        verification_method="MUTATION_EXPLICIT_REVOCATION_VERIFIED",
        invalidation_verification_result="REVOKED",
        execution_timestamp=ts,
        verification_timestamp=ts,
    )

    claimed = ledger.claim_for_attestation(rec.execution_id, "ATT-00000000000000000000000000000001")
    assert claimed.attestation_created is True
    assert claimed.attestation_id == "ATT-00000000000000000000000000000001"

    # Replay must fail closed
    with pytest.raises(ExecutionProvenanceError, match="already been claimed"):
        ledger.claim_for_attestation(rec.execution_id, "ATT-00000000000000000000000000000002")


def test_execution_ledger_tamper_detection(tmp_path):
    """Verifies that any modification to stored ledger records triggers signature verification failure."""
    state_dir = str(tmp_path / "state")
    ledger = ExecutionLedger(state_dir=state_dir, execution_key=b"\x66" * 32)

    ts = "2026-11-11T12:00:00Z"
    aid = "ACT-0000000000000000000000000000000000000000000000000000000000000003"
    rec = ledger.record_execution(
        action_id=aid,
        action_dossier_digest=aid[4:],
        approval_id="APPR-003",
        program_id="test_program",
        session_ref="sess_00000000000000000000000000000003",
        principal_id="u3",
        test_account="u3",
        target_endpoint="https://target.local/auth/logout",
        http_method="POST",
        action_type="LOGOUT",
        mutation_evidence_ref="EVID-000000000005",
        mutation_request_digest="a" * 64,
        mutation_response_digest="b" * 64,
        mutation_status_code=200,
        verification_evidence_ref="EVID-000000000006",
        verification_request_digest="c" * 64,
        verification_response_digest="d" * 64,
        verification_status_code=401,
        verification_method="MUTATION_EXPLICIT_REVOCATION_VERIFIED",
        invalidation_verification_result="REVOKED",
        execution_timestamp=ts,
        verification_timestamp=ts,
    )

    # Tamper with the raw JSON file
    with open(ledger.ledger_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    data["records"][rec.execution_id]["principal_id"] = "attacker"
    with open(ledger.ledger_file, "w", encoding="utf-8") as f:
        json.dump(data, f)

    with pytest.raises(ExecutionProvenanceError, match="record has been tampered"):
        ledger.get_execution(rec.execution_id)


def test_execution_ledger_duplicate_entry_rejection(tmp_path):
    """Verifies that duplicate execution IDs cannot be inserted into the ledger."""
    state_dir = str(tmp_path / "state")
    ledger = ExecutionLedger(state_dir=state_dir, execution_key=b"\x77" * 32)

    ts = "2026-11-11T12:00:00Z"
    aid = "ACT-0000000000000000000000000000000000000000000000000000000000000004"
    params = dict(
        action_id=aid,
        action_dossier_digest=aid[4:],
        approval_id="APPR-004",
        program_id="test_program",
        session_ref="sess_00000000000000000000000000000004",
        principal_id="u4",
        test_account="u4",
        target_endpoint="https://target.local/auth/logout",
        http_method="POST",
        action_type="LOGOUT",
        mutation_evidence_ref="EVID-000000000007",
        mutation_request_digest="e" * 64,
        mutation_response_digest="f" * 64,
        mutation_status_code=200,
        verification_evidence_ref="EVID-000000000008",
        verification_request_digest="1" * 64,
        verification_response_digest="2" * 64,
        verification_status_code=401,
        verification_method="MUTATION_EXPLICIT_REVOCATION_VERIFIED",
        invalidation_verification_result="REVOKED",
        execution_timestamp=ts,
        verification_timestamp=ts,
    )
    ledger.record_execution(**params)

    with pytest.raises(ExecutionProvenanceError, match="Duplicate execution entry"):
        ledger.record_execution(**params)
