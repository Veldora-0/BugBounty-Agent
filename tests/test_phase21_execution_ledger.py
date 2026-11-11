"""
Unit and regression tests for Phase 21 ExecutionLedger and ExecutionCapability.

Verifies:
- Tamper-evident execution ledger operations
- Cryptographic execution capabilities signed under execution_capability.key (CAP-SIG-...)
- HMAC-SHA256 cryptographic signatures over 25 canonical execution fields
- Strict evidence-to-ledger binding and disk byte recomputations
- Single-use claim for invalidation attestation issuance
- Replay attack rejection on claimed execution records
- Complete adversarial testing matrix (Corrections A, B, C, D):
  * Direct caller invokes record_execution() with fabricated data -> fails closed
  * Caller manually constructs ExecutionRecord -> marked is_testing_primitive, rejected by Mode A
  * Caller reuses legitimate record with altered action/session data -> fails closed
  * Caller reuses execution capability for another program -> fails closed
  * Caller substitutes another evidence reference -> fails closed
  * Caller modifies request/response digest -> fails closed
  * Duplicate execution issuance -> fails closed
  * Duplicate attestation issuance -> fails closed
  * Approval replay -> fails closed
  * Tampered mutation bytes on disk -> fails closed
  * Tampered verification bytes on disk -> fails closed
  * Swapped mutation/verification captures -> fails closed
  * Cross-execution capture reuse -> fails closed
  * Simulated Windows DACL enforcement failure -> fails closed
  * Simulated Windows DACL verification failure -> fails closed
"""

import copy
import hashlib
import hmac
import json
import os
import secrets
import stat
import time
from unittest.mock import patch
import pytest

from framework.auth_correlation.ledger import (
    ExecutionLedger,
    ExecutionRecord,
    ExecutionCapability,
    ExecutionProvenanceError,
    issue_execution_capability,
    get_or_create_execution_key,
    get_or_create_capability_key,
    CANONICAL_EXECUTION_FIELDS,
    CANONICAL_CAPABILITY_FIELDS,
    EXECUTION_ID_PATTERN,
    EXECUTION_SIG_PATTERN,
    CAPABILITY_ID_PATTERN,
    CAPABILITY_SIG_PATTERN,
    EXECUTION_DOMAIN,
    CAPABILITY_DOMAIN,
)
from framework.auth_correlation.model import (
    CorrelatedSessionContext,
    ControlledExecutionResult,
    CorrelationLifecycle,
    EvidencePersistenceError,
    SerializationSecurityError,
    AttestationSecurityError,
)
from framework.auth_correlation.revocation import (
    PostRevocationResourceValidator,
    ApprovalSecurityError,
    _create_controlled_invalidation_attestation_from_record,
    get_or_create_attestation_key,
)
from framework.common.evidence import EvidenceStore
from framework.validation.request import ControlledResponse


def _create_valid_execution_fixture(
    tmp_path,
    action_suffix: str = "01",
    prog_id: str = "test_program",
    sess_ref: str = "sess_00000000000000000000000000000001",
    principal_id: str = "u1",
    target_endpoint: str = "https://target.local/auth/logout",
    method: str = "POST",
    action_type: str = "LOGOUT",
    invalidation_result: str = "REVOKED",
    ver_method: str = "MUTATION_EXPLICIT_REVOCATION_VERIFIED",
):
    """Helper to create a fully consistent execution environment with authentic evidence and consumed approvals."""
    state_dir = str(tmp_path / f"state_{action_suffix}")
    key_dir = str(tmp_path / f"keys_{action_suffix}")
    ev_dir = str(tmp_path / f"ev_{action_suffix}")
    os.makedirs(state_dir, exist_ok=True)
    os.makedirs(key_dir, exist_ok=True)
    os.makedirs(ev_dir, exist_ok=True)

    store = EvidenceStore(ev_dir)
    ledger = ExecutionLedger(state_dir=state_dir, key_dir=key_dir)

    clean_aid = f"ACT-{(action_suffix * 32)[:64]}"
    app_id = f"APPR-{(action_suffix * 16)[:32]}"
    c_token = secrets.token_hex(32)
    ts = "2026-11-11T12:00:00Z"

    # Save mutation capture
    mut_req = f"{method} {target_endpoint}\nAction: {clean_aid}"
    mut_res = 'HTTP 200 OK\n{"status": "logged_out", "revoked": true}'
    mut_cap = store.save_http_capture(
        request_text=mut_req,
        response_text=mut_res,
        metadata={
            "event_type": "SESSION_REVOCATION",
            "session_ref": sess_ref,
            "principal_id": principal_id,
            "program_id": prog_id,
            "action_id": clean_aid,
        },
        prefix=f"mut_{action_suffix}",
    )

    # Save verification capture
    ver_req = f"GET /auth/verify?aid={clean_aid}\nAuthorization: Bearer test"
    ver_res = 'HTTP 401 Unauthorized\n{"error": "Session revoked"}'
    ver_cap = store.save_http_capture(
        request_text=ver_req,
        response_text=ver_res,
        metadata={
            "event_type": "SESSION_REVOCATION",
            "session_ref": sess_ref,
            "principal_id": principal_id,
            "program_id": prog_id,
            "action_id": clean_aid,
            "verification_method": ver_method,
        },
        prefix=f"ver_{action_suffix}",
    )

    # Register consumed approval
    consumed_path = os.path.join(state_dir, "consumed_approvals.json")
    consumed_entry = {
        "approval_id": app_id,
        "action_id": clean_aid,
        "consumption_token": c_token,
        "program_id": prog_id,
        "session_ref": sess_ref,
        "principal_id": principal_id,
        "test_account": principal_id,
        "target_endpoint": target_endpoint,
        "method": method,
        "action_type": action_type,
        "consumed_at": ts,
        "execution_id": None,
    }
    consumed_data = {"version": "1.0", "consumed": {clean_aid: consumed_entry}}
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump(consumed_data, f, indent=2)

    # Issue ExecutionCapability
    cap = issue_execution_capability(
        action_id=clean_aid,
        action_dossier_digest=clean_aid[4:],
        approval_id=app_id,
        program_id=prog_id,
        session_ref=sess_ref,
        principal_id=principal_id,
        test_account=principal_id,
        target_endpoint=target_endpoint,
        http_method=method,
        action_type=action_type,
        mutation_evidence_ref=mut_cap["evidence_id"],
        mutation_request_digest=mut_cap["request_sha256"],
        mutation_response_digest=mut_cap["response_sha256"],
        mutation_status_code=200,
        verification_evidence_ref=ver_cap["evidence_id"],
        verification_request_digest=ver_cap["request_sha256"],
        verification_response_digest=ver_cap["response_sha256"],
        verification_status_code=401,
        verification_method=ver_method,
        invalidation_verification_result=invalidation_result,
        execution_timestamp=ts,
        verification_timestamp=ts,
        consumption_token=c_token,
        key_dir=key_dir,
    )

    return ledger, cap, store, consumed_path, clean_aid, app_id, c_token


def test_execution_ledger_key_management(tmp_path):
    """Verifies execution and capability key retrieval, generation, and file security."""
    key_dir = str(tmp_path / "keys")
    os.makedirs(key_dir, exist_ok=True)

    exec_key1 = get_or_create_execution_key(key_dir=key_dir)
    assert isinstance(exec_key1, bytes)
    assert len(exec_key1) == 32

    # Second call retrieves identical key
    exec_key2 = get_or_create_execution_key(key_dir=key_dir)
    assert exec_key1 == exec_key2

    cap_key1 = get_or_create_capability_key(key_dir=key_dir)
    assert isinstance(cap_key1, bytes)
    assert len(cap_key1) == 32
    # Execution key and capability key are distinct
    assert exec_key1 != cap_key1

    cap_key2 = get_or_create_capability_key(key_dir=key_dir)
    assert cap_key1 == cap_key2

    assert os.path.isfile(os.path.join(key_dir, "execution_ledger.key"))
    assert os.path.isfile(os.path.join(key_dir, "execution_capability.key"))


def test_execution_ledger_record_and_get(tmp_path):
    """Verifies that authentic execution records are properly signed and verified upon retrieval."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "01")

    # Direct caller invoking without capability is strictly rejected
    with pytest.raises(ExecutionProvenanceError, match="Ordinary callers cannot create execution records"):
        ledger.record_execution(action_id="ACT-fabricated")

    # Record genuine execution
    rec = ledger.record_execution(
        capability=cap,
        evidence_store=store,
        consumed_approvals_path=consumed_path,
    )

    assert EXECUTION_ID_PATTERN.match(rec.execution_id)
    assert EXECUTION_SIG_PATTERN.match(rec.signature)
    assert rec.attestation_created is False
    assert rec.attestation_id is None
    assert rec.is_testing_primitive is False

    # Consumed approval was marked with execution_id
    with open(consumed_path, "r", encoding="utf-8") as f:
        consumed_check = json.load(f)
    assert consumed_check["consumed"][clean_aid]["execution_id"] == rec.execution_id

    # Retrieve and verify
    retrieved = ledger.get_execution(rec.execution_id)
    assert retrieved is not None
    assert retrieved.execution_id == rec.execution_id
    assert retrieved.signature == rec.signature
    assert retrieved.approval_id == app_id
    assert retrieved.action_id == clean_aid

    # Representation redaction
    repr_str = repr(rec)
    assert "EXEC-" in repr_str
    assert "ACT-" in repr_str


def test_execution_ledger_single_use_claim(tmp_path):
    """Verifies that claiming an execution record for an attestation succeeds once and rejects replay."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "02")

    rec = ledger.record_execution(
        capability=cap,
        evidence_store=store,
        consumed_approvals_path=consumed_path,
    )

    claimed = ledger.claim_for_attestation(rec.execution_id, "ATT-00000000000000000000000000000001")
    assert claimed.attestation_created is True
    assert claimed.attestation_id == "ATT-00000000000000000000000000000001"

    # Replay must fail closed
    with pytest.raises(ExecutionProvenanceError, match="already been claimed"):
        ledger.claim_for_attestation(rec.execution_id, "ATT-00000000000000000000000000000002")


def test_execution_ledger_tamper_detection(tmp_path):
    """Verifies that any modification to stored ledger records triggers signature verification failure."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "03")

    rec = ledger.record_execution(
        capability=cap,
        evidence_store=store,
        consumed_approvals_path=consumed_path,
    )

    # Tamper with the raw JSON file on disk
    with open(ledger.ledger_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    data["records"][rec.execution_id]["principal_id"] = "attacker"
    with open(ledger.ledger_file, "w", encoding="utf-8") as f:
        json.dump(data, f)

    with pytest.raises(ExecutionProvenanceError, match="record has been tampered"):
        ledger.get_execution(rec.execution_id)


def test_execution_ledger_duplicate_entry_rejection(tmp_path):
    """Verifies that duplicate execution issuance on the same action/approval is rejected."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "04")

    rec = ledger.record_execution(
        capability=cap,
        evidence_store=store,
        consumed_approvals_path=consumed_path,
    )

    # Attempting to record execution again with same capability/approval fails closed
    with pytest.raises(ExecutionProvenanceError, match="already been executed"):
        ledger.record_execution(
            capability=cap,
            evidence_store=store,
            consumed_approvals_path=consumed_path,
        )


def test_adversarial_direct_caller_fabricated_execution(tmp_path):
    """Correction A: Ordinary callers cannot forge execution records by calling record_execution with fabricated args."""
    state_dir = str(tmp_path / "state_fab")
    os.makedirs(state_dir, exist_ok=True)
    ledger = ExecutionLedger(state_dir=state_dir)

    with pytest.raises(ExecutionProvenanceError, match="Ordinary callers cannot create execution records"):
        ledger.record_execution(
            action_id="ACT-0000000000000000000000000000000000000000000000000000000000000001",
            approval_id="APPR-FORGED",
            target_endpoint="https://target.local/auth/logout",
        )


def test_adversarial_testing_primitive_rejected_by_mode_a(tmp_path):
    """Correction A: Low-level testing primitives are rejected by Mode A invalidation verification."""
    state_dir = str(tmp_path / "state_prim")
    key_dir = str(tmp_path / "keys_prim")
    ev_dir = str(tmp_path / "ev_prim")
    os.makedirs(state_dir, exist_ok=True)
    os.makedirs(key_dir, exist_ok=True)
    os.makedirs(ev_dir, exist_ok=True)

    store = EvidenceStore(ev_dir)
    ledger = ExecutionLedger(state_dir=state_dir, key_dir=key_dir)

    ts = "2026-11-11T12:00:00Z"
    aid = "ACT-0000000000000000000000000000000000000000000000000000000000000099"
    raw_rec = ledger._record_raw_record_for_testing(
        action_id=aid,
        action_dossier_digest=aid[4:],
        approval_id="APPR-RAW-TEST-01",
        program_id="test_program",
        session_ref="sess_00000000000000000000000000000099",
        principal_id="u99",
        test_account="u99",
        target_endpoint="https://target.local/auth/logout",
        http_method="POST",
        action_type="LOGOUT",
        mutation_evidence_ref="EVID-000000000091",
        mutation_request_digest="1" * 64,
        mutation_response_digest="2" * 64,
        mutation_status_code=200,
        verification_evidence_ref="EVID-000000000092",
        verification_request_digest="3" * 64,
        verification_response_digest="4" * 64,
        verification_status_code=401,
        verification_method="MUTATION_EXPLICIT_REVOCATION_VERIFIED",
        invalidation_verification_result="REVOKED",
        execution_timestamp=ts,
        verification_timestamp=ts,
    )
    assert raw_rec.is_testing_primitive is True

    # Mode A attestation creation from testing primitive must fail closed
    with pytest.raises((ExecutionProvenanceError, AttestationSecurityError), match="test primitive"):
        _create_controlled_invalidation_attestation_from_record(
            execution_record=raw_rec,
            execution_ledger=ledger,
            evidence_store=store,
            key_dir=key_dir,
        )


def test_adversarial_capability_reuse_across_programs(tmp_path):
    """Correction A/B: Reusing an execution capability for a different program fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "05", prog_id="prog_alpha")

    # Attacker tampers program_id in capability
    tampered_cap = copy.deepcopy(cap)
    tampered_cap.program_id = "prog_beta"

    # Signature fails closed immediately
    with pytest.raises(ExecutionProvenanceError, match="capability signature verification failed"):
        ledger.record_execution(
            capability=tampered_cap,
            evidence_store=store,
            consumed_approvals_path=consumed_path,
        )


def test_adversarial_evidence_reference_substitution(tmp_path):
    """Correction B: Substituting an unverified evidence reference in capability fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "06")

    # Attacker re-signs capability with substitute non-existent evidence reference
    cap_key = ledger._get_capability_key()
    sub_cap = issue_execution_capability(
        action_id=cap.action_id,
        action_dossier_digest=cap.action_dossier_digest,
        approval_id=cap.approval_id,
        program_id=cap.program_id,
        session_ref=cap.session_ref,
        principal_id=cap.principal_id,
        test_account=cap.test_account,
        target_endpoint=cap.target_endpoint,
        http_method=cap.http_method,
        action_type=cap.action_type,
        mutation_evidence_ref="EVID-FFFFFFFFFFFF",
        mutation_request_digest=cap.mutation_request_digest,
        mutation_response_digest=cap.mutation_response_digest,
        mutation_status_code=cap.mutation_status_code,
        verification_evidence_ref=cap.verification_evidence_ref,
        verification_request_digest=cap.verification_request_digest,
        verification_response_digest=cap.verification_response_digest,
        verification_status_code=cap.verification_status_code,
        verification_method=cap.verification_method,
        invalidation_verification_result=cap.invalidation_verification_result,
        execution_timestamp=cap.execution_timestamp,
        verification_timestamp=cap.verification_timestamp,
        consumption_token=cap.consumption_token,
        capability_key=cap_key,
    )

    with pytest.raises(ExecutionProvenanceError, match="Mutation evidence 'EVID-FFFFFFFFFFFF' not found"):
        ledger.record_execution(
            capability=sub_cap,
            evidence_store=store,
            consumed_approvals_path=consumed_path,
        )


def test_adversarial_request_response_digest_modification(tmp_path):
    """Correction B: Modifying request/response digest in capability fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "07")

    cap_key = ledger._get_capability_key()
    forged_cap = issue_execution_capability(
        action_id=cap.action_id,
        action_dossier_digest=cap.action_dossier_digest,
        approval_id=cap.approval_id,
        program_id=cap.program_id,
        session_ref=cap.session_ref,
        principal_id=cap.principal_id,
        test_account=cap.test_account,
        target_endpoint=cap.target_endpoint,
        http_method=cap.http_method,
        action_type=cap.action_type,
        mutation_evidence_ref=cap.mutation_evidence_ref,
        mutation_request_digest="f" * 64,  # Forged digest
        mutation_response_digest=cap.mutation_response_digest,
        mutation_status_code=cap.mutation_status_code,
        verification_evidence_ref=cap.verification_evidence_ref,
        verification_request_digest=cap.verification_request_digest,
        verification_response_digest=cap.verification_response_digest,
        verification_status_code=cap.verification_status_code,
        verification_method=cap.verification_method,
        invalidation_verification_result=cap.invalidation_verification_result,
        execution_timestamp=cap.execution_timestamp,
        verification_timestamp=cap.verification_timestamp,
        consumption_token=cap.consumption_token,
        capability_key=cap_key,
    )

    with pytest.raises(ExecutionProvenanceError, match="Mutation request digest mismatch with actual capture content"):
        ledger.record_execution(
            capability=forged_cap,
            evidence_store=store,
            consumed_approvals_path=consumed_path,
        )


def test_adversarial_tampered_mutation_bytes_on_disk(tmp_path):
    """Correction B: Tampering with raw mutation capture bytes on disk fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "08")

    mut_ev = store.get_evidence(cap.mutation_evidence_ref)
    with open(mut_ev["capture_path"], "ab") as f:
        f.write(b"\nTAMPERED_MUTATION_BYTES")

    with pytest.raises(ExecutionProvenanceError, match="not found or corrupted in EvidenceStore"):
        ledger.record_execution(
            capability=cap,
            evidence_store=store,
            consumed_approvals_path=consumed_path,
        )


def test_adversarial_tampered_verification_bytes_on_disk(tmp_path):
    """Correction B: Tampering with raw verification capture bytes on disk fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "09")

    ver_ev = store.get_evidence(cap.verification_evidence_ref)
    with open(ver_ev["capture_path"], "ab") as f:
        f.write(b"\nTAMPERED_VERIFICATION_BYTES")

    with pytest.raises(ExecutionProvenanceError, match="not found or corrupted in EvidenceStore"):
        ledger.record_execution(
            capability=cap,
            evidence_store=store,
            consumed_approvals_path=consumed_path,
        )


def test_adversarial_swapped_mutation_and_verification_captures(tmp_path):
    """Correction B: Swapping mutation and verification captures fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "10")

    cap_key = ledger._get_capability_key()
    swapped_cap = issue_execution_capability(
        action_id=cap.action_id,
        action_dossier_digest=cap.action_dossier_digest,
        approval_id=cap.approval_id,
        program_id=cap.program_id,
        session_ref=cap.session_ref,
        principal_id=cap.principal_id,
        test_account=cap.test_account,
        target_endpoint=cap.target_endpoint,
        http_method=cap.http_method,
        action_type=cap.action_type,
        mutation_evidence_ref=cap.verification_evidence_ref,  # Swapped
        mutation_request_digest=cap.verification_request_digest,
        mutation_response_digest=cap.verification_response_digest,
        mutation_status_code=cap.mutation_status_code,
        verification_evidence_ref=cap.mutation_evidence_ref,  # Swapped
        verification_request_digest=cap.mutation_request_digest,
        verification_response_digest=cap.mutation_response_digest,
        verification_status_code=cap.verification_status_code,
        verification_method=cap.verification_method,
        invalidation_verification_result=cap.invalidation_verification_result,
        execution_timestamp=cap.execution_timestamp,
        verification_timestamp=cap.verification_timestamp,
        consumption_token=cap.consumption_token,
        capability_key=cap_key,
    )

    with pytest.raises(ExecutionProvenanceError, match="evidence metadata"):
        ledger.record_execution(
            capability=swapped_cap,
            evidence_store=store,
            consumed_approvals_path=consumed_path,
        )


def test_adversarial_cross_execution_evidence_reuse(tmp_path):
    """Correction B: Attempting to bind previously recorded evidence to another execution fails closed."""
    ledger, cap1, store, consumed_path1, clean_aid1, app_id1, c_token1 = _create_valid_execution_fixture(tmp_path, "11a")

    # Record first execution
    rec1 = ledger.record_execution(
        capability=cap1,
        evidence_store=store,
        consumed_approvals_path=consumed_path1,
    )

    # Now attempt second execution trying to reuse cap1's mutation evidence
    clean_aid2 = "ACT-" + "2" * 64
    app_id2 = "APPR-" + "2" * 32
    c_token2 = secrets.token_hex(32)
    consumed_path2 = os.path.join(ledger.state_dir, "consumed_approvals.json")
    with open(consumed_path2, "r", encoding="utf-8") as f:
        cdata = json.load(f)
    cdata["consumed"][clean_aid2] = {
        "approval_id": app_id2,
        "action_id": clean_aid2,
        "consumption_token": c_token2,
        "program_id": cap1.program_id,
        "session_ref": cap1.session_ref,
        "principal_id": cap1.principal_id,
        "test_account": cap1.principal_id,
        "target_endpoint": cap1.target_endpoint,
        "method": cap1.http_method,
        "action_type": cap1.action_type,
        "consumed_at": "2026-11-11T12:00:00Z",
        "execution_id": None,
    }
    with open(consumed_path2, "w", encoding="utf-8") as f:
        json.dump(cdata, f, indent=2)

    # Create new verification capture
    ver_cap2 = store.save_http_capture(
        request_text=f"GET /auth/verify?aid={clean_aid2}\nAuthorization: Bearer test",
        response_text='HTTP 401 Unauthorized\n{"error": "Session revoked"}',
        metadata={
            "event_type": "SESSION_REVOCATION",
            "session_ref": cap1.session_ref,
            "principal_id": cap1.principal_id,
            "program_id": cap1.program_id,
            "action_id": clean_aid2,
            "verification_method": "MUTATION_EXPLICIT_REVOCATION_VERIFIED",
        },
        prefix="ver_11b",
    )

    cap_key = ledger._get_capability_key()
    cap2 = issue_execution_capability(
        action_id=clean_aid2,
        action_dossier_digest=clean_aid2[4:],
        approval_id=app_id2,
        program_id=cap1.program_id,
        session_ref=cap1.session_ref,
        principal_id=cap1.principal_id,
        test_account=cap1.principal_id,
        target_endpoint=cap1.target_endpoint,
        http_method=cap1.http_method,
        action_type=cap1.action_type,
        mutation_evidence_ref=cap1.mutation_evidence_ref,  # Reused evidence!
        mutation_request_digest=cap1.mutation_request_digest,
        mutation_response_digest=cap1.mutation_response_digest,
        mutation_status_code=200,
        verification_evidence_ref=ver_cap2["evidence_id"],
        verification_request_digest=ver_cap2["request_sha256"],
        verification_response_digest=ver_cap2["response_sha256"],
        verification_status_code=401,
        verification_method="MUTATION_EXPLICIT_REVOCATION_VERIFIED",
        invalidation_verification_result="REVOKED",
        execution_timestamp="2026-11-11T12:00:00Z",
        verification_timestamp="2026-11-11T12:00:00Z",
        consumption_token=c_token2,
        capability_key=cap_key,
    )

    with pytest.raises(ExecutionProvenanceError, match="cross-execution reuse rejected"):
        ledger.record_execution(
            capability=cap2,
            evidence_store=store,
            consumed_approvals_path=consumed_path2,
        )


def test_adversarial_windows_dacl_failures_fail_closed(tmp_path):
    """Correction C: Simulated Windows DACL enforcement and verification failures fail closed."""
    key_dir = str(tmp_path / "keys_dacl")
    os.makedirs(key_dir, exist_ok=True)

    # 1. Enforcement failure fails closed
    with patch("framework.auth_correlation.ledger._enforce_windows_directory_dacl", side_effect=SerializationSecurityError("DACL failed")):
        with patch("os.name", "nt"):
            with pytest.raises((ExecutionProvenanceError, SerializationSecurityError), match="DACL failed"):
                get_or_create_execution_key(key_dir=key_dir)

    # 2. Verification failure fails closed
    with patch("framework.auth_correlation.ledger._verify_windows_directory_security", side_effect=SerializationSecurityError("Insecure permissions")):
        with patch("os.name", "nt"):
            with pytest.raises((ExecutionProvenanceError, SerializationSecurityError), match="Insecure permissions"):
                get_or_create_capability_key(key_dir=key_dir)
