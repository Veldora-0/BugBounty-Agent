"""
Unit and regression tests for Phase 21 ExecutionLedger and ExecutionCapability.

Verifies:
- Tamper-evident execution ledger operations
- Cryptographic execution capabilities signed under execution_capability.key (CAP-SIG-...)
- HMAC-SHA256 cryptographic signatures over 25 canonical execution fields
- Strict evidence-to-ledger binding and disk byte recomputations
- Single-use claim for invalidation attestation issuance
- Replay attack rejection on claimed execution records
- Complete 16-row approval failure matrix (Section 2)
- Complete 30 adversarial testing matrix (AT-01 through AT-30) (Section 5 & 6)
- 10 Independent security review attacks (Section 7)
- Genuine Mode B end-to-end execution workflow test using isolated deterministic offline transport
"""

import copy
import hashlib
import hmac
import json
import os
import secrets
import stat
import time
from unittest.mock import patch, MagicMock
import pytest

from framework.auth_correlation.ledger import (
    ExecutionLedger,
    ExecutionRecord,
    ExecutionCapability,
    ExecutionProvenanceError,
    issue_execution_capability,
    create_test_execution_capability,
    get_or_create_execution_key,
    get_or_create_capability_key,
    sign_consumption_receipt,
    verify_consumed_approval_entry,
    CANONICAL_EXECUTION_FIELDS,
    CANONICAL_CAPABILITY_FIELDS,
    CANONICAL_ACTION_FIELDS,
    RECEIPT_FIELDS,
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
    get_or_create_approval_key,
)
from framework.common.evidence import EvidenceStore
from framework.validation.request import ControlledRequest, ControlledResponse
from framework.auth_correlation.dispatcher import ControlledDispatchResult


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

    app_key = get_or_create_approval_key(key_dir=key_dir)
    auth_tok = secrets.token_hex(32)
    store = EvidenceStore(ev_dir, authority_token=auth_tok)
    ledger = ExecutionLedger(state_dir=state_dir, key_dir=key_dir, approval_key=app_key)

    app_id = f"APPR-{'0' * 28}{action_suffix[:4]}"
    ts = "2026-11-11T12:00:00Z"
    action_dossier = {
        "action_type": action_type,
        "created_at": ts,
        "method": method,
        "program_id": prog_id,
        "target_endpoint": target_endpoint,
        "test_account": principal_id,
        "ttl": 3600,
        "unique_approval_id": app_id,
    }
    canonical_str = json.dumps({k: action_dossier[k] for k in CANONICAL_ACTION_FIELDS}, sort_keys=True)
    clean_aid = f"ACT-{hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()}"
    op_sig = f"SIG-{hmac.new(app_key, canonical_str.encode('utf-8'), hashlib.sha256).hexdigest()}"
    c_token = secrets.token_hex(32)
    d_op_id = f"DISP-OP-{secrets.token_hex(32).upper()}"

    # Save mutation capture using save_transport_dispatch_capture
    mut_req_obj = ControlledRequest(
        url=target_endpoint,
        method=method,
        headers={"Action": clean_aid, "X-Correlation-Session": sess_ref, "X-Correlation-Dispatch": d_op_id},
    )
    mut_res_obj = ControlledResponse(
        status_code=200,
        headers={"Content-Type": "application/json"},
        body_bytes=b'{"status": "logged_out", "revoked": true}',
    )
    mut_cap = store.save_transport_dispatch_capture(
        request=mut_req_obj,
        response=mut_res_obj,
        action_id=clean_aid,
        approval_id=app_id,
        session_ref=sess_ref,
        principal_id=principal_id,
        program_id=prog_id,
        dispatch_op_id=d_op_id,
        is_verification=False,
        prefix=f"mut_{action_suffix}",
        authority_token=auth_tok,
    )

    # Save verification capture using save_transport_dispatch_capture
    ver_req_obj = ControlledRequest(
        url=f"{target_endpoint}?aid={clean_aid}",
        method="GET",
        headers={"Authorization": "Bearer test", "X-Correlation-Dispatch": f"{d_op_id}-VERIFY"},
    )
    ver_res_obj = ControlledResponse(
        status_code=401,
        headers={"Content-Type": "application/json"},
        body_bytes=b'{"error": "Session revoked"}',
    )
    ver_cap = store.save_transport_dispatch_capture(
        request=ver_req_obj,
        response=ver_res_obj,
        action_id=clean_aid,
        approval_id=app_id,
        session_ref=sess_ref,
        principal_id=principal_id,
        program_id=prog_id,
        dispatch_op_id=d_op_id,
        is_verification=True,
        verification_method=ver_method,
        prefix=f"ver_{action_suffix}",
        authority_token=auth_tok,
    )

    # Register consumed approval with cryptographic receipt
    consumed_path = os.path.join(state_dir, "consumed_approvals.json")
    consumed_entry = {
        "approval_id": app_id,
        "action_id": clean_aid,
        "consumption_token": c_token,
        "dispatch_op_id": d_op_id,
        "program_id": prog_id,
        "session_ref": sess_ref,
        "principal_id": principal_id,
        "test_account": principal_id,
        "target_endpoint": target_endpoint,
        "method": method,
        "action_type": action_type,
        "consumed_at": ts,
        "execution_id": None,
        "action_dossier": action_dossier,
        "action_dossier_digest": hashlib.sha256(canonical_str.encode("utf-8")).hexdigest(),
        "operator_signature": op_sig,
    }
    consumed_entry["receipt_signature"] = sign_consumption_receipt(consumed_entry, app_key)
    consumed_data = {"version": "1.0", "consumed": {clean_aid: consumed_entry}}
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump(consumed_data, f, indent=2)

    dispatch_res = ControlledDispatchResult(
        dispatch_op_id=d_op_id,
        action_id=clean_aid,
        action_dossier_digest=consumed_entry["action_dossier_digest"],
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
        is_genuine_dispatch=True,
    )

    cap = issue_execution_capability(
        dispatch_result=dispatch_res,
        key_dir=key_dir,
        evidence_store=store,
        consumed_approvals_path=consumed_path,
        approval_key=app_key,
    )

    return ledger, cap, store, consumed_path, clean_aid, app_id, c_token


# ==============================================================================
# SECTION 1: BASIC EXECUTION LEDGER OPERATIONS
# ==============================================================================

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


# ==============================================================================
# SECTION 2: 16-ROW APPROVAL FAILURE MATRIX REGRESSION TESTS (Correction B)
# ==============================================================================

def test_approval_failure_row01_registry_missing(tmp_path):
    """Row 1: Approval registry missing fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "row01")
    missing_path = os.path.join(str(tmp_path), "nonexistent", "consumed.json")
    with pytest.raises(ExecutionProvenanceError, match="does not exist"):
        ledger.record_execution(
            capability=cap,
            evidence_store=store,
            consumed_approvals_path=missing_path,
        )


def test_approval_failure_row02_registry_not_a_file(tmp_path):
    """Row 2: Approval registry path is a directory (not a regular file) fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "row02")
    dir_path = str(tmp_path / "reg_is_dir")
    os.makedirs(dir_path, exist_ok=True)
    with pytest.raises(ExecutionProvenanceError, match="is not a regular file"):
        ledger.record_execution(
            capability=cap,
            evidence_store=store,
            consumed_approvals_path=dir_path,
        )


def test_approval_failure_row03_registry_unreadable(tmp_path):
    """Row 3: Approval registry unreadable (e.g. PermissionError) fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "row03")
    orig_open = open
    def mock_open(path, *args, **kwargs):
        if "consumed_approvals.json" in str(path):
            raise PermissionError("Permission denied")
        return orig_open(path, *args, **kwargs)

    with patch("builtins.open", side_effect=mock_open):
        with pytest.raises(ExecutionProvenanceError, match="Failed to read consumed approvals registry"):
            ledger.record_execution(
                capability=cap,
                evidence_store=store,
                consumed_approvals_path=consumed_path,
            )


def test_approval_failure_row04_invalid_json(tmp_path):
    """Row 4: Approval registry corrupted JSON fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "row04")
    with open(consumed_path, "w", encoding="utf-8") as f:
        f.write("{invalid_json_content: corrupt")
    with pytest.raises(ExecutionProvenanceError, match="invalid JSON"):
        ledger.record_execution(
            capability=cap,
            evidence_store=store,
            consumed_approvals_path=consumed_path,
        )


def test_approval_failure_row05_invalid_schema(tmp_path):
    """Row 5: Approval registry invalid schema (missing version or consumed dict) fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "row05")

    # Subcase A: Root is not a dict
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump(["not", "a", "dict"], f)
    with pytest.raises(ExecutionProvenanceError, match="root must be a dict"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)

    # Subcase B: Missing version
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump({"consumed": {}}, f)
    with pytest.raises(ExecutionProvenanceError, match="missing or invalid version"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)

    # Subcase C: Consumed is not a dict
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump({"version": "1.0", "consumed": "not_a_dict"}, f)
    with pytest.raises(ExecutionProvenanceError, match="missing or invalid consumed dictionary"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_approval_failure_row06_missing_action_receipt(tmp_path):
    """Row 6: Action receipt missing in registry fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "row06")
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump({"version": "1.0", "consumed": {}}, f)
    with pytest.raises(ExecutionProvenanceError, match="has not been consumed in approval registry"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_approval_failure_row07_wrong_approval_id(tmp_path):
    """Row 7: Wrong approval ID in receipt fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "row07")
    app_key = ledger._approval_key
    with open(consumed_path, "r", encoding="utf-8") as f:
        cdata = json.load(f)
    cdata["consumed"][clean_aid]["approval_id"] = "APPR-FORGED-0000"
    cdata["consumed"][clean_aid]["receipt_signature"] = sign_consumption_receipt(cdata["consumed"][clean_aid], app_key)
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump(cdata, f)
    with pytest.raises(ExecutionProvenanceError, match="Approval ID mismatch"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_approval_failure_row08_wrong_consumption_token(tmp_path):
    """Row 8: Wrong consumption token in receipt fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "row08")
    app_key = ledger._approval_key
    with open(consumed_path, "r", encoding="utf-8") as f:
        cdata = json.load(f)
    cdata["consumed"][clean_aid]["consumption_token"] = "TOKEN-TAMPERED-0000"
    cdata["consumed"][clean_aid]["receipt_signature"] = sign_consumption_receipt(cdata["consumed"][clean_aid], app_key)
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump(cdata, f)
    with pytest.raises(ExecutionProvenanceError, match="Consumption token mismatch"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_approval_failure_row09_wrong_program(tmp_path):
    """Row 9: Wrong program in receipt fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "row09")
    app_key = ledger._approval_key
    with open(consumed_path, "r", encoding="utf-8") as f:
        cdata = json.load(f)
    cdata["consumed"][clean_aid]["program_id"] = "program_other"
    cdata["consumed"][clean_aid]["receipt_signature"] = sign_consumption_receipt(cdata["consumed"][clean_aid], app_key)
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump(cdata, f)
    with pytest.raises(ExecutionProvenanceError, match="Program ID mismatch"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_approval_failure_row10_wrong_test_account(tmp_path):
    """Row 10: Wrong test account in receipt fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "row10")
    app_key = ledger._approval_key
    with open(consumed_path, "r", encoding="utf-8") as f:
        cdata = json.load(f)
    cdata["consumed"][clean_aid]["test_account"] = "attacker_account"
    cdata["consumed"][clean_aid]["receipt_signature"] = sign_consumption_receipt(cdata["consumed"][clean_aid], app_key)
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump(cdata, f)
    with pytest.raises(ExecutionProvenanceError, match="Test account mismatch"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_approval_failure_row11_wrong_target(tmp_path):
    """Row 11: Wrong target endpoint in receipt fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "row11")
    app_key = ledger._approval_key
    with open(consumed_path, "r", encoding="utf-8") as f:
        cdata = json.load(f)
    cdata["consumed"][clean_aid]["target_endpoint"] = "https://unauthorized.target/auth/logout"
    cdata["consumed"][clean_aid]["receipt_signature"] = sign_consumption_receipt(cdata["consumed"][clean_aid], app_key)
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump(cdata, f)
    with pytest.raises(ExecutionProvenanceError, match="Target endpoint mismatch"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_approval_failure_row12_wrong_method(tmp_path):
    """Row 12: Wrong method in receipt fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "row12")
    app_key = ledger._approval_key
    with open(consumed_path, "r", encoding="utf-8") as f:
        cdata = json.load(f)
    cdata["consumed"][clean_aid]["method"] = "DELETE"
    cdata["consumed"][clean_aid]["receipt_signature"] = sign_consumption_receipt(cdata["consumed"][clean_aid], app_key)
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump(cdata, f)
    with pytest.raises(ExecutionProvenanceError, match="HTTP method mismatch"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_approval_failure_row13_wrong_action_type(tmp_path):
    """Row 13: Wrong action type in receipt fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "row13")
    app_key = ledger._approval_key
    with open(consumed_path, "r", encoding="utf-8") as f:
        cdata = json.load(f)
    cdata["consumed"][clean_aid]["action_type"] = "PASSWORD_CHANGE"
    cdata["consumed"][clean_aid]["receipt_signature"] = sign_consumption_receipt(cdata["consumed"][clean_aid], app_key)
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump(cdata, f)
    with pytest.raises(ExecutionProvenanceError, match="Action type mismatch"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_approval_failure_row14_wrong_session_ref(tmp_path):
    """Row 14: Wrong session reference in receipt fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "row14")
    app_key = ledger._approval_key
    with open(consumed_path, "r", encoding="utf-8") as f:
        cdata = json.load(f)
    cdata["consumed"][clean_aid]["session_ref"] = "sess_mismatched_0000000000000000000"
    cdata["consumed"][clean_aid]["receipt_signature"] = sign_consumption_receipt(cdata["consumed"][clean_aid], app_key)
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump(cdata, f)
    with pytest.raises(ExecutionProvenanceError, match="Session reference mismatch"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_approval_failure_row15_wrong_principal_id(tmp_path):
    """Row 15: Wrong principal ID in receipt fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "row15")
    app_key = ledger._approval_key
    with open(consumed_path, "r", encoding="utf-8") as f:
        cdata = json.load(f)
    cdata["consumed"][clean_aid]["principal_id"] = "principal_mismatched"
    cdata["consumed"][clean_aid]["receipt_signature"] = sign_consumption_receipt(cdata["consumed"][clean_aid], app_key)
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump(cdata, f)
    with pytest.raises(ExecutionProvenanceError, match="Principal ID mismatch"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_approval_failure_row16_replayed_receipt(tmp_path):
    """Row 16: Replayed receipt (already linked to execution_id) fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "row16")
    with open(consumed_path, "r", encoding="utf-8") as f:
        cdata = json.load(f)
    cdata["consumed"][clean_aid]["execution_id"] = "EXEC-PREVIOUS-RUN-0000000000000000"
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump(cdata, f)
    with pytest.raises(ExecutionProvenanceError, match="duplicate execution rejected"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


# ==============================================================================
# SECTION 3: ADVERSARIAL TESTING MATRIX (AT-01 THROUGH AT-30)
# ==============================================================================

def test_adversarial_at01_direct_call_fabricated_args(tmp_path):
    """AT-01: Direct call to issue_execution_capability with fabricated values (no disk evidence) fails closed."""
    state_dir = str(tmp_path / "state_at01")
    key_dir = str(tmp_path / "keys_at01")
    ev_dir = str(tmp_path / "ev_at01")
    os.makedirs(state_dir, exist_ok=True)
    os.makedirs(key_dir, exist_ok=True)
    os.makedirs(ev_dir, exist_ok=True)

    store = EvidenceStore(ev_dir)
    app_key = get_or_create_approval_key(key_dir=key_dir)
    consumed_path = os.path.join(state_dir, "consumed_approvals.json")
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump({"version": "1.0", "consumed": {}}, f)

    aid = "ACT-" + "1" * 64
    with pytest.raises(ExecutionProvenanceError, match="prerequisite verification failed|not found|requires a valid ControlledDispatchResult"):
        issue_execution_capability(
            action_id=aid,
            action_dossier_digest="1" * 64,
            approval_id="APPR-" + "1" * 32,
            program_id="prog1",
            session_ref="sess1",
            principal_id="u1",
            test_account="u1",
            target_endpoint="https://target.local/logout",
            http_method="POST",
            action_type="LOGOUT",
            mutation_evidence_ref="EVID-NONEXISTENT-1",
            mutation_request_digest="0" * 64,
            mutation_response_digest="0" * 64,
            mutation_status_code=200,
            verification_evidence_ref="EVID-NONEXISTENT-2",
            verification_request_digest="0" * 64,
            verification_response_digest="0" * 64,
            verification_status_code=401,
            verification_method="MUTATION_EXPLICIT_REVOCATION_VERIFIED",
            invalidation_verification_result="REVOKED",
            execution_timestamp="2026-11-11T12:00:00Z",
            verification_timestamp="2026-11-11T12:00:00Z",
            consumption_token=secrets.token_hex(32),
            key_dir=key_dir,
            evidence_store=store,
            consumed_approvals_path=consumed_path,
            approval_key=app_key,
        )


def test_adversarial_at02_import_issuer_cannot_mint_trusted_provenance(tmp_path):
    """AT-02: Importing issuer from defining module cannot mint provenance without authentic transport captures."""
    from framework.auth_correlation.ledger import issue_execution_capability as direct_issuer
    state_dir = str(tmp_path / "state_at02")
    key_dir = str(tmp_path / "keys_at02")
    ev_dir = str(tmp_path / "ev_at02")
    os.makedirs(state_dir, exist_ok=True)
    os.makedirs(key_dir, exist_ok=True)
    os.makedirs(ev_dir, exist_ok=True)

    store = EvidenceStore(ev_dir)
    app_key = get_or_create_approval_key(key_dir=key_dir)
    consumed_path = os.path.join(state_dir, "consumed_approvals.json")
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump({"version": "1.0", "consumed": {}}, f)

    with pytest.raises(ExecutionProvenanceError):
        direct_issuer(
            action_id="ACT-" + "2" * 64,
            action_dossier_digest="2" * 64,
            approval_id="APPR-" + "2" * 32,
            program_id="prog2",
            session_ref="sess2",
            principal_id="u2",
            test_account="u2",
            target_endpoint="https://target.local/logout",
            http_method="POST",
            action_type="LOGOUT",
            mutation_evidence_ref="EVID-222222222222",
            mutation_request_digest="2" * 64,
            mutation_response_digest="2" * 64,
            mutation_status_code=200,
            verification_evidence_ref="EVID-333333333333",
            verification_request_digest="3" * 64,
            verification_response_digest="3" * 64,
            verification_status_code=401,
            verification_method="MUTATION_EXPLICIT_REVOCATION_VERIFIED",
            invalidation_verification_result="REVOKED",
            execution_timestamp="2026-11-11T12:00:00Z",
            verification_timestamp="2026-11-11T12:00:00Z",
            consumption_token=secrets.token_hex(32),
            key_dir=key_dir,
            evidence_store=store,
            consumed_approvals_path=consumed_path,
            approval_key=app_key,
        )


def test_adversarial_at03_construct_capability_manually_fails_closed(tmp_path):
    """AT-03: Constructing ExecutionCapability dataclass manually is rejected by ledger and provenance verification."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at03")

    fake_cap = ExecutionCapability(
        approval_id=app_id,
        action_id=clean_aid,
        action_dossier_digest=cap.action_dossier_digest,
        program_id=cap.program_id,
        session_ref=cap.session_ref,
        principal_id=cap.principal_id,
        test_account=cap.test_account,
        target_endpoint=cap.target_endpoint,
        http_method="POST",
        action_type="LOGOUT",
        mutation_evidence_ref=cap.mutation_evidence_ref,
        mutation_request_digest=cap.mutation_request_digest,
        mutation_response_digest=cap.mutation_response_digest,
        mutation_status_code=200,
        verification_evidence_ref=cap.verification_evidence_ref,
        verification_request_digest=cap.verification_request_digest,
        verification_response_digest=cap.verification_response_digest,
        verification_status_code=401,
        verification_method="MUTATION_EXPLICIT_REVOCATION_VERIFIED",
        invalidation_verification_result="REVOKED",
        execution_timestamp="2026-11-11T12:00:00Z",
        verification_timestamp="2026-11-11T12:00:00Z",
        consumption_token=c_token,
        capability_id="CAP-" + "0" * 64,
        signature="CAP-SIG-" + "F" * 64,
    )

    with pytest.raises(ExecutionProvenanceError, match="capability signature verification failed"):
        ledger.record_execution(capability=fake_cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_adversarial_at04_valid_hmac_over_fabricated_fields_rejected(tmp_path):
    """AT-04: Valid HMAC signature over fabricated execution fields is rejected because transport evidence is missing."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at04")
    cap_key = ledger._get_capability_key()

    # Compute valid HMAC over fabricated fields
    payload = {k: getattr(cap, k) for k in CANONICAL_CAPABILITY_FIELDS if k not in ("capability_id", "signature")}
    payload["mutation_evidence_ref"] = "EVID-0123456789ab"
    payload["verification_evidence_ref"] = "EVID-cdef01234567"
    hash_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    cap_id = f"CAP-{hashlib.sha256(hash_bytes).hexdigest().upper()}"
    payload["capability_id"] = cap_id
    sign_bytes = json.dumps({k: payload[k] for k in CANONICAL_CAPABILITY_FIELDS}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = f"CAP-SIG-{hmac.new(cap_key, sign_bytes, hashlib.sha256).hexdigest().upper()}"

    forged_cap = ExecutionCapability(
        **payload,
        signature=sig,
    )

    with pytest.raises(ExecutionProvenanceError, match="not found or corrupted in EvidenceStore"):
        ledger.record_execution(capability=forged_cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_adversarial_at05_save_http_capture_rejects_controlled_source(tmp_path):
    """AT-05: Caller calling save_http_capture with capture_source='CONTROLLED_TRANSPORT_DISPATCH' is rejected with ValueError."""
    store = EvidenceStore(str(tmp_path / "ev_at05"))
    with pytest.raises(ValueError, match="Ordinary callers cannot specify controlled transport capture_source metadata"):
        store.save_http_capture(
            request_text="POST /logout",
            response_text="200 OK",
            metadata={"capture_source": "CONTROLLED_TRANSPORT_DISPATCH"},
        )

    with pytest.raises(ValueError, match="Ordinary callers cannot specify controlled transport capture_source metadata"):
        store.save_http_capture(
            request_text="POST /logout",
            response_text="200 OK",
            metadata={"evidence_class": "CONTROLLED_TRANSPORT_DISPATCH"},
        )


def test_adversarial_at06_manually_created_consumed_approvals_rejected(tmp_path):
    """AT-06: Manually created consumed_approvals.json without approval.key is rejected by ledger verification."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at06")

    # Overwrite consumed_approvals with unsigned fabricated entry
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump({
            "version": "1.0",
            "consumed": {
                clean_aid: {
                    "approval_id": app_id,
                    "action_id": clean_aid,
                    "consumption_token": c_token,
                    "program_id": cap.program_id,
                    "session_ref": cap.session_ref,
                    "principal_id": cap.principal_id,
                    "test_account": cap.principal_id,
                    "target_endpoint": cap.target_endpoint,
                    "method": cap.http_method,
                    "action_type": cap.action_type,
                    "dispatch_op_id": cap.dispatch_op_id,
                    "consumed_at": "2026-11-11T12:00:00Z",
                    "execution_id": None,
                    # No operator_signature or receipt_signature!
                }
            }
        }, f)

    with pytest.raises(ExecutionProvenanceError, match="signature verification failed|cryptographic signature verification"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_adversarial_at07_replay_of_consumed_approval_rejected(tmp_path):
    """AT-07: Replay of consumed approval already linked to an execution is rejected fail-closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at07")
    rec1 = ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)
    assert rec1 is not None

    with pytest.raises(ExecutionProvenanceError, match="duplicate execution rejected"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_adversarial_at08_replay_capability_different_program_rejected(tmp_path):
    """AT-08: Capability field program_id modification fails signature verification."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at08", prog_id="prog_alpha")
    tampered_cap = copy.deepcopy(cap)
    tampered_cap.program_id = "prog_beta"

    with pytest.raises(ExecutionProvenanceError, match="capability signature verification failed"):
        ledger.record_execution(capability=tampered_cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_adversarial_at09_replay_capability_different_account_rejected(tmp_path):
    """AT-09: Capability field principal_id modification fails signature verification."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at09", principal_id="user_original")
    tampered_cap = copy.deepcopy(cap)
    tampered_cap.principal_id = "user_attacker"

    with pytest.raises(ExecutionProvenanceError, match="capability signature verification failed"):
        ledger.record_execution(capability=tampered_cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_adversarial_at10_evidence_reference_substitution_rejected(tmp_path):
    """AT-10: Substituting unverified evidence reference in capability fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at10")
    cap_key = ledger._get_capability_key()

    d_res = ControlledDispatchResult(
        dispatch_op_id=cap.dispatch_op_id,
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
        is_genuine_dispatch=True,
    )
    with pytest.raises(ExecutionProvenanceError, match="not found"):
        issue_execution_capability(
            dispatch_result=d_res,
            capability_key=cap_key,
            evidence_store=store,
            consumed_approvals_path=consumed_path,
            approval_key=ledger._approval_key,
        )


def test_adversarial_at11_request_digest_modification_rejected(tmp_path):
    """AT-11: Modifying request digest in capability fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at11")
    cap_key = ledger._get_capability_key()

    d_res = ControlledDispatchResult(
        dispatch_op_id=cap.dispatch_op_id,
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
        mutation_request_digest="f" * 64,
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
        is_genuine_dispatch=True,
    )
    with pytest.raises(ExecutionProvenanceError, match="digest mismatch"):
        issue_execution_capability(
            dispatch_result=d_res,
            capability_key=cap_key,
            evidence_store=store,
            consumed_approvals_path=consumed_path,
            approval_key=ledger._approval_key,
        )


def test_adversarial_at12_response_digest_modification_rejected(tmp_path):
    """AT-12: Modifying response digest in capability fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at12")
    cap_key = ledger._get_capability_key()

    d_res = ControlledDispatchResult(
        dispatch_op_id=cap.dispatch_op_id,
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
        mutation_request_digest=cap.mutation_request_digest,
        mutation_response_digest="e" * 64,
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
        is_genuine_dispatch=True,
    )
    with pytest.raises(ExecutionProvenanceError, match="digest mismatch"):
        issue_execution_capability(
            dispatch_result=d_res,
            capability_key=cap_key,
            evidence_store=store,
            consumed_approvals_path=consumed_path,
            approval_key=ledger._approval_key,
        )


def test_adversarial_at13_tampered_mutation_bytes_on_disk_fails_closed(tmp_path):
    """AT-13: Tampering with raw mutation capture bytes on disk fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at13")
    mut_ev = store.get_evidence(cap.mutation_evidence_ref)
    with open(mut_ev["capture_path"], "ab") as f:
        f.write(b"\nTAMPERED_MUTATION_BYTES")

    with pytest.raises(ExecutionProvenanceError, match="not found or corrupted in EvidenceStore"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_adversarial_at14_tampered_verification_bytes_on_disk_fails_closed(tmp_path):
    """AT-14: Tampering with raw verification capture bytes on disk fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at14")
    ver_ev = store.get_evidence(cap.verification_evidence_ref)
    with open(ver_ev["capture_path"], "ab") as f:
        f.write(b"\nTAMPERED_VERIFICATION_BYTES")

    with pytest.raises(ExecutionProvenanceError, match="not found or corrupted in EvidenceStore"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_adversarial_at15_swapped_mutation_and_verification_captures_rejected(tmp_path):
    """AT-15: Swapping mutation and verification captures fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at15")
    cap_key = ledger._get_capability_key()

    swapped_dres = ControlledDispatchResult(
        dispatch_op_id=cap.dispatch_op_id,
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
        mutation_status_code=cap.verification_status_code,
        verification_evidence_ref=cap.mutation_evidence_ref,  # Swapped
        verification_request_digest=cap.mutation_request_digest,
        verification_response_digest=cap.mutation_response_digest,
        verification_status_code=cap.mutation_status_code,
        verification_method=cap.verification_method,
        invalidation_verification_result=cap.invalidation_verification_result,
        execution_timestamp=cap.execution_timestamp,
        verification_timestamp=cap.verification_timestamp,
        consumption_token=cap.consumption_token,
        is_genuine_dispatch=True,
    )

    with pytest.raises(ExecutionProvenanceError, match="evidence metadata swapped|cannot be a verification capture|points to verification evidence"):
        issue_execution_capability(
            dispatch_result=swapped_dres,
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
            evidence_store=store,
            consumed_approvals_path=consumed_path,
            approval_key=ledger._approval_key,
        )


def test_adversarial_at16_cross_execution_mutation_evidence_reuse_rejected(tmp_path):
    """AT-16: Reusing mutation evidence across different executions fails closed."""
    ledger, cap1, store, consumed_path1, clean_aid1, app_id1, c_token1 = _create_valid_execution_fixture(tmp_path, "at16a")
    rec1 = ledger.record_execution(capability=cap1, evidence_store=store, consumed_approvals_path=consumed_path1)
    assert rec1 is not None

    clean_aid2 = "ACT-" + "2" * 64
    app_id2 = "APPR-" + "2" * 32
    c_token2 = secrets.token_hex(32)
    consumed_path2 = os.path.join(ledger.state_dir, "consumed_approvals.json")
    with open(consumed_path2, "r", encoding="utf-8") as f:
        cdata = json.load(f)

    dossier2 = {
        "action_type": cap1.action_type,
        "created_at": "2026-11-11T12:00:00Z",
        "method": cap1.http_method,
        "program_id": cap1.program_id,
        "target_endpoint": cap1.target_endpoint,
        "test_account": cap1.principal_id,
        "ttl": 3600,
        "unique_approval_id": app_id2,
    }
    canonical2 = json.dumps({k: dossier2[k] for k in CANONICAL_ACTION_FIELDS}, sort_keys=True)
    clean_aid2 = f"ACT-{hashlib.sha256(canonical2.encode('utf-8')).hexdigest()}"
    op_sig2 = f"SIG-{hmac.new(ledger._approval_key, canonical2.encode('utf-8'), hashlib.sha256).hexdigest()}"

    d_op_id2 = f"DISP-OP-{secrets.token_hex(32).upper()}"
    entry2 = {
        "approval_id": app_id2,
        "action_id": clean_aid2,
        "consumption_token": c_token2,
        "dispatch_op_id": d_op_id2,
        "program_id": cap1.program_id,
        "session_ref": cap1.session_ref,
        "principal_id": cap1.principal_id,
        "test_account": cap1.principal_id,
        "target_endpoint": cap1.target_endpoint,
        "method": cap1.http_method,
        "action_type": cap1.action_type,
        "consumed_at": "2026-11-11T12:00:00Z",
        "execution_id": None,
        "action_dossier": dossier2,
        "action_dossier_digest": hashlib.sha256(canonical2.encode("utf-8")).hexdigest(),
        "operator_signature": op_sig2,
    }
    entry2["receipt_signature"] = sign_consumption_receipt(entry2, ledger._approval_key)
    cdata["consumed"][clean_aid2] = entry2
    with open(consumed_path2, "w", encoding="utf-8") as f:
        json.dump(cdata, f, indent=2)

    v_req_obj = ControlledRequest(
        url=f"{cap1.target_endpoint}?aid={clean_aid2}",
        method="GET",
        headers={"Authorization": "Bearer test", "X-Correlation-Dispatch": f"{d_op_id2}-VERIFY"},
    )
    v_res_obj = ControlledResponse(
        status_code=401,
        headers={"Content-Type": "application/json"},
        body_bytes=b'{"error": "Session revoked"}',
    )
    ver_cap2 = store.save_transport_dispatch_capture(
        request=v_req_obj,
        response=v_res_obj,
        action_id=clean_aid2,
        approval_id=app_id2,
        session_ref=cap1.session_ref,
        principal_id=cap1.principal_id,
        program_id=cap1.program_id,
        dispatch_op_id=d_op_id2,
        is_verification=True,
        verification_method="MUTATION_EXPLICIT_REVOCATION_VERIFIED",
        prefix="ver_at16b",
        authority_token=store._authority_token,
    )

    cap_key = ledger._get_capability_key()
    cap2 = ExecutionCapability(
        action_id=clean_aid2,
        action_dossier_digest=entry2["action_dossier_digest"],
        approval_id=app_id2,
        program_id=cap1.program_id,
        session_ref=cap1.session_ref,
        principal_id=cap1.principal_id,
        test_account=cap1.principal_id,
        target_endpoint=cap1.target_endpoint,
        http_method=cap1.http_method,
        action_type=cap1.action_type,
        mutation_evidence_ref=cap1.mutation_evidence_ref,  # Reused evidence
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
        dispatch_op_id=d_op_id2,
        capability_id="CAP-" + "2" * 64,
        signature="CAP-SIG-" + "2" * 64,
    )
    # Compute genuine signature for cap2
    hash_payload = {k: getattr(cap2, k) for k in CANONICAL_CAPABILITY_FIELDS if k != "capability_id"}
    hash_bytes = json.dumps(hash_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    cap2.capability_id = f"CAP-{hashlib.sha256(hash_bytes).hexdigest().upper()}"
    sign_payload = {k: getattr(cap2, k) for k in CANONICAL_CAPABILITY_FIELDS}
    sign_bytes = json.dumps(sign_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    cap2.signature = f"CAP-SIG-{hmac.new(cap_key, sign_bytes, hashlib.sha256).hexdigest().upper()}"

    with pytest.raises(ExecutionProvenanceError, match="cross-execution reuse rejected"):
        ledger.record_execution(capability=cap2, evidence_store=store, consumed_approvals_path=consumed_path2)


def test_adversarial_at17_cross_execution_verification_evidence_reuse_rejected(tmp_path):
    """AT-17: Reusing verification evidence across different executions fails closed."""
    ledger, cap1, store, consumed_path1, clean_aid1, app_id1, c_token1 = _create_valid_execution_fixture(tmp_path, "at17a")
    rec1 = ledger.record_execution(capability=cap1, evidence_store=store, consumed_approvals_path=consumed_path1)
    assert rec1 is not None

    app_id2 = "APPR-" + "3" * 32
    c_token2 = secrets.token_hex(32)
    consumed_path2 = os.path.join(ledger.state_dir, "consumed_approvals.json")
    with open(consumed_path2, "r", encoding="utf-8") as f:
        cdata = json.load(f)

    dossier2 = {
        "action_type": cap1.action_type,
        "created_at": "2026-11-11T12:00:00Z",
        "method": cap1.http_method,
        "program_id": cap1.program_id,
        "target_endpoint": cap1.target_endpoint,
        "test_account": cap1.principal_id,
        "ttl": 3600,
        "unique_approval_id": app_id2,
    }
    canonical2 = json.dumps({k: dossier2[k] for k in CANONICAL_ACTION_FIELDS}, sort_keys=True)
    clean_aid2 = f"ACT-{hashlib.sha256(canonical2.encode('utf-8')).hexdigest()}"
    op_sig2 = f"SIG-{hmac.new(ledger._approval_key, canonical2.encode('utf-8'), hashlib.sha256).hexdigest()}"

    d_op_id2 = f"DISP-OP-{secrets.token_hex(32).upper()}"
    entry2 = {
        "approval_id": app_id2,
        "action_id": clean_aid2,
        "consumption_token": c_token2,
        "dispatch_op_id": d_op_id2,
        "program_id": cap1.program_id,
        "session_ref": cap1.session_ref,
        "principal_id": cap1.principal_id,
        "test_account": cap1.principal_id,
        "target_endpoint": cap1.target_endpoint,
        "method": cap1.http_method,
        "action_type": cap1.action_type,
        "consumed_at": "2026-11-11T12:00:00Z",
        "execution_id": None,
        "action_dossier": dossier2,
        "action_dossier_digest": hashlib.sha256(canonical2.encode("utf-8")).hexdigest(),
        "operator_signature": op_sig2,
    }
    entry2["receipt_signature"] = sign_consumption_receipt(entry2, ledger._approval_key)
    cdata["consumed"][clean_aid2] = entry2
    with open(consumed_path2, "w", encoding="utf-8") as f:
        json.dump(cdata, f, indent=2)

    m_req_obj = ControlledRequest(
        url=cap1.target_endpoint,
        method=cap1.http_method,
        headers={"Action": clean_aid2, "X-Correlation-Dispatch": d_op_id2},
    )
    m_res_obj = ControlledResponse(
        status_code=200,
        headers={"Content-Type": "application/json"},
        body_bytes=b'{"status": "ok"}',
    )
    mut_cap2 = store.save_transport_dispatch_capture(
        request=m_req_obj,
        response=m_res_obj,
        action_id=clean_aid2,
        approval_id=app_id2,
        session_ref=cap1.session_ref,
        principal_id=cap1.principal_id,
        program_id=cap1.program_id,
        dispatch_op_id=d_op_id2,
        is_verification=False,
        prefix="mut_at17b",
        authority_token=store._authority_token,
    )

    cap_key = ledger._get_capability_key()
    cap2 = ExecutionCapability(
        action_id=clean_aid2,
        action_dossier_digest=entry2["action_dossier_digest"],
        approval_id=app_id2,
        program_id=cap1.program_id,
        session_ref=cap1.session_ref,
        principal_id=cap1.principal_id,
        test_account=cap1.principal_id,
        target_endpoint=cap1.target_endpoint,
        http_method=cap1.http_method,
        action_type=cap1.action_type,
        mutation_evidence_ref=mut_cap2["evidence_id"],
        mutation_request_digest=mut_cap2["request_sha256"],
        mutation_response_digest=mut_cap2["response_sha256"],
        mutation_status_code=200,
        verification_evidence_ref=cap1.verification_evidence_ref,  # Reused verification evidence
        verification_request_digest=cap1.verification_request_digest,
        verification_response_digest=cap1.verification_response_digest,
        verification_status_code=401,
        verification_method="MUTATION_EXPLICIT_REVOCATION_VERIFIED",
        invalidation_verification_result="REVOKED",
        execution_timestamp="2026-11-11T12:00:00Z",
        verification_timestamp="2026-11-11T12:00:00Z",
        consumption_token=c_token2,
        dispatch_op_id=d_op_id2,
        capability_id="CAP-" + "3" * 64,
        signature="CAP-SIG-" + "3" * 64,
    )
    hash_payload = {k: getattr(cap2, k) for k in CANONICAL_CAPABILITY_FIELDS if k != "capability_id"}
    hash_bytes = json.dumps(hash_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    cap2.capability_id = f"CAP-{hashlib.sha256(hash_bytes).hexdigest().upper()}"
    sign_payload = {k: getattr(cap2, k) for k in CANONICAL_CAPABILITY_FIELDS}
    sign_bytes = json.dumps(sign_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    cap2.signature = f"CAP-SIG-{hmac.new(cap_key, sign_bytes, hashlib.sha256).hexdigest().upper()}"

    with pytest.raises(ExecutionProvenanceError, match="cross-execution reuse rejected"):
        ledger.record_execution(capability=cap2, evidence_store=store, consumed_approvals_path=consumed_path2)


def test_adversarial_at18_missing_approval_registry_file_rejected(tmp_path):
    """AT-18: Non-existent approval registry file fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at18")
    with pytest.raises(ExecutionProvenanceError, match="does not exist"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=str(tmp_path / "nonexistent.json"))


def test_adversarial_at19_unreadable_approval_registry_fails_closed(tmp_path):
    """AT-19: Unreadable approval registry (PermissionError) fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at19")
    orig_open = open
    def mock_open(path, *args, **kwargs):
        if "consumed_approvals.json" in str(path):
            raise PermissionError("Access denied")
        return orig_open(path, *args, **kwargs)

    with patch("builtins.open", side_effect=mock_open):
        with pytest.raises(ExecutionProvenanceError, match="Failed to read consumed approvals registry"):
            ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_adversarial_at20_corrupted_approval_registry_json_fails_closed(tmp_path):
    """AT-20: Corrupted JSON in consumed_approvals.json fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at20")
    with open(consumed_path, "w", encoding="utf-8") as f:
        f.write("{corrupt_json: true")
    with pytest.raises(ExecutionProvenanceError, match="invalid JSON"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_adversarial_at21_approval_registry_schema_invalid_fails_closed(tmp_path):
    """AT-21: Consumed approvals registry with invalid root schema fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at21")
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump({"bad_key": 123}, f)
    with pytest.raises(ExecutionProvenanceError, match="missing or invalid version"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_adversarial_at22_forged_consumption_token_rejected(tmp_path):
    """AT-22: Consumed approval entry with mismatched consumption token fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at22")
    with open(consumed_path, "r", encoding="utf-8") as f:
        cdata = json.load(f)
    cdata["consumed"][clean_aid]["consumption_token"] = "TOKEN-WRONG"
    cdata["consumed"][clean_aid]["receipt_signature"] = sign_consumption_receipt(cdata["consumed"][clean_aid], ledger._approval_key)
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump(cdata, f)
    with pytest.raises(ExecutionProvenanceError, match="Consumption token mismatch"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_adversarial_at23_forged_operator_signature_rejected(tmp_path):
    """AT-23: Consumed approval entry with forged operator_signature (SIG-...) fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at23")
    with open(consumed_path, "r", encoding="utf-8") as f:
        cdata = json.load(f)
    cdata["consumed"][clean_aid]["operator_signature"] = "SIG-" + "0" * 64
    cdata["consumed"][clean_aid]["receipt_signature"] = sign_consumption_receipt(cdata["consumed"][clean_aid], ledger._approval_key)
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump(cdata, f)
    with pytest.raises(ExecutionProvenanceError, match="signature verification failed|cryptographic signature verification"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_adversarial_at24_forged_receipt_signature_rejected(tmp_path):
    """AT-24: Consumed approval entry with forged receipt_signature (RCPT-SIG-...) fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at24")
    with open(consumed_path, "r", encoding="utf-8") as f:
        cdata = json.load(f)
    cdata["consumed"][clean_aid]["receipt_signature"] = "RCPT-SIG-" + "F" * 64
    with open(consumed_path, "w", encoding="utf-8") as f:
        json.dump(cdata, f)
    with pytest.raises(ExecutionProvenanceError, match="signature verification failed|cryptographic signature verification"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_adversarial_at25_concurrent_execution_consumption(tmp_path):
    """AT-25: Concurrent execution requests consuming the same approval -> exactly one succeeds, others fail closed."""
    import concurrent.futures
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at25")
    _ = ledger._get_key()
    _ = ledger._get_capability_key()

    results = []
    errors = []

    def run_record():
        try:
            r = ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)
            results.append(r)
        except ExecutionProvenanceError as e:
            errors.append(e)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = [ex.submit(run_record) for _ in range(4)]
        concurrent.futures.wait(futures)

    assert len(results) == 1
    assert len(errors) == 3
    for err in errors:
        s = str(err).lower()
        assert "duplicate execution" in s or "already been executed" in s or "cross-execution reuse" in s


def test_adversarial_at26_interrupted_persistence_midway(tmp_path):
    """AT-26: Interrupted ledger persistence (os.replace failure) leaves state intact and fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at26")

    with patch("framework.auth_correlation.ledger.os.replace", side_effect=OSError("Disk write interrupted")):
        with pytest.raises(ExecutionProvenanceError, match="Failed to update consumed approval registry|Failed to persist execution ledger"):
            ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)

    with open(consumed_path, "r", encoding="utf-8") as f:
        cdata = json.load(f)
    assert cdata["version"] in (1, "1.0")


def test_adversarial_at27_windows_dacl_enforcement_failure_fails_closed(tmp_path):
    """AT-27: Windows DACL enforcement failure fails closed."""
    key_dir = str(tmp_path / "keys_at27")
    os.makedirs(key_dir, exist_ok=True)
    with patch("framework.auth_correlation.ledger._enforce_windows_directory_dacl", side_effect=SerializationSecurityError("Fatal DACL error")):
        with patch("os.name", "nt"):
            with pytest.raises((ExecutionProvenanceError, SerializationSecurityError), match="Fatal DACL error"):
                get_or_create_execution_key(key_dir=key_dir)


def test_adversarial_at28_windows_dacl_verification_failure_fails_closed(tmp_path):
    """AT-28: Windows DACL verification failure fails closed."""
    key_dir = str(tmp_path / "keys_at28")
    os.makedirs(key_dir, exist_ok=True)
    with patch("framework.auth_correlation.ledger._verify_windows_directory_security", side_effect=SerializationSecurityError("Insecure permissions")):
        with patch("os.name", "nt"):
            with pytest.raises((ExecutionProvenanceError, SerializationSecurityError), match="Insecure permissions"):
                get_or_create_capability_key(key_dir=key_dir)


def test_adversarial_at29_testing_primitive_rejected_by_ledger_and_mode_a(tmp_path):
    """AT-29: Low-level testing primitives (is_testing_primitive=True) are rejected by record_execution and Mode A attestation."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "at29")
    test_cap = create_test_execution_capability(
        action_id=clean_aid,
        action_dossier_digest=cap.action_dossier_digest,
        approval_id=app_id,
        program_id=cap.program_id,
        session_ref=cap.session_ref,
        principal_id=cap.principal_id,
        test_account=cap.test_account,
        target_endpoint=cap.target_endpoint,
        http_method=cap.http_method,
        action_type=cap.action_type,
        mutation_evidence_ref=cap.mutation_evidence_ref,
        mutation_request_digest=cap.mutation_request_digest,
        mutation_response_digest=cap.mutation_response_digest,
        mutation_status_code=200,
        verification_evidence_ref=cap.verification_evidence_ref,
        verification_request_digest=cap.verification_request_digest,
        verification_response_digest=cap.verification_response_digest,
        verification_status_code=401,
        verification_method=cap.verification_method,
        invalidation_verification_result="REVOKED",
        execution_timestamp=cap.execution_timestamp,
        verification_timestamp=cap.verification_timestamp,
        consumption_token=c_token,
        capability_key=ledger._get_capability_key(),
    )
    assert test_cap.is_testing_primitive is True

    # 1. record_execution strictly rejects testing primitive capability
    with pytest.raises(ExecutionProvenanceError, match="testing primitive"):
        ledger.record_execution(capability=test_cap, evidence_store=store, consumed_approvals_path=consumed_path)

    # 2. Raw record marked is_testing_primitive is rejected by Mode A attestation
    raw_rec = ledger._record_raw_record_for_testing(
        action_id=clean_aid,
        action_dossier_digest=clean_aid[4:],
        approval_id="APPR-RAW-TEST-01",
        program_id="test_program",
        session_ref=cap.session_ref,
        principal_id=cap.principal_id,
        test_account=cap.principal_id,
        target_endpoint=cap.target_endpoint,
        http_method="POST",
        action_type="LOGOUT",
        mutation_evidence_ref=cap.mutation_evidence_ref,
        mutation_request_digest=cap.mutation_request_digest,
        mutation_response_digest=cap.mutation_response_digest,
        mutation_status_code=200,
        verification_evidence_ref=cap.verification_evidence_ref,
        verification_request_digest=cap.verification_request_digest,
        verification_response_digest=cap.verification_response_digest,
        verification_status_code=401,
        verification_method="MUTATION_EXPLICIT_REVOCATION_VERIFIED",
        invalidation_verification_result="REVOKED",
        execution_timestamp="2026-11-11T12:00:00Z",
        verification_timestamp="2026-11-11T12:00:00Z",
    )
    assert raw_rec.is_testing_primitive is True

    with pytest.raises((ExecutionProvenanceError, AttestationSecurityError), match="test primitive"):
        _create_controlled_invalidation_attestation_from_record(
            execution_record=raw_rec,
            execution_ledger=ledger,
            evidence_store=store,
            key_dir=ledger._key_dir,
        )


def test_adversarial_at30_genuine_mode_b_lifecycle_end_to_end(tmp_path):
    """
    AT-30: Legitimate controlled Mode B execution lifecycle end-to-end.
    Exercises genuine execution workflow via PostRevocationResourceValidator.execute_controlled_invalidation
    using an isolated deterministic offline test transport.
    Proves:
    1. Approval validation
    2. Single-use consumption
    3. Scope check
    4. Controlled mutation dispatch & actual wire response captured
    5. Controlled verification dispatch & actual wire response captured
    6. Durable evidence persisted as CONTROLLED_TRANSPORT_DISPATCH
    7. Trusted ExecutionRecord issued and signed in ledger
    8. Successful Mode A invalidation provenance verification
    9. Rejection if any bound field or evidence byte changes
    """
    state_dir = str(tmp_path / "state_at30")
    key_dir = str(tmp_path / "keys_at30")
    ev_dir = str(tmp_path / "ev_at30")
    os.makedirs(state_dir, exist_ok=True)
    os.makedirs(key_dir, exist_ok=True)
    os.makedirs(ev_dir, exist_ok=True)

    app_key = get_or_create_approval_key(key_dir=key_dir)
    auth_tok = secrets.token_hex(32)
    store = EvidenceStore(ev_dir, authority_token=auth_tok)
    ledger = ExecutionLedger(state_dir=state_dir, key_dir=key_dir, approval_key=app_key)

    class MockScopeEngine:
        def is_in_scope(self, url: str) -> bool:
            return True

    mock_scope = MockScopeEngine()

    # Mock engine that deterministically responds to mutation and verification requests
    class MockEngine:
        def __init__(self):
            self.requests = []

        def send_request(self, req: ControlledRequest) -> ControlledResponse:
            self.requests.append(req)
            if req.method == "POST":
                # Mutation response
                return ControlledResponse(
                    status_code=200,
                    headers={"Content-Type": "application/json", "Set-Cookie": "sess=; Max-Age=0"},
                    body_bytes=b'{"status": "logged_out", "revoked": true}',
                    elapsed_ms=15.0,
                    source_ip="127.0.0.1",
                )
            else:
                # Post-mutation verification probe response
                return ControlledResponse(
                    status_code=401,
                    headers={"Content-Type": "application/json"},
                    body_bytes=b'{"error": "Unauthorized", "revoked": true}',
                    elapsed_ms=12.0,
                    source_ip="127.0.0.1",
                )

    mock_engine = MockEngine()
    validator = PostRevocationResourceValidator(
        validation_engine=mock_engine,
        execution_ledger=ledger,
        evidence_store=store,
        scope_engine=mock_scope,
        approval_key_dir=key_dir,
        state_dir=state_dir,
        program_id="test_program",
    )

    sess_ref = "sess_00000000000000000000000000000030"
    sess = CorrelatedSessionContext(
        session_ref=sess_ref,
        principal_id="user30",
        volatile_headers={"Authorization": "Bearer test_token"},
        lifecycle=CorrelationLifecycle.VERIFIED,
    )

    from tests.test_phase21_preflight_and_revocation import sign_action_approval

    app_id = "APPR-00000000000000000000000000000030"
    dossier = {
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": "test_program",
        "target_endpoint": "https://target.local/auth/logout",
        "test_account": "user30",
        "ttl": 3600,
        "unique_approval_id": app_id,
    }
    signed_dossier = sign_action_approval(dossier, approval_key=app_key)
    clean_aid = signed_dossier["action_id"]

    from framework.auth_correlation.ipc.service import IsolatedExecutionDispatcher
    from framework.auth_correlation.ipc.client import IsolatedDispatcherClient
    disp_pipe = rf"\\.\pipe\test_at30_{secrets.token_hex(4)}" if os.name == "nt" else str(tmp_path / "at30.sock")
    disp = IsolatedExecutionDispatcher(
        program_id="test_program",
        pipe_name=disp_pipe if os.name == "nt" else None,
        socket_path=disp_pipe if os.name != "nt" else None,
        key_dir=key_dir,
        state_dir=state_dir,
        evidence_dir=str(store.evidence_dir),
        approval_key=app_key,
        transport_engine=mock_engine,
        scope_engine=mock_scope,
        is_lab=True,
    )
    disp.start()
    client = IsolatedDispatcherClient(endpoint_type="pipe" if os.name == "nt" else "unix", address=disp_pipe)
    validator._dispatcher_client = client
    validator._dispatcher_verification_key = disp.signing_key

    try:
        # 1. Execute genuine Mode B invalidation workflow
        success = validator.execute_controlled_invalidation(
            session_ctx=sess,
            action_id=clean_aid,
            action_dossier=signed_dossier,
        )
        assert success is True
        assert sess.lifecycle == CorrelationLifecycle.REVOKED
        assert sess.invalidation_evidence_ref is not None

        # 2. Verify evidence persistence
        att_ev = store.get_invalidation_attestation(sess.invalidation_evidence_ref)
        assert att_ev is not None
        assert att_ev["event_type"] == "SESSION_REVOCATION"

        # 3. Verify Mode A provenance verification succeeds
        provenance_valid, reason, _ = validator.verify_invalidation_provenance(
            invalidation_evidence_ref=sess.invalidation_evidence_ref,
            session_ctx=sess,
        )
        assert provenance_valid is True

        # 4. Single-use approval consumption: Attempting second invalidation with same approval fails closed
        with pytest.raises(ApprovalSecurityError, match="already been consumed"):
            validator.execute_controlled_invalidation(
                session_ctx=sess,
                action_id=clean_aid,
                action_dossier=signed_dossier,
            )

        # 5. Tampering with evidence bytes triggers immediate provenance failure
        mut_ev_id = att_ev["mutation_evidence_ref"]
        mut_ev = store.get_evidence(mut_ev_id)
        with open(mut_ev["capture_path"], "ab") as f:
            f.write(b"\nTAMPERED_POST_EXECUTION")

        # Mode A provenance re-verification now fails closed
        provenance_tampered, _, _ = validator.verify_invalidation_provenance(
            invalidation_evidence_ref=sess.invalidation_evidence_ref,
            session_ctx=sess,
        )
        assert provenance_tampered is False
    finally:
        disp.stop()


# ==============================================================================
# SECTION 4: 10 INDEPENDENT SECURITY REVIEW ATTACKS (Section 7)
# ==============================================================================

def test_attack_01_fake_capability_construction(tmp_path):
    """Attack 1: Construct a fake capability and try to obtain a trusted ledger record."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "att01")

    fake_cap = ExecutionCapability(
        approval_id="APPR-FAKE1234",
        action_id=clean_aid,
        action_dossier_digest=clean_aid[4:],
        program_id=cap.program_id,
        session_ref=cap.session_ref,
        principal_id=cap.principal_id,
        test_account=cap.test_account,
        target_endpoint=cap.target_endpoint,
        http_method="POST",
        action_type="LOGOUT",
        mutation_evidence_ref=cap.mutation_evidence_ref,
        mutation_request_digest=cap.mutation_request_digest,
        mutation_response_digest=cap.mutation_response_digest,
        mutation_status_code=200,
        verification_evidence_ref=cap.verification_evidence_ref,
        verification_request_digest=cap.verification_request_digest,
        verification_response_digest=cap.verification_response_digest,
        verification_status_code=401,
        verification_method="MUTATION_EXPLICIT_REVOCATION_VERIFIED",
        invalidation_verification_result="REVOKED",
        execution_timestamp="2026-11-11T12:00:00Z",
        verification_timestamp="2026-11-11T12:00:00Z",
        consumption_token=c_token,
        capability_id="CAP-" + "0" * 64,
        signature="CAP-SIG-" + "F" * 64,
    )
    with pytest.raises(ExecutionProvenanceError, match="capability signature verification failed"):
        ledger.record_execution(capability=fake_cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_attack_02_capability_issuer_with_fabricated_evidence(tmp_path):
    """Attack 2: Call capability issuer with fabricated mutation and verification evidence."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "att02")
    cap_key = ledger._get_capability_key()

    fake_dres = ControlledDispatchResult(
        dispatch_op_id="DISP-OP-" + "0" * 64,
        action_id=clean_aid,
        action_dossier_digest=clean_aid[4:],
        approval_id=app_id,
        program_id=cap.program_id,
        session_ref=cap.session_ref,
        principal_id=cap.principal_id,
        test_account=cap.test_account,
        target_endpoint=cap.target_endpoint,
        http_method="POST",
        action_type="LOGOUT",
        mutation_evidence_ref="EVID-112233445566",
        mutation_request_digest="0" * 64,
        mutation_response_digest="0" * 64,
        mutation_status_code=200,
        verification_evidence_ref="EVID-778899AABBCC",
        verification_request_digest="1" * 64,
        verification_response_digest="1" * 64,
        verification_status_code=401,
        verification_method="MUTATION_EXPLICIT_REVOCATION_VERIFIED",
        invalidation_verification_result="REVOKED",
        execution_timestamp="2026-11-11T12:00:00Z",
        verification_timestamp="2026-11-11T12:00:00Z",
        consumption_token=c_token,
        is_genuine_dispatch=True,
    )

    with pytest.raises(ExecutionProvenanceError, match="not found"):
        issue_execution_capability(
            dispatch_result=fake_dres,
            action_id=clean_aid,
            action_dossier_digest=clean_aid[4:],
            approval_id=app_id,
            program_id=cap.program_id,
            session_ref=cap.session_ref,
            principal_id=cap.principal_id,
            test_account=cap.test_account,
            target_endpoint=cap.target_endpoint,
            http_method="POST",
            action_type="LOGOUT",
            mutation_evidence_ref="EVID-112233445566",
            mutation_request_digest="0" * 64,
            mutation_response_digest="0" * 64,
            mutation_status_code=200,
            verification_evidence_ref="EVID-778899AABBCC",
            verification_request_digest="0" * 64,
            verification_response_digest="0" * 64,
            verification_status_code=401,
            verification_method="MUTATION_EXPLICIT_REVOCATION_VERIFIED",
            invalidation_verification_result="REVOKED",
            execution_timestamp="2026-11-11T12:00:00Z",
            verification_timestamp="2026-11-11T12:00:00Z",
            consumption_token=c_token,
            capability_key=cap_key,
            evidence_store=store,
            consumed_approvals_path=consumed_path,
            approval_key=ledger._approval_key,
        )


def test_attack_03_supply_nonexistent_approval_registry(tmp_path):
    """Attack 3: Supply a nonexistent approval registry path."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "att03")
    fake_reg = str(tmp_path / "ghost_registry.json")
    with pytest.raises(ExecutionProvenanceError, match="does not exist"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=fake_reg)


def test_attack_04_supply_forged_or_replayed_receipt(tmp_path):
    """Attack 4: Supply a forged or replayed approval receipt."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "att04")

    # 1. First record succeeds and marks receipt consumed
    rec1 = ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)
    assert rec1 is not None

    # 2. Replay attempt using same capability and consumed approval
    with pytest.raises(ExecutionProvenanceError, match="duplicate execution rejected"):
        ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_attack_05_manual_evidence_without_transport_dispatch(tmp_path):
    """Attack 5: Create evidence files and metadata manually, attempt to pass as genuine Mode B evidence."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "att05")

    # Save evidence without capture_source="CONTROLLED_TRANSPORT_DISPATCH"
    mut_manual = store.save_http_capture(
        request_text="POST /logout HTTP/1.1",
        response_text="HTTP/1.1 200 OK",
        metadata={
            "event_type": "SESSION_REVOCATION",
            "session_ref": cap.session_ref,
            "principal_id": cap.principal_id,
            "program_id": cap.program_id,
            "action_id": clean_aid,
            "capture_source": "MANUAL_CALLER_UPLOAD",
        },
        prefix="att05_mut",
    )
    cap_key = ledger._get_capability_key()

    manual_dres = ControlledDispatchResult(
        dispatch_op_id=cap.dispatch_op_id,
        action_id=clean_aid,
        action_dossier_digest=clean_aid[4:],
        approval_id=app_id,
        program_id=cap.program_id,
        session_ref=cap.session_ref,
        principal_id=cap.principal_id,
        test_account=cap.test_account,
        target_endpoint=cap.target_endpoint,
        http_method="POST",
        action_type="LOGOUT",
        mutation_evidence_ref=mut_manual["evidence_id"],
        mutation_request_digest=mut_manual["request_sha256"],
        mutation_response_digest=mut_manual["response_sha256"],
        mutation_status_code=200,
        verification_evidence_ref=cap.verification_evidence_ref,
        verification_request_digest=cap.verification_request_digest,
        verification_response_digest=cap.verification_response_digest,
        verification_status_code=cap.verification_status_code,
        verification_method=cap.verification_method,
        invalidation_verification_result=cap.invalidation_verification_result,
        execution_timestamp=cap.execution_timestamp,
        verification_timestamp=cap.verification_timestamp,
        consumption_token=c_token,
        is_genuine_dispatch=True,
    )

    with pytest.raises(ExecutionProvenanceError, match="was not captured by controlled transport dispatch"):
        issue_execution_capability(
            dispatch_result=manual_dres,
            action_id=clean_aid,
            action_dossier_digest=clean_aid[4:],
            approval_id=app_id,
            program_id=cap.program_id,
            session_ref=cap.session_ref,
            principal_id=cap.principal_id,
            test_account=cap.test_account,
            target_endpoint=cap.target_endpoint,
            http_method="POST",
            action_type="LOGOUT",
            mutation_evidence_ref=mut_manual["evidence_id"],
            mutation_request_digest=mut_manual["request_sha256"],
            mutation_response_digest=mut_manual["response_sha256"],
            mutation_status_code=200,
            verification_evidence_ref=cap.verification_evidence_ref,
            verification_request_digest=cap.verification_request_digest,
            verification_response_digest=cap.verification_response_digest,
            verification_status_code=cap.verification_status_code,
            verification_method=cap.verification_method,
            invalidation_verification_result=cap.invalidation_verification_result,
            execution_timestamp=cap.execution_timestamp,
            verification_timestamp=cap.verification_timestamp,
            consumption_token=c_token,
            capability_key=cap_key,
            evidence_store=store,
            consumed_approvals_path=consumed_path,
            approval_key=ledger._approval_key,
        )


def test_attack_06_reuse_genuine_capability_across_executions(tmp_path):
    """Attack 6: Reuse a genuine capability across a different execution."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "att06")
    rec1 = ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)
    assert rec1 is not None

    state_dir2 = str(tmp_path / "state_att06_new")
    os.makedirs(state_dir2, exist_ok=True)
    ledger2 = ExecutionLedger(state_dir=state_dir2, key_dir=ledger._key_dir, approval_key=ledger._approval_key)
    with pytest.raises(ExecutionProvenanceError, match="duplicate execution rejected"):
        ledger2.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)


def test_attack_07_modify_evidence_after_issuance(tmp_path):
    """Attack 7: Modify evidence on disk after a record has been issued."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "att07")
    rec = ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)
    assert rec is not None

    mut_ev = store.get_evidence(cap.mutation_evidence_ref)
    assert mut_ev is not None
    with open(mut_ev["capture_path"], "ab") as f:
        f.write(b"\nTAMPERED_POST_ISSUANCE")

    assert store.get_evidence(cap.mutation_evidence_ref) is None


def test_attack_08_windows_dacl_failures(tmp_path):
    """Attack 8: Cause Windows DACL enforcement or verification to fail."""
    key_dir = str(tmp_path / "keys_att08")
    os.makedirs(key_dir, exist_ok=True)
    with patch("framework.auth_correlation.ledger._enforce_windows_directory_dacl", side_effect=SerializationSecurityError("Fatal DACL error")):
        with patch("os.name", "nt"):
            with pytest.raises((ExecutionProvenanceError, SerializationSecurityError), match="Fatal DACL error"):
                get_or_create_execution_key(key_dir=key_dir)


def test_attack_09_interrupted_persistence_midway(tmp_path):
    """Attack 9: Interrupt evidence or ledger persistence midway fails closed."""
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "att09")

    with patch("framework.auth_correlation.ledger.os.replace", side_effect=OSError("Disk write interrupted")):
        with pytest.raises(ExecutionProvenanceError, match="Failed to update consumed approval registry|Failed to persist execution ledger"):
            ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)

    with open(consumed_path, "r", encoding="utf-8") as f:
        cdata = json.load(f)
    assert cdata["version"] in (1, "1.0")


def test_attack_10_concurrent_approval_consumption(tmp_path):
    """Attack 10: Attempt concurrent use of the same approval."""
    import concurrent.futures
    ledger, cap, store, consumed_path, clean_aid, app_id, c_token = _create_valid_execution_fixture(tmp_path, "att10")
    _ = ledger._get_key()
    _ = ledger._get_capability_key()

    results = []
    errors = []

    def run_record():
        try:
            r = ledger.record_execution(capability=cap, evidence_store=store, consumed_approvals_path=consumed_path)
            results.append(r)
        except ExecutionProvenanceError as e:
            errors.append(e)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = [ex.submit(run_record) for _ in range(4)]
        concurrent.futures.wait(futures)

    assert len(results) == 1
    assert len(errors) == 3
    for err in errors:
        s = str(err).lower()
        assert "duplicate execution" in s or "already been executed" in s or "cross-execution reuse" in s
