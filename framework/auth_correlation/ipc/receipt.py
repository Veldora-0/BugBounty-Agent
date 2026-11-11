"""
Phase 21: Signed Execution Receipts.

Defines the structure, canonical serialization, cryptographic signing,
and independent verification for execution receipts produced by the isolated
execution dispatcher authority.

Receipts bind:
- Receipt ID, version, dispatcher identity, and signing key ID
- Action ID, action dossier digest, approval ID, request nonce, and execution ID
- Target endpoint, HTTP method, action type, and scope decision
- Evidence record references and integrity digests (SHA-256)
- Independent verification outcome ('REVOKED')
- Cryptographic HMAC-SHA256 signature produced with dispatcher private key
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re
from typing import Any, Dict, Optional, Tuple


RECEIPT_VERSION = 1

RECEIPT_ID_PATTERN = re.compile(r"^RCPT-[0-9A-Fa-f]{32}$")
ACTION_ID_PATTERN = re.compile(r"^ACT-[0-9A-Fa-f]{64}$")
APPROVAL_ID_PATTERN = re.compile(r"^APPR-[0-9A-Fa-f]{16,64}$")
EXECUTION_ID_PATTERN = re.compile(r"^EXEC-[0-9A-Fa-f]{32}$")
NONCE_PATTERN = re.compile(r"^NONCE-[0-9A-Fa-f]{32}$")
EVIDENCE_REF_PATTERN = re.compile(r"^EVID-[0-9A-F]{12}$")
SIG_PATTERN = re.compile(r"^SIG-[0-9a-f]{64}$")

CANONICAL_RECEIPT_FIELDS = (
    "action_dossier_digest",
    "action_id",
    "action_type",
    "approval_id",
    "consumption_token",
    "dispatch_op_id",
    "dispatcher_id",
    "dispatcher_key_id",
    "execution_id",
    "execution_outcome",
    "http_method",
    "issued_at",
    "mutation_evidence",
    "principal_id",
    "program_id",
    "receipt_id",
    "request_nonce",
    "scope_decision",
    "target_endpoint",
    "verification_evidence",
    "version",
)

CANONICAL_EVIDENCE_FIELDS = (
    "evidence_id",
    "request_sha256",
    "response_sha256",
    "status_code",
    "timestamp",
)

CANONICAL_VERIFICATION_EVIDENCE_FIELDS = (
    "evidence_id",
    "invalidation_result",
    "request_sha256",
    "response_sha256",
    "status_code",
    "timestamp",
    "verification_method",
)


def canonicalize_receipt(receipt_dict: Dict[str, Any]) -> str:
    """
    Produces deterministic canonical JSON string across all canonical fields.
    Excludes the 'signature' field itself.
    """
    clean_dict: Dict[str, Any] = {}
    for f in CANONICAL_RECEIPT_FIELDS:
        if f not in receipt_dict:
            raise ValueError(f"Missing canonical receipt field: '{f}'")
        val = receipt_dict[f]
        if f == "mutation_evidence":
            if not isinstance(val, dict):
                raise ValueError("mutation_evidence must be a dictionary")
            clean_dict[f] = {ef: val[ef] for ef in CANONICAL_EVIDENCE_FIELDS if ef in val}
        elif f == "verification_evidence":
            if not isinstance(val, dict):
                raise ValueError("verification_evidence must be a dictionary")
            clean_dict[f] = {ef: val[ef] for ef in CANONICAL_VERIFICATION_EVIDENCE_FIELDS if ef in val}
        else:
            clean_dict[f] = val

    return json.dumps(clean_dict, sort_keys=True, separators=(",", ":"))


def sign_execution_receipt(receipt_dict: Dict[str, Any], signing_key: bytes) -> str:
    """
    Computes cryptographic HMAC-SHA256 signature over the canonical receipt string.
    Returns signature formatted as SIG-<64-hex>.
    """
    if not isinstance(signing_key, (bytes, bytearray)) or len(signing_key) < 32:
        raise ValueError("Dispatcher signing key must be at least 32 bytes")

    canonical_str = canonicalize_receipt(receipt_dict)
    sig_hex = hmac.new(signing_key, canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"SIG-{sig_hex}"


def verify_execution_receipt(
    receipt_dict: Dict[str, Any],
    verification_key: bytes,
    expected_action_id: Optional[str] = None,
    expected_nonce: Optional[str] = None,
    expected_program_id: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Strictly verifies an ExecutionReceipt:
    1. Validates all required canonical fields and formats.
    2. Validates version == 1 and scope_decision == 'ALLOWED'.
    3. Validates invalidation_result == 'REVOKED'.
    4. Validates matching action_id, nonce, program_id if expected values provided.
    5. Cryptographically verifies HMAC-SHA256 signature using verification_key.
    Returns (is_valid: bool, reason: str).
    """
    if not isinstance(receipt_dict, dict):
        return False, "Receipt must be a dictionary"

    sig = receipt_dict.get("signature")
    if not isinstance(sig, str) or not SIG_PATTERN.match(sig):
        return False, f"Invalid receipt signature format: '{sig}'"

    version = receipt_dict.get("version")
    if version != RECEIPT_VERSION:
        return False, f"Unsupported receipt version: {version}"

    rcpt_id = receipt_dict.get("receipt_id")
    if not isinstance(rcpt_id, str) or not RECEIPT_ID_PATTERN.match(rcpt_id):
        return False, f"Invalid receipt_id format: '{rcpt_id}'"

    aid = receipt_dict.get("action_id")
    if not isinstance(aid, str) or not ACTION_ID_PATTERN.match(aid):
        return False, f"Invalid action_id format in receipt: '{aid}'"

    if expected_action_id and aid != expected_action_id:
        return False, f"Receipt action_id '{aid}' does not match expected '{expected_action_id}'"

    nonce = receipt_dict.get("request_nonce")
    if not isinstance(nonce, str) or not NONCE_PATTERN.match(nonce):
        return False, f"Invalid request_nonce format in receipt: '{nonce}'"

    if expected_nonce and nonce != expected_nonce:
        return False, f"Receipt nonce '{nonce}' does not match expected request nonce '{expected_nonce}'"

    prog = receipt_dict.get("program_id")
    if expected_program_id and prog != expected_program_id:
        return False, f"Receipt program_id '{prog}' does not match expected '{expected_program_id}'"

    scope_dec = receipt_dict.get("scope_decision")
    if scope_dec != "ALLOWED":
        return False, f"Receipt indicates non-allowed scope decision: '{scope_dec}'"

    ver_ev = receipt_dict.get("verification_evidence")
    if not isinstance(ver_ev, dict):
        return False, "Receipt missing verification_evidence descriptor"

    inv_res = ver_ev.get("invalidation_result")
    if inv_res != "REVOKED":
        return False, f"Verification evidence reports invalidation_result='{inv_res}' (expected 'REVOKED')"

    # Check cryptographic signature
    try:
        canonical_str = canonicalize_receipt(receipt_dict)
    except Exception as e:
        return False, f"Failed to canonicalize receipt: {e}"

    expected_sig_hex = hmac.new(verification_key, canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig[4:], expected_sig_hex):
        return False, "Receipt cryptographic signature verification failed (tampered or wrong key)"

    return True, "Receipt cryptographically verified"
