"""
Tests for Phase 21 State Management, Symmetrical Schema Validation, and Persistence Security.

Verifies:
- Exact SUPPORTED_SCHEMA_ID validation (positive & negative cases)
- Referential integrity and duplicate identifier rejection
- Descriptor-based writing with os.fstat(), st_nlink == 1, and permissions (0o077 == 0)
- Descriptor-based load with O_NOFOLLOW, hard link rejection, and private permissions
- Workspace confinement and intermediate directory security
- Length-prefixed keyed HMAC key generation and session fingerprinting
- Corrupted state quarantine
"""

import json
import os
import stat
import pytest

from framework.auth_correlation.model import (
    CorrelatedPrincipalContext,
    CorrelatedSessionContext,
    CorrelationHypothesis,
    CorrelationFinding,
    CorrelationLifecycle,
    SerializationSecurityError,
    StateSecurityValidationError,
)
from framework.auth_correlation.state import (
    AuthCorrelationStateManager,
    KeySecurityError,
    validate_state_schema,
    _verify_and_prepare_state_dir,
    SUPPORTED_SCHEMA_ID,
)


def test_schema_identifier_positive_and_negative():
    """TC-STATE-09: Verifies exact matching of SUPPORTED_SCHEMA_ID before saving and after loading."""
    base_valid = {
        "$schema": SUPPORTED_SCHEMA_ID,
        "version": "1.0.0",
        "program": "acme-corp",
        "created_at": "2026-11-06T20:00:00Z",
        "last_updated": "2026-11-06T20:00:00Z",
        "key_id": "1a2b3c4d",
        "principals": {},
        "sessions": {},
        "hypotheses": [],
        "findings": [],
    }
    # Positive case: exact match passes
    assert validate_state_schema(base_valid)["$schema"] == SUPPORTED_SCHEMA_ID

    # Negative case 1: Missing $schema
    missing_schema = {k: v for k, v in base_valid.items() if k != "$schema"}
    with pytest.raises(StateSecurityValidationError):
        validate_state_schema(missing_schema)

    # Negative case 2: Non-string $schema (integer, boolean, dict, list, None)
    for bad_val in [123, True, False, None, {}, ["schema"]]:
        with pytest.raises(StateSecurityValidationError):
            validate_state_schema({**base_valid, "$schema": bad_val})

    # Negative case 3: Unsupported / unknown schema URI
    unsupported_schemas = [
        "https://bugbounty.local/schemas/auth-correlation-v2.json",
        "http://json-schema.org/draft-07/schema#",
        "https://bugbounty.local/schemas/auth-correlation-v0.json",
        "https://example.com/schema.json",
    ]
    for unk in unsupported_schemas:
        with pytest.raises(StateSecurityValidationError):
            validate_state_schema({**base_valid, "$schema": unk})

    # Negative case 4: Whitespace-padded or case-mismatched URI
    tampered_schemas = [
        " https://bugbounty.local/schemas/auth-correlation-v1.json",
        "https://bugbounty.local/schemas/auth-correlation-v1.json ",
        "HTTPS://BUGBOUNTY.LOCAL/schemas/auth-correlation-v1.json",
    ]
    for tamp in tampered_schemas:
        with pytest.raises(StateSecurityValidationError):
            validate_state_schema({**base_valid, "$schema": tamp})


def test_referential_integrity_and_duplicates_rejected():
    """Verifies that missing principal references or duplicate IDs raise StateSecurityValidationError."""
    base_state = {
        "$schema": SUPPORTED_SCHEMA_ID,
        "version": "1.0.0",
        "program": "acme",
        "created_at": "2026-11-06T20:00:00Z",
        "last_updated": "2026-11-06T20:00:00Z",
        "key_id": "1a2b3c4d",
        "principals": {
            "usr_a": {
                "principal_id": "usr_a",
                "tenant_id": "t1",
                "role": "USER",
                "privilege_level": None,
                "verification_status": "VERIFIED",
                "evidence_refs": [],
                "confidence": 0.9,
            }
        },
        "sessions": {},
        "hypotheses": [],
        "findings": [],
    }

    # Session references nonexistent principal
    bad_session_state = {
        **base_state,
        "sessions": {
            "sess_00000000000000000000000000000001": {
                "session_ref": "sess_00000000000000000000000000000001",
                "principal_id": "nonexistent_user",
                "hmac_fingerprint": None,
                "lifecycle": "CREATED",
                "expires_at": None,
                "verified_at": None,
                "metadata": {},
            }
        }
    }
    with pytest.raises(StateSecurityValidationError, match="references nonexistent principal_id"):
        validate_state_schema(bad_session_state)

    # Hypothesis references nonexistent principal
    bad_hyp_state = {
        **base_state,
        "hypotheses": [
            {
                "hypothesis_id": "HYP-01",
                "category": "TENANT_ISOLATION",
                "target_endpoint": "/api/test",
                "principal_a_id": "usr_a",
                "principal_b_id": "usr_ghost",
                "preflight_status": "CREATED",
                "expected_result": "ISOLATED",
                "validation_status": "PENDING",
            }
        ]
    }
    with pytest.raises(StateSecurityValidationError, match="references nonexistent principal_id"):
        validate_state_schema(bad_hyp_state)

    # Duplicate hypothesis ID
    dup_hyp_state = {
        **base_state,
        "hypotheses": [
            {
                "hypothesis_id": "HYP-01",
                "category": "TENANT_ISOLATION",
                "target_endpoint": "/api/test",
                "principal_a_id": "usr_a",
                "principal_b_id": "usr_a",
                "preflight_status": "CREATED",
                "expected_result": "ISOLATED",
                "validation_status": "PENDING",
            },
            {
                "hypothesis_id": "HYP-01",
                "category": "TENANT_ISOLATION",
                "target_endpoint": "/api/test2",
                "principal_a_id": "usr_a",
                "principal_b_id": "usr_a",
                "preflight_status": "CREATED",
                "expected_result": "ISOLATED",
                "validation_status": "PENDING",
            }
        ]
    }
    with pytest.raises(StateSecurityValidationError, match="Duplicate hypothesis_id"):
        validate_state_schema(dup_hyp_state)


def test_state_dir_security_and_workspace_confinement(tmp_path):
    """Verifies workspace boundary confinement and directory component security."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_dir = workspace / "state"

    # Directory escaping workspace boundary rejected
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    with pytest.raises(SerializationSecurityError, match="escapes workspace boundary"):
        _verify_and_prepare_state_dir(str(outside_dir), str(workspace))

    # Symlink ancestor rejected on POSIX
    if os.name != "nt":
        nested = workspace / "sub"
        nested.mkdir()
        sym = workspace / "sub_sym"
        os.symlink(str(outside_dir), str(sym))
        target_dir = sym / "state"
        with pytest.raises(SerializationSecurityError, match="is a symbolic link"):
            _verify_and_prepare_state_dir(str(target_dir), str(workspace))

    # Valid preparation
    prepared = _verify_and_prepare_state_dir(str(state_dir), str(workspace))
    assert os.path.exists(prepared)


def test_atomic_persistence_save_and_descriptor_load(tmp_path):
    """Verifies save_state() atomic replacement and descriptor-based load_state() checks."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_dir = workspace / "state"
    key_dir = tmp_path / "keys"

    mgr = AuthCorrelationStateManager(
        program_id="test-prog",
        workspace_root=str(workspace),
        state_dir=str(state_dir),
        key_dir=str(key_dir),
    )

    p1 = CorrelatedPrincipalContext(principal_id="u1", role="USER", verification_status="VERIFIED")
    mgr.principals["u1"] = p1

    s1 = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1")
    hyp = CorrelationHypothesis(
        hypothesis_id="HYP-01",
        category="TENANT_ISOLATION",
        target_endpoint="/api/orders",
        principal_a_id="u1",
        principal_b_id="u1",
    )

    # 1. Save state
    mgr.save_state([s1], [hyp], [])
    state_file = state_dir / "auth_correlation.json"
    assert state_file.exists()

    # Destination symlink attack prevention
    if os.name != "nt":
        fake_dest = tmp_path / "hijack.json"
        fake_dest.touch()
        os.unlink(str(state_file))
        os.symlink(str(fake_dest), str(state_file))
        with pytest.raises(SerializationSecurityError, match="destination state file is a symbolic link"):
            mgr.save_state([s1], [hyp], [])
        os.unlink(str(state_file))
        # Restore valid file
        mgr.save_state([s1], [hyp], [])

    # 2. Descriptor load checks on POSIX
    if os.name != "nt":
        # Check hardlink rejection (st_nlink != 1)
        hardlink_file = state_dir / "auth_correlation.json.link"
        os.link(str(state_file), str(hardlink_file))
        with pytest.raises(StateSecurityValidationError, match="unexpected hardlinks"):
            mgr.load_state()
        os.unlink(str(hardlink_file))

        # Check non-private permissions rejection (e.g. 0640)
        os.chmod(str(state_file), 0o640)
        with pytest.raises(StateSecurityValidationError, match="state file permissions are not private"):
            mgr.load_state()

        # Restore private permissions (0600)
        os.chmod(str(state_file), 0o600)

    # 3. Successful load and schema verification
    loaded = mgr.load_state()
    assert loaded["$schema"] == SUPPORTED_SCHEMA_ID
    assert loaded["program"] == "test-prog"
    assert "u1" in loaded["principals"]
    assert "sess_00000000000000000000000000000001" in loaded["sessions"]


def test_hmac_fingerprinting_and_quarantine(tmp_path):
    """Verifies length-prefixed HMAC fingerprinting and state quarantine."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_dir = workspace / "state"
    key_dir = tmp_path / "keys"

    mgr = AuthCorrelationStateManager(
        program_id="prog_alpha",
        workspace_root=str(workspace),
        state_dir=str(state_dir),
        key_dir=str(key_dir),
    )

    fp1 = mgr.compute_session_fingerprint("token_value_123", "prog_alpha", "BEARER")
    fp2 = mgr.compute_session_fingerprint("token_value_123", "prog_alpha", "BEARER")
    assert fp1 == fp2
    assert len(fp1) == 32

    # Different program_id produces different fingerprint
    fp_diff = mgr.compute_session_fingerprint("token_value_123", "prog_beta", "BEARER")
    assert fp1 != fp_diff

    # Quarantine corrupted state
    state_file = state_dir / "auth_correlation.json"
    state_dir.mkdir(exist_ok=True)
    state_file.write_text("{corrupted json", encoding="utf-8")
    assert state_file.exists()

    mgr.quarantine_corrupted_state()
    assert not state_file.exists()
    # Confirms quarantine file was generated
    corrupted_files = list(state_dir.glob("auth_correlation.corrupted.*.json"))
    assert len(corrupted_files) == 1


def test_state_directory_security_native_platform_enforcement(tmp_path):
    """Verifies native platform DACL (Windows) and POSIX permission enforcement for state directories."""
    workspace = tmp_path / "ws_sec"
    workspace.mkdir()
    state_dir = workspace / "sec_state"

    if os.name == "nt":
        import subprocess
        from framework.auth_correlation.state import (
            _enforce_windows_directory_dacl,
            _verify_windows_directory_security,
        )

        state_dir.mkdir()
        # Enforce protected DACL
        _enforce_windows_directory_dacl(str(state_dir))
        # Verification passes on protected DACL
        _verify_windows_directory_security(str(state_dir))

        # Grant unsafe write permission to Everyone
        subprocess.run(["icacls", str(state_dir), "/grant", "Everyone:(OI)(CI)W"], capture_output=True)
        with pytest.raises(SerializationSecurityError, match="grants unsafe write access"):
            _verify_windows_directory_security(str(state_dir))
    else:
        # On POSIX: verify group- or world-writable directory rejection
        state_dir.mkdir(mode=0o777)
        os.chmod(str(state_dir), 0o777)
        with pytest.raises(SerializationSecurityError, match="must not be group- or world-writable"):
            _verify_and_prepare_state_dir(str(state_dir), str(workspace))


def test_external_hmac_key_security_enforcement(tmp_path):
    """Verifies that external HMAC key directory and key file require strict private security."""
    key_dir = tmp_path / "keys_test"
    mgr = AuthCorrelationStateManager(
        program_id="test_key_prog",
        workspace_root=str(tmp_path),
        key_dir=str(key_dir),
    )
    key, kid = mgr.get_or_create_hmac_key()
    assert len(key) == 32
    assert len(kid) == 8

    key_file = key_dir / "auth_correlation.key"
    assert key_file.exists()

    if os.name != "nt":
        # Make key file non-private (0o644)
        os.chmod(str(key_file), 0o644)
        mgr_fail = AuthCorrelationStateManager(
            program_id="test_key_prog",
            workspace_root=str(tmp_path),
            key_dir=str(key_dir),
        )
        with pytest.raises(KeySecurityError, match="Key file permissions are not private"):
            mgr_fail.get_or_create_hmac_key()

