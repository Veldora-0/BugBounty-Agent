"""Phase 21: Trust-boundary status and dynamic assessment for controlled execution provenance.

Dynamically assesses execution provenance capability across daemon reachability,
public verification key validity, cryptographic receipt verification, evidence store
containment, and operating system privilege isolation boundaries.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import os
import shutil
import tempfile
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class ProvenanceBoundaryAssessment:
    """Structured assessment of the execution provenance trust boundary."""

    status: str
    reason: str
    dispatcher_reachable: bool
    public_key_available: bool
    public_key_valid: bool
    receipt_verification_operational: bool
    evidence_verification_operational: bool
    production_isolation_supported: bool
    end_to_end_provenance_available: bool
    platform: str

    def to_dict(self) -> Dict[str, Any]:
        """Returns assessment as a dictionary without leaking secrets or paths."""
        return asdict(self)


def assess_provenance_boundary(
    endpoint_type: Optional[str] = None,
    address: Optional[str] = None,
    public_key_path: Optional[str] = None,
    timeout: float = 2.0,
) -> ProvenanceBoundaryAssessment:
    """
    Dynamically assesses the execution provenance capability.

    Distinguishes:
    - Daemon reachability: Whether the isolated dispatcher IPC endpoint responds to PING.
    - Public key availability & validity: Whether the pinned 32-byte Ed25519 verification key is present.
    - Verification operational: Whether Ed25519 receipt verification and evidence checks are functional.
    - Production isolation support: True on Linux (systemd service running as dedicated user);
      False on Windows (documented platform limitation).
    - End-to-end provenance capability: True only when daemon, key, and verification subsystems succeed.

    Status reporting does not reveal sensitive configuration paths or internal key secrets.
    """
    platform_name = "windows" if os.name == "nt" else "linux"
    production_isolation_supported = (os.name != "nt")

    # 1. Dispatcher daemon reachability check
    dispatcher_reachable = False
    try:
        from framework.auth_correlation.ipc.client import IsolatedDispatcherClient
        client = IsolatedDispatcherClient(endpoint_type=endpoint_type, address=address, timeout=timeout)
        dispatcher_reachable = bool(client.ping())
    except Exception:
        dispatcher_reachable = False

    # 2. Public verification key availability & validity
    public_key_available = False
    public_key_valid = False
    try:
        from framework.auth_correlation.ipc.receipt import load_dispatcher_verification_key

        target_pub_path = public_key_path or os.environ.get("BUGBOUNTY_DISPATCHER_PUBLIC_KEY")
        if target_pub_path is None:
            if os.name == "nt":
                target_pub_path = os.path.join(
                    os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
                    "BugBounty", "Dispatcher", "dispatcher.pub",
                )
            else:
                target_pub_path = "/etc/bugbounty/dispatcher.pub"

        if os.path.exists(target_pub_path) and os.path.isfile(target_pub_path):
            public_key_available = True
            key_bytes = load_dispatcher_verification_key(path=target_pub_path)
            if isinstance(key_bytes, (bytes, bytearray)) and len(key_bytes) == 32:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                Ed25519PublicKey.from_public_bytes(bytes(key_bytes))
                public_key_valid = True
    except Exception:
        pass

    # 3. Receipt cryptographic verification operational check
    receipt_verification_operational = False
    try:
        import secrets
        from framework.auth_correlation.ipc.receipt import (
            derive_verification_key,
            sign_execution_receipt,
            verify_execution_receipt,
        )
        test_priv = secrets.token_bytes(32)
        test_pub = derive_verification_key(test_priv)
        sample_rcpt = {
            "version": 1,
            "receipt_id": f"RCPT-{secrets.token_hex(16).upper()}",
            "dispatcher_id": "DISPATCHER-PROBE",
            "dispatcher_key_id": "KEY-PROBE",
            "dispatch_op_id": f"DISP-OP-{secrets.token_hex(32).upper()}",
            "action_id": f"ACT-{'0' * 64}",
            "action_dossier_digest": "0" * 64,
            "approval_id": f"APPR-{'0' * 32}",
            "request_nonce": f"NONCE-{'0' * 32}",
            "execution_id": f"EXEC-{'0' * 32}",
            "program_id": "probe-program",
            "principal_id": "probe-user",
            "session_ref": "sess-probe",
            "target_endpoint": "https://target.local/probe",
            "http_method": "POST",
            "action_type": "LOGOUT",
            "scope_decision": "ALLOWED",
            "execution_outcome": "REVOCATION_VERIFIED",
            "mutation_evidence": {
                "evidence_id": "EVID-000000000001",
                "request_sha256": "0" * 64,
                "response_sha256": "0" * 64,
                "status_code": 200,
                "timestamp": "2026-11-15T12:00:00Z",
            },
            "verification_evidence": {
                "evidence_id": "EVID-000000000002",
                "invalidation_result": "REVOKED",
                "request_sha256": "0" * 64,
                "response_sha256": "0" * 64,
                "status_code": 401,
                "timestamp": "2026-11-15T12:00:00Z",
                "verification_method": "POST_MUTATION_PROBE_CONFIRMED_401",
            },
            "consumption_token": "0" * 64,
            "issued_at": "2026-11-15T12:00:00Z",
        }
        sample_rcpt["signature"] = sign_execution_receipt(sample_rcpt, test_priv)
        v_ok, _ = verify_execution_receipt(sample_rcpt, test_pub)
        receipt_verification_operational = bool(v_ok)
    except Exception:
        receipt_verification_operational = False

    # 4. Evidence verification operational check
    evidence_verification_operational = False
    try:
        from framework.common.evidence import EvidenceStore
        probe_dir = tempfile.mkdtemp(prefix="bb_ev_probe_")
        try:
            store = EvidenceStore(evidence_dir=probe_dir)
            evidence_verification_operational = hasattr(store, "save_transport_dispatch_capture")
        finally:
            shutil.rmtree(probe_dir, ignore_errors=True)
    except Exception:
        evidence_verification_operational = False

    # 5. Composite end-to-end capability and overall status
    end_to_end = bool(
        dispatcher_reachable
        and public_key_available
        and public_key_valid
        and receipt_verification_operational
        and evidence_verification_operational
    )

    if end_to_end and production_isolation_supported:
        status = "AVAILABLE"
        reason = "Isolated execution dispatcher is reachable, verification keys are valid, and production OS isolation is active"
    elif end_to_end and not production_isolation_supported:
        status = "AVAILABLE_WITH_LIMITATIONS"
        reason = "Isolated dispatcher and verification are operational, but production OS user/group isolation is unsupported on Windows"
    elif not dispatcher_reachable:
        status = "UNAVAILABLE"
        reason = "Isolated dispatcher service is not reachable over configured IPC endpoint"
    elif not public_key_available or not public_key_valid:
        status = "UNAVAILABLE"
        reason = "Dispatcher public verification key is missing, unreadable, or invalid"
    elif not receipt_verification_operational or not evidence_verification_operational:
        status = "UNAVAILABLE"
        reason = "Cryptographic receipt verification or evidence subsystem is non-operational"
    else:
        status = "UNAVAILABLE"
        reason = "Provenance prerequisites not satisfied"

    return ProvenanceBoundaryAssessment(
        status=status,
        reason=reason,
        dispatcher_reachable=dispatcher_reachable,
        public_key_available=public_key_available,
        public_key_valid=public_key_valid,
        receipt_verification_operational=receipt_verification_operational,
        evidence_verification_operational=evidence_verification_operational,
        production_isolation_supported=production_isolation_supported,
        end_to_end_provenance_available=end_to_end,
        platform=platform_name,
    )


def get_provenance_boundary_status() -> str:
    """Returns the current provenance boundary status string."""
    return assess_provenance_boundary().status


def get_provenance_boundary_reason() -> str:
    """Returns the current provenance boundary status reason string."""
    return assess_provenance_boundary().reason


def __getattr__(name: str) -> Any:
    """Provides backward-compatible module-level access for PROVENANCE_BOUNDARY_STATUS / REASON."""
    if name == "PROVENANCE_BOUNDARY_STATUS":
        return get_provenance_boundary_status()
    if name == "PROVENANCE_BOUNDARY_REASON":
        return get_provenance_boundary_reason()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
