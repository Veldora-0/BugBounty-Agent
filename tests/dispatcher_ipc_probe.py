"""Send a deliberately invalid Mode B approval to the live isolated dispatcher.

This probe uses a reserved loopback port and an invalid signature. The dispatcher
must reject the request before any transport activity, approval consumption, or
evidence write can occur.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.auth_correlation.ipc.client import IsolatedDispatcherClient


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: dispatcher_ipc_probe.py <unix-socket>")

    client = IsolatedDispatcherClient(endpoint_type="unix", address=sys.argv[1], timeout=3.0)
    program_id = "phase21-isolation-probe"
    canonical_fields = {
        "action_type": "LOGOUT",
        "created_at": time.time(),
        "method": "POST",
        "program_id": program_id,
        "target_endpoint": "https://phase21-isolation-probe.invalid/logout",
        "test_account": "phase21-isolation-probe",
        "ttl": 300.0,
        "unique_approval_id": f"APPR-{secrets.token_hex(8).upper()}",
    }
    canonical = json.dumps(canonical_fields, sort_keys=True)
    action_id = "ACT-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    dossier = {
        **canonical_fields,
        "action_id": action_id,
        "approval_signature": "SIG-" + ("0" * 64),
    }

    response = client.dispatch_mutation(
        program_id=program_id,
        action_id=action_id,
        action_dossier=dossier,
        session_context={
            "session_ref": "sess_" + ("0" * 32),
            "principal_id": "phase21-isolation-probe",
            "volatile_headers": {},
        },
    )

    allowed_rejections = {"MISSING_APPROVAL_KEY", "INVALID_OPERATOR_SIGNATURE"}
    if response.get("status") != "REJECTED" or response.get("error_code") not in allowed_rejections:
        raise SystemExit(
            "FAIL: live dispatcher did not reject the invalid operator approval: "
            f"status={response.get('status')!r}, error_code={response.get('error_code')!r}"
        )
    if response.get("receipt") is not None:
        raise SystemExit("FAIL: rejected request unexpectedly returned an execution receipt")

    print(f"PASS: live dispatcher rejected invalid approval ({response['error_code']}) before execution.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
