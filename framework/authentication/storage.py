"""
State Persistence & Workspace Storage Engine (Phase 14.1 / 14.2).

Persists discovered authentication surfaces, identities, session models, hypotheses,
and findings to state/authentication.json.
Enforces atomic cross-platform file replacement, explicit corruption detection,
and resume capability.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
import uuid
from typing import Any, Dict, List, Optional

from framework.authentication.models import (
    AuthenticationFindingCandidate,
    AuthenticationFlow,
    AuthenticationHypothesis,
    AuthenticationStep,
    IdentityProfile,
    SessionProfile,
    TokenMetadata,
)


class CorruptedStateError(Exception):
    """Raised when an existing state file exists on disk but is unparseable or corrupted."""
    pass


class AuthenticationStateManager:
    """Manages serialization and atomic persistence of authentication state."""

    def __init__(self, workspace_dir: str) -> None:
        self.workspace_dir = os.path.abspath(workspace_dir)
        self.state_dir = os.path.join(self.workspace_dir, "state")
        self.state_file = os.path.join(self.state_dir, "authentication.json")

    def save_state(
        self,
        surfaces: List[AuthenticationStep],
        identities: List[IdentityProfile],
        flows: List[AuthenticationFlow],
        sessions: List[SessionProfile],
        hypotheses: List[AuthenticationHypothesis],
        findings: List[AuthenticationFindingCandidate],
        evidence_records: List[Dict[str, Any]],
        token_metadata: Optional[List[TokenMetadata]] = None,
    ) -> None:
        """Atomically serializes and writes authentication state to disk."""
        os.makedirs(self.state_dir, exist_ok=True)

        payload: Dict[str, Any] = {
            "version": "1.14.0",
            "surfaces": [s.to_dict() for s in surfaces],
            "identities": [i.to_dict() for i in identities],
            "flows": [f.to_dict() for f in flows],
            "sessions": [s.to_dict() for s in sessions],
            "hypotheses": [h.to_dict() for h in hypotheses],
            "findings": [f.to_dict() for f in findings],
            "evidence": evidence_records,
            "tokens": [t.to_dict() for t in (token_metadata or [])],
        }

        # Write to temporary file in same directory, flush, fsync, then atomic os.replace
        temp_file = os.path.join(self.state_dir, f"authentication_{os.getpid()}_{uuid.uuid4().hex[:6]}.tmp")
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_file, self.state_file)
        finally:
            if os.path.isfile(temp_file):
                try:
                    os.remove(temp_file)
                except OSError:
                    pass

    def load_state(self) -> Dict[str, Any]:
        """Loads state from disk if present. Fails closed and raises CorruptedStateError on corrupt JSON."""
        if not os.path.isfile(self.state_file):
            return {
                "surfaces": [],
                "identities": [],
                "flows": [],
                "sessions": [],
                "hypotheses": [],
                "findings": [],
                "evidence": [],
                "tokens": [],
                "is_corrupted": False,
            }

        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return {
                "surfaces": [AuthenticationStep.from_dict(s) for s in data.get("surfaces", [])],
                "identities": [IdentityProfile.from_dict(i) for i in data.get("identities", [])],
                "flows": [AuthenticationFlow.from_dict(fl) for fl in data.get("flows", [])],
                "sessions": [SessionProfile.from_dict(sp) for sp in data.get("sessions", [])],
                "hypotheses": [AuthenticationHypothesis.from_dict(h) for h in data.get("hypotheses", [])],
                "findings": [AuthenticationFindingCandidate.from_dict(fc) for fc in data.get("findings", [])],
                "evidence": data.get("evidence", []),
                "tokens": [TokenMetadata.from_dict(t) for t in data.get("tokens", [])],
                "is_corrupted": False,
            }
        except Exception as e:
            ts = int(time.time())
            corrupt_backup = f"{self.state_file}.corrupt.{ts}"
            try:
                shutil.copy2(self.state_file, corrupt_backup)
            except OSError:
                pass
            print(f"[-] Error: Failed to parse authentication state from {self.state_file}: {e}", file=sys.stderr)
            print(f"[-] Corrupted state backed up to {corrupt_backup}", file=sys.stderr)
            raise CorruptedStateError(f"Authentication state file '{self.state_file}' is corrupted: {e}") from e
