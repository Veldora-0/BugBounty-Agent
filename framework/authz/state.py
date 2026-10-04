"""
State Management for Authorization Intelligence & Validation (Phase 8).

Provides persistent, atomic, resumable storage for principals, sessions,
resources, policies, approvals, test cases, and findings in:
~/BugBounty-Workspace/programs/<program>/state/authorization.json
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import tempfile
from typing import Any, Dict, List, Optional

from framework.authz.model import (
    AuthorizationTestCase,
    ExpectedAccessPolicy,
    PrincipalProfile,
    ResourceAccessTarget,
    SessionProfile,
)


class AuthorizationStateManager:
    """
    Manages local persistent authorization state in state/authorization.json.
    """

    def __init__(self, program_dir: str):
        self.program_dir = os.path.abspath(program_dir)
        self.state_dir = os.path.join(self.program_dir, "state")
        os.makedirs(self.state_dir, exist_ok=True)

        self.authz_file = os.path.join(self.state_dir, "authorization.json")
        self._init_file()

    def _init_file(self) -> None:
        """Initializes empty authorization.json if not present."""
        if not os.path.exists(self.authz_file):
            default_content = {
                "version": "1.0.0",
                "program": os.path.basename(self.program_dir),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "state_hash": "",
                "principals": {},
                "sessions": {},
                "resources": {},
                "policies": {},
                "test_cases": {},
                "approved_tests": {},
                "findings": {},
                "completed_fingerprints": {},
                "summary": {
                    "total_principals": 0,
                    "total_resources": 0,
                    "total_test_cases": 0,
                    "approved_test_cases": 0,
                    "findings_recorded": 0,
                    "by_category": {},
                    "by_lifecycle": {},
                },
            }
            self._atomic_write_json(default_content)

    def _read_json(self) -> Dict[str, Any]:
        """Reads authorization state safely."""
        try:
            with open(self.authz_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {
                "version": "1.0.0",
                "program": os.path.basename(self.program_dir),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "state_hash": "",
                "principals": {},
                "sessions": {},
                "resources": {},
                "policies": {},
                "test_cases": {},
                "approved_tests": {},
                "findings": {},
                "completed_fingerprints": {},
                "summary": {},
            }

    def _atomic_write_json(self, data: Dict[str, Any]) -> None:
        """Writes data atomically using a temporary file replacement."""
        data["last_updated"] = datetime.now(timezone.utc).isoformat()
        num_tests = len(data.get("test_cases", {}))
        num_finds = len(data.get("findings", {}))
        data["state_hash"] = hashlib.sha256(f"{num_tests}:{num_finds}:{data['last_updated']}".encode("utf-8")).hexdigest()[:16]

        # Recompute summary
        by_cat: Dict[str, int] = {}
        by_life: Dict[str, int] = {}
        for tc in data.get("test_cases", {}).values():
            c = tc.get("category", "unknown")
            by_cat[c] = by_cat.get(c, 0) + 1
            l = tc.get("lifecycle_state", "CANDIDATE")
            by_life[l] = by_life.get(l, 0) + 1

        data["summary"] = {
            "total_principals": len(data.get("principals", {})),
            "total_resources": len(data.get("resources", {})),
            "total_test_cases": num_tests,
            "approved_test_cases": len(data.get("approved_tests", {})),
            "findings_recorded": num_finds,
            "by_category": by_cat,
            "by_lifecycle": by_life,
        }

        dir_name = os.path.dirname(self.authz_file)
        with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
            json.dump(data, tf, indent=2)
            temp_path = tf.name
        os.replace(temp_path, self.authz_file)

    # ---------------- Principal Operations ----------------

    def save_principal(self, principal: PrincipalProfile) -> PrincipalProfile:
        data = self._read_json()
        prins = data.get("principals", {})
        prins[principal.principal_id] = principal.to_dict()
        data["principals"] = prins
        self._atomic_write_json(data)
        return principal

    def get_principal(self, principal_id: str) -> Optional[PrincipalProfile]:
        data = self._read_json()
        p = data.get("principals", {}).get(principal_id)
        return PrincipalProfile.from_dict(p) if p else None

    def list_principals(self) -> List[PrincipalProfile]:
        data = self._read_json()
        return [PrincipalProfile.from_dict(p) for p in data.get("principals", {}).values()]

    # ---------------- Session Operations ----------------

    def save_session(self, session: SessionProfile) -> SessionProfile:
        data = self._read_json()
        sess = data.get("sessions", {})
        sess[session.session_id] = session.to_dict()
        data["sessions"] = sess
        self._atomic_write_json(data)
        return session

    def get_session(self, session_id: str) -> Optional[SessionProfile]:
        data = self._read_json()
        s = data.get("sessions", {}).get(session_id)
        return SessionProfile.from_dict(s) if s else None

    # ---------------- Resource Operations ----------------

    def save_resource(self, resource: ResourceAccessTarget) -> ResourceAccessTarget:
        data = self._read_json()
        res = data.get("resources", {})
        res[resource.target_id] = resource.to_dict()
        data["resources"] = res
        self._atomic_write_json(data)
        return resource

    def get_resource(self, target_id: str) -> Optional[ResourceAccessTarget]:
        data = self._read_json()
        r = data.get("resources", {}).get(target_id)
        return ResourceAccessTarget.from_dict(r) if r else None

    def list_resources(self) -> List[ResourceAccessTarget]:
        data = self._read_json()
        return [ResourceAccessTarget.from_dict(r) for r in data.get("resources", {}).values()]

    # ---------------- Policy Operations ----------------

    def save_policy(self, policy_key: str, policy: ExpectedAccessPolicy) -> ExpectedAccessPolicy:
        data = self._read_json()
        pols = data.get("policies", {})
        pols[policy_key] = policy.to_dict()
        data["policies"] = pols
        self._atomic_write_json(data)
        return policy

    def get_policy(self, policy_key: str) -> Optional[ExpectedAccessPolicy]:
        data = self._read_json()
        p = data.get("policies", {}).get(policy_key)
        return ExpectedAccessPolicy.from_dict(p) if p else None

    # ---------------- Test Case & Approval Operations ----------------

    def save_test_case(self, test_case: AuthorizationTestCase) -> AuthorizationTestCase:
        data = self._read_json()
        tcs = data.get("test_cases", {})
        tcs[test_case.test_id] = test_case.to_dict()
        data["test_cases"] = tcs
        self._atomic_write_json(data)
        return test_case

    def get_test_case(self, test_id: str) -> Optional[AuthorizationTestCase]:
        data = self._read_json()
        t = data.get("test_cases", {}).get(test_id)
        return AuthorizationTestCase.from_dict(t) if t else None

    def list_test_cases(self, category: Optional[str] = None, approved_only: bool = False) -> List[AuthorizationTestCase]:
        data = self._read_json()
        cases = [AuthorizationTestCase.from_dict(t) for t in data.get("test_cases", {}).values()]
        if category:
            cases = [c for c in cases if c.category.value == category or c.category == category]
        if approved_only:
            cases = [c for c in cases if c.approval_status == "APPROVED"]
        return cases

    def approve_test_case(self, test_id: str, approved_by: str = "researcher") -> bool:
        """Explicit human approval gate for high-impact authorization test execution."""
        data = self._read_json()
        tcs = data.get("test_cases", {})
        if test_id not in tcs:
            return False

        tcs[test_id]["approval_status"] = "APPROVED"
        tcs[test_id]["lifecycle_state"] = "APPROVED"
        data["test_cases"] = tcs

        approved = data.get("approved_tests", {})
        approved[test_id] = {
            "test_id": test_id,
            "approved_by": approved_by,
            "approved_at": datetime.now(timezone.utc).isoformat(),
        }
        data["approved_tests"] = approved
        self._atomic_write_json(data)
        return True

    def is_test_approved(self, test_id: str) -> bool:
        data = self._read_json()
        return test_id in data.get("approved_tests", {})

    # ---------------- Findings & Summary ----------------

    def save_finding(self, finding_id: str, finding_dict: Dict[str, Any]) -> None:
        data = self._read_json()
        finds = data.get("findings", {})
        finds[finding_id] = finding_dict
        data["findings"] = finds
        self._atomic_write_json(data)

    def get_summary(self) -> Dict[str, Any]:
        data = self._read_json()
        return data.get("summary", {})
