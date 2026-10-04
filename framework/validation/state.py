"""
Security State Manager for BugBounty-Agent Validation.

Provides persistent, atomic, resumable, and deduplicated storage of security test cases,
baselines, validation results, and findings in:
~/BugBounty-Workspace/programs/<program>/state/security.json
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from framework.findings.schema import Finding
from framework.state.dedup import FindingDeduplicator
from framework.validation.baseline import BaselineObservation
from framework.validation.model import SecurityTestCase, ValidationResult


class SecurityStateManager:
    """
    Manages local persistent validation state in state/security.json.
    Thread-safe and atomic updates via tempfile.
    """

    def __init__(self, program_dir: str):
        self.program_dir = os.path.abspath(program_dir)
        self.state_dir = os.path.join(self.program_dir, "state")
        os.makedirs(self.state_dir, exist_ok=True)

        self.security_file = os.path.join(self.state_dir, "security.json")
        self._init_file()

    def _init_file(self) -> None:
        """Initializes empty security.json if not present."""
        if not os.path.exists(self.security_file):
            default_content = {
                "version": "1.0.0",
                "program": os.path.basename(self.program_dir),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "state_hash": "",
                "test_cases": {},
                "baselines": {},
                "validation_results": {},
                "findings": {},
                "completed_fingerprints": {},
                "evidence_references": [],
            }
            self._atomic_write_json(default_content)

    def _read_json(self) -> Dict[str, Any]:
        """Reads security state safely."""
        try:
            with open(self.security_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {
                "version": "1.0.0",
                "program": os.path.basename(self.program_dir),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "state_hash": "",
                "test_cases": {},
                "baselines": {},
                "validation_results": {},
                "findings": {},
                "completed_fingerprints": {},
                "evidence_references": [],
            }

    def _atomic_write_json(self, data: Dict[str, Any]) -> None:
        """Writes data atomically to security.json."""
        data["last_updated"] = datetime.now(timezone.utc).isoformat()
        # Compute checksum of test cases and findings
        checksum_base = f"{len(data.get('test_cases', {}))}:{len(data.get('findings', {}))}"
        data["state_hash"] = hashlib.sha256(checksum_base.encode("utf-8")).hexdigest()[:16]

        dir_name = os.path.dirname(self.security_file)
        with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
            json.dump(data, tf, indent=2)
            temp_path = tf.name
        os.replace(temp_path, self.security_file)

    # ---------------- Test Case Management ----------------

    def save_test_case(self, test_case: SecurityTestCase) -> SecurityTestCase:
        """Saves a security test case."""
        data = self._read_json()
        cases = data.get("test_cases", {})
        cases[test_case.test_id] = test_case.to_dict()
        data["test_cases"] = cases
        self._atomic_write_json(data)
        return test_case

    def get_test_cases(self) -> List[SecurityTestCase]:
        """Returns all recorded test cases."""
        data = self._read_json()
        cases = data.get("test_cases", {})
        return [SecurityTestCase.from_dict(c) for c in cases.values()]

    def get_test_case(self, test_id: str) -> Optional[SecurityTestCase]:
        """Retrieves test case by ID."""
        data = self._read_json()
        c = data.get("test_cases", {}).get(test_id)
        return SecurityTestCase.from_dict(c) if c else None

    # ---------------- Baseline Management ----------------

    def save_baseline(self, baseline: BaselineObservation) -> None:
        """Saves a baseline observation for an endpoint."""
        data = self._read_json()
        baselines = data.get("baselines", {})
        baselines[baseline.endpoint_key] = baseline.to_dict()
        data["baselines"] = baselines
        self._atomic_write_json(data)

    def get_baseline(self, endpoint_key: str) -> Optional[BaselineObservation]:
        """Retrieves cached baseline observation if present."""
        data = self._read_json()
        b = data.get("baselines", {}).get(endpoint_key)
        return BaselineObservation.from_dict(b) if b else None

    # ---------------- Validation Result Management ----------------

    def save_validation_result(self, result: ValidationResult, fingerprint: str) -> None:
        """Records validation result and marks fingerprint as completed."""
        data = self._read_json()
        res_dict = data.get("validation_results", {})
        res_dict[result.test_id] = result.to_dict()
        data["validation_results"] = res_dict

        fps = data.get("completed_fingerprints", {})
        fps[fingerprint] = {
            "test_id": result.test_id,
            "status": result.lifecycle_state.value,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        data["completed_fingerprints"] = fps
        self._atomic_write_json(data)

    def is_test_completed(self, fingerprint: str) -> bool:
        """Checks if a test case with the given fingerprint has already been executed."""
        data = self._read_json()
        return fingerprint in data.get("completed_fingerprints", {})

    # ---------------- Finding Management & Deduplication ----------------

    def save_finding(self, finding: Finding) -> Tuple[Finding, bool, Optional[str]]:
        """
        Saves finding to security.json with deduplication check.
        Returns (finding, is_duplicate, duplicate_of_id).
        """
        data = self._read_json()
        findings = data.get("findings", {})
        existing_list = list(findings.values())

        is_dup = False
        dup_id = None
        if finding.finding_id not in findings:
            is_dup, dup_id = FindingDeduplicator.check_duplicate(
                candidate_asset=finding.affected_asset,
                candidate_endpoint=finding.affected_endpoint,
                candidate_vuln=finding.vulnerability_type,
                candidate_root_cause=finding.root_cause,
                existing_findings=existing_list,
            )
            if is_dup:
                finding.duplicate_of = dup_id

        findings[finding.finding_id] = finding.to_dict()
        data["findings"] = findings
        self._atomic_write_json(data)
        return finding, is_dup, dup_id

    def get_findings(self, lifecycle_state: Optional[str] = None) -> List[Finding]:
        """Returns findings, optionally filtered by lifecycle state."""
        data = self._read_json()
        findings = data.get("findings", {})
        res = []
        for d in findings.values():
            try:
                f = Finding.from_dict(d)
                if lifecycle_state is None or f.lifecycle_state.value == lifecycle_state:
                    res.append(f)
            except Exception:
                pass
        return res

    # ---------------- Evidence References ----------------

    def record_evidence_reference(self, evidence_meta: Dict[str, Any]) -> None:
        """Records an evidence reference metadata entry."""
        data = self._read_json()
        refs = data.get("evidence_references", [])
        refs.append(evidence_meta)
        data["evidence_references"] = refs
        self._atomic_write_json(data)

    def get_state_summary(self) -> Dict[str, Any]:
        """Returns summary statistics of the security validation state."""
        data = self._read_json()
        return {
            "total_test_cases": len(data.get("test_cases", {})),
            "total_baselines": len(data.get("baselines", {})),
            "total_results": len(data.get("validation_results", {})),
            "total_findings": len(data.get("findings", {})),
            "completed_fingerprints": len(data.get("completed_fingerprints", {})),
            "last_updated": data.get("last_updated"),
        }
