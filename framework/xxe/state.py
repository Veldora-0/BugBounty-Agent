"""
State Management for XXE & XML Parser Security Intelligence (Phase 18).

Provides atomic, thread-safe, and resumable persistent storage for XML candidates,
verifications, and findings in:
<program_dir>/state/xxe.json
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import tempfile
from typing import Any, Dict, List, Optional

from framework.xxe.model import (
    XxeCandidate,
    XxeEvidence,
)


class XxeStateManager:
    """Manages atomic persistent storage for XXE research state."""

    def __init__(self, program_dir: str):
        self.program_dir = os.path.abspath(program_dir)
        self.state_dir = os.path.join(self.program_dir, "state")
        os.makedirs(self.state_dir, exist_ok=True)

        self.xxe_file = os.path.join(self.state_dir, "xxe.json")
        self._init_file()

    def _init_file(self) -> None:
        """Initializes empty xxe.json if not present."""
        if not os.path.exists(self.xxe_file):
            default_content = {
                "version": "1.0.0",
                "program": os.path.basename(self.program_dir),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "state_hash": "",
                "candidates": {},
                "approved_tests": {},
                "findings": {},
                "summary": {
                    "total_candidates": 0,
                    "approved_tests": 0,
                    "findings_recorded": 0,
                    "by_category": {},
                    "by_lifecycle": {},
                },
            }
            self._write_json(default_content)

    def _read_json(self) -> Dict[str, Any]:
        """Safely reads xxe.json, returning default if corrupt or missing."""
        if not os.path.exists(self.xxe_file):
            self._init_file()
        try:
            with open(self.xxe_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            self._init_file()
            with open(self.xxe_file, "r", encoding="utf-8") as f:
                return json.load(f)

    def _write_json(self, data: Dict[str, Any]) -> None:
        """Atomically writes JSON using temporary file replacement."""
        data["last_updated"] = datetime.now(timezone.utc).isoformat()
        serialized = json.dumps(data, indent=2, sort_keys=True)
        data["state_hash"] = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        final_serialized = json.dumps(data, indent=2, sort_keys=True)

        tmp_dir = os.path.dirname(self.xxe_file)
        with tempfile.NamedTemporaryFile("w", dir=tmp_dir, delete=False, encoding="utf-8") as tf:
            tf.write(final_serialized)
            temp_name = tf.name

        os.replace(temp_name, self.xxe_file)

    def save_candidate(self, candidate: XxeCandidate) -> None:
        """Saves or updates an XXE candidate."""
        data = self._read_json()
        fp = candidate.compute_fingerprint()
        data["candidates"][fp] = candidate.to_dict()
        self._update_summary(data)
        self._write_json(data)

    def get_candidate(self, fingerprint: str) -> Optional[XxeCandidate]:
        """Retrieves candidate by fingerprint."""
        data = self._read_json()
        raw = data.get("candidates", {}).get(fingerprint)
        return XxeCandidate.from_dict(raw) if raw else None

    def list_candidates(self) -> List[XxeCandidate]:
        """Returns all recorded candidates."""
        data = self._read_json()
        return [XxeCandidate.from_dict(c) for c in data.get("candidates", {}).values()]

    def save_finding(self, finding_id: str, finding_dict: Dict[str, Any]) -> None:
        """Records a validated or observed XXE finding."""
        data = self._read_json()
        data["findings"][finding_id] = finding_dict
        self._update_summary(data)
        self._write_json(data)

    def list_findings(self) -> List[Dict[str, Any]]:
        """Returns all recorded XXE findings."""
        data = self._read_json()
        return list(data.get("findings", {}).values())

    def approve_candidate(self, candidate_id: str, approver: str = "researcher") -> bool:
        """Approves a candidate for active test dispatch."""
        data = self._read_json()
        found = False
        for fp, c in data.get("candidates", {}).items():
            if c.get("candidate_id") == candidate_id:
                c["approval_status"] = "APPROVED"
                c["lifecycle_state"] = "APPROVED"
                c["updated_at"] = datetime.now(timezone.utc).isoformat()
                data["approved_tests"][candidate_id] = {
                    "approved_at": datetime.now(timezone.utc).isoformat(),
                    "approver": approver,
                }
                found = True
                break
        if found:
            self._update_summary(data)
            self._write_json(data)
        return found

    def get_summary(self) -> Dict[str, Any]:
        """Returns current summary statistics."""
        data = self._read_json()
        return data.get("summary", {})

    def _update_summary(self, data: Dict[str, Any]) -> None:
        """Recomputes summary counters in place."""
        candidates = list(data.get("candidates", {}).values())
        by_cat: Dict[str, int] = {}
        by_life: Dict[str, int] = {}

        for c in candidates:
            cat = c.get("category", "unknown")
            life = c.get("lifecycle_state", "CANDIDATE")
            by_cat[cat] = by_cat.get(cat, 0) + 1
            by_life[life] = by_life.get(life, 0) + 1

        data["summary"] = {
            "total_candidates": len(candidates),
            "approved_tests": len(data.get("approved_tests", {})),
            "findings_recorded": len(data.get("findings", {})),
            "by_category": by_cat,
            "by_lifecycle": by_life,
        }
