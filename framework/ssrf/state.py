"""
State Management for SSRF & Out-of-Band Interaction Intelligence (Phase 9).

Provides persistent, atomic, and resumable storage for candidates, canaries,
interactions, approvals, and verified findings in:
~/BugBounty-Workspace/programs/<program>/state/ssrf.json
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import tempfile
from typing import Any, Dict, List, Optional

from framework.ssrf.model import (
    SsrfCandidate,
    SsrfInteraction,
)


class SsrfStateManager:
    """
    Manages atomic local persistent storage for SSRF intelligence.
    """

    def __init__(self, program_dir: str):
        self.program_dir = os.path.abspath(program_dir)
        self.state_dir = os.path.join(self.program_dir, "state")
        os.makedirs(self.state_dir, exist_ok=True)

        self.ssrf_file = os.path.join(self.state_dir, "ssrf.json")
        self._init_file()

    def _init_file(self) -> None:
        """Initializes empty ssrf.json if not present."""
        if not os.path.exists(self.ssrf_file):
            default_content = {
                "version": "1.0.0",
                "program": os.path.basename(self.program_dir),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "state_hash": "",
                "candidates": {},
                "canaries": {},
                "approved_tests": {},
                "interactions": {},
                "findings": {},
                "summary": {
                    "total_candidates": 0,
                    "approved_tests": 0,
                    "interactions_received": 0,
                    "findings_recorded": 0,
                    "by_category": {},
                    "by_lifecycle": {},
                },
            }
            self._atomic_write_json(default_content)

    def _read_json(self) -> Dict[str, Any]:
        """Reads SSRF state safely."""
        try:
            with open(self.ssrf_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {
                "version": "1.0.0",
                "program": os.path.basename(self.program_dir),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "state_hash": "",
                "candidates": {},
                "canaries": {},
                "approved_tests": {},
                "interactions": {},
                "findings": {},
                "summary": {},
            }

    def _atomic_write_json(self, data: Dict[str, Any]) -> None:
        """Writes state atomically using temporary file replacement."""
        data["last_updated"] = datetime.now(timezone.utc).isoformat()
        num_cands = len(data.get("candidates", {}))
        num_finds = len(data.get("findings", {}))
        data["state_hash"] = hashlib.sha256(f"{num_cands}:{num_finds}:{data['last_updated']}".encode("utf-8")).hexdigest()[:16]

        by_cat: Dict[str, int] = {}
        by_life: Dict[str, int] = {}
        for c in data.get("candidates", {}).values():
            cat = c.get("category", "unknown")
            by_cat[cat] = by_cat.get(cat, 0) + 1
            life = c.get("lifecycle_state", "CANDIDATE")
            by_life[life] = by_life.get(life, 0) + 1

        data["summary"] = {
            "total_candidates": num_cands,
            "approved_tests": len(data.get("approved_tests", {})),
            "interactions_received": len(data.get("interactions", {})),
            "findings_recorded": num_finds,
            "by_category": by_cat,
            "by_lifecycle": by_life,
        }

        dir_name = os.path.dirname(self.ssrf_file)
        with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
            json.dump(data, tf, indent=2)
            temp_path = tf.name
        os.replace(temp_path, self.ssrf_file)

    # ---------------- Candidate Operations ----------------

    def save_candidate(self, candidate: SsrfCandidate) -> SsrfCandidate:
        data = self._read_json()
        cands = data.get("candidates", {})
        cands[candidate.candidate_id] = candidate.to_dict()
        data["candidates"] = cands
        self._atomic_write_json(data)
        return candidate

    def get_candidate(self, candidate_id: str) -> Optional[SsrfCandidate]:
        data = self._read_json()
        c = data.get("candidates", {}).get(candidate_id)
        return SsrfCandidate.from_dict(c) if c else None

    def list_candidates(self, category: Optional[str] = None) -> List[SsrfCandidate]:
        data = self._read_json()
        cands = [SsrfCandidate.from_dict(c) for c in data.get("candidates", {}).values()]
        if category:
            cands = [c for c in cands if c.category.value == category or c.category == category]
        return cands

    # ---------------- Approval Operations ----------------

    def approve_test_case(self, test_id: str, approved_by: str = "researcher") -> bool:
        data = self._read_json()
        cands = data.get("candidates", {})
        if test_id not in cands:
            return False

        cands[test_id]["approval_status"] = "APPROVED"
        cands[test_id]["lifecycle_state"] = "APPROVED"
        data["candidates"] = cands

        appr = data.get("approved_tests", {})
        appr[test_id] = {
            "test_id": test_id,
            "approved_by": approved_by,
            "approved_at": datetime.now(timezone.utc).isoformat(),
        }
        data["approved_tests"] = appr
        self._atomic_write_json(data)
        return True

    def is_test_approved(self, test_id: str) -> bool:
        data = self._read_json()
        return test_id in data.get("approved_tests", {})

    # ---------------- Interaction Operations ----------------

    def save_interaction(self, interaction: SsrfInteraction) -> None:
        data = self._read_json()
        ints = data.get("interactions", {})
        ints[interaction.interaction_id] = interaction.to_dict()
        data["interactions"] = ints
        self._atomic_write_json(data)

    def list_interactions(self, canary_token: Optional[str] = None) -> List[SsrfInteraction]:
        data = self._read_json()
        raw_ints = data.get("interactions", {}).values()
        ints = [SsrfInteraction.from_dict(i) for i in raw_ints]
        if canary_token:
            ints = [i for i in ints if i.canary_token == canary_token]
        return ints

    # ---------------- Findings & Summary Operations ----------------

    def save_finding(self, finding_id: str, finding_dict: Dict[str, Any]) -> None:
        data = self._read_json()
        finds = data.get("findings", {})
        finds[finding_id] = finding_dict
        data["findings"] = finds
        self._atomic_write_json(data)

    def get_summary(self) -> Dict[str, Any]:
        data = self._read_json()
        return data.get("summary", {})
