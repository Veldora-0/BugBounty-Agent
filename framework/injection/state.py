"""
State Management for Injection Intelligence & Controlled Validation (Phase 10).

Provides atomic, persistent, and resumable state tracking for injection candidates,
prioritization records, differential test evidence, and deduplicated findings in:
~/BugBounty-Workspace/programs/<program>/state/injection.json
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import tempfile
from typing import Any, Dict, List, Optional
import uuid

from framework.injection.model import (
    InjectionCandidate,
    InjectionEvidence,
    InjectionType,
)


class InjectionStateManager:
    """Manages atomic persistent storage for the injection subsystem."""

    def __init__(self, program_dir: str):
        self.program_dir = os.path.abspath(program_dir)
        self.state_dir = os.path.join(self.program_dir, "state")
        os.makedirs(self.state_dir, exist_ok=True)

        self.injection_file = os.path.join(self.state_dir, "injection.json")
        self._init_file()

    def _init_file(self) -> None:
        """Initializes empty injection.json if not present."""
        if not os.path.exists(self.injection_file):
            default_content = {
                "version": "1.0.0",
                "program": os.path.basename(self.program_dir),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "state_hash": "",
                "candidates": {},
                "test_fingerprints": {},
                "evidence": {},
                "findings": {},
                "summary": {
                    "total_candidates": 0,
                    "tested_candidates": 0,
                    "findings_recorded": 0,
                    "by_family": {
                        "sql": 0,
                        "nosql": 0,
                        "ssti": 0,
                        "command": 0,
                    },
                    "by_confidence": {},
                    "by_lifecycle": {},
                },
            }
            self._atomic_write_json(default_content)

    def _atomic_write_json(self, data: Dict[str, Any]) -> None:
        """Atomic write using temporary file replacement."""
        data["last_updated"] = datetime.now(timezone.utc).isoformat()
        body = json.dumps(data, indent=2, sort_keys=True)
        data["state_hash"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
        final_str = json.dumps(data, indent=2, sort_keys=True)

        temp_path = f"{self.injection_file}.tmp.{os.getpid()}_{uuid.uuid4().hex[:8]}"
        with open(temp_path, "w", encoding="utf-8") as tf:
            tf.write(final_str)

        os.replace(temp_path, self.injection_file)

    def load_state(self) -> Dict[str, Any]:
        """Loads and returns current injection state."""
        try:
            with open(self.injection_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            self._init_file()
            with open(self.injection_file, "r", encoding="utf-8") as f:
                return json.load(f)

    def save_candidate(self, candidate: InjectionCandidate) -> None:
        """Persists or updates an injection candidate."""
        state = self.load_state()
        state["candidates"][candidate.candidate_id] = candidate.to_dict()
        self._update_summary(state)
        self._atomic_write_json(state)

    def get_candidate(self, candidate_id: str) -> Optional[InjectionCandidate]:
        """Retrieves a candidate by identifier."""
        state = self.load_state()
        c_dict = state["candidates"].get(candidate_id)
        if c_dict:
            return InjectionCandidate.from_dict(c_dict)
        return None

    def list_candidates(self) -> List[InjectionCandidate]:
        """Lists all recorded candidates."""
        state = self.load_state()
        return [InjectionCandidate.from_dict(d) for d in state["candidates"].values()]

    def record_test_fingerprint(self, fingerprint: str, status: str = "TESTED") -> None:
        """Records a completed test fingerprint to prevent duplicate probes on resume."""
        state = self.load_state()
        state["test_fingerprints"][fingerprint] = {
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._atomic_write_json(state)

    def is_fingerprint_tested(self, fingerprint: str) -> bool:
        """Checks if a candidate fingerprint was already tested."""
        state = self.load_state()
        return fingerprint in state["test_fingerprints"]

    def record_evidence(self, evidence: InjectionEvidence) -> None:
        """Persists an evidence record."""
        state = self.load_state()
        state["evidence"][evidence.evidence_id] = evidence.to_dict()
        self._atomic_write_json(state)

    def record_finding(self, finding_dict: Dict[str, Any]) -> None:
        """Persists a verified injection finding."""
        state = self.load_state()
        f_id = finding_dict.get("id") or f"inj-find-{len(state['findings']) + 1}"
        state["findings"][f_id] = finding_dict
        self._update_summary(state)
        self._atomic_write_json(state)

    def list_findings(self) -> List[Dict[str, Any]]:
        state = self.load_state()
        return list(state["findings"].values())

    def _update_summary(self, state: Dict[str, Any]) -> None:
        """Recomputes summary statistics."""
        candidates = state.get("candidates", {})
        findings = state.get("findings", {})

        by_family: Dict[str, int] = {"sql": 0, "nosql": 0, "ssti": 0, "command": 0}
        by_conf: Dict[str, int] = {}
        by_life: Dict[str, int] = {}

        for c in candidates.values():
            fam = c.get("family", "unknown")
            by_family[fam] = by_family.get(fam, 0) + 1
            conf = c.get("confidence", "CANDIDATE")
            by_conf[conf] = by_conf.get(conf, 0) + 1
            life = c.get("lifecycle", "CANDIDATE")
            by_life[life] = by_life.get(life, 0) + 1

        state["summary"] = {
            "total_candidates": len(candidates),
            "tested_candidates": len(state.get("test_fingerprints", {})),
            "findings_recorded": len(findings),
            "by_family": by_family,
            "by_confidence": by_conf,
            "by_lifecycle": by_life,
        }
