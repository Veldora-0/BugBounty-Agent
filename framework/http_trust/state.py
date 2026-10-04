"""
State Management for HTTP / Header Trust Subsystem (Phase 11).

Provides atomic, persistent, and resumable state tracking for header trust candidates,
differential test evidence, CORS/HPP observations, and deduplicated findings in:
~/BugBounty-Workspace/programs/<program>/state/http-trust.json
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from typing import Any, Dict, List, Optional
import uuid

from framework.http_trust.model import (
    HeaderTrustCandidate,
    HeaderTrustEvidence,
    HttpTrustCategory,
    HttpTrustTestCase,
)


class HttpTrustStateManager:
    """Manages atomic persistent storage for the HTTP / Header Trust subsystem."""

    def __init__(self, program_dir: str):
        self.program_dir = os.path.abspath(program_dir)
        self.state_dir = os.path.join(self.program_dir, "state")
        os.makedirs(self.state_dir, exist_ok=True)

        self.state_file = os.path.join(self.state_dir, "http-trust.json")
        self._init_file()

    def _init_file(self) -> None:
        """Initializes empty http-trust.json if not present."""
        if not os.path.exists(self.state_file):
            default_content = {
                "version": "1.0.0",
                "program": os.path.basename(self.program_dir),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "state_hash": "",
                "candidates": {},
                "test_fingerprints": {},
                "test_cases": {},
                "evidence": {},
                "findings": {},
                "summary": {
                    "total_candidates": 0,
                    "tested_candidates": 0,
                    "findings_recorded": 0,
                    "by_category": {
                        "host": 0,
                        "forwarded": 0,
                        "scheme": 0,
                        "redirect": 0,
                        "url_poisoning": 0,
                        "cors": 0,
                        "hpp": 0,
                        "cache": 0,
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

        temp_path = f"{self.state_file}.tmp.{os.getpid()}_{uuid.uuid4().hex[:8]}"
        with open(temp_path, "w", encoding="utf-8") as tf:
            tf.write(final_str)

        os.replace(temp_path, self.state_file)

    def load_state(self) -> Dict[str, Any]:
        """Loads and returns current http-trust state."""
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            self._init_file()
            with open(self.state_file, "r", encoding="utf-8") as f:
                return json.load(f)

    def save_candidate(self, candidate: HeaderTrustCandidate) -> None:
        """Persists or updates a candidate."""
        state = self.load_state()
        state["candidates"][candidate.candidate_id] = candidate.to_dict()
        self._update_summary(state)
        self._atomic_write_json(state)

    def get_candidate(self, candidate_id: str) -> Optional[HeaderTrustCandidate]:
        """Retrieves a candidate by identifier."""
        state = self.load_state()
        c_dict = state["candidates"].get(candidate_id)
        if c_dict:
            return HeaderTrustCandidate.from_dict(c_dict)
        return None

    def list_candidates(self) -> List[HeaderTrustCandidate]:
        """Lists all recorded candidates."""
        state = self.load_state()
        return [HeaderTrustCandidate.from_dict(d) for d in state["candidates"].values()]

    def record_test_case(self, test_case: HttpTrustTestCase) -> None:
        """Persists an executed test case."""
        state = self.load_state()
        state["test_cases"][test_case.test_id] = test_case.to_dict()
        self._atomic_write_json(state)

    def record_test_fingerprint(self, fingerprint: str, status: str = "TESTED") -> None:
        """Records a completed test fingerprint to prevent duplicate probes on resume."""
        state = self.load_state()
        state["test_fingerprints"][fingerprint] = {
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._atomic_write_json(state)

    def is_fingerprint_tested(self, fingerprint: str) -> bool:
        """Checks if a test fingerprint was already completed."""
        state = self.load_state()
        return fingerprint in state["test_fingerprints"]

    def record_evidence(self, evidence: HeaderTrustEvidence) -> None:
        """Persists an evidence record."""
        state = self.load_state()
        state["evidence"][evidence.evidence_id] = evidence.to_dict()
        self._atomic_write_json(state)

    def record_finding(self, finding_dict: Dict[str, Any]) -> None:
        """Persists a verified HTTP trust finding."""
        state = self.load_state()
        f_id = finding_dict.get("id") or f"http-find-{len(state['findings']) + 1}"
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

        by_cat: Dict[str, int] = {
            "host": 0,
            "forwarded": 0,
            "scheme": 0,
            "redirect": 0,
            "url_poisoning": 0,
            "cors": 0,
            "hpp": 0,
            "cache": 0,
        }
        by_conf: Dict[str, int] = {}
        by_life: Dict[str, int] = {}

        for c in candidates.values():
            cat = c.get("category", "host")
            by_cat[cat] = by_cat.get(cat, 0) + 1
            conf = c.get("confidence", "CANDIDATE")
            by_conf[conf] = by_conf.get(conf, 0) + 1
            life = c.get("lifecycle", "CANDIDATE")
            by_life[life] = by_life.get(life, 0) + 1

        state["summary"] = {
            "total_candidates": len(candidates),
            "tested_candidates": len(state.get("test_fingerprints", {})),
            "findings_recorded": len(findings),
            "by_category": by_cat,
            "by_confidence": by_conf,
            "by_lifecycle": by_life,
        }
