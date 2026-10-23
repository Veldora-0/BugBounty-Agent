"""
Persistent State Management for BugBounty-Agent Infrastructure Intelligence.

Manages program-scoped state/infrastructure.json atomically.
Enforces that raw credentials and target secrets are never committed to state files.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import re
import tempfile
from typing import Any, Dict, List, Optional, Set

from framework.common.evidence import sanitize_sensitive_data
from framework.infrastructure.model import ExposureCandidate, ExposureHypothesis


class InfrastructureStateManager:
    """Manages persistent infrastructure exposure state per bug bounty program."""

    def __init__(self, program_dir: str):
        self.program_dir = os.path.abspath(program_dir)
        self.state_dir = os.path.join(self.program_dir, "state")
        os.makedirs(self.state_dir, exist_ok=True)
        self.state_file = os.path.join(self.state_dir, "infrastructure.json")
        self._init_file()

    def _init_file(self) -> None:
        """Initializes empty state structure if not present."""
        if not os.path.exists(self.state_file):
            default_state: Dict[str, Any] = {
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "candidates": [],
                "hypotheses": [],
                "findings": [],
                "tested_fingerprints": [],
                "summary": {
                    "total_candidates": 0,
                    "total_hypotheses": 0,
                    "validated_findings": 0,
                    "observations": 0,
                    "rejected": 0,
                    "access_restricted": 0,
                },
            }
            self._atomic_write(default_state)

    def _atomic_write(self, data: Dict[str, Any]) -> None:
        """Safely writes JSON state atomically to prevent corruption."""
        dir_name = os.path.dirname(self.state_file)
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix="infra_state_", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, self.state_file)
        except Exception:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            raise

    def load_state(self) -> Dict[str, Any]:
        """Loads state dictionary from disk."""
        if not os.path.exists(self.state_file):
            self._init_file()
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            self._init_file()
            with open(self.state_file, "r", encoding="utf-8") as f:
                return json.load(f)

    def save_candidate(self, candidate: ExposureCandidate) -> None:
        """Adds or updates an exposure candidate."""
        state = self.load_state()
        cands: List[Dict[str, Any]] = state.get("candidates", [])
        cand_dict = candidate.to_dict()

        existing_idx = next((i for i, c in enumerate(cands) if c.get("candidate_id") == candidate.candidate_id), None)
        if existing_idx is not None:
            cands[existing_idx] = cand_dict
        else:
            cands.append(cand_dict)

        state["candidates"] = cands
        state["updated_at"] = datetime.now(timezone.utc).isoformat()
        state["summary"]["total_candidates"] = len(cands)
        self._atomic_write(state)

    def save_hypothesis(self, hypothesis: ExposureHypothesis) -> None:
        """Adds or updates an exposure hypothesis."""
        state = self.load_state()
        hyps: List[Dict[str, Any]] = state.get("hypotheses", [])
        hyp_dict = hypothesis.to_dict()

        existing_idx = next((i for i, h in enumerate(hyps) if h.get("hypothesis_id") == hypothesis.hypothesis_id), None)
        if existing_idx is not None:
            hyps[existing_idx] = hyp_dict
        else:
            hyps.append(hyp_dict)

        state["hypotheses"] = hyps
        state["updated_at"] = datetime.now(timezone.utc).isoformat()
        state["summary"]["total_hypotheses"] = len(hyps)
        self._atomic_write(state)

    def record_finding(self, finding_dict: Dict[str, Any]) -> None:
        """Records a finding with sanitized evidence into state."""
        state = self.load_state()
        findings: List[Dict[str, Any]] = state.get("findings", [])

        # Sanitize any string fields in finding
        finding_raw_str = json.dumps(finding_dict)
        finding_scrubbed_str = re.sub(
            r"([A-Z0-9_]*(?:PASS|PWD|SECRET|KEY|TOKEN|AUTH|CREDENTIAL|PRIVATE)[A-Z0-9_]*\s*=\s*)[^\"\r\n\\]+",
            r"\g<1>[REDACTED_BY_BB_AGENT]",
            finding_raw_str,
            flags=re.IGNORECASE,
        )
        clean_finding = json.loads(sanitize_sensitive_data(finding_scrubbed_str))
        fid = clean_finding.get("finding_id")

        existing_idx = next((i for i, f in enumerate(findings) if f.get("finding_id") == fid), None)
        if existing_idx is not None:
            findings[existing_idx] = clean_finding
        else:
            findings.append(clean_finding)

        state["findings"] = findings
        state["updated_at"] = datetime.now(timezone.utc).isoformat()

        # Update summary counters
        summary = state.get("summary", {})
        validated_count = sum(1 for f in findings if f.get("lifecycle_state") == "VALIDATED")
        obs_count = sum(1 for f in findings if f.get("lifecycle_state") == "OBSERVATION")
        summary["validated_findings"] = validated_count
        summary["observations"] = obs_count
        state["summary"] = summary

        self._atomic_write(state)

    def record_tested_fingerprint(self, fingerprint: str) -> None:
        """Records a test fingerprint to prevent redundant probes."""
        state = self.load_state()
        fps = set(state.get("tested_fingerprints", []))
        fps.add(fingerprint)
        state["tested_fingerprints"] = sorted(list(fps))
        self._atomic_write(state)

    def is_fingerprint_tested(self, fingerprint: str) -> bool:
        """Checks if a test fingerprint was already evaluated."""
        state = self.load_state()
        return fingerprint in state.get("tested_fingerprints", [])

    def get_summary(self) -> Dict[str, Any]:
        """Returns high-level summary of infrastructure exposure state."""
        state = self.load_state()
        return state.get("summary", {})
