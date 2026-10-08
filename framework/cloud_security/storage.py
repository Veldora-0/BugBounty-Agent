"""
Atomic State Storage and Persistence for Cloud Intelligence (Phase 13).

Persists:
- cloud assets
- provider observations
- services
- resource fingerprints
- exposure hypotheses
- validated findings
- rejected hypotheses
- audit records

Stored at: ~/BugBounty-Workspace/programs/<program>/state/cloud.json
Strictly excludes unmasked secrets, session cookies, and authentication keys.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, List, Optional
import uuid

from framework.cloud_security.models import (
    CloudAsset,
    CloudExposureHypothesis,
    CloudFindingCandidate,
    CloudResource,
)
from framework.common.evidence import sanitize_sensitive_data


class CloudStateManager:
    """Manages atomic reads and writes of cloud security state for a program."""

    def __init__(self, program_dir: str):
        self.program_dir = os.path.abspath(program_dir)
        self.state_dir = os.path.join(self.program_dir, "state")
        self.state_file = os.path.join(self.state_dir, "cloud.json")
        os.makedirs(self.state_dir, exist_ok=True)

    def load_state(self) -> Dict[str, Any]:
        """Loads state dictionary or returns initialized blank structure."""
        if not os.path.isfile(self.state_file):
            return {
                "version": "1.0",
                "assets": [],
                "resources": [],
                "hypotheses": [],
                "findings": [],
                "rejected_hypotheses": [],
                "tested_fingerprints": [],
            }

        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {
                "version": "1.0",
                "assets": [],
                "resources": [],
                "hypotheses": [],
                "findings": [],
                "rejected_hypotheses": [],
                "tested_fingerprints": [],
            }

    def save_state(self, state: Dict[str, Any]) -> None:
        """Atomically saves the state dictionary to cloud.json."""
        # Sanitize any stringified representations
        serialized = json.dumps(state, indent=2, ensure_ascii=False)
        clean_text = sanitize_sensitive_data(serialized)

        temp_path = f"{self.state_file}.tmp.{os.getpid()}_{uuid.uuid4().hex[:8]}"
        with open(temp_path, "w", encoding="utf-8") as tf:
            tf.write(clean_text)
            tf.flush()
            os.fsync(tf.fileno())

        os.replace(temp_path, self.state_file)

    def record_asset(self, asset: CloudAsset) -> None:
        """Appends or updates a CloudAsset."""
        state = self.load_state()
        existing = [a for a in state["assets"] if a["id"] != asset.id]
        existing.append(asset.to_dict())
        state["assets"] = existing
        self.save_state(state)

    def record_hypothesis(self, hypothesis: CloudExposureHypothesis) -> None:
        """Appends or updates a CloudExposureHypothesis."""
        state = self.load_state()
        existing = [h for h in state["hypotheses"] if h["id"] != hypothesis.id]
        existing.append(hypothesis.to_dict())
        state["hypotheses"] = existing
        self.save_state(state)

    def record_finding(self, finding: CloudFindingCandidate) -> None:
        """Appends or updates a CloudFindingCandidate."""
        state = self.load_state()
        existing = [f for f in state["findings"] if f["candidate_id"] != finding.candidate_id]
        existing.append(finding.to_dict())
        state["findings"] = existing
        self.save_state(state)

    def mark_fingerprint_tested(self, fingerprint: str) -> None:
        """Records a test fingerprint to enable resume without duplicate probes."""
        state = self.load_state()
        tested = set(state.get("tested_fingerprints", []))
        tested.add(fingerprint)
        state["tested_fingerprints"] = sorted(list(tested))
        self.save_state(state)

    def is_fingerprint_tested(self, fingerprint: str) -> bool:
        """Checks if a fingerprint has already been executed."""
        state = self.load_state()
        return fingerprint in state.get("tested_fingerprints", [])

    def get_summary(self) -> Dict[str, Any]:
        """Returns statistical summary of recorded cloud intelligence."""
        state = self.load_state()
        return {
            "total_assets": len(state.get("assets", [])),
            "total_resources": len(state.get("resources", [])),
            "total_hypotheses": len(state.get("hypotheses", [])),
            "total_findings": len(state.get("findings", [])),
            "tested_count": len(state.get("tested_fingerprints", [])),
        }
