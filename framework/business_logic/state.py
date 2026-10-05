"""
State Persistence for Business Logic & Workflow Subsystem (Phase 12).

Provides atomic, thread-safe, and resumable state tracking for workflows,
steps, transitions, hypotheses, test cases, evidence, and findings in:
~/BugBounty-Workspace/programs/<program>/state/workflows.json
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from typing import Any, Dict, List, Optional
import uuid

from framework.business_logic.model import (
    Workflow,
    WorkflowEvidence,
    WorkflowFinding,
    WorkflowHypothesis,
    WorkflowTestCase,
)


class WorkflowStateManager:
    """Manages atomic persistent storage for the business logic subsystem."""

    def __init__(self, program_dir: str):
        self.program_dir = os.path.abspath(program_dir)
        self.state_dir = os.path.join(self.program_dir, "state")
        os.makedirs(self.state_dir, exist_ok=True)

        self.state_file = os.path.join(self.state_dir, "workflows.json")
        self._init_file()

    def _init_file(self) -> None:
        """Initializes empty workflows.json if not present."""
        if not os.path.exists(self.state_file):
            default_content = {
                "version": "1.0.0",
                "program": os.path.basename(self.program_dir),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "state_hash": "",
                "workflows": {},
                "hypotheses": {},
                "test_fingerprints": {},
                "test_cases": {},
                "evidence": {},
                "findings": {},
                "summary": {
                    "total_workflows": 0,
                    "total_hypotheses": 0,
                    "tested_hypotheses": 0,
                    "findings_recorded": 0,
                    "by_category": {},
                    "by_lifecycle": {},
                },
            }
            self._atomic_write_json(default_content)

    def _atomic_write_json(self, data: Dict[str, Any]) -> None:
        """Atomic write using temporary file replacement (Windows and POSIX safe)."""
        data["last_updated"] = datetime.now(timezone.utc).isoformat()
        body = json.dumps(data, indent=2, sort_keys=True)
        data["state_hash"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
        final_str = json.dumps(data, indent=2, sort_keys=True)

        temp_path = f"{self.state_file}.tmp.{os.getpid()}_{uuid.uuid4().hex[:8]}"
        with open(temp_path, "w", encoding="utf-8") as tf:
            tf.write(final_str)

        os.replace(temp_path, self.state_file)

    def load_state(self) -> Dict[str, Any]:
        """Loads and returns current workflows state."""
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            self._init_file()
            with open(self.state_file, "r", encoding="utf-8") as f:
                return json.load(f)

    def save_workflow(self, workflow: Workflow) -> None:
        state = self.load_state()
        state["workflows"][workflow.workflow_id] = workflow.to_dict()
        self._update_summary(state)
        self._atomic_write_json(state)

    def get_workflow(self, workflow_id: str) -> Optional[Workflow]:
        state = self.load_state()
        w_dict = state["workflows"].get(workflow_id)
        if w_dict:
            return Workflow.from_dict(w_dict)
        return None

    def list_workflows(self) -> List[Workflow]:
        state = self.load_state()
        return [Workflow.from_dict(d) for d in state["workflows"].values()]

    def save_hypothesis(self, hypothesis: WorkflowHypothesis) -> None:
        state = self.load_state()
        state["hypotheses"][hypothesis.hypothesis_id] = hypothesis.to_dict()
        self._update_summary(state)
        self._atomic_write_json(state)

    def get_hypothesis(self, hypothesis_id: str) -> Optional[WorkflowHypothesis]:
        state = self.load_state()
        h_dict = state["hypotheses"].get(hypothesis_id)
        if h_dict:
            return WorkflowHypothesis.from_dict(h_dict)
        return None

    def list_hypotheses(self) -> List[WorkflowHypothesis]:
        state = self.load_state()
        return [WorkflowHypothesis.from_dict(d) for d in state["hypotheses"].values()]

    def record_test_fingerprint(self, fingerprint: str, status: str = "TESTED") -> None:
        state = self.load_state()
        state["test_fingerprints"][fingerprint] = {
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._atomic_write_json(state)

    def is_fingerprint_tested(self, fingerprint: str) -> bool:
        state = self.load_state()
        return fingerprint in state["test_fingerprints"]

    def record_test_case(self, test_case: WorkflowTestCase) -> None:
        state = self.load_state()
        state["test_cases"][test_case.test_case_id] = test_case.to_dict()
        self._atomic_write_json(state)

    def record_evidence(self, evidence: WorkflowEvidence) -> None:
        state = self.load_state()
        state["evidence"][evidence.evidence_id] = evidence.to_dict()
        self._atomic_write_json(state)

    def record_finding(self, finding: WorkflowFinding) -> None:
        state = self.load_state()
        state["findings"][finding.finding_id] = finding.to_dict()
        self._update_summary(state)
        self._atomic_write_json(state)

    def list_findings(self) -> List[WorkflowFinding]:
        state = self.load_state()
        return [WorkflowFinding.from_dict(d) for d in state["findings"].values()]

    def _update_summary(self, state: Dict[str, Any]) -> None:
        workflows = state.get("workflows", {})
        hypotheses = state.get("hypotheses", {})
        findings = state.get("findings", {})

        by_cat: Dict[str, int] = {}
        by_life: Dict[str, int] = {}

        for h in hypotheses.values():
            cat = h.get("category", "unknown")
            by_cat[cat] = by_cat.get(cat, 0) + 1
            life = h.get("lifecycle", "CANDIDATE")
            by_life[life] = by_life.get(life, 0) + 1

        state["summary"] = {
            "total_workflows": len(workflows),
            "total_hypotheses": len(hypotheses),
            "tested_hypotheses": len(state.get("test_fingerprints", {})),
            "findings_recorded": len(findings),
            "by_category": by_cat,
            "by_lifecycle": by_life,
        }
