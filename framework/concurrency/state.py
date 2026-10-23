"""
Persistent State Management for Race Conditions & Distributed Workflows.

Manages program-scoped state/concurrency.json atomically.
Enforces that raw credentials, tokens, and target secrets are never committed.
Provides schema self-healing for empty or legacy state files.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import re
import tempfile
from typing import Any, Dict, List, Optional

from framework.common.evidence import sanitize_sensitive_data
from framework.concurrency.model import RaceConditionHypothesis, RaceConditionTestResult


def get_default_concurrency_state() -> Dict[str, Any]:
    """Returns a fresh default structure for concurrency intelligence state."""
    return {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "hypotheses": [],
        "test_results": [],
        "findings": [],
        "tested_fingerprints": [],
        "summary": {
            "total_hypotheses": 0,
            "tested_hypotheses": 0,
            "confirmed_vulnerabilities": 0,
            "validated_findings": 0,
            "concurrency_controlled": 0,
            "controlled_observations": 0,
            "inconclusive": 0,
            "inconclusive_observations": 0,
            "total_probes_dispatched": 0,
        },
    }


def normalize_concurrency_state(data: Any) -> Dict[str, Any]:
    """Ensures state dictionary conforms to schema and has all required keys."""
    default = get_default_concurrency_state()
    if not isinstance(data, dict):
        return default

    normalized = dict(data)
    for list_key in ("hypotheses", "test_results", "findings", "tested_fingerprints"):
        if list_key not in normalized or not isinstance(normalized[list_key], list):
            normalized[list_key] = []

    if "summary" not in normalized or not isinstance(normalized["summary"], dict):
        normalized["summary"] = dict(default["summary"])
    else:
        summary = dict(normalized["summary"])
        for sum_key, sum_val in default["summary"].items():
            if sum_key not in summary:
                summary[sum_key] = sum_val
        normalized["summary"] = summary

    if "updated_at" not in normalized or not normalized["updated_at"]:
        normalized["updated_at"] = default["updated_at"]

    return normalized


def _sanitize_data_recursive(val: Any) -> Any:
    """Recursively redacts sensitive tokens, passwords, and secrets in primitive data structures."""
    if isinstance(val, str):
        scrubbed = re.sub(
            r"([A-Z0-9_]*(?:PASS|PWD|SECRET|KEY|TOKEN|AUTH|CREDENTIAL|PRIVATE)[A-Z0-9_]*\s*[:=]\s*)[^\s,;&\"']+",
            r"\g<1>[REDACTED_BY_BB_AGENT]",
            val,
            flags=re.IGNORECASE,
        )
        return sanitize_sensitive_data(scrubbed)
    elif isinstance(val, dict):
        return {k: _sanitize_data_recursive(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [_sanitize_data_recursive(v) for v in val]
    return val


class ConcurrencyStateManager:
    """Manages persistent concurrency intelligence state per bug bounty program."""

    def __init__(self, program_dir: str):
        self.program_dir = os.path.abspath(program_dir)
        self.state_dir = os.path.join(self.program_dir, "state")
        os.makedirs(self.state_dir, exist_ok=True)
        self.state_file = os.path.join(self.state_dir, "concurrency.json")
        self._init_file()

    def _init_file(self) -> None:
        """Initializes default state structure if not present or missing required keys."""
        if not os.path.exists(self.state_file) or os.path.getsize(self.state_file) == 0:
            self._atomic_write(get_default_concurrency_state())
        else:
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                normalized = normalize_concurrency_state(data)
                if normalized != data:
                    self._atomic_write(normalized)
            except (json.JSONDecodeError, OSError):
                self._atomic_write(get_default_concurrency_state())

    def _atomic_write(self, data: Dict[str, Any]) -> None:
        """Safely writes JSON state atomically to prevent corruption."""
        dir_name = os.path.dirname(self.state_file)
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix="concurrency_state_", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            for attempt in range(5):
                try:
                    os.replace(tmp_path, self.state_file)
                    break
                except PermissionError:
                    if attempt == 4:
                        raise
                    time.sleep(0.02 * (attempt + 1))
        except Exception:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            raise

    def load_state(self) -> Dict[str, Any]:
        """Loads state dictionary from disk, normalizing structure if needed."""
        if not os.path.exists(self.state_file):
            self._init_file()
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            self._init_file()
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)

        normalized = normalize_concurrency_state(data)
        if normalized != data:
            try:
                self._atomic_write(normalized)
            except Exception:
                pass
        return normalized

    def save_hypothesis(self, hypothesis: RaceConditionHypothesis) -> None:
        """Adds or updates a race hypothesis with secret sanitization."""
        state = self.load_state()
        hyps: List[Dict[str, Any]] = state.get("hypotheses", [])
        hyp_dict = hypothesis.to_dict()

        # Sanitize hypothesis dict
        clean_hyp = _sanitize_data_recursive(hyp_dict)

        existing_idx = next((i for i, h in enumerate(hyps) if h.get("hypothesis_id") == hypothesis.hypothesis_id), None)
        if existing_idx is not None:
            hyps[existing_idx] = clean_hyp
        else:
            hyps.append(clean_hyp)

        state["hypotheses"] = hyps
        state["updated_at"] = datetime.now(timezone.utc).isoformat()
        state["summary"]["total_hypotheses"] = len(hyps)
        self._atomic_write(state)

    def record_test_result(self, result: RaceConditionTestResult) -> None:
        """Records a test outcome with sanitized evidence."""
        state = self.load_state()
        results: List[Dict[str, Any]] = state.get("test_results", [])
        res_dict = result.to_dict()

        clean_res = _sanitize_data_recursive(res_dict)

        existing_idx = next((i for i, r in enumerate(results) if r.get("hypothesis_id") == result.hypothesis_id), None)
        if existing_idx is not None:
            results[existing_idx] = clean_res
        else:
            results.append(clean_res)

        state["test_results"] = results
        state["updated_at"] = datetime.now(timezone.utc).isoformat()
        
        # Recalculate summary counters
        summary = state.get("summary", {})
        summary["total_hypotheses"] = len(state.get("hypotheses", []))
        summary["tested_hypotheses"] = len(results)
        
        conf_vulns = sum(1 for r in results if r.get("is_vulnerable") and r.get("confidence") == "CONFIRMED")
        controlled = sum(1 for r in results if r.get("confidence") == "CONCURRENCY_CONTROLLED")
        inconclusive = sum(1 for r in results if r.get("confidence") == "INCONCLUSIVE")
        total_probes = sum(r.get("burst_size", 0) for r in results)
        
        summary["confirmed_vulnerabilities"] = conf_vulns
        summary["validated_findings"] = sum(1 for f in state.get("findings", []) if f.get("lifecycle_state") in ("VALIDATED", "SIMULATED"))
        summary["concurrency_controlled"] = controlled
        summary["controlled_observations"] = controlled
        summary["inconclusive"] = inconclusive
        summary["inconclusive_observations"] = inconclusive
        summary["total_probes_dispatched"] = total_probes
        state["summary"] = summary

        self._atomic_write(state)

    def record_finding(self, finding_dict: Dict[str, Any]) -> None:
        """Records a validated finding into state."""
        state = self.load_state()
        findings: List[Dict[str, Any]] = state.get("findings", [])

        clean_finding = _sanitize_data_recursive(finding_dict)
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
        summary["validated_findings"] = sum(1 for f in findings if f.get("lifecycle_state") in ("VALIDATED", "SIMULATED"))
        summary["confirmed_vulnerabilities"] = summary["validated_findings"]
        state["summary"] = summary

        self._atomic_write(state)

    def record_tested_fingerprint(self, fingerprint: str) -> None:
        """Records a test fingerprint to prevent redundant concurrent probes."""
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
        """Returns summary dictionary."""
        state = self.load_state()
        return state.get("summary", {})
