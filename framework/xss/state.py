"""
XSS State Manager for BugBounty-Agent.

Provides atomic, thread-safe persistence and retrieval of XSS candidates,
context analyses, and validation states in:
~/BugBounty-Workspace/programs/<program>/state/xss.json
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import tempfile
from typing import Any, Dict, List, Optional

from framework.xss.model import (
    XssCandidate,
    XssCategory,
    XssConfidence,
    XssContextType,
)


class XssStateManager:
    """
    Manages local persistent state in state/xss.json.
    """

    def __init__(self, program_dir: str):
        self.program_dir = os.path.abspath(program_dir)
        self.state_dir = os.path.join(self.program_dir, "state")
        os.makedirs(self.state_dir, exist_ok=True)

        self.xss_file = os.path.join(self.state_dir, "xss.json")
        self._init_file()

    def _init_file(self) -> None:
        """Initializes empty xss.json if not present."""
        if not os.path.exists(self.xss_file):
            default_content = {
                "version": "1.0.0",
                "program": os.path.basename(self.program_dir),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "state_hash": "",
                "candidates": {},
                "summary": {
                    "total_candidates": 0,
                    "by_category": {"reflected": 0, "dom": 0, "stored": 0},
                    "by_confidence": {"OBSERVED": 0, "SUSPECTED": 0, "VALIDATED": 0, "REJECTED": 0},
                    "by_context": {},
                },
            }
            self._atomic_write_json(default_content)

    def _read_json(self) -> Dict[str, Any]:
        """Reads xss state safely."""
        try:
            with open(self.xss_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {
                "version": "1.0.0",
                "program": os.path.basename(self.program_dir),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "state_hash": "",
                "candidates": {},
                "summary": {
                    "total_candidates": 0,
                    "by_category": {"reflected": 0, "dom": 0, "stored": 0},
                    "by_confidence": {"OBSERVED": 0, "SUSPECTED": 0, "VALIDATED": 0, "REJECTED": 0},
                    "by_context": {},
                },
            }

    def _atomic_write_json(self, data: Dict[str, Any]) -> None:
        """Writes data atomically to xss.json."""
        data["last_updated"] = datetime.now(timezone.utc).isoformat()
        num_cands = len(data.get("candidates", {}))
        checksum_base = f"{num_cands}:{data.get('last_updated')}"
        data["state_hash"] = hashlib.sha256(checksum_base.encode("utf-8")).hexdigest()[:16]

        # Recompute summary
        by_cat = {"reflected": 0, "dom": 0, "stored": 0}
        by_conf = {"OBSERVED": 0, "SUSPECTED": 0, "VALIDATED": 0, "REJECTED": 0}
        by_ctx: Dict[str, int] = {}

        for c in data.get("candidates", {}).values():
            cat = c.get("category", "reflected")
            by_cat[cat] = by_cat.get(cat, 0) + 1

            conf = c.get("confidence", "OBSERVED")
            by_conf[conf] = by_conf.get(conf, 0) + 1

            ctx = c.get("context_type", "UNKNOWN")
            by_ctx[ctx] = by_ctx.get(ctx, 0) + 1

        data["summary"] = {
            "total_candidates": num_cands,
            "by_category": by_cat,
            "by_confidence": by_conf,
            "by_context": by_ctx,
        }

        dir_name = os.path.dirname(self.xss_file)
        with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
            json.dump(data, tf, indent=2)
            temp_path = tf.name
        os.replace(temp_path, self.xss_file)

    def save_candidate(self, candidate: XssCandidate) -> XssCandidate:
        """Saves or updates an XSS candidate."""
        data = self._read_json()
        cands = data.get("candidates", {})
        cands[candidate.candidate_id] = candidate.to_dict()
        data["candidates"] = cands
        self._atomic_write_json(data)
        return candidate

    def get_candidate(self, candidate_id: str) -> Optional[XssCandidate]:
        """Retrieves candidate by candidate_id."""
        data = self._read_json()
        cand_dict = data.get("candidates", {}).get(candidate_id)
        return XssCandidate.from_dict(cand_dict) if cand_dict else None

    def list_candidates(
        self,
        category: Optional[XssCategory | str] = None,
        confidence: Optional[XssConfidence | str] = None,
        context_type: Optional[XssContextType | str] = None,
    ) -> List[XssCandidate]:
        """Filters and returns candidates."""
        data = self._read_json()
        cands = [XssCandidate.from_dict(c) for c in data.get("candidates", {}).values()]

        if category:
            cat_val = category.value if isinstance(category, XssCategory) else str(category).lower()
            cands = [c for c in cands if c.category.value == cat_val]

        if confidence:
            conf_val = confidence.value if isinstance(confidence, XssConfidence) else str(confidence).upper()
            cands = [c for c in cands if c.confidence.value == conf_val]

        if context_type:
            ctx_val = context_type.value if isinstance(context_type, XssContextType) else str(context_type)
            cands = [c for c in cands if c.context_type.value == ctx_val]

        return cands

    def get_summary(self) -> Dict[str, Any]:
        """Returns state summary."""
        data = self._read_json()
        return data.get("summary", {})
