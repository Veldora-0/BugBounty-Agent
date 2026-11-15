"""
Phase 22.1: Attack Path State Management.

Provides durable, atomic persistence for the attack graph in state/attack_graph.json.
Enforces private directory permissions, atomic writes with transient Windows lock retries,
and corruption recovery. Decoupled from framework/state/manager.py to prevent core regressions.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import shutil
import tempfile
import time
from typing import Any, Dict, Optional

from framework.attack_path.model import AttackGraph, assert_no_raw_secrets


class AttackPathStateError(Exception):
    """Raised when attack graph state cannot be read, written, or secured."""
    pass


class AttackPathStateManager:
    """
    Manages isolated persistent attack graph storage for a specific bug bounty program.
    """

    def __init__(self, program_dir: str) -> None:
        self.program_dir = os.path.abspath(program_dir)
        self.state_dir = os.path.join(self.program_dir, "state")
        self.graph_file = os.path.join(self.state_dir, "attack_graph.json")
        self.plans_file = os.path.join(self.state_dir, "validation_plans.json")
        self.audit_file = os.path.join(self.state_dir, "validation_audit.jsonl")
        self._ensure_secure_directories()

    def _ensure_secure_directories(self) -> None:
        """Enforces private directory permissions across Windows and POSIX platforms."""
        os.makedirs(self.state_dir, exist_ok=True)
        if os.name == "nt":
            try:
                from framework.auth_correlation.state import _enforce_windows_directory_dacl
                _enforce_windows_directory_dacl(self.state_dir)
            except Exception:
                pass
        else:
            try:
                os.chmod(self.state_dir, 0o700)
            except OSError:
                pass

    def get_graph_path(self) -> str:
        """Returns the canonical path to the attack graph JSON file."""
        return self.graph_file

    def load_graph(self) -> AttackGraph:
        """
        Loads the AttackGraph from disk.
        If file does not exist, returns an empty AttackGraph.
        If file is corrupted or malformed, creates a recovery backup and reinitializes cleanly.
        """
        if not os.path.isfile(self.graph_file):
            return AttackGraph()

        try:
            with open(self.graph_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("Attack graph JSON root must be an object")
            return AttackGraph.from_dict(data)
        except Exception as exc:
            # Recovery: backup corrupted graph and return fresh graph
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            corrupt_backup = f"{self.graph_file}.corrupt.{ts}"
            try:
                shutil.copy2(self.graph_file, corrupt_backup)
            except OSError:
                pass
            return AttackGraph()

    def save_graph(self, graph: AttackGraph) -> None:
        """
        Atomically saves the AttackGraph to disk via temporary file rename.
        Enforces zero-secret assertions and private file security (POSIX 0600 / Windows DACL).
        Includes retry logic for transient Windows file locks.
        """
        dir_name = os.path.dirname(self.graph_file)
        os.makedirs(dir_name, exist_ok=True)

        temp_path = None
        try:
            data = graph.to_dict()
            # Enforce zero-secret assertion before persisting state to disk
            assert_no_raw_secrets(data, "persisted_attack_graph")

            with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
                json.dump(data, tf, indent=2)
                temp_path = tf.name

            # Enforce private file permissions
            if os.name == "nt":
                try:
                    from framework.auth_correlation.state import _enforce_windows_file_dacl
                    _enforce_windows_file_dacl(temp_path)
                except Exception:
                    pass
            else:
                try:
                    os.chmod(temp_path, 0o600)
                except OSError:
                    pass

            # Atomic replace with retry for transient Windows file locks
            for attempt in range(5):
                try:
                    os.replace(temp_path, self.graph_file)
                    temp_path = None
                    break
                except PermissionError:
                    if attempt == 4 or os.name != "nt":
                        raise
                    time.sleep(0.05)
        except Exception as exc:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            raise AttackPathStateError(f"Failed to persist attack graph: {exc}") from exc

    def save_plans(self, plans: Dict[str, Any]) -> None:
        """
        Atomically saves validation plans to state/validation_plans.json.
        Enforces zero-secret assertions and private file security.
        """
        dir_name = os.path.dirname(self.plans_file)
        os.makedirs(dir_name, exist_ok=True)

        temp_path = None
        try:
            data = {
                pid: p.to_dict() if hasattr(p, "to_dict") else p
                for pid, p in plans.items()
            }
            assert_no_raw_secrets(data, "persisted_validation_plans")

            with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
                json.dump(data, tf, indent=2)
                temp_path = tf.name

            if os.name == "nt":
                try:
                    from framework.auth_correlation.state import _enforce_windows_file_dacl
                    _enforce_windows_file_dacl(temp_path)
                except Exception:
                    pass
            else:
                try:
                    os.chmod(temp_path, 0o600)
                except OSError:
                    pass

            for attempt in range(5):
                try:
                    os.replace(temp_path, self.plans_file)
                    temp_path = None
                    break
                except PermissionError:
                    if attempt == 4 or os.name != "nt":
                        raise
                    time.sleep(0.05)
        except Exception as exc:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            raise AttackPathStateError(f"Failed to persist validation plans: {exc}") from exc

    def load_plans(self) -> Dict[str, Any]:
        """
        Loads validation plans from state/validation_plans.json.
        Returns a mapping of plan_id -> ChainValidationPlan.
        """
        from framework.attack_path.validator import ChainValidationPlan

        if not os.path.isfile(self.plans_file):
            return {}

        try:
            with open(self.plans_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("Validation plans JSON root must be an object")

            plans: Dict[str, ChainValidationPlan] = {}
            for pid, p_dict in data.items():
                if isinstance(p_dict, dict):
                    plans[pid] = ChainValidationPlan.from_dict(p_dict)
            return plans
        except Exception as exc:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            corrupt_backup = f"{self.plans_file}.corrupt.{ts}"
            try:
                shutil.copy2(self.plans_file, corrupt_backup)
            except OSError:
                pass
            return {}

    def append_audit_event(self, event: Any) -> None:
        """
        Appends an immutable audit event to state/validation_audit.jsonl.
        Enforces zero-secret assertions and private file security.
        """
        event_dict = event.to_dict() if hasattr(event, "to_dict") else dict(event)
        assert_no_raw_secrets(event_dict, "persisted_audit_event")

        dir_name = os.path.dirname(self.audit_file)
        os.makedirs(dir_name, exist_ok=True)

        try:
            line = json.dumps(event_dict, separators=(",", ":")) + "\n"
            with open(self.audit_file, "a", encoding="utf-8") as f:
                f.write(line)

            if os.name == "nt":
                try:
                    from framework.auth_correlation.state import _enforce_windows_file_dacl
                    _enforce_windows_file_dacl(self.audit_file)
                except Exception:
                    pass
            else:
                try:
                    os.chmod(self.audit_file, 0o600)
                except OSError:
                    pass
        except Exception as exc:
            raise AttackPathStateError(f"Failed to append audit event: {exc}") from exc

    def load_audit_events(self) -> List[Any]:
        """Loads all validation audit events from state/validation_audit.jsonl."""
        from framework.attack_path.validator import ValidationAuditEvent

        if not os.path.isfile(self.audit_file):
            return []

        events = []
        try:
            with open(self.audit_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict):
                            events.append(ValidationAuditEvent.from_dict(obj))
                    except Exception:
                        continue
            return events
        except Exception:
            return []

