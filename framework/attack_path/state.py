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

from framework.attack_path.model import AttackGraph


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
        Includes retry logic for transient Windows file locks.
        """
        data = graph.to_dict()
        dir_name = os.path.dirname(self.graph_file)
        os.makedirs(dir_name, exist_ok=True)

        temp_path = None
        try:
            with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
                json.dump(data, tf, indent=2)
                temp_path = tf.name

            # Enforce private file permissions
            if os.name != "nt":
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
