"""
Configuration and Runtime Path Manager for BugBounty-Agent.

Ensures complete physical separation between the Git repository code
and sensitive local target data.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional
import yaml


DEFAULT_RUNTIME_DIR_NAME = "BugBounty-Workspace"

PROGRAM_SUBDIRECTORIES = [
    "scope",
    "targets",
    "recon",
    "web",
    "js",
    "api",
    "scans",
    "evidence",
    "findings",
    "reports",
    "state",
    "logs",
]


def get_workspace_root() -> str:
    """
    Resolves the base workspace directory for runtime data.
    Precedence:
    1. BUGBOUNTY_WORKSPACE environment variable
    2. ~/BugBounty-Workspace/ in the user's home directory
    3. ~/.local/share/bugbounty-agent/
    """
    env_dir = os.environ.get("BUGBOUNTY_WORKSPACE")
    if env_dir:
        return os.path.abspath(env_dir)

    home = os.path.expanduser("~")
    primary = os.path.join(home, DEFAULT_RUNTIME_DIR_NAME)
    return primary


def get_program_dir(program_name: str, workspace_root: Optional[str] = None) -> str:
    """Returns the absolute directory path for a specific program."""
    base = workspace_root or get_workspace_root()
    clean_name = "".join(c for c in program_name if c.isalnum() or c in ("-", "_")).lower()
    if not clean_name:
        raise ValueError(f"Invalid program name: {program_name}")
    return os.path.join(base, "programs", clean_name)


def init_program_workspace(program_name: str, workspace_root: Optional[str] = None) -> Dict[str, str]:
    """
    Initializes the local workspace directory structure for a program.
    Creates all required subdirectories and returns their paths.
    """
    prog_dir = get_program_dir(program_name, workspace_root)
    paths = {"program_root": prog_dir}

    for subdir in PROGRAM_SUBDIRECTORIES:
        p = os.path.join(prog_dir, subdir)
        os.makedirs(p, exist_ok=True)
        paths[subdir] = p

    return paths


def list_local_programs(workspace_root: Optional[str] = None) -> List[str]:
    """Lists all initialized programs in the local workspace."""
    base = workspace_root or get_workspace_root()
    programs_dir = os.path.join(base, "programs")
    if not os.path.isdir(programs_dir):
        return []
    return [
        d for d in os.listdir(programs_dir)
        if os.path.isdir(os.path.join(programs_dir, d))
    ]
