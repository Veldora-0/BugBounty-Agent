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


def resolve_program_scope_file(
    program_dir: Optional[str] = None,
    explicit_scope_path: Optional[str] = None,
) -> Optional[str]:
    """
    Deterministically resolves the scope configuration file path for a program workspace.

    Resolution precedence:
    1. Explicit scope path (explicit_scope_path):
       - If explicitly specified, it is normalized. If the file exists, returns its absolute path.
       - If it does not exist or is invalid, returns None (fails closed; never falls back).
    2. Canonical initialized program scope path: <program_dir>/scope/scope.yaml (created by bb-init).
    3. Legacy program root fallback: <program_dir>/scope.yaml.

    Returns:
        Absolute path to the valid scope file, or None if no valid scope file is found.
    """
    if explicit_scope_path:
        norm_override = os.path.abspath(explicit_scope_path)
        if os.path.isfile(norm_override):
            return norm_override
        # Explicit path provided but does not exist: fail closed (do NOT silently fall back)
        return None

    if not program_dir:
        return None

    norm_prog = os.path.abspath(program_dir)

    # Precedence 2: Canonical path created by bb-init (<program_dir>/scope/scope.yaml)
    canonical_path = os.path.join(norm_prog, "scope", "scope.yaml")
    if os.path.isfile(canonical_path):
        return canonical_path

    # Precedence 3: Legacy program root fallback (<program_dir>/scope.yaml)
    legacy_path = os.path.join(norm_prog, "scope.yaml")
    if os.path.isfile(legacy_path):
        return legacy_path

    return None

