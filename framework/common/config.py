"""
Configuration and Runtime Path Manager for BugBounty-Agent.

Ensures complete physical separation between the Git repository code
and sensitive local target data.
"""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
from typing import Dict, List, Optional
import yaml


# Retained for callers that imported the old constant; it is not the default.
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


def ensure_private_directory(path: str) -> str:
    """Create or verify a directory reserved for program data (mode 0700/DACL)."""
    abs_path = os.path.abspath(path)
    os.makedirs(abs_path, mode=0o700, exist_ok=True)
    if os.path.islink(abs_path):
        raise PermissionError(f"Sensitive directory must not be a symbolic link: {abs_path}")
    if os.name == "nt":
        from framework.auth_correlation.state import (
            _enforce_windows_directory_dacl,
            _verify_windows_directory_security,
        )
        _enforce_windows_directory_dacl(abs_path)
        _verify_windows_directory_security(abs_path)
    else:
        st = os.lstat(abs_path)
        if st.st_uid != os.getuid():
            raise PermissionError(f"Sensitive directory is not owned by the current user: {abs_path}")
        if st.st_mode & 0o777 != 0o700:
            os.chmod(abs_path, 0o700)
        st = os.lstat(abs_path)
        if st.st_mode & 0o777 != 0o700:
            raise PermissionError(f"Could not enforce mode 0700 on sensitive directory: {abs_path}")
    return abs_path


def write_private_text_file(path: str, content: str) -> None:
    """Atomically write sensitive text with mode 0600 or the current-user DACL."""
    abs_path = os.path.abspath(path)
    parent = ensure_private_directory(os.path.dirname(abs_path))
    if os.path.islink(abs_path):
        raise PermissionError(f"Sensitive file must not be a symbolic link: {abs_path}")
    fd, temp_path = tempfile.mkstemp(prefix=".private-write-", dir=parent, text=True)
    try:
        if os.name != "nt":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "nt":
            from framework.auth_correlation.state import (
                _enforce_windows_file_dacl,
                _verify_windows_file_security,
            )
            _enforce_windows_file_dacl(temp_path)
            _verify_windows_file_security(temp_path)
        else:
            mode = os.stat(temp_path).st_mode & 0o777
            if mode != 0o600:
                raise PermissionError(f"Could not enforce mode 0600 on sensitive file: {temp_path}")
        os.replace(temp_path, abs_path)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise


def get_workspace_root() -> str:
    """
    Resolves the base directory for program data.

    Precedence:
    1. An explicit BUGBOUNTY_WORKSPACE override
    2. The current working directory (the directory OpenCode was opened in)
    """
    env_dir = os.environ.get("BUGBOUNTY_WORKSPACE")
    if env_dir:
        return os.path.abspath(env_dir)
    return os.path.abspath(os.getcwd())


def get_agent_knowledge_dir() -> str:
    """Return persistent Bug-Bounty agent data under the global OpenCode config."""
    config_dir = os.environ.get("OPENCODE_CONFIG_DIR", os.path.expanduser("~/.config/opencode"))
    return os.path.abspath(os.path.join(config_dir, "bug-bounty-agent", "knowledge"))


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
    ensure_private_directory(prog_dir)
    paths = {"program_root": prog_dir}

    for subdir in PROGRAM_SUBDIRECTORIES:
        p = os.path.join(prog_dir, subdir)
        paths[subdir] = ensure_private_directory(p)

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

