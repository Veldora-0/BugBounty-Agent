"""
System Environment and Tool Detection for BugBounty-Agent.

Detects OS, architecture, package managers, system runtimes, and inspects
installed security tools, version tags, and capability statuses.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from framework.tools.registry import ToolDef, ToolRegistry


# Common locations added to search PATH on Linux/Kali
EXTENDED_SEARCH_PATHS = [
    os.path.expanduser("~/.local/bin"),
    os.path.expanduser("~/go/bin"),
    os.path.expanduser("~/.cargo/bin"),
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
]


def get_system_architecture() -> Tuple[str, str]:
    """
    Returns normalized (os_name, arch).
    os_name: 'linux', 'darwin', 'windows'
    arch: 'amd64', 'arm64', '386'
    """
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system.startswith("linux"):
        os_name = "linux"
    elif system == "darwin":
        os_name = "darwin"
    elif system.startswith("win"):
        os_name = "windows"
    else:
        os_name = system

    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    elif machine in ("i386", "i686", "x86"):
        arch = "386"
    else:
        arch = machine

    return os_name, arch


def find_executable(binary_name: str) -> Optional[str]:
    """Finds binary path checking current PATH and standard user installation directories."""
    path = shutil.which(binary_name)
    if path:
        return os.path.abspath(path)

    # Check common user install paths if not in current PATH
    for p in EXTENDED_SEARCH_PATHS:
        candidate = os.path.join(p, binary_name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return os.path.abspath(candidate)
        # On Windows, check with .exe
        if os.name == "nt":
            cand_exe = candidate + ".exe"
            if os.path.isfile(cand_exe):
                return os.path.abspath(cand_exe)

    return None


def extract_version_from_output(output: str) -> Optional[str]:
    """Extracts semantic version (e.g. 2.6.0, v1.3.2) from command stdout/stderr."""
    if not output:
        return None
    # Matches patterns like v1.2.3, 2.6.0, 3.2.0-dev
    match = re.search(r"(?:v|version\s+|ver\s*)?([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-zA-Z0-9\.]+)?)", output, re.IGNORECASE)
    if match:
        return match.group(1).lstrip("v")
    return None


def compare_semver(installed: str, required: str) -> bool:
    """Returns True if installed version is >= required version."""
    def parse_parts(v: str) -> List[int]:
        clean = v.split("-")[0].lstrip("v")
        parts = []
        for p in clean.split("."):
            if p.isdigit():
                parts.append(int(p))
            else:
                parts.append(0)
        return parts

    try:
        inst_parts = parse_parts(installed)
        req_parts = parse_parts(required)
        return inst_parts >= req_parts
    except Exception:
        return True


class ToolDetector:
    """Inspects host system for installed security tools and capabilities."""

    def __init__(self, registry: Optional[ToolRegistry] = None):
        self.registry = registry or ToolRegistry()

    def inspect_tool(self, tool: ToolDef) -> Dict[str, Any]:
        """Runs health check on a specific tool entry."""
        binary_path = find_executable(tool.binary)
        installed = binary_path is not None
        version = None
        version_ok = True
        status = "MISSING"

        if installed:
            verify_cmd = tool.verify.get("command")
            if verify_cmd:
                try:
                    # Run verify command safely with short timeout
                    parts = verify_cmd.split()
                    parts[0] = binary_path  # use absolute path
                    res = subprocess.run(
                        parts,
                        capture_output=True,
                        text=True,
                        timeout=5,
                        errors="replace",
                    )
                    combined_out = (res.stdout + " " + res.stderr).strip()
                    version = extract_version_from_output(combined_out)
                except Exception:
                    pass

            min_ver = tool.verify.get("min_version")
            if version and min_ver:
                version_ok = compare_semver(version, min_ver)
                if not version_ok:
                    status = "OUTDATED"
                else:
                    status = "INSTALLED"
            else:
                status = "INSTALLED"
        else:
            if tool.is_auto_installable():
                status = "INSTALLABLE"
            else:
                status = "MISSING_MANUAL"

        return {
            "name": tool.name,
            "binary": tool.binary,
            "installed": installed,
            "path": binary_path,
            "version": version or "unknown",
            "version_ok": version_ok,
            "min_version": tool.verify.get("min_version"),
            "status": status,
            "tier": tool.tier,
            "category": tool.category,
            "capabilities": tool.capabilities,
        }

    def detect_all(self) -> Dict[str, Dict[str, Any]]:
        """Inspects all tools in registry."""
        results = {}
        for tool in self.registry.all_tools():
            results[tool.name] = self.inspect_tool(tool)
        return results

    def get_summary(self) -> Dict[str, Any]:
        """Provides high-level summary of tool readiness."""
        all_info = self.detect_all()
        installed = [name for name, data in all_info.items() if data["installed"]]
        missing = [name for name, data in all_info.items() if not data["installed"]]
        outdated = [name for name, data in all_info.items() if data["status"] == "OUTDATED"]

        return {
            "total_supported": len(all_info),
            "installed_count": len(installed),
            "missing_count": len(missing),
            "outdated_count": len(outdated),
            "installed": installed,
            "missing": missing,
            "outdated": outdated,
            "tools": all_info,
        }
