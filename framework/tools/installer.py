"""
Safe On-Demand Tool Installer for BugBounty-Agent.

Enforces deterministic installation methods:
1. Official Kali/Debian package (apt)
2. Official GitHub release binary (with architecture & release validation)
3. Language package managers (go install, pipx install, cargo install)

Security Invariants:
- Never executes arbitrary shell strings or unapproved remote scripts.
- Rejects unknown tools not registered in config/tools.yaml.
- Installs to ~/.local/bin by default to minimize sudo requirements.
- Records installation provenance for auditability.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from typing import Any, Dict, List, Optional, Tuple

from framework.tools.dependencies import DependencyResolver
from framework.tools.detector import (
    ToolDetector,
    find_executable,
    get_system_architecture,
)
from framework.tools.registry import ToolDef, ToolRegistry


DEFAULT_PROVENANCE_FILE = os.path.expanduser("~/.config/bugbounty-agent/tool_provenance.json")
DEFAULT_USER_BIN = os.path.expanduser("~/.local/bin")


class InstallerSecurityError(ValueError):
    """Raised when an installation request violates framework security invariants."""
    pass


class InstallPlan:
    """Represents a planned installation sequence before execution."""

    def __init__(self, tool_name: str, method: str, command: List[str], target_path: str, notes: str):
        self.tool_name = tool_name
        self.method = method
        self.command = command
        self.target_path = target_path
        self.notes = notes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool_name,
            "method": self.method,
            "command": " ".join(self.command),
            "target_path": self.target_path,
            "notes": self.notes,
        }


class ToolInstaller:
    """Safe, on-demand tool installer and dependency manager."""

    def __init__(
        self,
        registry: Optional[ToolRegistry] = None,
        provenance_file: Optional[str] = None,
        bin_dir: Optional[str] = None,
    ):
        self.registry = registry or ToolRegistry()
        self.detector = ToolDetector(self.registry)
        self.resolver = DependencyResolver(self.registry)
        self.provenance_file = provenance_file or DEFAULT_PROVENANCE_FILE
        self.bin_dir = bin_dir or DEFAULT_USER_BIN

    def record_provenance(self, tool_name: str, record: Dict[str, Any]) -> None:
        """Stores local installation metadata for auditability."""
        os.makedirs(os.path.dirname(self.provenance_file), exist_ok=True)
        data = {}
        if os.path.isfile(self.provenance_file):
            try:
                with open(self.provenance_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                data = {}

        data[tool_name] = {
            **record,
            "installed_at": datetime.now(timezone.utc).isoformat(),
        }

        with open(self.provenance_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def plan_install(self, tool_name: str) -> InstallPlan:
        """
        Creates a safe, validated installation plan for a registered tool.
        Rejects unknown tools and unapproved methods.
        """
        tool = self.registry.get_tool(tool_name)
        if not tool:
            raise InstallerSecurityError(f"Rejected unapproved tool: '{tool_name}' is not in the registry.")

        if not tool.is_auto_installable():
            raise InstallerSecurityError(f"Tool '{tool_name}' requires manual installation (marked auto_install: false).")

        os_name, arch = get_system_architecture()
        if os_name not in tool.platforms:
            raise InstallerSecurityError(
                f"Tool '{tool_name}' does not support current platform '{os_name}'. Supported: {tool.platforms}"
            )

        install_cfg = tool.install
        preferred = install_cfg.get("preferred", "official-release")

        # Select method based on platform and availability
        if preferred == "apt" and os_name == "linux" and shutil.which("apt-get"):
            pkg = install_cfg.get("apt_package", tool.binary)
            return InstallPlan(
                tool_name=tool.name,
                method="apt",
                command=["sudo", "apt-get", "install", "-y", pkg],
                target_path=f"/usr/bin/{tool.binary}",
                notes="Installs official Kali/Debian package via apt",
            )

        if preferred == "go" or (shutil.which("go") and install_cfg.get("go_package")):
            pkg = install_cfg.get("go_package")
            if not pkg:
                raise InstallerSecurityError(f"Missing go_package definition for {tool_name}")
            return InstallPlan(
                tool_name=tool.name,
                method="go",
                command=["go", "install", "-v", pkg],
                target_path=os.path.join(os.path.expanduser("~/go/bin"), tool.binary),
                notes=f"Compiles from official source via Go toolchain ({pkg})",
            )

        if preferred == "pipx" or install_cfg.get("pip_package"):
            pkg = install_cfg.get("pip_package", tool.binary)
            if shutil.which("pipx"):
                cmd = ["pipx", "install", pkg]
            else:
                cmd = [sys.executable, "-m", "pip", "install", "--user", pkg]
            return InstallPlan(
                tool_name=tool.name,
                method="pipx",
                command=cmd,
                target_path=os.path.join(self.bin_dir, tool.binary),
                notes=f"Installs isolated Python package ({pkg})",
            )

        if preferred == "cargo" and shutil.which("cargo") and install_cfg.get("cargo_package"):
            pkg = install_cfg.get("cargo_package")
            return InstallPlan(
                tool_name=tool.name,
                method="cargo",
                command=["cargo", "install", pkg],
                target_path=os.path.join(os.path.expanduser("~/.cargo/bin"), tool.binary),
                notes=f"Compiles Rust binary via cargo ({pkg})",
            )

        # Fallback to official GitHub release artifact if repo is declared
        release_repo = install_cfg.get("release_repo")
        if release_repo:
            return InstallPlan(
                tool_name=tool.name,
                method="official-release",
                command=["internal:download_release", release_repo],
                target_path=os.path.join(self.bin_dir, tool.binary),
                notes=f"Downloads official release artifact from https://github.com/{release_repo}",
            )

        raise InstallerSecurityError(f"No viable safe installation method found for tool '{tool_name}' on {os_name}/{arch}")

    def execute_install(self, tool_name: str, dry_run: bool = False) -> Dict[str, Any]:
        """
        Executes an installation plan with pre-checks, execution, verification,
        and provenance logging.
        """
        # 1. Check if already installed
        info = self.detector.inspect_tool(self.registry.get_tool(tool_name))
        if info["installed"] and info["version_ok"]:
            return {
                "success": True,
                "tool": tool_name,
                "already_installed": True,
                "version": info["version"],
                "path": info["path"],
            }

        # 2. Check and install prerequisites first
        prereqs = self.resolver.resolve_install_order([tool_name])
        for prereq_name in prereqs:
            if prereq_name.lower() == tool_name.lower():
                continue
            p_info = self.detector.inspect_tool(self.registry.get_tool(prereq_name))
            if not p_info["installed"]:
                if dry_run:
                    continue
                p_res = self.execute_install(prereq_name, dry_run=False)
                if not p_res.get("success"):
                    return {
                        "success": False,
                        "tool": tool_name,
                        "error": f"Failed to install prerequisite '{prereq_name}': {p_res.get('error')}",
                    }

        # 3. Formulate plan
        plan = self.plan_install(tool_name)
        if dry_run:
            return {"success": True, "dry_run": True, "plan": plan.to_dict()}

        os.makedirs(self.bin_dir, exist_ok=True)

        # 4. Execute installation
        try:
            if plan.method in ("apt", "go", "pipx", "cargo"):
                subprocess.run(plan.command, check=True, timeout=300)
            elif plan.method == "official-release":
                self._download_and_extract_release(tool_name)
            else:
                raise InstallerSecurityError(f"Unsupported execution method: {plan.method}")
        except Exception as e:
            return {
                "success": False,
                "tool": tool_name,
                "error": f"Execution failed: {str(e)}",
            }

        # 5. Post-installation steps (e.g. Playwright browser binaries)
        if tool_name.lower() == "playwright":
            try:
                subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=True, timeout=180)
            except Exception as e:
                return {"success": False, "tool": tool_name, "error": f"Playwright browser install failed: {e}"}

        # 6. Verify resulting binary
        post_info = self.detector.inspect_tool(self.registry.get_tool(tool_name))
        if not post_info["installed"]:
            return {
                "success": False,
                "tool": tool_name,
                "error": "Binary was not found on PATH or target path after installation.",
            }

        # 7. Record provenance
        self.record_provenance(tool_name, {
            "method": plan.method,
            "version": post_info["version"],
            "binary_path": post_info["path"],
            "status": "VERIFIED",
        })

        return {
            "success": True,
            "tool": tool_name,
            "version": post_info["version"],
            "path": post_info["path"],
            "method": plan.method,
        }

    def _download_and_extract_release(self, tool_name: str) -> None:
        """
        Safely downloads and extracts an official GitHub release asset.
        Only downloads from api.github.com / github.com releases.
        """
        tool = self.registry.get_tool(tool_name)
        if not tool:
            raise InstallerSecurityError(f"Tool '{tool_name}' is not in the registry.")
        release_repo = tool.install.get("release_repo")
        if not release_repo:
            raise InstallerSecurityError("No release repository configured.")

        os_name, arch = get_system_architecture()
        api_url = f"https://api.github.com/repos/{release_repo}/releases/latest"

        req = urllib.request.Request(api_url, headers={"User-Agent": "BugBounty-Agent/1.1"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        assets = data.get("assets", [])
        matched_asset = None

        # Architecture matching
        for asset in assets:
            name = asset.get("name", "").lower()
            if os_name in name and arch in name:
                if name.endswith((".tar.gz", ".zip", ".tgz")):
                    matched_asset = asset
                    break

        if not matched_asset:
            raise InstallerSecurityError(f"No suitable binary release asset found for {os_name}/{arch} in {release_repo}")

        download_url = matched_asset.get("browser_download_url")
        if not download_url or not download_url.startswith("https://github.com/"):
            raise InstallerSecurityError(f"Rejected unapproved download URL: {download_url}")

        with tempfile.TemporaryDirectory() as tmp_dir:
            archive_path = os.path.join(tmp_dir, "release_archive")
            urllib.request.urlretrieve(download_url, archive_path)

            # Extract binary
            target_binary = tool.binary
            extracted_bin = None

            if download_url.endswith(".zip"):
                with zipfile.ZipFile(archive_path, "r") as zf:
                    zf.extractall(tmp_dir)
            else:
                with tarfile.open(archive_path, "r:*") as tf:
                    tf.extractall(tmp_dir)

            for root, _, files in os.walk(tmp_dir):
                for f in files:
                    if f.lower() == target_binary.lower() or f.lower() == (target_binary + ".exe").lower():
                        extracted_bin = os.path.join(root, f)
                        break

            if not extracted_bin or not os.path.isfile(extracted_bin):
                raise InstallerSecurityError(f"Could not locate binary '{target_binary}' inside downloaded archive.")

            dest_path = os.path.join(self.bin_dir, target_binary)
            shutil.copyfile(extracted_bin, dest_path)
            os.chmod(dest_path, 0o755)
