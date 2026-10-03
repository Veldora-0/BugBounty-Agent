"""
Tool Update and Maintenance Manager for BugBounty-Agent.

Inspects installed tools, detects outdated versions against registry minimums,
and generates safe update plans.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from framework.tools.detector import ToolDetector
from framework.tools.installer import ToolInstaller
from framework.tools.registry import ToolRegistry


class ToolUpdater:
    """Manages version inspection and safe updates for installed security tools."""

    def __init__(
        self,
        registry: Optional[ToolRegistry] = None,
        installer: Optional[ToolInstaller] = None,
    ):
        self.registry = registry or ToolRegistry()
        self.detector = ToolDetector(self.registry)
        self.installer = installer or ToolInstaller(self.registry)

    def check_updates(self) -> List[Dict[str, Any]]:
        """Scans all installed tools for outdated versions or updates."""
        all_info = self.detector.detect_all()
        updates_needed = []

        for name, data in all_info.items():
            if not data["installed"]:
                continue

            tool = self.registry.get_tool(name)
            if not tool:
                continue

            min_ver = tool.verify.get("min_version")
            cur_ver = data["version"]
            is_outdated = data["status"] == "OUTDATED"

            if is_outdated:
                updates_needed.append({
                    "tool": name,
                    "current_version": cur_ver,
                    "min_version": min_ver,
                    "install_method": tool.install.get("preferred"),
                    "status": "OUTDATED",
                })

        return updates_needed

    def plan_update(self, tool_name: str) -> Dict[str, Any]:
        """Generates an installation/update plan for an existing tool."""
        plan = self.installer.plan_install(tool_name)
        return {
            "tool": tool_name,
            "method": plan.method,
            "command": plan.command,
            "notes": plan.notes,
        }

    def update_tool(self, tool_name: str) -> Dict[str, Any]:
        """Executes safe update for a specific tool."""
        return self.installer.execute_install(tool_name, dry_run=False)
