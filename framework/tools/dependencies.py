"""
Dependency Resolver for BugBounty-Agent Tools.

Resolves tool-to-tool prerequisites (e.g. shuffledns -> massdns) and runtime
dependencies (e.g. Playwright -> browser binaries, Go tools -> Go toolchain).
"""

from __future__ import annotations

import shutil
from typing import Dict, List, Optional, Set

from framework.tools.registry import ToolDef, ToolRegistry


# Runtime prerequisites mapped to verification checks
SYSTEM_DEPENDENCY_CHECKS = {
    "go": lambda: shutil.which("go") is not None,
    "python3": lambda: shutil.which("python3") is not None or shutil.which("python") is not None,
    "pipx": lambda: shutil.which("pipx") is not None,
    "git": lambda: shutil.which("git") is not None,
    "cargo": lambda: shutil.which("cargo") is not None,
    "docker": lambda: shutil.which("docker") is not None,
}


class DependencyResolver:
    """Computes ordered installation sequences ensuring prerequisites are met."""

    def __init__(self, registry: Optional[ToolRegistry] = None):
        self.registry = registry or ToolRegistry()

    def get_runtime_prerequisites(self, tool: ToolDef) -> List[str]:
        """Identifies language/system runtimes required to install and execute the tool."""
        prereqs = []
        install_method = tool.install.get("preferred", "")

        if install_method == "go" or tool.install.get("go_package"):
            prereqs.append("go")
        if install_method == "pipx" or tool.install.get("pip_package"):
            prereqs.append("pipx")
        if install_method == "cargo" or tool.install.get("cargo_package"):
            prereqs.append("cargo")

        # Tool specific post-install steps
        if tool.name.lower() == "playwright":
            prereqs.append("playwright-browsers")

        return prereqs

    def resolve_install_order(self, target_tools: List[str]) -> List[str]:
        """
        Performs topological sorting to determine safe installation order.
        Prerequisites appear before dependents (e.g. massdns before shuffledns).
        """
        ordered: List[str] = []
        visited: Set[str] = set()
        visiting: Set[str] = set()

        def visit(name: str):
            clean_name = name.lower()
            if clean_name in visiting:
                # Cycle detected, ignore to prevent infinite recursion
                return
            if clean_name in visited:
                return

            visiting.add(clean_name)
            tool = self.registry.get_tool(clean_name)
            if tool:
                for dep in tool.dependencies:
                    visit(dep)

            visiting.remove(clean_name)
            visited.add(clean_name)
            ordered.append(clean_name)

        for t in target_tools:
            visit(t)

        return ordered

    def check_missing_prerequisites(self, tool_name: str) -> List[str]:
        """Returns missing runtime dependencies for a specific tool on this system."""
        tool = self.registry.get_tool(tool_name)
        if not tool:
            return []

        missing = []
        prereqs = self.get_runtime_prerequisites(tool)
        for p in prereqs:
            check_fn = SYSTEM_DEPENDENCY_CHECKS.get(p)
            if check_fn and not check_fn():
                missing.append(p)
        return missing
