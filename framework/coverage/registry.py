"""Loads and validates the repository-owned vulnerability coverage catalog.

The registry is descriptive metadata. It performs no target requests and never
infers that a listed capability was exercised for a particular program.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import yaml

from framework.tools.registry import ToolRegistry


class CoverageRegistryError(ValueError):
    """Raised when coverage metadata is malformed or misrepresents the tree."""


ALLOWED_STATUSES = {"partial", "manual-assisted", "planned", "out-of-scope"}
ALLOWED_TOOL_STATUSES = {"not-required", "registry-only", "engine-integrated", "not-registered"}
REQUIRED_FIELDS = {
    "id", "title", "area", "status", "engine", "cli", "tools", "tool_status",
    "proof", "prerequisites", "limits", "references",
}


class CoverageRegistry:
    """Read-only view of the static coverage catalog and its repository wiring."""

    def __init__(self, repo_root: Optional[str] = None, registry_path: Optional[str] = None):
        if repo_root is None:
            repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        self.repo_root = os.path.abspath(repo_root)
        self.registry_path = os.path.abspath(
            registry_path or os.path.join(self.repo_root, "config", "vulnerability-coverage.yaml")
        )
        self.data = self._load()
        self.classes: List[Dict[str, Any]] = list(self.data.get("classes", []))

    def _load(self) -> Dict[str, Any]:
        if not os.path.isfile(self.registry_path):
            raise CoverageRegistryError(f"Coverage registry not found: {self.registry_path}")
        try:
            with open(self.registry_path, "r", encoding="utf-8") as stream:
                data = yaml.safe_load(stream)
        except (OSError, yaml.YAMLError) as exc:
            raise CoverageRegistryError(f"Unable to read coverage registry: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("classes"), list):
            raise CoverageRegistryError("Coverage registry must contain a classes list")
        return data

    def validate(self) -> List[str]:
        """Return structural and repository-wiring errors; never access networks."""
        errors: List[str] = []
        statuses = set(self.data.get("statuses", []))
        tool_statuses = set(self.data.get("tool_statuses", []))
        if not statuses.issubset(ALLOWED_STATUSES):
            errors.append(f"Unknown coverage statuses declared: {sorted(statuses - ALLOWED_STATUSES)}")
        if not tool_statuses.issubset(ALLOWED_TOOL_STATUSES):
            errors.append(f"Unknown tool statuses declared: {sorted(tool_statuses - ALLOWED_TOOL_STATUSES)}")

        try:
            tool_registry = ToolRegistry(os.path.join(self.repo_root, "config", "tools.yaml"))
            known_tools = {tool.name for tool in tool_registry.all_tools()}
        except Exception as exc:  # report bad registry linkage as a validation result
            known_tools = set()
            errors.append(f"Unable to load tool registry: {exc}")

        seen_ids = set()
        for index, item in enumerate(self.classes):
            prefix = f"classes[{index}]"
            if not isinstance(item, dict):
                errors.append(f"{prefix} must be a mapping")
                continue
            missing = REQUIRED_FIELDS - set(item)
            if missing:
                errors.append(f"{prefix} missing fields: {', '.join(sorted(missing))}")
                continue
            class_id = item.get("id")
            if not isinstance(class_id, str) or not class_id.strip():
                errors.append(f"{prefix} has an empty or invalid id")
                continue
            if class_id in seen_ids:
                errors.append(f"Duplicate coverage id: {class_id}")
            seen_ids.add(class_id)

            status = item.get("status")
            if status not in statuses:
                errors.append(f"{class_id}: unsupported status {status!r}")
            tool_status = item.get("tool_status")
            if tool_status not in tool_statuses:
                errors.append(f"{class_id}: unsupported tool_status {tool_status!r}")

            engine = item.get("engine")
            cli = item.get("cli")
            if status == "partial" and (not engine or not cli):
                errors.append(f"{class_id}: partial coverage requires an engine and CLI path")
            for label, path in (("engine", engine), ("cli", cli)):
                if path is not None and not os.path.isfile(os.path.join(self.repo_root, path)):
                    errors.append(f"{class_id}: {label} path does not exist: {path}")
            if cli is not None and engine is None:
                errors.append(f"{class_id}: a CLI path cannot be set without an engine path")

            tools = item.get("tools")
            if not isinstance(tools, list) or any(not isinstance(name, str) for name in tools):
                errors.append(f"{class_id}: tools must be a list of names")
                continue
            missing_tools = sorted(set(tools) - known_tools)
            if missing_tools and tool_status != "not-registered":
                errors.append(
                    f"{class_id}: unregistered tools must use tool_status 'not-registered': "
                    f"{', '.join(missing_tools)}"
                )
            if not missing_tools and tool_status == "not-registered":
                errors.append(f"{class_id}: tool_status is not-registered but all listed tools exist")

            for field in ("proof", "limits"):
                if not isinstance(item.get(field), str) or not item[field].strip():
                    errors.append(f"{class_id}: {field} must be a non-empty string")
        return errors

    def summary(self, area: Optional[str] = None, status: Optional[str] = None) -> Dict[str, Any]:
        """Return a filtered, machine-readable inventory with coverage totals."""
        items = self.classes
        if area:
            items = [item for item in items if item.get("area", "").lower() == area.lower()]
        if status:
            items = [item for item in items if item.get("status") == status]
        counts = {key: 0 for key in sorted(ALLOWED_STATUSES)}
        for item in items:
            state = item.get("status")
            if state in counts:
                counts[state] += 1
        return {
            "registry_version": self.data.get("version"),
            "target_requests_sent": False,
            "class_count": len(items),
            "status_counts": counts,
            "classes": items,
        }


def load_coverage_registry(repo_root: Optional[str] = None) -> CoverageRegistry:
    return CoverageRegistry(repo_root=repo_root)
