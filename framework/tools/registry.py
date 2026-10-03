"""
Tool Registry for BugBounty-Agent.

Loads, validates, and provides structured query interfaces for config/tools.yaml.
Maintains curated tiers: CORE, SPECIALIST, PROVIDER-BACKED, OPTIONAL, LEGACY.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
import yaml


VALID_TIERS = {"CORE", "SPECIALIST", "PROVIDER-BACKED", "OPTIONAL", "LEGACY"}


class ToolDef:
    """Represents a validated tool definition from the registry."""

    def __init__(self, data: Dict[str, Any]):
        self.raw = data
        self.name: str = data.get("name", "").strip()
        self.category: str = data.get("category", "").strip()
        self.binary: str = data.get("binary", self.name).strip()
        self.tier: str = data.get("tier", "OPTIONAL").strip().upper()
        self.description: str = data.get("description", "").strip()
        self.capabilities: List[str] = data.get("capabilities", [])
        self.fallback: Optional[str] = data.get("fallback")
        self.platforms: List[str] = data.get("platforms", ["linux"])
        self.install: Dict[str, Any] = data.get("install", {})
        self.dependencies: List[str] = data.get("dependencies", [])
        self.api_key: Dict[str, Any] = data.get("api_key", {})
        self.official_url: str = data.get("official_url", "")
        self.documentation_url: str = data.get("documentation_url", "")
        self.verify: Dict[str, Any] = data.get("verify", {})
        self.security_notes: str = data.get("security_notes", "")

    def is_auto_installable(self) -> bool:
        """Returns True if the tool is eligible for safe automatic installation."""
        return bool(self.install.get("auto_install", False))

    def requires_api_key(self) -> bool:
        """Returns True if tool strictly requires an API key to operate."""
        return bool(self.api_key.get("required", False))

    def has_optional_providers(self) -> bool:
        """Returns True if tool operates without keys but benefits from optional providers."""
        return bool(self.api_key.get("optional_providers", False))

    def get_env_vars(self) -> List[str]:
        """Returns environment variable names used by this tool."""
        return list(self.api_key.get("env_vars", []))

    def get_docs_path(self) -> Optional[str]:
        """Returns relative path to documentation for this tool."""
        return self.api_key.get("docs_path")

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.raw)

    def __repr__(self) -> str:
        return f"<ToolDef name='{self.name}' tier='{self.tier}' category='{self.category}'>"


class ToolRegistry:
    """Manages the full catalog of supported security tools."""

    def __init__(self, registry_path: Optional[str] = None):
        if registry_path is None:
            # Default to config/tools.yaml relative to repository root
            repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
            self.registry_path = os.path.join(repo_root, "config", "tools.yaml")
        else:
            self.registry_path = os.path.abspath(registry_path)

        self._tools: Dict[str, ToolDef] = {}
        self._capabilities: Dict[str, List[str]] = {}
        self.load()

    def load(self) -> None:
        """Loads and indexes the tools registry file."""
        if not os.path.isfile(self.registry_path):
            raise FileNotFoundError(f"Tool registry file not found: {self.registry_path}")

        with open(self.registry_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        raw_tools = data.get("tools", [])
        self._tools.clear()
        self._capabilities.clear()

        for item in raw_tools:
            tool = ToolDef(item)
            if not tool.name:
                continue
            self._tools[tool.name.lower()] = tool

            for cap in tool.capabilities:
                cap_key = cap.lower().strip()
                if cap_key not in self._capabilities:
                    self._capabilities[cap_key] = []
                self._capabilities[cap_key].append(tool.name)

    def get_tool(self, name: str) -> Optional[ToolDef]:
        """Looks up a tool by canonical name or binary name."""
        if not name:
            return None
        key = name.strip().lower()
        if key in self._tools:
            return self._tools[key]
        for t in self._tools.values():
            if t.binary.lower() == key:
                return t
        return None

    def list_tools(
        self,
        tier: Optional[str] = None,
        category: Optional[str] = None,
    ) -> List[ToolDef]:
        """Returns tools filtered by tier and/or category."""
        results = []
        for t in self._tools.values():
            if tier and t.tier != tier.strip().upper():
                continue
            if category and t.category.lower() != category.strip().lower():
                continue
            results.append(t)
        return results

    def find_by_capability(self, capability: str) -> List[ToolDef]:
        """Returns all tools declaring a specific capability tag."""
        names = self._capabilities.get(capability.strip().lower(), [])
        return [self._tools[name.lower()] for name in names if name.lower() in self._tools]

    def all_capabilities(self) -> List[str]:
        """Returns all registered capability tags sorted."""
        return sorted(list(self._capabilities.keys()))

    def all_tools(self) -> List[ToolDef]:
        """Returns all registered tools."""
        return list(self._tools.values())

    def validate_registry(self) -> List[str]:
        """
        Validates the integrity of the tool registry.
        Checks for valid tiers, existing fallbacks, and required fields.
        Returns a list of error strings (empty if valid).
        """
        errors = []
        for name, tool in self._tools.items():
            if not tool.name:
                errors.append(f"Tool entry missing name: {tool.raw}")
            if tool.tier not in VALID_TIERS:
                errors.append(f"Tool '{name}' has invalid tier '{tool.tier}'. Must be one of {VALID_TIERS}")
            if not tool.category:
                errors.append(f"Tool '{name}' missing category.")
            if not tool.binary:
                errors.append(f"Tool '{name}' missing binary name.")
            if tool.fallback and tool.fallback.lower() not in self._tools:
                errors.append(f"Tool '{name}' specifies unknown fallback tool '{tool.fallback}'.")
            if tool.fallback and tool.fallback.lower() == name.lower():
                errors.append(f"Tool '{name}' specifies itself as fallback.")
            for dep in tool.dependencies:
                if dep.lower() not in self._tools:
                    errors.append(f"Tool '{name}' specifies unknown dependency '{dep}'.")
        return errors
