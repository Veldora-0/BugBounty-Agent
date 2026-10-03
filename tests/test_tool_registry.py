"""
Tests for Tool Registry parsing, validation, and schema consistency.
"""

import os
import pytest

from framework.tools.registry import ToolDef, ToolRegistry, VALID_TIERS


def test_registry_loading_and_tiers():
    registry = ToolRegistry()
    tools = registry.all_tools()
    assert len(tools) >= 40

    for tool in tools:
        assert tool.name, "Tool must have a canonical name"
        assert tool.category, f"Tool {tool.name} must have a category"
        assert tool.tier in VALID_TIERS, f"Tool {tool.name} has invalid tier {tool.tier}"
        assert tool.binary, f"Tool {tool.name} must specify a binary"
        assert isinstance(tool.capabilities, list), f"Capabilities of {tool.name} must be a list"


def test_core_tools_present():
    registry = ToolRegistry()
    core_names = [
        "subfinder", "dnsx", "httpx", "naabu", "nuclei",
        "katana", "ffuf", "arjun", "amass", "assetfinder"
    ]
    for name in core_names:
        tool = registry.get_tool(name)
        assert tool is not None, f"Expected CORE tool '{name}' in registry"
        assert tool.tier == "CORE", f"Tool '{name}' should be in CORE tier"


def test_registry_validation_clean():
    registry = ToolRegistry()
    errors = registry.validate_registry()
    assert len(errors) == 0, f"Tool registry validation failed with errors: {errors}"


def test_capability_indexing():
    registry = ToolRegistry()
    sub_tools = registry.find_by_capability("passive-subdomain-discovery")
    tool_names = [t.name for t in sub_tools]
    assert "subfinder" in tool_names
    assert "amass" in tool_names

    fuzz_tools = registry.find_by_capability("content-fuzzing")
    fuzz_names = [t.name for t in fuzz_tools]
    assert "ffuf" in fuzz_names
