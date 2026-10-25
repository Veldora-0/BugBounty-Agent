"""
Tests for Tool Registry parsing, validation, schema consistency, and legacy ToolDetector adapter.
"""

import os
from unittest.mock import MagicMock, patch
import pytest

from framework.common.tools import KNOWN_TOOLS, ToolDetector
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


def test_legacy_detector_public_api_and_known_tools_contract():
    """Verifies public exports and KNOWN_TOOLS dictionary structure in framework.common.tools."""
    from framework.common import ToolDetector as CommonToolDetector, KNOWN_TOOLS as CommonKnownTools
    assert CommonToolDetector is ToolDetector
    assert CommonKnownTools is KNOWN_TOOLS
    assert isinstance(KNOWN_TOOLS, dict)
    assert len(KNOWN_TOOLS) >= 10
    for name, meta in KNOWN_TOOLS.items():
        assert "category" in meta
        assert "description" in meta
        assert "install_kali" in meta

    info = ToolDetector.check_tool("subfinder")
    assert info["name"] == "subfinder"
    assert "installed" in info
    assert "path" in info
    assert "category" in info
    assert "description" in info
    assert "install_hint" in info


def test_legacy_detector_registry_enumeration_and_summary():
    """Verifies detect_all() and get_summary() using ToolRegistry API."""
    all_tools = ToolDetector.detect_all()
    assert isinstance(all_tools, dict)
    assert len(all_tools) >= 40
    assert "subfinder" in all_tools
    assert "httpx" in all_tools

    summary = ToolDetector.get_summary()
    assert isinstance(summary, dict)
    assert "total_supported" in summary
    assert "installed_count" in summary
    assert "installed_tools" in summary
    assert "missing_tools" in summary
    assert "details" in summary
    assert summary["total_supported"] == len(all_tools)
    assert summary["installed_count"] == len(summary["installed_tools"])
    assert len(summary["installed_tools"]) + len(summary["missing_tools"]) == summary["total_supported"]


def test_legacy_detector_missing_registry_fallback():
    """Verifies graceful fallback to KNOWN_TOOLS when ToolRegistry is unavailable."""
    with patch.object(ToolDetector, "_get_registry", return_value=None):
        tools = ToolDetector.detect_all()
        assert set(tools.keys()) == set(KNOWN_TOOLS.keys())

        # Known tool check uses KNOWN_TOOLS
        known_res = ToolDetector.check_tool("subfinder")
        assert known_res["category"] == KNOWN_TOOLS["subfinder"]["category"]
        assert known_res["install_hint"] == KNOWN_TOOLS["subfinder"]["install_kali"]

        # Unknown tool falls back to custom
        unknown_res = ToolDetector.check_tool("nonexistent_utility_xyz")
        assert unknown_res["category"] == "custom"
        assert unknown_res["description"] == "Custom utility"
        assert unknown_res["installed"] is False
        assert unknown_res["path"] is None


def test_legacy_detector_installation_hint_variations():
    """Verifies parsing of apt, go, pipx, preferred string, and dict command hints."""
    mock_reg = MagicMock()

    # Case A: apt_package
    tool_apt = ToolDef({
        "name": "tool_apt",
        "category": "recon",
        "description": "Apt tool",
        "install": {"preferred": "apt", "apt_package": "apt-pkg"},
    })

    # Case B: go_package
    tool_go = ToolDef({
        "name": "tool_go",
        "category": "recon",
        "description": "Go tool",
        "install": {"preferred": "go", "go_package": "github.com/org/repo"},
    })

    # Case C: pip_package
    tool_pip = ToolDef({
        "name": "tool_pip",
        "category": "recon",
        "description": "Pip tool",
        "install": {"preferred": "pipx", "pip_package": "pip-pkg"},
    })

    # Case D: String-valued preferred without package
    tool_pref_str = ToolDef({
        "name": "tool_pref_str",
        "category": "recon",
        "description": "Release tool",
        "install": {"preferred": "official-release"},
    })

    # Case E: Dict-valued command (mock/legacy variation)
    tool_dict_cmd = ToolDef({
        "name": "tool_dict_cmd",
        "category": "recon",
        "description": "Dict command tool",
        "install": {"preferred": {"command": "cargo install dict-cmd"}},
    })

    mock_reg.get_tool.side_effect = lambda n: {
        "tool_apt": tool_apt,
        "tool_go": tool_go,
        "tool_pip": tool_pip,
        "tool_pref_str": tool_pref_str,
        "tool_dict_cmd": tool_dict_cmd,
    }.get(n)

    with patch.object(ToolDetector, "_get_registry", return_value=mock_reg):
        res_apt = ToolDetector.check_tool("tool_apt")
        assert res_apt["install_hint"] == "sudo apt install apt-pkg"

        res_go = ToolDetector.check_tool("tool_go")
        assert res_go["install_hint"] == "go install -v github.com/org/repo"

        res_pip = ToolDetector.check_tool("tool_pip")
        assert res_pip["install_hint"] == "pipx install pip-pkg"

        res_pref = ToolDetector.check_tool("tool_pref_str")
        assert res_pref["install_hint"] == "official-release"

        res_cmd = ToolDetector.check_tool("tool_dict_cmd")
        assert res_cmd["install_hint"] == "cargo install dict-cmd"


def test_legacy_detector_unknown_tool_and_missing_executable():
    """Verifies that unlisted tools and missing executables return safe non-installed records."""
    res = ToolDetector.check_tool("unregistered_phantom_tool_abc_999")
    assert res["name"] == "unregistered_phantom_tool_abc_999"
    assert res["installed"] is False
    assert res["path"] is None
    assert res["category"] == "custom"
    assert res["description"] == "Custom utility"
