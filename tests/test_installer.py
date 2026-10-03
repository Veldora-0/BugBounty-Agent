"""
Tests for Safe Tool Installer planning, semver comparison, and mocked execution.
"""

import os
import tempfile
import pytest

from framework.tools.detector import compare_semver, extract_version_from_output, get_system_architecture
from framework.tools.installer import InstallPlan, ToolInstaller
from framework.tools.registry import ToolRegistry


def test_semver_comparisons():
    assert compare_semver("2.6.0", "2.5.0") is True
    assert compare_semver("2.6.0", "2.6.0") is True
    assert compare_semver("1.9.5", "2.0.0") is False
    assert compare_semver("v3.2.1", "3.0.0") is True


def test_version_extraction_regex():
    assert extract_version_from_output("subfinder version 2.6.4") == "2.6.4"
    assert extract_version_from_output("httpx v1.3.8 (ProjectDiscovery)") == "1.3.8"
    assert extract_version_from_output("nuclei engine v3.2.0-dev") == "3.2.0-dev"
    assert extract_version_from_output("ffuf v2.1.0-git") == "2.1.0-git"
    assert extract_version_from_output("unknown binary") is None


def test_architecture_detection():
    os_name, arch = get_system_architecture()
    assert os_name in ("linux", "darwin", "windows")
    assert arch in ("amd64", "arm64", "386")


def test_plan_generation_official_release():
    installer = ToolInstaller()
    plan = installer.plan_install("subfinder")

    assert plan.tool_name == "subfinder"
    assert plan.method in ("official-release", "apt", "go")
    assert "subfinder" in plan.target_path


def test_mocked_install_execution():
    with tempfile.TemporaryDirectory() as tmp_dir:
        prov_file = os.path.join(tmp_dir, "provenance.json")
        bin_dir = os.path.join(tmp_dir, "bin")

        installer = ToolInstaller(provenance_file=prov_file, bin_dir=bin_dir)

        # Dry run must not execute network commands or write binaries
        res = installer.execute_install("katana", dry_run=True)
        assert res["success"] is True
        assert res["dry_run"] is True
        assert res["plan"]["tool"] == "katana"
        assert not os.path.exists(bin_dir) or len(os.listdir(bin_dir)) == 0


def test_provenance_recording():
    with tempfile.TemporaryDirectory() as tmp_dir:
        prov_file = os.path.join(tmp_dir, "provenance.json")
        installer = ToolInstaller(provenance_file=prov_file)

        installer.record_provenance("mock-tool", {
            "version": "1.0.0",
            "method": "official-release",
            "binary_path": "/tmp/mock-tool",
            "status": "VERIFIED",
        })

        assert os.path.isfile(prov_file)
        with open(prov_file, "r", encoding="utf-8") as f:
            content = f.read()
        assert "mock-tool" in content
        assert "1.0.0" in content
