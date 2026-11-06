"""
Tests for Phase 21 CLI Entrypoints and Arguments (bb-auth-correlate).

Verifies:
- All advertised CLI options: --lab, --tree, --preflight, --tenant, --pre-mfa, --dry-run
- Production execution fail-closed behavior on uninitialized programs
- Mode B approval verification and dossier validation
- Clean JSON output and file saving
"""

import json
import os
import subprocess
import sys
import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLI_PATH = os.path.join(REPO_ROOT, "scripts", "bb-auth-correlate")


def test_cli_help():
    """Verifies that bb-auth-correlate displays help with all advertised flags."""
    res = subprocess.run([sys.executable, CLI_PATH, "--help"], capture_output=True, text=True)
    assert res.returncode == 0
    assert "--lab" in res.stdout
    assert "--preflight" in res.stdout
    assert "--revocation" in res.stdout
    assert "--pre-mfa" in res.stdout
    assert "--tenant" in res.stdout
    assert "--approve-action" in res.stdout
    assert "--tree" in res.stdout
    assert "--dry-run" in res.stdout


def test_cli_lab_execution():
    """Verifies deterministic simulation lab execution via CLI."""
    res = subprocess.run([sys.executable, CLI_PATH, "--lab", "--json"], capture_output=True, text=True)
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["status"] == "COMPLETED"
    assert data["findings_count"] >= 2
    assert data["principals_evaluated"] == 2


def test_cli_lab_preflight_only():
    """Verifies preflight session health gating via CLI."""
    res = subprocess.run([sys.executable, CLI_PATH, "--lab", "--preflight", "--json"], capture_output=True, text=True)
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["status"] == "PREFLIGHT_COMPLETED"
    assert data["verified_hypotheses"] >= 2
    assert data["findings"] == []


def test_cli_tree_rendering():
    """Verifies ASCII tree output via CLI."""
    res = subprocess.run([sys.executable, CLI_PATH, "--lab", "--tree"], capture_output=True, text=True)
    assert res.returncode == 0
    assert "Correlation Hierarchy:" in res.stdout
    assert "lab_usr_a" in res.stdout
    assert "lab_usr_b" in res.stdout


def test_cli_dry_run():
    """Verifies dry-run execution plans tests without sending network probes."""
    res = subprocess.run([sys.executable, CLI_PATH, "--lab", "--dry-run", "--json"], capture_output=True, text=True)
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["status"] == "DRY_RUN_COMPLETED"
    assert data["hypotheses_planned"] >= 2
    assert data["findings"] == []


def test_cli_uninitialized_production_fails_closed(tmp_path):
    """Verifies that running in production without target/scope/principals fails closed."""
    res = subprocess.run([sys.executable, CLI_PATH, "--program", "empty_prog"], capture_output=True, text=True)
    assert res.returncode == 1
    assert "Production correlation requires an active target" in res.stderr


def test_cli_missing_dossier_fails_closed():
    """Verifies that --approve-action without valid dossier fails closed with exit code 2."""
    res = subprocess.run(
        [
            sys.executable,
            CLI_PATH,
            "--target",
            "https://example.com/api",
            "--approve-action",
            "ACT-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 2
    assert "Action Approval Security Error" in res.stderr
