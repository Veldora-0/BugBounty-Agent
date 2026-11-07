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

from framework.auth_correlation.model import CorrelatedPrincipalContext, CorrelatedSessionContext
from framework.auth_correlation.state import AuthCorrelationStateManager

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


def test_cli_corrupted_state_file_fails_closed(tmp_path):
    """Verifies that corrupted state file fails closed with exit code 1."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_file = state_dir / "auth_correlation.json"
    state_file.write_text("{malformed: corrupted json...", encoding="utf-8")
    
    res = subprocess.run(
        [sys.executable, CLI_PATH, "--workspace", str(tmp_path), "--target", "https://example.com/api"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 1
    assert "Corrupted or invalid correlation state file" in res.stderr


def test_cli_production_insufficient_principals_fails_closed(tmp_path):
    """Verifies that active production correlation fails closed when fewer than 2 principals/sessions exist."""
    res = subprocess.run(
        [sys.executable, CLI_PATH, "--workspace", str(tmp_path), "--target", "https://example.com/api"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 1
    assert "requires at least two registered principals and sessions" in res.stderr


def test_cli_production_out_of_scope_target_fails_closed(tmp_path):
    """Verifies that active production correlation with an out-of-scope target fails closed."""
    scope_yaml = """
program:
  name: "test_prog"
targets:
  urls:
    - "https://authorized.example.com/api/"
"""
    (tmp_path / "scope.yaml").write_text(scope_yaml, encoding="utf-8")
    mgr = AuthCorrelationStateManager(program_id="test_prog", workspace_root=str(tmp_path))
    p1 = CorrelatedPrincipalContext(principal_id="user_1", role="MEMBER")
    p2 = CorrelatedPrincipalContext(principal_id="user_2", role="MEMBER")
    mgr.principals[p1.principal_id] = p1
    mgr.principals[p2.principal_id] = p2
    s1 = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="user_1", volatile_headers={"Authorization": "Bearer tok1"})
    s2 = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000002", principal_id="user_2", volatile_headers={"Authorization": "Bearer tok2"})
    mgr.save_state([s1, s2], [], [])

    res = subprocess.run(
        [sys.executable, CLI_PATH, "--workspace", str(tmp_path), "--target", "https://unauthorized-evil.com/api/test"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 1
    assert "is outside configured program scope" in res.stderr


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


def test_cli_sign_dossier(tmp_path):
    """Verifies that --sign-dossier produces a cryptographically signed dossier with action_id and approval_signature."""
    import time
    dossier = {
        "action_type": "LOGOUT",
        "target_endpoint": "https://example.com/api/logout",
        "test_account": "test_user_1",
        "method": "POST",
        "program_id": "test_program",
        "unique_approval_id": "appr_test_001",
        "created_at": time.time(),
        "ttl": 300,
    }
    raw_path = tmp_path / "raw_dossier.json"
    raw_path.write_text(json.dumps(dossier), encoding="utf-8")

    res = subprocess.run(
        [sys.executable, CLI_PATH, "--sign-dossier", str(raw_path)],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    signed_data = json.loads(res.stdout)
    assert "action_id" in signed_data
    assert signed_data["action_id"].startswith("ACT-")
    assert "approval_signature" in signed_data
    assert signed_data["approval_signature"].startswith("SIG-")
    assert signed_data["action_type"] == "LOGOUT"
    assert signed_data["target_endpoint"] == "https://example.com/api/logout"

    out_path = tmp_path / "signed_dossier.json"
    res2 = subprocess.run(
        [sys.executable, CLI_PATH, "--sign-dossier", str(raw_path), "--output", str(out_path)],
        capture_output=True,
        text=True,
    )
    assert res2.returncode == 0
    assert os.path.exists(out_path)
    file_data = json.loads(out_path.read_text(encoding="utf-8"))
    assert file_data["action_id"] == signed_data["action_id"]
    assert file_data["approval_signature"] == signed_data["approval_signature"]

