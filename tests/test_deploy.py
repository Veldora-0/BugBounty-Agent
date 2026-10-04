"""
Unit tests for OpenCodeDeployer and Global Bug-Bounty deployment/synchronization.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import pytest

from framework.tools.deployer import OpenCodeDeployer

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def temp_env():
    """Provides temporary target directories for testing global deployment."""
    temp_dir = tempfile.mkdtemp(prefix="bb_test_deploy_")
    config_dir = os.path.join(temp_dir, "config", "opencode")
    bin_dir = os.path.join(temp_dir, "local", "bin")

    yield {"temp_dir": temp_dir, "config_dir": config_dir, "bin_dir": bin_dir}

    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)


def test_deployer_copy_mode(temp_env):
    """Verifies that deployer deploys agent, 17 skills, scripts, and config in copy mode."""
    deployer = OpenCodeDeployer(
        repo_root=REPO_ROOT,
        config_dir=temp_env["config_dir"],
        bin_dir=temp_env["bin_dir"],
    )

    res = deployer.deploy(mode="copy")
    assert res["status"] == "SUCCESS"
    assert res["agent"]["status"] == "ok"
    assert res["agent"]["mode"] == "copied"
    assert res["skills"]["status"] == "ok"
    assert res["skills"]["skills_deployed"] == 17
    assert res["scripts"]["status"] == "ok"
    assert res["scripts"]["scripts_linked"] >= 13

    # Verify agent file exists in destination
    agent_path = os.path.join(temp_env["config_dir"], "agents", "bug-bounty.md")
    assert os.path.isfile(agent_path)
    with open(agent_path, "r", encoding="utf-8") as f:
        content = f.read()
    assert "name: Bug-Bounty" in content
    assert "mode: primary" in content

    # Verify skills in destination
    skills_path = os.path.join(temp_env["config_dir"], "skills")
    skill_dirs = [d for d in os.listdir(skills_path) if os.path.isdir(os.path.join(skills_path, d))]
    assert len(skill_dirs) == 17

    # Verify each skill contains SKILL.md
    for s in skill_dirs:
        skill_md = os.path.join(skills_path, s, "SKILL.md")
        assert os.path.isfile(skill_md), f"Missing SKILL.md for {s}"

    # Verify global config
    cfg_file = os.path.join(temp_env["config_dir"], "opencode.jsonc")
    assert os.path.isfile(cfg_file)
    with open(cfg_file, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    assert cfg["default_agent"] == "Bug-Bounty"
    assert cfg["subagent_depth"] == 1
    assert "agent" not in cfg
    assert "agents" not in cfg

    # Verify scripts in bin dir
    bin_files = os.listdir(temp_env["bin_dir"])
    assert "bb-scope-check" in bin_files
    assert "bb-doctor" in bin_files
    assert "bb-deploy" in bin_files

    # Verify check_status
    st = deployer.check_status()
    assert st["is_valid"] is True
    assert st["agent_deployed"] is True
    assert st["skills_count"] == 17
    assert st["default_agent"] == "Bug-Bounty"


def test_deployer_idempotency(temp_env):
    """Verifies that running deploy multiple times succeeds cleanly without corruption."""
    deployer = OpenCodeDeployer(
        repo_root=REPO_ROOT,
        config_dir=temp_env["config_dir"],
        bin_dir=temp_env["bin_dir"],
    )

    res1 = deployer.deploy(mode="copy")
    assert res1["status"] == "SUCCESS"

    res2 = deployer.deploy(mode="copy")
    assert res2["status"] == "SUCCESS"

    st = deployer.check_status()
    assert st["is_valid"] is True
    assert st["skills_count"] == 17


def test_deployer_uninstall(temp_env):
    """Verifies that uninstall cleans up global agent, skills, and links."""
    deployer = OpenCodeDeployer(
        repo_root=REPO_ROOT,
        config_dir=temp_env["config_dir"],
        bin_dir=temp_env["bin_dir"],
    )

    deployer.deploy(mode="copy")
    assert deployer.check_status()["is_valid"] is True

    un_res = deployer.uninstall()
    assert un_res["agent_removed"] is True
    assert un_res["skills_removed"] == 17
    assert un_res["scripts_removed"] >= 13

    st = deployer.check_status()
    assert st["is_valid"] is False
    assert st["agent_deployed"] is False
    assert st["skills_count"] == 0


def test_duplicate_prevention_check():
    """Verifies that no project-local .opencode/agents/ exists in repository root."""
    deployer = OpenCodeDeployer(repo_root=REPO_ROOT)
    dup = deployer.check_duplicate_prevention()
    assert dup["duplicate_risk"] is False
    assert dup["status"] == "CLEAN"
