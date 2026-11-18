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
    """Verifies that deployer deploys agent, 18 skills, scripts, and config in copy mode."""
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
    assert res["skills"]["skills_deployed"] == 18
    assert res["scripts"]["status"] == "ok"
    assert res["scripts"]["scripts_linked"] >= 13
    assert res["commands"]["status"] == "ok"
    assert res["commands"]["command"] == "Arise"

    # Verify agent file exists in destination with exact canonical name Bug-Bounty.md
    agent_path = os.path.join(temp_env["config_dir"], "agents", "Bug-Bounty.md")
    assert os.path.isfile(agent_path)
    with open(agent_path, "r", encoding="utf-8") as f:
        content = f.read()
    assert "name: Bug-Bounty" in content
    assert "mode: primary" in content

    # Verify skills in destination
    skills_path = os.path.join(temp_env["config_dir"], "skills")
    skill_dirs = [d for d in os.listdir(skills_path) if os.path.isdir(os.path.join(skills_path, d))]
    assert len(skill_dirs) == 18

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
    assert os.path.isfile(os.path.join(temp_env["config_dir"], "commands", "Arise.md"))

    # Verify scripts in bin dir
    bin_files = os.listdir(temp_env["bin_dir"])
    assert "bb-scope-check" in bin_files
    assert "bb-doctor" in bin_files
    assert "bb-deploy" in bin_files

    # Verify check_status
    st = deployer.check_status()
    assert st["is_valid"] is True
    assert st["agent_deployed"] is True
    assert st["skills_count"] == 18
    assert st["arise_command_deployed"] is True
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
    assert st["skills_count"] == 18


def test_deployer_uninstall(temp_env):
    """Verifies that uninstall cleans up global agent, skills, and links."""
    deployer = OpenCodeDeployer(
        repo_root=REPO_ROOT,
        config_dir=temp_env["config_dir"],
        bin_dir=temp_env["bin_dir"],
    )

    custom_commands = os.path.join(temp_env["config_dir"], "commands")
    os.makedirs(custom_commands, exist_ok=True)
    custom_command = os.path.join(custom_commands, "keep.md")
    with open(custom_command, "w", encoding="utf-8") as stream:
        stream.write("# User command\n")

    deployer.deploy(mode="copy")
    assert deployer.check_status()["is_valid"] is True

    un_res = deployer.uninstall()
    assert un_res["status"] == "ok"
    assert un_res["agent_removed"] is True
    assert un_res["skills_removed"] == 18
    assert un_res["scripts_removed"] >= 13
    assert un_res["arise_command_removed"] is True
    assert os.path.isfile(custom_command)
    assert not os.path.exists(os.path.join(temp_env["config_dir"], "opencode.jsonc"))

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


def test_deployer_preserves_old_lowercase_agent(temp_env):
    """A case-sensitive legacy name may belong to the user, so deployment preserves it."""
    target_agents = os.path.join(temp_env["config_dir"], "agents")
    os.makedirs(target_agents, exist_ok=True)
    legacy_file = os.path.join(target_agents, "bug-bounty.md")
    with open(legacy_file, "w", encoding="utf-8") as f:
        f.write("# Legacy lowercase agent\n")

    deployer = OpenCodeDeployer(
        repo_root=REPO_ROOT,
        config_dir=temp_env["config_dir"],
        bin_dir=temp_env["bin_dir"],
    )

    res = deployer.deploy(mode="copy")
    assert res["status"] == "WARNING"
    assert res["duplicate_prevention"]["duplicate_risk"] is True

    canonical_file = os.path.join(target_agents, "Bug-Bounty.md")
    assert os.path.isfile(canonical_file)
    with open(canonical_file, "r", encoding="utf-8") as f:
        content = f.read()
    if os.name == "nt":
        # Windows uses a case-insensitive filesystem: the legacy name collides
        # with Bug-Bounty.md, so preflight must preserve it and refuse deployment.
        assert res["agent"]["status"] == "error"
        assert content == "# Legacy lowercase agent\n"
    else:
        assert "name: Bug-Bounty" in content
    with open(legacy_file, "r", encoding="utf-8") as f:
        assert f.read() == "# Legacy lowercase agent\n"


def test_deployer_does_not_overwrite_user_arise_command(temp_env):
    commands_dir = os.path.join(temp_env["config_dir"], "commands")
    os.makedirs(commands_dir, exist_ok=True)
    custom = os.path.join(commands_dir, "Arise.md")
    with open(custom, "w", encoding="utf-8") as stream:
        stream.write("# Existing personal command\n")

    deployer = OpenCodeDeployer(repo_root=REPO_ROOT,
                                config_dir=temp_env["config_dir"],
                                bin_dir=temp_env["bin_dir"])
    result = deployer.deploy_commands(prefer_symlink=False)
    assert result["status"] == "error"
    assert "Refusing to overwrite" in result["message"]
    with open(custom, "r", encoding="utf-8") as stream:
        assert stream.read() == "# Existing personal command\n"


def test_deploy_preflight_preserves_skill_and_script_collisions(temp_env):
    """An unmanaged skill or binary collision aborts before any deployment changes."""
    deployer = OpenCodeDeployer(
        repo_root=REPO_ROOT,
        config_dir=temp_env["config_dir"],
        bin_dir=temp_env["bin_dir"],
    )
    skill_path = os.path.join(temp_env["config_dir"], "skills", "scope-management")
    os.makedirs(skill_path, exist_ok=True)
    user_skill = os.path.join(skill_path, "notes.txt")
    with open(user_skill, "w", encoding="utf-8") as stream:
        stream.write("user content")
    script_path = os.path.join(temp_env["bin_dir"], "bb-doctor")
    os.makedirs(temp_env["bin_dir"], exist_ok=True)
    with open(script_path, "w", encoding="utf-8") as stream:
        stream.write("user executable")

    result = deployer.deploy(mode="copy")
    assert result["status"] == "WARNING"
    assert len(result["preflight_errors"]) == 2
    assert not os.path.exists(os.path.join(temp_env["config_dir"], "agents", "Bug-Bounty.md"))
    assert not os.path.exists(os.path.join(temp_env["config_dir"], "opencode.jsonc"))
    with open(user_skill, "r", encoding="utf-8") as stream:
        assert stream.read() == "user content"
    with open(script_path, "r", encoding="utf-8") as stream:
        assert stream.read() == "user executable"


def test_invalid_jsonc_config_is_preserved_and_blocks_deploy(temp_env):
    deployer = OpenCodeDeployer(
        repo_root=REPO_ROOT,
        config_dir=temp_env["config_dir"],
        bin_dir=temp_env["bin_dir"],
    )
    os.makedirs(temp_env["config_dir"], exist_ok=True)
    config_path = os.path.join(temp_env["config_dir"], "opencode.jsonc")
    original = b'{\n  "user": true,\n  /* never closed\n'
    with open(config_path, "wb") as stream:
        stream.write(original)

    result = deployer.deploy(mode="copy")
    assert result["status"] == "WARNING"
    assert "Invalid JSONC" in result["preflight_errors"][0]
    assert not os.path.exists(os.path.join(temp_env["config_dir"], "agents", "Bug-Bounty.md"))
    with open(config_path, "rb") as stream:
        assert stream.read() == original


def test_jsonc_user_config_is_preserved_and_restored_on_uninstall(temp_env):
    deployer = OpenCodeDeployer(
        repo_root=REPO_ROOT,
        config_dir=temp_env["config_dir"],
        bin_dir=temp_env["bin_dir"],
    )
    os.makedirs(temp_env["config_dir"], exist_ok=True)
    config_path = os.path.join(temp_env["config_dir"], "opencode.jsonc")
    original = (
        '{\n  // keep this note\n  "user_setting": {"url": "https://example.test/a//b"},\n'
        '  "agents": {"Personal": {"mode": "primary"}},\n'
        '  "permissions": [], // trailing comma is valid JSONC\n}\n'
    ).encode("utf-8")
    with open(config_path, "wb") as stream:
        stream.write(original)

    result = deployer.deploy(mode="copy")
    assert result["status"] == "SUCCESS"
    with open(config_path, "r", encoding="utf-8") as stream:
        configured = json.load(stream)
    assert configured["user_setting"]["url"] == "https://example.test/a//b"
    assert configured["agents"]["Personal"]["mode"] == "primary"
    assert configured["default_agent"] == "Bug-Bounty"
    assert any(rule.get("action") == "subagent" for rule in configured["permissions"])

    result = deployer.uninstall()
    assert result["status"] == "ok"
    with open(config_path, "rb") as stream:
        assert stream.read() == original


def test_uninstall_preserves_modified_deployment_and_user_config(temp_env):
    deployer = OpenCodeDeployer(
        repo_root=REPO_ROOT,
        config_dir=temp_env["config_dir"],
        bin_dir=temp_env["bin_dir"],
    )
    assert deployer.deploy(mode="copy")["status"] == "SUCCESS"
    custom_agent = os.path.join(temp_env["config_dir"], "agents", "Bug-Bounty.md")
    with open(custom_agent, "a", encoding="utf-8") as stream:
        stream.write("\n# User customization\n")
    config_path = os.path.join(temp_env["config_dir"], "opencode.jsonc")
    with open(config_path, "a", encoding="utf-8") as stream:
        stream.write("\n")

    result = deployer.uninstall()
    assert result["status"] == "partial"
    assert any(custom_agent in item for item in result["preserved"])
    assert any(config_path in item for item in result["preserved"])
    assert os.path.isfile(custom_agent)
    assert os.path.isfile(config_path)
    assert not os.path.exists(os.path.join(temp_env["config_dir"], "skills", "authorization"))


def test_deploy_refuses_to_replace_a_changed_config_backup(temp_env):
    deployer = OpenCodeDeployer(
        repo_root=REPO_ROOT,
        config_dir=temp_env["config_dir"],
        bin_dir=temp_env["bin_dir"],
    )
    os.makedirs(temp_env["config_dir"], exist_ok=True)
    config_path = os.path.join(temp_env["config_dir"], "opencode.jsonc")
    with open(config_path, "w", encoding="utf-8") as stream:
        stream.write('{"user_setting": true}\n')
    assert deployer.deploy(mode="copy")["status"] == "SUCCESS"

    backup_path = deployer.config_backup_file
    with open(backup_path, "a", encoding="utf-8") as stream:
        stream.write("user changed backup\n")
    with open(config_path, "rb") as stream:
        deployed_config = stream.read()
    agent_path = os.path.join(temp_env["config_dir"], "agents", "Bug-Bounty.md")
    with open(agent_path, "rb") as stream:
        deployed_agent = stream.read()

    result = deployer.deploy(mode="copy")
    assert result["status"] == "WARNING"
    assert any("original OpenCode config" in error for error in result["preflight_errors"])
    with open(config_path, "rb") as stream:
        assert stream.read() == deployed_config
    with open(agent_path, "rb") as stream:
        assert stream.read() == deployed_agent
    with open(backup_path, "r", encoding="utf-8") as stream:
        assert stream.read().endswith("user changed backup\n")
