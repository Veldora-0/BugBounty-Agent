"""
OpenCode Global Deployment and Synchronization Engine.

Deploys and synchronizes the canonical Bug-Bounty agent and 18 modular skills
from the BugBounty-Agent repository into the user's global OpenCode environment
(~/.config/opencode/ and ~/.local/bin/).
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import stat
import sys
from typing import Any, Dict, List, Optional


class OpenCodeDeployer:
    """Manages the global deployment and synchronization of Bug-Bounty agent and skills."""

    def __init__(
        self,
        repo_root: Optional[str] = None,
        config_dir: Optional[str] = None,
        bin_dir: Optional[str] = None,
    ) -> None:
        if repo_root is None:
            repo_root = os.environ.get(
                "BUGBOUNTY_AGENT_DIR",
                os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..")),
            )
        self.repo_root = os.path.abspath(repo_root)

        if config_dir is None:
            config_dir = os.environ.get(
                "OPENCODE_CONFIG_DIR",
                os.path.expanduser("~/.config/opencode"),
            )
        self.config_dir = os.path.abspath(config_dir)

        if bin_dir is None:
            bin_dir = os.environ.get(
                "BUGBOUNTY_BIN_DIR",
                os.path.expanduser("~/.local/bin"),
            )
        self.bin_dir = os.path.abspath(bin_dir)

        self.agents_src = os.path.join(self.repo_root, "agents")
        self.skills_src = os.path.join(self.repo_root, "skills")
        self.scripts_src = os.path.join(self.repo_root, "scripts")

        self.target_agents = os.path.join(self.config_dir, "agents")
        self.target_skills = os.path.join(self.config_dir, "skills")
        self.target_config_file = os.path.join(self.config_dir, "opencode.jsonc")

    def _link_or_copy(self, src: str, dst: str, prefer_symlink: bool = True) -> str:
        """Creates a symlink or falls back to copying if symlinks fail."""
        # Clean existing dst
        if os.path.islink(dst) or os.path.isfile(dst):
            os.remove(dst)
        elif os.path.isdir(dst):
            shutil.rmtree(dst)

        parent = os.path.dirname(dst)
        os.makedirs(parent, exist_ok=True)

        if prefer_symlink:
            try:
                is_dir = os.path.isdir(src)
                os.symlink(src, dst, target_is_directory=is_dir)
                return "symlinked"
            except (OSError, NotImplementedError):
                pass  # Fall back to copy

        if os.path.isdir(src):
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
        return "copied"

    def deploy_agent(self, prefer_symlink: bool = True) -> Dict[str, Any]:
        """Deploys the canonical Bug-Bounty agent to global OpenCode agents directory."""
        agent_file = os.path.join(self.agents_src, "Bug-Bounty.md")
        if not os.path.isfile(agent_file):
            return {"status": "error", "message": f"Canonical agent not found: {agent_file}"}

        os.makedirs(self.target_agents, exist_ok=True)

        # Remove legacy lowercase deployment if present
        for fname in os.listdir(self.target_agents):
            if fname == "bug-bounty.md":
                legacy_file = os.path.join(self.target_agents, fname)
                try:
                    if os.path.islink(legacy_file) or os.path.isfile(legacy_file):
                        os.remove(legacy_file)
                except OSError:
                    pass

        dst = os.path.join(self.target_agents, "Bug-Bounty.md")
        mode = self._link_or_copy(agent_file, dst, prefer_symlink=prefer_symlink)
        return {"status": "ok", "agent": "Bug-Bounty", "mode": mode, "destination": dst}

    def deploy_skills(self, prefer_symlink: bool = True) -> Dict[str, Any]:
        """Deploys all 18 skills to global OpenCode skills directory."""
        if not os.path.isdir(self.skills_src):
            return {"status": "error", "message": f"Skills source directory not found: {self.skills_src}"}

        os.makedirs(self.target_skills, exist_ok=True)
        results = {}

        for skill_name in sorted(os.listdir(self.skills_src)):
            src_skill = os.path.join(self.skills_src, skill_name)
            if not os.path.isdir(src_skill):
                continue
            dst_skill = os.path.join(self.target_skills, skill_name)
            mode = self._link_or_copy(src_skill, dst_skill, prefer_symlink=prefer_symlink)
            results[skill_name] = mode

        return {"status": "ok", "skills_deployed": len(results), "details": results}

    def deploy_scripts(self, prefer_symlink: bool = True) -> Dict[str, Any]:
        """Links CLI wrapper scripts to user bin directory (~/.local/bin) for global execution."""
        if not os.path.isdir(self.scripts_src):
            return {"status": "error", "message": f"Scripts directory not found: {self.scripts_src}"}

        os.makedirs(self.bin_dir, exist_ok=True)
        results = {}

        for script in sorted(os.listdir(self.scripts_src)):
            if script.endswith(".cmd"):
                continue
            src_script = os.path.join(self.scripts_src, script)
            if not os.path.isfile(src_script):
                continue

            dst_script = os.path.join(self.bin_dir, script)
            mode = self._link_or_copy(src_script, dst_script, prefer_symlink=prefer_symlink)

            # Ensure executable permissions on non-symlink copies
            try:
                st = os.stat(dst_script)
                os.chmod(dst_script, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            except Exception:
                pass

            results[script] = mode

        return {"status": "ok", "scripts_linked": len(results), "details": results}

    def configure_global_opencode(self) -> Dict[str, Any]:
        """Ensures global opencode.jsonc sets Bug-Bounty as default agent and enforces permissions."""
        os.makedirs(self.config_dir, exist_ok=True)

        existing_cfg: Dict[str, Any] = {}
        if os.path.isfile(self.target_config_file):
            try:
                with open(self.target_config_file, "r", encoding="utf-8") as f:
                    lines = [l for l in f if not l.strip().startswith("//")]
                    existing_cfg = json.loads("\n".join(lines))
            except Exception:
                existing_cfg = {}

        # Set Bug-Bounty as global default and subagent depth to 1
        existing_cfg["$schema"] = "https://opencode.ai/config.json"
        existing_cfg["default_agent"] = "Bug-Bounty"
        existing_cfg["subagent_depth"] = 1

        # Remove any inline duplicate agent definitions
        existing_cfg.pop("agent", None)
        existing_cfg.pop("agents", None)

        # Baseline security permissions to ensure safety globally
        baseline_permissions = [
            {
                "action": "shell",
                "resource": "*",
                "effect": "ask",
                "description": "Default baseline: require human confirmation for any unspecified shell command"
            },
            {
                "action": "subagent",
                "resource": "*",
                "effect": "deny",
                "description": "Single-agent architecture: separate subagent spawning is disabled in favor of modular skills"
            },
            {
                "action": "read",
                "resource": "*",
                "effect": "allow",
                "description": "Permit local file reading across workspace and project files"
            },
            {
                "action": "glob",
                "resource": "*",
                "effect": "allow",
                "description": "Permit local filesystem globbing and directory listing"
            },
            {
                "action": "grep",
                "resource": "*",
                "effect": "allow",
                "description": "Permit local code and state searching"
            },
            {
                "action": "edit",
                "resource": "*",
                "effect": "allow",
                "description": "Permit editing project configuration, state, and reports"
            },
            {
                "action": "shell",
                "resource": "*bb-scope-check*",
                "effect": "allow",
                "description": "Permit offline scope verification checks without prompt"
            },
            {
                "action": "shell",
                "resource": "*bb-target-normalize*",
                "effect": "allow",
                "description": "Permit local target normalization utility without prompt"
            },
            {
                "action": "shell",
                "resource": "*bb-init*",
                "effect": "allow",
                "description": "Permit local workspace initialization without prompt"
            },
            {
                "action": "shell",
                "resource": "*bb-doctor*",
                "effect": "allow",
                "description": "Permit local system diagnostics and health checks without prompt"
            },
            {
                "action": "shell",
                "resource": "*bb-evidence*",
                "effect": "allow",
                "description": "Permit local evidence sanitization and storage without prompt"
            },
            {
                "action": "shell",
                "resource": "git push *",
                "effect": "ask",
                "description": "Require explicit confirmation before pushing changes to remote repository"
            },
            {
                "action": "shell",
                "resource": "*submit*report*",
                "effect": "deny",
                "description": "Strictly deny automated vulnerability report submission to external platforms"
            },
            {
                "action": "shell",
                "resource": "curl * | *sh*",
                "effect": "deny",
                "description": "Strictly deny piping unverified remote scripts directly to shell"
            },
            {
                "action": "shell",
                "resource": "wget * | *sh*",
                "effect": "deny",
                "description": "Strictly deny piping unverified remote scripts directly to shell"
            }
        ]

        if "permissions" not in existing_cfg or not isinstance(existing_cfg["permissions"], list):
            existing_cfg["permissions"] = baseline_permissions
        else:
            # Preserve user rules, ensuring subagent deny rule is present
            has_subagent_deny = any(
                p.get("action") == "subagent" and p.get("effect") == "deny"
                for p in existing_cfg["permissions"]
            )
            if not has_subagent_deny:
                existing_cfg["permissions"].insert(1, {
                    "action": "subagent",
                    "resource": "*",
                    "effect": "deny",
                    "description": "Single-agent architecture: separate subagent spawning is disabled in favor of modular skills"
                })

        with open(self.target_config_file, "w", encoding="utf-8") as f:
            json.dump(existing_cfg, f, indent=2)

        return {"status": "ok", "config_file": self.target_config_file, "default_agent": "Bug-Bounty"}

    def check_duplicate_prevention(self) -> Dict[str, Any]:
        """Verifies that no project-local .opencode/agents/ or legacy lowercase agent exists."""
        legacy_agents = os.path.join(self.repo_root, ".opencode", "agents")
        has_local_agents = os.path.isdir(legacy_agents) and any(
            f.endswith(".md") for f in os.listdir(legacy_agents)
        )
        has_lowercase_global = False
        if os.path.isdir(self.target_agents):
            for f in os.listdir(self.target_agents):
                if f == "bug-bounty.md":
                    has_lowercase_global = True
                    break

        duplicate_risk = has_local_agents or has_lowercase_global
        if has_local_agents:
            msg = "Project-local .opencode/agents/ contains agent files which cause duplicate discovery!"
        elif has_lowercase_global:
            msg = "Legacy lowercase ~/.config/opencode/agents/bug-bounty.md detected alongside canonical Bug-Bounty.md!"
        else:
            msg = "Clean: No project-local agents; Bug-Bounty discovered exclusively from global configuration."

        return {
            "duplicate_risk": duplicate_risk,
            "status": "DUPLICATE_DETECTED" if duplicate_risk else "CLEAN",
            "message": msg,
        }

    def deploy(self, mode: str = "auto") -> Dict[str, Any]:
        """
        Executes full deployment:
        1. Deploys agent to ~/.config/opencode/agents/Bug-Bounty.md
        2. Deploys 18 skills to ~/.config/opencode/skills/
        3. Configures default_agent and permissions in ~/.config/opencode/opencode.jsonc
        4. Links CLI utilities to ~/.local/bin/
        5. Verifies duplicate prevention
        """
        prefer_symlink = mode != "copy"

        agent_res = self.deploy_agent(prefer_symlink=prefer_symlink)
        skills_res = self.deploy_skills(prefer_symlink=prefer_symlink)
        scripts_res = self.deploy_scripts(prefer_symlink=prefer_symlink)
        config_res = self.configure_global_opencode()
        dup_check = self.check_duplicate_prevention()

        success = (
            agent_res.get("status") == "ok"
            and skills_res.get("status") == "ok"
            and config_res.get("status") == "ok"
            and not dup_check["duplicate_risk"]
        )

        return {
            "status": "SUCCESS" if success else "WARNING",
            "agent": agent_res,
            "skills": skills_res,
            "scripts": scripts_res,
            "config": config_res,
            "duplicate_prevention": dup_check,
        }

    def uninstall(self) -> Dict[str, Any]:
        """Removes global Bug-Bounty agent, skills, and binary links."""
        agent_dst = os.path.join(self.target_agents, "Bug-Bounty.md")
        legacy_dst = os.path.join(self.target_agents, "bug-bounty.md")
        for target in [agent_dst, legacy_dst]:
            if os.path.islink(target) or os.path.isfile(target):
                try:
                    os.remove(target)
                except OSError:
                    pass

        skills_removed = 0
        if os.path.isdir(self.skills_src) and os.path.isdir(self.target_skills):
            for skill_name in os.listdir(self.skills_src):
                dst = os.path.join(self.target_skills, skill_name)
                if os.path.islink(dst) or os.path.isfile(dst):
                    os.remove(dst)
                    skills_removed += 1
                elif os.path.isdir(dst):
                    shutil.rmtree(dst)
                    skills_removed += 1

        scripts_removed = 0
        if os.path.isdir(self.scripts_src) and os.path.isdir(self.bin_dir):
            for script in os.listdir(self.scripts_src):
                if script.endswith(".cmd"):
                    continue
                dst = os.path.join(self.bin_dir, script)
                if os.path.islink(dst) or os.path.isfile(dst):
                    os.remove(dst)
                    scripts_removed += 1

        return {
            "status": "ok",
            "agent_removed": not os.path.exists(agent_dst),
            "skills_removed": skills_removed,
            "scripts_removed": scripts_removed,
        }

    def check_status(self) -> Dict[str, Any]:
        """Audits current global deployment status."""
        agent_dst = os.path.join(self.target_agents, "Bug-Bounty.md")
        agent_deployed = os.path.exists(agent_dst)
        agent_is_symlink = os.path.islink(agent_dst)

        deployed_skills = []
        if os.path.isdir(self.target_skills):
            deployed_skills = [
                d for d in os.listdir(self.target_skills)
                if os.path.exists(os.path.join(self.target_skills, d, "SKILL.md"))
            ]

        default_agent = None
        if os.path.isfile(self.target_config_file):
            try:
                with open(self.target_config_file, "r", encoding="utf-8") as f:
                    cfg = json.loads("\n".join([l for l in f if not l.strip().startswith("//")]))
                    default_agent = cfg.get("default_agent")
            except Exception:
                pass

        dup = self.check_duplicate_prevention()

        is_valid = (
            agent_deployed
            and len(deployed_skills) >= 18
            and default_agent == "Bug-Bounty"
            and not dup["duplicate_risk"]
        )

        return {
            "is_valid": is_valid,
            "agent_deployed": agent_deployed,
            "agent_symlink": agent_is_symlink,
            "agent_path": agent_dst,
            "skills_count": len(deployed_skills),
            "skills_dir": self.target_skills,
            "default_agent": default_agent,
            "global_config": self.target_config_file,
            "duplicate_prevention": dup,
        }
