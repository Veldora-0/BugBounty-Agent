"""
OpenCode Global Deployment and Synchronization Engine.

Deploys and synchronizes the canonical Bug-Bounty agent, 18 modular skills,
and the /Arise command from the BugBounty-Agent repository into global OpenCode
(~/.config/opencode/ and ~/.local/bin/).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
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
        self.commands_src = os.path.join(self.repo_root, ".opencode", "commands")

        self.target_agents = os.path.join(self.config_dir, "agents")
        self.target_skills = os.path.join(self.config_dir, "skills")
        self.target_commands = os.path.join(self.config_dir, "commands")
        self.target_config_file = os.path.join(self.config_dir, "opencode.jsonc")
        self.manifest_file = os.path.join(self.config_dir, ".bugbounty-agent-deployment.json")
        self.config_backup_file = os.path.join(self.config_dir, ".bugbounty-agent-opencode.jsonc.backup")

    @staticmethod
    def _strip_jsonc(text: str) -> str:
        """Remove JSONC comments and trailing commas without changing string contents."""
        output: List[str] = []
        index = 0
        while index < len(text):
            char = text[index]
            if char == '"':
                start = index
                index += 1
                while index < len(text):
                    if text[index] == "\\":
                        index += 2
                        continue
                    if text[index] == '"':
                        index += 1
                        break
                    index += 1
                output.append(text[start:index])
                continue
            if char == "/" and index + 1 < len(text) and text[index + 1] == "/":
                index += 2
                while index < len(text) and text[index] not in "\r\n":
                    index += 1
                continue
            if char == "/" and index + 1 < len(text) and text[index + 1] == "*":
                end = text.find("*/", index + 2)
                if end < 0:
                    raise ValueError("Unterminated JSONC block comment")
                output.extend("\n" for c in text[index:end + 2] if c in "\r\n")
                index = end + 2
                continue
            if char == ",":
                lookahead = index + 1
                while lookahead < len(text) and text[lookahead].isspace():
                    lookahead += 1
                if lookahead < len(text) and text[lookahead] in "}]":
                    index += 1
                    continue
            output.append(char)
            index += 1
        uncommented = "".join(output)
        # Comments are removed before trailing commas, so a comment may occur between
        # a comma and its closing bracket. This second pass still respects strings.
        normalized: List[str] = []
        index = 0
        while index < len(uncommented):
            if uncommented[index] == '"':
                start = index
                index += 1
                while index < len(uncommented):
                    if uncommented[index] == "\\":
                        index += 2
                        continue
                    if uncommented[index] == '"':
                        index += 1
                        break
                    index += 1
                normalized.append(uncommented[start:index])
                continue
            if uncommented[index] == ",":
                lookahead = index + 1
                while lookahead < len(uncommented) and uncommented[lookahead].isspace():
                    lookahead += 1
                if lookahead < len(uncommented) and uncommented[lookahead] in "}]":
                    index += 1
                    continue
            normalized.append(uncommented[index])
            index += 1
        return "".join(normalized)

    @staticmethod
    def _digest_path(path: str) -> str:
        """Return a stable SHA-256 digest for a regular file or copied directory tree."""
        digest = hashlib.sha256()
        if os.path.islink(path):
            digest.update(b"L\0" + os.readlink(path).encode("utf-8", "surrogateescape"))
            return digest.hexdigest()
        if os.path.isfile(path):
            digest.update(b"F\0")
            with open(path, "rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            return digest.hexdigest()
        if not os.path.isdir(path):
            raise OSError(f"Cannot fingerprint missing deployment path: {path}")

        for root, dirnames, filenames in os.walk(path, topdown=True, followlinks=False):
            dirnames.sort()
            filenames.sort()
            for name in list(dirnames):
                full_path = os.path.join(root, name)
                relative = os.path.relpath(full_path, path).replace(os.sep, "/")
                if os.path.islink(full_path):
                    digest.update(b"L\0" + relative.encode("utf-8", "surrogateescape") + b"\0")
                    digest.update(os.readlink(full_path).encode("utf-8", "surrogateescape"))
                    dirnames.remove(name)
                else:
                    digest.update(b"D\0" + relative.encode("utf-8", "surrogateescape") + b"\0")
            for name in filenames:
                full_path = os.path.join(root, name)
                relative = os.path.relpath(full_path, path).replace(os.sep, "/")
                if os.path.islink(full_path):
                    digest.update(b"L\0" + relative.encode("utf-8", "surrogateescape") + b"\0")
                    digest.update(os.readlink(full_path).encode("utf-8", "surrogateescape"))
                else:
                    digest.update(b"F\0" + relative.encode("utf-8", "surrogateescape") + b"\0")
                    with open(full_path, "rb") as stream:
                        for block in iter(lambda: stream.read(1024 * 1024), b""):
                            digest.update(block)
        return digest.hexdigest()

    @staticmethod
    def _sha256_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _sha256_file(path: str) -> str:
        with open(path, "rb") as stream:
            return hashlib.sha256(stream.read()).hexdigest()

    def _load_manifest(self) -> Dict[str, Any]:
        """Load deployment ownership metadata; refuse malformed metadata rather than guessing."""
        if not os.path.lexists(self.manifest_file):
            return {"schema_version": 1, "entries": {}, "config": None}
        if os.path.islink(self.manifest_file) or not os.path.isfile(self.manifest_file):
            raise ValueError(f"Deployment manifest is not a regular file: {self.manifest_file}")
        with open(self.manifest_file, "r", encoding="utf-8") as stream:
            manifest = json.load(stream)
        if (not isinstance(manifest, dict) or manifest.get("schema_version") != 1
                or not isinstance(manifest.get("entries"), dict)
                or (manifest.get("config") is not None and not isinstance(manifest.get("config"), dict))):
            raise ValueError("Unsupported or malformed BugBounty-Agent deployment manifest")
        for destination, entry in manifest["entries"].items():
            if (not isinstance(destination, str) or not os.path.isabs(destination)
                    or not isinstance(entry, dict)
                    or entry.get("mode") not in {"symlink", "copy"}
                    or entry.get("kind") not in {"file", "directory"}
                    or not isinstance(entry.get("source"), str)
                    or not isinstance(entry.get("sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])):
                raise ValueError("Malformed entry in BugBounty-Agent deployment manifest")
        config_entry = manifest.get("config")
        if config_entry is not None:
            valid_hash = lambda value: isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
            if (not isinstance(config_entry.get("original_exists"), bool)
                    or not valid_hash(config_entry.get("deployed_sha256"))
                    or (config_entry["original_exists"] and not valid_hash(config_entry.get("original_sha256")))
                    or (not config_entry["original_exists"] and config_entry.get("original_sha256") is not None)
                    or (config_entry.get("original_mode") is not None
                        and (not isinstance(config_entry.get("original_mode"), int)
                             or not 0 <= config_entry["original_mode"] <= 0o777))):
                raise ValueError("Malformed OpenCode config ownership metadata")
        return manifest

    def _save_manifest(self, manifest: Dict[str, Any]) -> None:
        os.makedirs(self.config_dir, mode=0o700, exist_ok=True)
        if os.path.lexists(self.manifest_file) and (os.path.islink(self.manifest_file) or not os.path.isfile(self.manifest_file)):
            raise ValueError(f"Deployment manifest path is not a regular file: {self.manifest_file}")
        fd, temporary = tempfile.mkstemp(prefix=".bb-deploy-manifest-", dir=self.config_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(manifest, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.manifest_file)
        finally:
            if os.path.exists(temporary):
                os.remove(temporary)

    def _expected_assets(self) -> Dict[str, str]:
        """Map destinations to repository sources used by deploy and safe uninstall."""
        assets: Dict[str, str] = {}
        agent = os.path.join(self.agents_src, "Bug-Bounty.md")
        if os.path.isfile(agent):
            assets[os.path.join(self.target_agents, "Bug-Bounty.md")] = agent
        if os.path.isdir(self.skills_src):
            for name in sorted(os.listdir(self.skills_src)):
                source = os.path.join(self.skills_src, name)
                if os.path.isdir(source):
                    assets[os.path.join(self.target_skills, name)] = source
        if os.path.isdir(self.scripts_src):
            for name in sorted(os.listdir(self.scripts_src)):
                source = os.path.join(self.scripts_src, name)
                if not name.endswith(".cmd") and os.path.isfile(source):
                    assets[os.path.join(self.bin_dir, name)] = source
        command = os.path.join(self.commands_src, "Arise.md")
        if os.path.isfile(command):
            assets[os.path.join(self.target_commands, "Arise.md")] = command
        return assets

    @staticmethod
    def _remove_path(path: str) -> None:
        if os.path.islink(path) or os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)

    def _entry_matches(self, destination: str, source: str, entry: Optional[Dict[str, Any]]) -> bool:
        """Check that a destination is still exactly the asset this deployer installed."""
        if not os.path.lexists(destination):
            return False
        if os.path.islink(destination):
            target = os.path.abspath(os.path.join(os.path.dirname(destination), os.readlink(destination)))
            return (entry is not None and entry.get("mode") == "symlink"
                    and entry.get("source") == source
                    and os.path.normcase(target) == os.path.normcase(os.path.abspath(source)))
        if entry is None or entry.get("mode") != "copy" or entry.get("source") != source:
            return False
        try:
            expected_kind = "directory" if os.path.isdir(source) else "file"
            actual_kind = "directory" if os.path.isdir(destination) else "file"
            return (entry.get("kind") == expected_kind == actual_kind
                    and self._digest_path(destination) == entry.get("sha256"))
        except OSError:
            return False

    def _install_asset(self, src: str, dst: str, prefer_symlink: bool = True,
                       executable: bool = False) -> str:
        """Install one asset atomically, replacing only a verified prior deployment."""
        manifest = self._load_manifest()
        old_entry = manifest["entries"].get(dst)
        if os.path.lexists(dst) and not self._entry_matches(dst, src, old_entry):
            raise FileExistsError(f"Refusing to overwrite an unmanaged or modified file: {dst}")

        if os.path.islink(dst) and self._entry_matches(dst, src, old_entry) and prefer_symlink:
            manifest["entries"][dst] = {
                "source": src, "kind": "directory" if os.path.isdir(src) else "file",
                "mode": "symlink", "sha256": self._digest_path(src),
            }
            self._save_manifest(manifest)
            return "symlinked"

        parent = os.path.dirname(dst)
        os.makedirs(parent, exist_ok=True)
        temporary_dir = tempfile.mkdtemp(prefix=".bb-deploy-", dir=parent)
        staged = os.path.join(temporary_dir, "payload")
        backup = os.path.join(temporary_dir, "previous")
        moved_old = False
        installed = False
        try:
            mode = "copied"
            if prefer_symlink:
                try:
                    os.symlink(src, staged, target_is_directory=os.path.isdir(src))
                    mode = "symlink"
                except (OSError, NotImplementedError):
                    pass
            if mode == "copied":
                if os.path.isdir(src):
                    shutil.copytree(src, staged, symlinks=True)
                else:
                    shutil.copy2(src, staged, follow_symlinks=False)
                    if executable:
                        os.chmod(staged, os.stat(staged).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

            if os.path.lexists(dst):
                os.replace(dst, backup)
                moved_old = True
            os.replace(staged, dst)
            installed = True

            manifest["entries"][dst] = {
                "source": src,
                "kind": "directory" if os.path.isdir(src) else "file",
                "mode": "copy" if mode == "copied" else "symlink",
                "sha256": self._digest_path(dst) if mode == "copied" else self._digest_path(src),
            }
            try:
                self._save_manifest(manifest)
            except Exception:
                self._remove_path(dst)
                installed = False
                if moved_old:
                    os.replace(backup, dst)
                    moved_old = False
                raise

            if moved_old:
                self._remove_path(backup)
                moved_old = False
            return "symlinked" if mode == "symlink" else "copied"
        except Exception:
            if installed and os.path.lexists(dst):
                self._remove_path(dst)
            if moved_old and os.path.lexists(backup):
                os.replace(backup, dst)
            raise
        finally:
            if os.path.isdir(temporary_dir):
                shutil.rmtree(temporary_dir, ignore_errors=True)

    def _preflight(self) -> List[str]:
        """Find collisions before deploy mutates any managed destination."""
        errors: List[str] = []
        try:
            manifest = self._load_manifest()
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return [str(exc)]
        for destination, source in self._expected_assets().items():
            entry = manifest["entries"].get(destination)
            if os.path.lexists(destination) and not self._entry_matches(destination, source, entry):
                errors.append(f"Refusing to overwrite unmanaged or modified file: {destination}")
        try:
            config, original_bytes = self._read_global_config()
            permissions = config.get("permissions")
            if permissions is not None and (
                not isinstance(permissions, list) or any(not isinstance(rule, dict) for rule in permissions)
            ):
                errors.append("OpenCode config 'permissions' must be an array of objects; refusing partial deployment.")
            config_meta = manifest.get("config")
            backup_exists = os.path.lexists(self.config_backup_file)
            if config_meta is None and backup_exists:
                errors.append("Config backup path exists without deployment ownership; refusing to replace it.")
            elif config_meta and config_meta.get("original_exists"):
                if (os.path.islink(self.config_backup_file) or not os.path.isfile(self.config_backup_file)
                        or self._sha256_file(self.config_backup_file) != config_meta.get("original_sha256")):
                    errors.append("The saved original OpenCode config is missing or changed; refusing to deploy over it.")
            elif config_meta and backup_exists:
                errors.append("An unexpected config backup exists for a deployment with no original config; preserving it.")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"Global OpenCode config cannot be safely updated: {exc}")
        return errors

    def deploy_agent(self, prefer_symlink: bool = True) -> Dict[str, Any]:
        """Deploys the canonical Bug-Bounty agent to global OpenCode agents directory."""
        agent_file = os.path.join(self.agents_src, "Bug-Bounty.md")
        if not os.path.isfile(agent_file):
            return {"status": "error", "message": f"Canonical agent not found: {agent_file}"}

        dst = os.path.join(self.target_agents, "Bug-Bounty.md")
        try:
            mode = self._install_asset(agent_file, dst, prefer_symlink=prefer_symlink)
            return {"status": "ok", "agent": "Bug-Bounty", "mode": mode, "destination": dst}
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return {"status": "error", "message": str(exc), "destination": dst}

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
            try:
                results[skill_name] = self._install_asset(src_skill, dst_skill, prefer_symlink=prefer_symlink)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                return {"status": "error", "message": str(exc), "details": results}

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
            try:
                results[script] = self._install_asset(
                    src_script, dst_script, prefer_symlink=prefer_symlink, executable=True
                )
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                return {"status": "error", "message": str(exc), "details": results}

        return {"status": "ok", "scripts_linked": len(results), "details": results}

    def deploy_commands(self, prefer_symlink: bool = True) -> Dict[str, Any]:
        """Deploys the repository-owned /Arise prompt globally without replacing other commands."""
        command_file = os.path.join(self.commands_src, "Arise.md")
        if not os.path.isfile(command_file):
            return {"status": "error", "message": f"/Arise command not found: {command_file}"}
        dst = os.path.join(self.target_commands, "Arise.md")
        try:
            mode = self._install_asset(command_file, dst, prefer_symlink=prefer_symlink)
            return {"status": "ok", "command": "Arise", "mode": mode, "destination": dst}
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return {"status": "error", "message": str(exc), "destination": dst}

    def _owns_arise_command(self, path: str) -> bool:
        """Returns true only for a symlink to, or unchanged copy of, this repository command."""
        source = os.path.join(self.commands_src, "Arise.md")
        if os.path.islink(path):
            return os.path.realpath(path) == os.path.realpath(source)
        if not os.path.isfile(path) or not os.path.isfile(source):
            return False
        try:
            with open(path, "rb") as deployed, open(source, "rb") as canonical:
                return deployed.read() == canonical.read()
        except OSError:
            return False

    def _read_global_config(self) -> tuple[Dict[str, Any], Optional[bytes]]:
        """Read valid JSONC config, returning its parsed value and exact original bytes."""
        if not os.path.lexists(self.target_config_file):
            return {}, None
        if os.path.islink(self.target_config_file) or not os.path.isfile(self.target_config_file):
            raise ValueError(f"OpenCode config must be a regular file: {self.target_config_file}")
        with open(self.target_config_file, "rb") as stream:
            raw = stream.read()
        try:
            parsed = json.loads(self._strip_jsonc(raw.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"Invalid JSONC in {self.target_config_file}: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValueError("OpenCode config root must be a JSON object")
        return parsed, raw

    @staticmethod
    def _atomic_write(path: str, content: bytes, mode: int = 0o600) -> None:
        parent = os.path.dirname(path)
        os.makedirs(parent, mode=0o700, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".bb-deploy-write-", dir=parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.remove(temporary)

    def configure_global_opencode(self) -> Dict[str, Any]:
        """Ensures global opencode.jsonc sets Bug-Bounty as default agent and enforces permissions."""
        os.makedirs(self.config_dir, exist_ok=True)

        try:
            manifest = self._load_manifest()
            existing_cfg, original_bytes = self._read_global_config()
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return {"status": "error", "message": str(exc), "config_file": self.target_config_file}

        # Set Bug-Bounty as global default and subagent depth to 1
        existing_cfg["$schema"] = "https://opencode.ai/config.json"
        existing_cfg["default_agent"] = "Bug-Bounty"
        existing_cfg["subagent_depth"] = 1

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

        if "permissions" not in existing_cfg:
            existing_cfg["permissions"] = baseline_permissions
        elif not isinstance(existing_cfg["permissions"], list):
            return {"status": "error", "message": "OpenCode config 'permissions' must be an array; preserving the existing config."}
        else:
            if any(not isinstance(rule, dict) for rule in existing_cfg["permissions"]):
                return {"status": "error", "message": "OpenCode config contains a non-object permission rule; preserving the existing config."}
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

        output = (json.dumps(existing_cfg, indent=2) + "\n").encode("utf-8")
        previous_config_meta = manifest.get("config")
        previous_backup = None
        if os.path.lexists(self.config_backup_file):
            if os.path.islink(self.config_backup_file) or not os.path.isfile(self.config_backup_file):
                return {"status": "error", "message": "Config backup path is not a regular file; preserving it."}
            with open(self.config_backup_file, "rb") as stream:
                previous_backup = stream.read()
        if previous_config_meta is None and previous_backup is not None:
            return {"status": "error", "message": "Config backup path already exists without deployment ownership; preserving it."}
        if previous_config_meta and previous_config_meta.get("original_exists"):
            if (previous_backup is None
                    or self._sha256_bytes(previous_backup) != previous_config_meta.get("original_sha256")):
                return {"status": "error", "message": "Original config backup is missing or changed; preserving current config."}
        elif previous_config_meta and previous_backup is not None:
            return {"status": "error", "message": "Unexpected config backup exists without an original config; preserving it."}

        output_meta: Dict[str, Any]
        current_hash = self._sha256_bytes(original_bytes) if original_bytes is not None else None
        if (previous_config_meta and current_hash == previous_config_meta.get("deployed_sha256")):
            output_meta = dict(previous_config_meta)
        else:
            output_meta = {
                "original_exists": original_bytes is not None,
                "original_sha256": current_hash,
                "original_mode": stat.S_IMODE(os.stat(self.target_config_file).st_mode) if original_bytes is not None else None,
            }
            if original_bytes is not None:
                try:
                    self._atomic_write(self.config_backup_file, original_bytes, 0o600)
                except OSError as exc:
                    return {"status": "error", "message": f"Could not back up existing config: {exc}"}
            elif os.path.lexists(self.config_backup_file):
                os.remove(self.config_backup_file)

        original_mode = 0o600
        if original_bytes is not None:
            original_mode = stat.S_IMODE(os.stat(self.target_config_file).st_mode)
        try:
            self._atomic_write(self.target_config_file, output, original_mode)
            output_meta["deployed_sha256"] = hashlib.sha256(output).hexdigest()
            manifest["config"] = output_meta
            self._save_manifest(manifest)
        except Exception as exc:
            try:
                if original_bytes is None:
                    if os.path.lexists(self.target_config_file):
                        os.remove(self.target_config_file)
                else:
                    self._atomic_write(self.target_config_file, original_bytes, original_mode)
                if previous_backup is None:
                    if os.path.lexists(self.config_backup_file):
                        os.remove(self.config_backup_file)
                else:
                    self._atomic_write(self.config_backup_file, previous_backup, 0o600)
            except OSError:
                pass
            return {"status": "error", "message": f"Could not atomically configure OpenCode: {exc}"}

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
        5. Deploys the /Arise global slash command
        6. Verifies duplicate prevention
        """
        prefer_symlink = mode != "copy"

        preflight_errors = self._preflight()
        if preflight_errors:
            message = "; ".join(preflight_errors)
            failed = {"status": "error", "message": message}
            return {
                "status": "WARNING", "preflight_errors": preflight_errors,
                "agent": failed, "skills": failed, "scripts": failed,
                "commands": failed, "config": failed,
                "duplicate_prevention": self.check_duplicate_prevention(),
            }

        agent_res = self.deploy_agent(prefer_symlink=prefer_symlink)
        skills_res = self.deploy_skills(prefer_symlink=prefer_symlink)
        scripts_res = self.deploy_scripts(prefer_symlink=prefer_symlink)
        commands_res = self.deploy_commands(prefer_symlink=prefer_symlink)
        config_res = self.configure_global_opencode()
        dup_check = self.check_duplicate_prevention()

        success = (
            agent_res.get("status") == "ok"
            and skills_res.get("status") == "ok"
            and scripts_res.get("status") == "ok"
            and commands_res.get("status") == "ok"
            and config_res.get("status") == "ok"
            and not dup_check["duplicate_risk"]
        )

        return {
            "status": "SUCCESS" if success else "WARNING",
            "agent": agent_res,
            "skills": skills_res,
            "scripts": scripts_res,
            "commands": commands_res,
            "config": config_res,
            "duplicate_prevention": dup_check,
        }

    def uninstall(self) -> Dict[str, Any]:
        """Remove only unchanged assets recorded as this repository's deployment."""
        try:
            manifest = self._load_manifest()
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return {"status": "error", "message": str(exc), "removed": [], "preserved": []}

        removed: List[str] = []
        preserved: List[str] = []
        assets = self._expected_assets()
        for destination, source in assets.items():
            entry = manifest["entries"].get(destination)
            if not os.path.lexists(destination):
                manifest["entries"].pop(destination, None)
                continue
            if self._entry_matches(destination, source, entry):
                try:
                    self._remove_path(destination)
                    manifest["entries"].pop(destination, None)
                    removed.append(destination)
                except OSError as exc:
                    preserved.append(f"{destination}: {exc}")
            else:
                preserved.append(f"{destination}: modified or not recorded as managed")

        config_meta = manifest.get("config")
        config_restored = False
        if config_meta and os.path.lexists(self.target_config_file):
            try:
                current_hash = self._sha256_file(self.target_config_file)
                if current_hash == config_meta.get("deployed_sha256"):
                    if config_meta.get("original_exists"):
                        if (os.path.islink(self.config_backup_file) or not os.path.isfile(self.config_backup_file)
                                or self._sha256_file(self.config_backup_file) != config_meta.get("original_sha256")):
                            preserved.append(f"{self.target_config_file}: original config backup missing or changed")
                        else:
                            with open(self.config_backup_file, "rb") as stream:
                                original = stream.read()
                            self._atomic_write(self.target_config_file, original, config_meta.get("original_mode") or 0o600)
                            config_restored = True
                    else:
                        if os.path.lexists(self.config_backup_file):
                            preserved.append(f"{self.config_backup_file}: unexpected backup exists; preserving config")
                        else:
                            os.remove(self.target_config_file)
                            config_restored = True
                    if config_restored:
                        manifest["config"] = None
                        if os.path.lexists(self.config_backup_file):
                            try:
                                os.remove(self.config_backup_file)
                            except OSError as exc:
                                preserved.append(f"{self.config_backup_file}: {exc}")
                else:
                    preserved.append(f"{self.target_config_file}: changed by the user since deployment")
            except OSError as exc:
                preserved.append(f"{self.target_config_file}: {exc}")
        elif config_meta and not os.path.lexists(self.target_config_file):
            # The user removed the config. Do not recreate it during uninstall.
            if os.path.lexists(self.config_backup_file):
                if (config_meta.get("original_exists")
                        and not os.path.islink(self.config_backup_file)
                        and os.path.isfile(self.config_backup_file)
                        and self._sha256_file(self.config_backup_file) == config_meta.get("original_sha256")):
                    try:
                        os.remove(self.config_backup_file)
                        manifest["config"] = None
                    except OSError as exc:
                        preserved.append(f"{self.config_backup_file}: {exc}")
                else:
                    preserved.append(f"{self.config_backup_file}: changed or unexpected backup; preserving it")
            else:
                manifest["config"] = None

        try:
            has_entries = bool(manifest["entries"])
            if has_entries or manifest.get("config") is not None:
                self._save_manifest(manifest)
            elif os.path.lexists(self.manifest_file):
                os.remove(self.manifest_file)
        except OSError as exc:
            preserved.append(f"Deployment manifest: {exc}")

        agent_dst = os.path.join(self.target_agents, "Bug-Bounty.md")
        command_dst = os.path.join(self.target_commands, "Arise.md")
        skills_removed = sum(1 for path in removed if os.path.dirname(path) == self.target_skills)
        scripts_removed = sum(1 for path in removed if os.path.dirname(path) == self.bin_dir)
        return {
            "status": "ok" if not preserved else "partial",
            "agent_removed": not os.path.lexists(agent_dst),
            "skills_removed": skills_removed,
            "scripts_removed": scripts_removed,
            "arise_command_removed": not os.path.lexists(command_dst),
            "config_restored": config_restored,
            "removed": removed,
            "preserved": preserved,
        }

    def check_status(self) -> Dict[str, Any]:
        """Audits current global deployment status."""
        agent_src = os.path.join(self.agents_src, "Bug-Bounty.md")
        agent_dst = os.path.join(self.target_agents, "Bug-Bounty.md")
        agent_deployed = False
        if os.path.isfile(agent_src) and os.path.isfile(agent_dst):
            try:
                with open(agent_src, "rb") as source, open(agent_dst, "rb") as deployed:
                    agent_deployed = source.read() == deployed.read()
            except OSError:
                agent_deployed = False
        elif os.path.islink(agent_dst):
            agent_deployed = os.path.normcase(os.path.abspath(os.path.join(os.path.dirname(agent_dst), os.readlink(agent_dst)))) == os.path.normcase(os.path.abspath(agent_src))
        agent_is_symlink = os.path.islink(agent_dst)
        arise_command_dst = os.path.join(self.target_commands, "Arise.md")
        arise_command_deployed = self._owns_arise_command(arise_command_dst)

        required_skills = [
            d for d in os.listdir(self.skills_src) if os.path.isdir(os.path.join(self.skills_src, d))
        ] if os.path.isdir(self.skills_src) else []
        deployed_skills = [
            d for d in required_skills
            if os.path.isfile(os.path.join(self.target_skills, d, "SKILL.md"))
        ]

        default_agent = None
        if os.path.isfile(self.target_config_file):
            try:
                with open(self.target_config_file, "r", encoding="utf-8") as f:
                    cfg = json.loads(self._strip_jsonc(f.read()))
                    default_agent = cfg.get("default_agent")
            except Exception:
                pass

        dup = self.check_duplicate_prevention()

        is_valid = (
            agent_deployed
            and len(deployed_skills) == len(required_skills)
            and default_agent == "Bug-Bounty"
            and arise_command_deployed
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
            "arise_command_deployed": arise_command_deployed,
            "arise_command_path": arise_command_dst,
            "global_config": self.target_config_file,
            "duplicate_prevention": dup,
        }
