"""
System Health and Diagnostic Engine (Doctor) for BugBounty-Agent.

Inspects system readiness across 9 categories:
SYSTEM, DEPENDENCIES, TOOLS, PROVIDERS, BROWSER, WORDLISTS, CONFIGURATION,
SCOPE ENGINE, OPEN CODE INTEGRATION.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from typing import Any, Dict, List, Optional

from framework.common.config import get_workspace_root
from framework.scope.engine import ScopeEngine, ScopeStatus
from framework.tools.detector import ToolDetector, find_executable, get_system_architecture
from framework.tools.providers import ProviderManager
from framework.tools.registry import ToolRegistry


class SystemDoctor:
    """Performs deep health and capability checks for BugBounty-Agent."""

    def __init__(self, registry: Optional[ToolRegistry] = None, secrets_file: Optional[str] = None):
        self.registry = registry or ToolRegistry()
        self.detector = ToolDetector(self.registry)
        self.provider_mgr = ProviderManager(secrets_file)

    def check_system(self) -> Dict[str, Any]:
        """Category 1: System info."""
        os_name, arch = get_system_architecture()
        return {
            "os": os_name,
            "architecture": arch,
            "platform_details": platform.platform(),
            "python_version": sys.version.split()[0],
            "workspace_root": get_workspace_root(),
        }

    def check_dependencies(self) -> Dict[str, Any]:
        """Category 2: System toolchains and runtimes."""
        deps = ["go", "python3", "pipx", "git", "cargo", "docker", "jq"]
        results = {}
        for d in deps:
            path = shutil.which(d)
            results[d] = {
                "installed": path is not None,
                "path": path,
                "status": "OK" if path else "MISSING",
            }
        return results

    def check_tools(self) -> Dict[str, Any]:
        """Category 3: Security tool suite."""
        tools_info = self.detector.detect_all()
        core_ready = True
        for name, data in tools_info.items():
            if data["tier"] == "CORE" and not data["installed"]:
                core_ready = False

        return {
            "core_ready": core_ready,
            "details": tools_info,
        }

    def check_providers(self) -> Dict[str, Any]:
        """Category 4: API providers and credentials."""
        return self.provider_mgr.get_all_providers_status()

    def check_browser(self) -> Dict[str, Any]:
        """Category 5: Browser automation environment."""
        playwright_installed = find_executable("playwright") is not None
        # Check if playwright python library is installed
        pw_lib = False
        try:
            import playwright
            pw_lib = True
        except ImportError:
            pw_lib = False

        return {
            "playwright_cli": playwright_installed,
            "playwright_python_lib": pw_lib,
            "status": "READY" if (playwright_installed or pw_lib) else "NOT_INSTALLED",
        }

    def check_wordlists(self) -> Dict[str, Any]:
        """Category 6: Wordlist availability."""
        kali_seclists = "/usr/share/seclists"
        user_seclists = os.path.expanduser("~/.local/share/bugbounty-agent/wordlists")

        has_kali = os.path.isdir(kali_seclists)
        has_user = os.path.isdir(user_seclists)

        return {
            "kali_seclists": has_kali,
            "user_local_wordlists": has_user,
            "status": "AVAILABLE" if (has_kali or has_user) else "MISSING_OPTIONAL",
        }

    def check_configuration(self) -> Dict[str, Any]:
        """Category 7: Configuration and secret storage."""
        sec_file = self.provider_mgr.secrets_file
        sec_exists = os.path.isfile(sec_file)
        workspace = get_workspace_root()
        ws_exists = os.path.isdir(workspace)

        return {
            "secrets_file": sec_file,
            "secrets_file_exists": sec_exists,
            "workspace_dir": workspace,
            "workspace_exists": ws_exists,
            "status": "OK" if ws_exists else "INITIALIZED_ON_FIRST_RUN",
        }

    def check_scope_engine(self) -> Dict[str, Any]:
        """Category 8: Scope Engine verification."""
        try:
            test_scope = {
                "program": {"name": "doctor-test"},
                "targets": {"domains": ["example.com"], "recursive_subdomains": {"enabled": True, "max_depth": 0}},
                "out_of_scope": {"domains": ["admin.example.com"]},
            }
            engine = ScopeEngine(test_scope)
            res1 = engine.check("api.example.com")
            res2 = engine.check("admin.example.com")
            res3 = engine.check("attacker.com")

            healthy = (
                res1.status == ScopeStatus.IN_SCOPE
                and res2.status == ScopeStatus.OUT_OF_SCOPE
                and res3.status == ScopeStatus.OUT_OF_SCOPE
            )
            return {"status": "HEALTHY" if healthy else "ERROR", "healthy": healthy}
        except Exception as e:
            return {"status": "ERROR", "healthy": False, "error": str(e)}

    def check_opencode_integration(self) -> Dict[str, Any]:
        """Category 9: OpenCode project configuration."""
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        opencode_jsonc = os.path.join(repo_root, "opencode.jsonc")
        agents_dir = os.path.join(repo_root, ".opencode", "agents")
        skills_dir = os.path.join(repo_root, ".opencode", "skills")

        has_config = os.path.isfile(opencode_jsonc)
        agent_files = [f for f in os.listdir(agents_dir) if f.endswith(".md")] if os.path.isdir(agents_dir) else []
        skill_dirs = [d for d in os.listdir(skills_dir) if os.path.isdir(os.path.join(skills_dir, d))] if os.path.isdir(skills_dir) else []

        default_agent = None
        subagent_depth = None
        permission_count = 0

        if has_config:
            try:
                import json
                with open(opencode_jsonc, "r", encoding="utf-8") as f:
                    lines = [l for l in f if not l.strip().startswith("//")]
                    cfg = json.loads("\n".join(lines))
                    default_agent = cfg.get("default_agent")
                    subagent_depth = cfg.get("subagent_depth")
                    permission_count = len(cfg.get("permissions", []))
            except Exception:
                pass

        has_opencode_bin = shutil.which("opencode") is not None

        return {
            "opencode_jsonc": has_config,
            "agent_count": len(agent_files),
            "skill_count": len(skill_dirs),
            "default_agent": default_agent,
            "subagent_depth": subagent_depth,
            "permission_rules": permission_count,
            "opencode_binary": has_opencode_bin,
            "runtime_status": "INSTALLED" if has_opencode_bin else "PENDING - requires Kali",
            "status": "READY" if (has_config and len(agent_files) >= 14 and len(skill_dirs) >= 14) else "INCOMPLETE",
        }

    def run_full_diagnosis(self) -> Dict[str, Any]:
        """Runs complete diagnostics across all 9 categories."""
        return {
            "system": self.check_system(),
            "dependencies": self.check_dependencies(),
            "tools": self.check_tools(),
            "providers": self.check_providers(),
            "browser": self.check_browser(),
            "wordlists": self.check_wordlists(),
            "configuration": self.check_configuration(),
            "scope_engine": self.check_scope_engine(),
            "opencode_integration": self.check_opencode_integration(),
        }
