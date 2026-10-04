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
        """Category 9: OpenCode project configuration & global deployment."""
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        opencode_jsonc = os.path.join(repo_root, "opencode.jsonc")
        agents_dir = os.path.join(repo_root, "agents")
        skills_dir = os.path.join(repo_root, "skills")
        legacy_agents_dir = os.path.join(repo_root, ".opencode", "agents")

        has_config = os.path.isfile(opencode_jsonc)
        agent_files = [f for f in os.listdir(agents_dir) if f.endswith(".md")] if os.path.isdir(agents_dir) else []
        skill_dirs = [d for d in os.listdir(skills_dir) if os.path.isdir(os.path.join(skills_dir, d))] if os.path.isdir(skills_dir) else []

        has_legacy_agents = os.path.isdir(legacy_agents_dir) and any(f.endswith(".md") for f in os.listdir(legacy_agents_dir))

        default_agent = None
        subagent_depth = None
        permission_count = 0
        has_redundant_jsonc_agents = False

        if has_config:
            try:
                import json
                with open(opencode_jsonc, "r", encoding="utf-8") as f:
                    lines = [l for l in f if not l.strip().startswith("//")]
                    cfg = json.loads("\n".join(lines))
                    default_agent = cfg.get("default_agent")
                    subagent_depth = cfg.get("subagent_depth")
                    permission_count = len(cfg.get("permissions", []))
                    has_redundant_jsonc_agents = "agent" in cfg or "agents" in cfg
            except Exception:
                pass

        has_opencode_bin = shutil.which("opencode") is not None

        # Check global deployment
        global_config_dir = os.environ.get("OPENCODE_CONFIG_DIR", os.path.expanduser("~/.config/opencode"))
        global_agent_file = os.path.join(global_config_dir, "agents", "Bug-Bounty.md")
        global_skills_dir = os.path.join(global_config_dir, "skills")
        global_skills_count = len([d for d in os.listdir(global_skills_dir) if os.path.isdir(os.path.join(global_skills_dir, d))]) if os.path.isdir(global_skills_dir) else 0
        is_globally_deployed = os.path.exists(global_agent_file) and global_skills_count >= 17

        source_ready = (
            has_config
            and len(agent_files) == 1
            and default_agent == "Bug-Bounty"
            and len(skill_dirs) >= 17
            and not has_redundant_jsonc_agents
            and not has_legacy_agents
        )

        return {
            "opencode_jsonc": has_config,
            "agent_count": len(agent_files),
            "skill_count": len(skill_dirs),
            "default_agent": default_agent,
            "subagent_depth": subagent_depth,
            "permission_rules": permission_count,
            "opencode_binary": has_opencode_bin,
            "runtime_status": "INSTALLED" if has_opencode_bin else "PENDING - requires Kali",
            "global_dir": global_config_dir,
            "global_deployed": is_globally_deployed,
            "global_status": "DEPLOYED" if is_globally_deployed else "PENDING - run bb-deploy",
            "duplicate_risk": "DETECTED" if has_legacy_agents else "CLEAN",
            "status": "READY" if source_ready else "INCOMPLETE",
        }

    def check_asset_engine(self) -> Dict[str, Any]:
        """Category 10: Asset Intelligence Engine verification."""
        try:
            from framework.assets.engine import AssetIntelligenceEngine
            from framework.assets.graph import AssetGraph
            from framework.assets.model import Asset, AssetType

            graph = AssetGraph()
            root = Asset.create(AssetType.ROOT_DOMAIN, "example.com")
            child = Asset.create(
                AssetType.SUBDOMAIN,
                "api.example.com",
                root_domain="example.com",
                discovery_depth=1,
            )
            graph.add_asset(root)
            graph.add_asset(child)
            tree = graph.get_subdomain_tree()
            healthy = len(graph.get_all_assets()) == 2 and tree["max_depth"] == 1
            return {"status": "HEALTHY" if healthy else "ERROR", "healthy": healthy}
        except Exception as e:
            return {"status": "ERROR", "healthy": False, "error": str(e)}

    def check_recon_engine(self) -> Dict[str, Any]:
        """Category 11: Reconnaissance Intelligence Engine verification."""
        try:
            from framework.recon.engine import ReconnaissanceEngine
            from framework.recon.model import HttpObservation
            from framework.recon.state import ReconStateManager

            obs = HttpObservation(
                url="https://example.com",
                scheme="https",
                host="example.com",
                port=443,
                status_code=200,
            )
            key_ok = obs.key.startswith("https://example.com")
            engine = ReconnaissanceEngine(passive_only=True)
            healthy = key_ok and engine.passive_only is True
            return {"status": "HEALTHY" if healthy else "ERROR", "healthy": healthy}
        except Exception as e:
            return {"status": "ERROR", "healthy": False, "error": str(e)}

    def check_webapp_engine(self) -> Dict[str, Any]:
        """Category 12: Web Application Intelligence Engine verification."""
        try:
            from framework.webapp.engine import WebApplicationIntelligenceEngine
            from framework.webapp.model import WebApplication, canonicalize_url
            from framework.webapp.parser import parse_page_html
            from framework.webapp.policy import CrawlPolicy

            canon = canonicalize_url("https://example.com:443/test/../app/")
            parsed = parse_page_html("<a href='/login'>Login</a>", "https://example.com/")
            policy = CrawlPolicy()
            engine = WebApplicationIntelligenceEngine(policy=policy)
            healthy = (
                canon == "https://example.com/app"
                and len(parsed["links"]) == 1
                and engine.policy.max_pages > 0
            )
            return {"status": "HEALTHY" if healthy else "ERROR", "healthy": healthy}
        except Exception as e:
            return {"status": "ERROR", "healthy": False, "error": str(e)}

    def check_javascript_engine(self) -> Dict[str, Any]:
        """Category 13: JavaScript Intelligence Engine verification."""
        try:
            from framework.javascript.analyzer import JavaScriptAnalyzer
            from framework.javascript.engine import JavaScriptIntelligenceEngine

            test_js = "fetch('/api/v1/user'); const apiKey = '" + "AKIA" + "IOSFODNN7EXAMPLE';"
            analyzer = JavaScriptAnalyzer(
                source_url="https://example.com/app.js",
                js_content=test_js,
            )
            analysis = analyzer.analyze_all()
            engine = JavaScriptIntelligenceEngine()
            healthy = (
                len(analysis["endpoints"]) == 1
                and len(analysis["interesting_strings"]) >= 1
                and engine.policy.max_files > 0
            )
            return {"status": "HEALTHY" if healthy else "ERROR", "healthy": healthy}
        except Exception as e:
            return {"status": "ERROR", "healthy": False, "error": str(e)}

    def check_api_engine(self) -> Dict[str, Any]:
        """Category 14: API Security & Parameter Intelligence Engine verification."""
        try:
            from framework.api.engine import ApiIntelligenceEngine
            from framework.api.model import ApiEndpoint, ApiParameter
            from framework.api.parser import infer_path_parameters, classify_parameter_role

            tmpl, params = infer_path_parameters("https://example.com/api/v1/users/12345")
            role = classify_parameter_role("user_id")
            engine = ApiIntelligenceEngine()
            healthy = (
                ("{user_id}" in tmpl or "{id}" in tmpl)
                and len(params) == 1
                and role == "user_id"
                and engine.policy.max_endpoints > 0
            )
            return {"status": "HEALTHY" if healthy else "ERROR", "healthy": healthy}
        except Exception as e:
            return {"status": "ERROR", "healthy": False, "error": str(e)}

    def run_full_diagnosis(self) -> Dict[str, Any]:
        """Runs complete diagnostics across all categories."""
        return {
            "system": self.check_system(),
            "dependencies": self.check_dependencies(),
            "tools": self.check_tools(),
            "providers": self.check_providers(),
            "browser": self.check_browser(),
            "wordlists": self.check_wordlists(),
            "configuration": self.check_configuration(),
            "scope_engine": self.check_scope_engine(),
            "asset_engine": self.check_asset_engine(),
            "recon_engine": self.check_recon_engine(),
            "webapp_engine": self.check_webapp_engine(),
            "javascript_engine": self.check_javascript_engine(),
            "api_engine": self.check_api_engine(),
            "opencode_integration": self.check_opencode_integration(),
        }
