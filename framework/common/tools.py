"""
External Tool Detection and Capability Adapter for BugBounty-Agent.

Detects common security research tools on the host system (e.g. Kali Linux),
reports capabilities, and enables graceful degradation when tools are missing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional


KNOWN_TOOLS: Dict[str, Dict[str, str]] = {
    # Recon / Passive & Active DNS
    "subfinder": {
        "category": "recon",
        "description": "Fast passive subdomain enumeration tool",
        "install_kali": "sudo apt install subfinder || go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    },
    "amass": {
        "category": "recon",
        "description": "In-depth attack surface mapping and asset discovery",
        "install_kali": "sudo apt install amass",
    },
    "assetfinder": {
        "category": "recon",
        "description": "Find domains and subdomains related to a given domain",
        "install_kali": "sudo apt install assetfinder || go install github.com/tomnomnom/assetfinder@latest",
    },
    "chaos": {
        "category": "recon",
        "description": "ProjectDiscovery Chaos API client for asset reconnaissance",
        "install_kali": "go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
    },
    "httpx": {
        "category": "http",
        "description": "Fast and multi-purpose HTTP toolkit for probing endpoints",
        "install_kali": "sudo apt install httpx-toolkit || go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    },
    # Content Discovery
    "ffuf": {
        "category": "content",
        "description": "Fast web fuzzer written in Go",
        "install_kali": "sudo apt install ffuf",
    },
    "dirsearch": {
        "category": "content",
        "description": "Web path scanner",
        "install_kali": "sudo apt install dirsearch",
    },
    "wfuzz": {
        "category": "content",
        "description": "Web application fuzzer",
        "install_kali": "sudo apt install wfuzz",
    },
    # Network / Port Discovery
    "naabu": {
        "category": "portscan",
        "description": "Fast port scanner written in Go with SYN/CONNECT capabilities",
        "install_kali": "sudo apt install naabu || go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    },
    # Vulnerability Signal & Templates
    "nuclei": {
        "category": "signal",
        "description": "Fast and customizable vulnerability scanner based on simple YAML DSL",
        "install_kali": "sudo apt install nuclei || go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    },
    # Subdomain takeover
    "subjack": {
        "category": "takeover",
        "description": "Subdomain takeover assessment tool",
        "install_kali": "go install github.com/haccer/subjack@latest",
    },
}


class ToolDetector:
    """Detects installed security tools on the host system."""

    @staticmethod
    def _get_registry():
        try:
            from framework.tools.registry import ToolRegistry
            return ToolRegistry()
        except Exception:
            return None

    @classmethod
    def check_tool(cls, tool_name: str) -> Dict[str, Any]:
        """Checks if an executable is found on PATH."""
        path = shutil.which(tool_name)
        info = KNOWN_TOOLS.get(tool_name)

        if info is None:
            reg = cls._get_registry()
            if reg and tool_name in reg:
                t = reg.get(tool_name)
                info = {
                    "category": t.category,
                    "description": t.description,
                    "install_hint": t.install.get("preferred", {}).get("command", ""),
                }
            else:
                info = {"category": "custom", "description": "Custom utility"}

        result = {
            "name": tool_name,
            "installed": path is not None,
            "path": path,
            "category": info.get("category", "unknown"),
            "description": info.get("description", ""),
            "install_hint": info.get("install_kali", info.get("install_hint", "")),
        }
        return result

    @classmethod
    def detect_all(cls) -> Dict[str, Dict[str, Any]]:
        """Scans PATH for registered security tools."""
        report = {}
        reg = cls._get_registry()
        tool_names = list(reg.tools.keys()) if reg else list(KNOWN_TOOLS.keys())
        for name in tool_names:
            report[name] = cls.check_tool(name)
        return report

    @classmethod
    def get_summary(cls) -> Dict[str, Any]:
        """Returns high-level overview of available tooling."""
        all_tools = cls.detect_all()
        installed = [name for name, data in all_tools.items() if data["installed"]]
        missing = [name for name, data in all_tools.items() if not data["installed"]]
        return {
            "total_supported": len(all_tools),
            "installed_count": len(installed),
            "installed_tools": installed,
            "missing_tools": missing,
            "details": all_tools,
        }
