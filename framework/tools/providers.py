"""
Provider and API Credential Manager for BugBounty-Agent.

Loads credentials strictly from environment variables and local configuration outside Git
(~/.config/bugbounty-agent/secrets.env). Never leaks secrets to logs or output.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


DEFAULT_CONFIG_DIR = os.path.expanduser("~/.config/bugbounty-agent")
DEFAULT_SECRETS_FILE = os.path.join(DEFAULT_CONFIG_DIR, "secrets.env")


# Provider definitions with descriptions and environment variables
KNOWN_PROVIDERS: Dict[str, Dict[str, Any]] = {
    "projectdiscovery-cloud": {
        "name": "ProjectDiscovery Cloud Platform (PDCP)",
        "env_vars": ["PDCP_API_KEY"],
        "used_by": ["chaos", "subfinder", "nuclei", "interactsh", "urlfinder"],
        "docs": "docs/tools/projectdiscovery-cloud.md",
        "official_url": "https://cloud.projectdiscovery.io/",
    },
    "shodan": {
        "name": "Shodan Search Engine",
        "env_vars": ["SHODAN_API_KEY"],
        "used_by": ["uncover", "subfinder"],
        "docs": "docs/tools/shodan.md",
        "official_url": "https://account.shodan.io/",
    },
    "censys": {
        "name": "Censys Search",
        "env_vars": ["CENSYS_API_TOKEN", "CENSYS_ORGANIZATION_ID"],
        "used_by": ["uncover", "subfinder"],
        "docs": "docs/tools/censys.md",
        "official_url": "https://censys.com/",
    },
    "securitytrails": {
        "name": "SecurityTrails DNS Data",
        "env_vars": ["SECURITYTRAILS_API_KEY"],
        "used_by": ["subfinder"],
        "docs": "docs/tools/securitytrails.md",
        "official_url": "https://securitytrails.com/",
    },
    "virustotal": {
        "name": "VirusTotal API",
        "env_vars": ["VT_API_KEY"],
        "used_by": ["subfinder"],
        "docs": "docs/tools/virustotal.md",
        "official_url": "https://www.virustotal.com/",
    },
    "urlscan": {
        "name": "urlscan.io",
        "env_vars": ["URLSCAN_API_KEY"],
        "used_by": ["subfinder"],
        "docs": "docs/tools/urlscan.md",
        "official_url": "https://urlscan.io/",
    },
    "github": {
        "name": "GitHub API",
        "env_vars": ["GITHUB_TOKEN"],
        "used_by": ["subfinder", "gitleaks"],
        "docs": "docs/tools/github.md",
        "official_url": "https://github.com/settings/tokens",
    },
    "wpscan": {
        "name": "WPScan Vulnerability Database",
        "env_vars": ["WPSCAN_API_TOKEN"],
        "used_by": ["wpscan"],
        "docs": "docs/tools/wpscan.md",
        "official_url": "https://wpscan.com/api",
    },
    "interactsh": {
        "name": "Interactsh OOB Server",
        "env_vars": ["INTERACTSH_TOKEN", "PDCP_API_KEY"],
        "used_by": ["interactsh-client"],
        "docs": "docs/tools/interactsh.md",
        "official_url": "https://github.com/projectdiscovery/interactsh",
    },
    "notify": {
        "name": "Notify Webhook Providers",
        "env_vars": ["DISCORD_WEBHOOK_URL", "SLACK_WEBHOOK_URL", "TELEGRAM_API_KEY"],
        "used_by": ["notify"],
        "docs": "docs/tools/notify.md",
        "official_url": "https://github.com/projectdiscovery/notify",
    },
}


class ProviderManager:
    """Manages credentials safely outside Git repositories."""

    def __init__(self, secrets_file: Optional[str] = None):
        self.secrets_file = secrets_file or os.environ.get("BUGBOUNTY_SECRETS") or DEFAULT_SECRETS_FILE
        self._file_credentials: Dict[str, str] = {}
        self.load_secrets_file()

    def load_secrets_file(self) -> None:
        """Parses KEY=VALUE pairs from local secrets.env if it exists."""
        self._file_credentials.clear()
        if not os.path.isfile(self.secrets_file):
            return

        try:
            with open(self.secrets_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, v = line.split("=", 1)
                        # Strip optional quotes
                        clean_val = v.strip().strip("'\"")
                        self._file_credentials[k.strip()] = clean_val
        except Exception:
            pass

    def get_credential(self, env_var_name: str) -> Optional[str]:
        """Looks up a credential from OS environment first, then local secrets.env."""
        # 1. Environment variable takes precedence
        val = os.environ.get(env_var_name)
        if val and val.strip():
            return val.strip()

        # 2. Local secrets.env
        file_val = self._file_credentials.get(env_var_name)
        if file_val and file_val.strip():
            return file_val.strip()

        return None

    def has_credential(self, env_var_name: str) -> bool:
        """Returns True if the credential is set and non-empty."""
        return self.get_credential(env_var_name) is not None

    def check_provider(self, provider_id: str) -> Dict[str, Any]:
        """Checks status of a registered provider without exposing secrets."""
        info = KNOWN_PROVIDERS.get(provider_id, {})
        env_vars = info.get("env_vars", [])
        configured_vars = [v for v in env_vars if self.has_credential(v)]
        missing_vars = [v for v in env_vars if not self.has_credential(v)]

        is_configured = len(configured_vars) > 0

        return {
            "id": provider_id,
            "name": info.get("name", provider_id),
            "configured": is_configured,
            "configured_vars": configured_vars,
            "missing_vars": missing_vars,
            "used_by": info.get("used_by", []),
            "docs": info.get("docs"),
        }

    def check_tool_providers(self, tool_name: str, tool_env_vars: List[str]) -> Dict[str, Any]:
        """Inspects provider status for a specific tool."""
        configured = [v for v in tool_env_vars if self.has_credential(v)]
        missing = [v for v in tool_env_vars if not self.has_credential(v)]

        return {
            "tool": tool_name,
            "has_credentials": len(configured) > 0,
            "configured_vars": configured,
            "missing_vars": missing,
        }

    def get_all_providers_status(self) -> Dict[str, Dict[str, Any]]:
        """Returns status for all known providers."""
        results = {}
        for pid in KNOWN_PROVIDERS:
            results[pid] = self.check_provider(pid)
        return results
