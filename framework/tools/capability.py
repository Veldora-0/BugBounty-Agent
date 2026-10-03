"""
Capability Graph and Fallback Resolver for BugBounty-Agent.

Enables workflow agents to query tools by capability rather than hardcoding names,
and resolves fallback tools gracefully when preferred tools are absent.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from framework.tools.registry import ToolDef, ToolRegistry


# 23 Canonical Capability Groups matching README & architecture
CAPABILITY_GROUPS = [
    "asset-discovery",
    "dns",
    "http-probing",
    "port-service-discovery",
    "url-discovery",
    "web-crawling",
    "content-discovery",
    "parameter-discovery",
    "javascript-analysis",
    "api-analysis",
    "xss-analysis",
    "injection-analysis",
    "authorization-analysis",
    "business-logic-analysis",
    "oob-testing",
    "vulnerability-scanning",
    "cloud-intelligence",
    "cms-security",
    "tls-network",
    "proxy-traffic",
    "secret-auditing",
    "pipeline-utility",
    "notifications",
]


class CapabilityGraph:
    """Manages mapping between security research capabilities and available tooling."""

    def __init__(self, registry: Optional[ToolRegistry] = None):
        self.registry = registry or ToolRegistry()

    def get_tools_for_capability(self, capability: str) -> List[ToolDef]:
        """Returns all tools capable of fulfilling the given capability, sorted by tier priority."""
        clean_cap = capability.strip().lower()
        # Aliases mapping
        alias_map = {
            "web-crawling": "crawling",
            "crawl": "crawling",
            "xss": "xss-analysis",
            "sqli": "sqli-analysis",
            "fuzzing": "content-fuzzing",
            "subdomains": "passive-subdomain-discovery",
            "subdomain": "passive-subdomain-discovery",
            "ports": "port-scanning",
            "oob": "oob-interaction",
            "secrets": "secret-detection",
        }
        target_cap = alias_map.get(clean_cap, clean_cap)

        tools = self.registry.find_by_capability(target_cap)

        # Also search by tool category if not matched by tag
        if not tools:
            tools = [t for t in self.registry.all_tools() if t.category.lower() == clean_cap or t.category.lower() == target_cap]

        tier_weights = {"CORE": 0, "SPECIALIST": 1, "PROVIDER-BACKED": 2, "OPTIONAL": 3, "LEGACY": 4}
        return sorted(tools, key=lambda t: tier_weights.get(t.tier, 99))

    def get_preferred_tool(self, capability: str) -> Optional[ToolDef]:
        """Returns the primary (preferred) tool for a capability."""
        tools = self.get_tools_for_capability(capability)
        return tools[0] if tools else None

    def get_fallback_tool(
        self,
        preferred_tool_name: str,
        installed_tool_names: Optional[List[str]] = None,
    ) -> Optional[ToolDef]:
        """
        Determines the best fallback tool if the preferred tool is missing or unavailable.
        Checks explicit fallback pointer first, then alternative tools sharing capabilities.
        """
        tool = self.registry.get_tool(preferred_tool_name)
        if not tool:
            return None

        # 1. Check explicit fallback property
        if tool.fallback:
            fb = self.registry.get_tool(tool.fallback)
            if fb:
                if installed_tool_names is None or fb.name.lower() in [i.lower() for i in installed_tool_names]:
                    return fb

        # 2. Search alternative tools with overlapping capabilities
        installed_set = {n.lower() for n in installed_tool_names} if installed_tool_names else None
        for cap in tool.capabilities:
            candidates = self.get_tools_for_capability(cap)
            for cand in candidates:
                if cand.name.lower() == tool.name.lower():
                    continue
                if cand.tier == "LEGACY":
                    continue
                if installed_set is None or cand.name.lower() in installed_set:
                    return cand

        return None

    def resolve_workflow_tooling(
        self,
        required_capabilities: List[str],
        installed_tool_names: List[str],
    ) -> Dict[str, Any]:
        """
        Plans tool selection for a set of workflow capabilities.
        Returns mapped tools, missing tools, and fallbacks.
        """
        installed_map = {n.lower(): n for n in installed_tool_names}
        selected = {}
        missing = []
        fallbacks = {}

        for cap in required_capabilities:
            preferred = self.get_preferred_tool(cap)
            if not preferred:
                missing.append({"capability": cap, "preferred": None, "reason": "No tool registered"})
                continue

            if preferred.name.lower() in installed_map:
                selected[cap] = preferred.name
            else:
                # Attempt to find installed fallback
                fb = self.get_fallback_tool(preferred.name, installed_tool_names)
                if fb:
                    selected[cap] = fb.name
                    fallbacks[preferred.name] = fb.name
                else:
                    missing.append({
                        "capability": cap,
                        "preferred": preferred.name,
                        "fallback": preferred.fallback,
                        "reason": f"Tool '{preferred.name}' is not installed",
                    })

        return {
            "selected": selected,
            "fallbacks": fallbacks,
            "missing": missing,
            "ready": len(missing) == 0,
        }
