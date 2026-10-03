"""
Tools Management Package for BugBounty-Agent.

Provides centralized tool intelligence, dependency resolution, safe on-demand
installation, health diagnostics, and API provider credential management.
"""

from framework.tools.capability import (
    CAPABILITY_GROUPS,
    CapabilityGraph,
)
from framework.tools.dependencies import (
    DependencyResolver,
)
from framework.tools.detector import (
    ToolDetector,
    find_executable,
    get_system_architecture,
)
from framework.tools.doctor import (
    SystemDoctor,
)
from framework.tools.installer import (
    InstallerSecurityError,
    InstallPlan,
    ToolInstaller,
)
from framework.tools.providers import (
    KNOWN_PROVIDERS,
    ProviderManager,
)
from framework.tools.registry import (
    VALID_TIERS,
    ToolDef,
    ToolRegistry,
)
from framework.tools.updater import (
    ToolUpdater,
)

__all__ = [
    "CAPABILITY_GROUPS",
    "CapabilityGraph",
    "DependencyResolver",
    "ToolDetector",
    "find_executable",
    "get_system_architecture",
    "SystemDoctor",
    "InstallerSecurityError",
    "InstallPlan",
    "ToolInstaller",
    "KNOWN_PROVIDERS",
    "ProviderManager",
    "VALID_TIERS",
    "ToolDef",
    "ToolRegistry",
    "ToolUpdater",
]
