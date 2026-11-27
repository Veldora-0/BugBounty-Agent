"""Static vulnerability and tool coverage inventory for BugBounty-Agent."""

from framework.coverage.registry import (
    CoverageRegistry,
    CoverageRegistryError,
    load_coverage_registry,
)

__all__ = ["CoverageRegistry", "CoverageRegistryError", "load_coverage_registry"]
