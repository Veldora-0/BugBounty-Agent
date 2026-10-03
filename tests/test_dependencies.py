"""
Tests for Dependency Resolution and Install Ordering.
"""

from framework.tools.dependencies import DependencyResolver
from framework.tools.registry import ToolRegistry


def test_dependency_chain_shuffledns():
    resolver = DependencyResolver()
    order = resolver.resolve_install_order(["shuffledns"])

    # massdns must be installed before shuffledns
    assert "massdns" in order
    assert "shuffledns" in order
    assert order.index("massdns") < order.index("shuffledns")


def test_multiple_dependency_resolution():
    resolver = DependencyResolver()
    order = resolver.resolve_install_order(["shuffledns", "katana", "ffuf"])

    assert "massdns" in order
    assert "shuffledns" in order
    assert "katana" in order
    assert "ffuf" in order
    assert order.index("massdns") < order.index("shuffledns")


def test_runtime_prerequisites():
    registry = ToolRegistry()
    resolver = DependencyResolver(registry)

    # Playwright requires browser binaries
    pw_tool = registry.get_tool("playwright")
    pw_prereqs = resolver.get_runtime_prerequisites(pw_tool)
    assert "playwright-browsers" in pw_prereqs

    # Go tool requires go toolchain
    katana_tool = registry.get_tool("katana")
    katana_prereqs = resolver.get_runtime_prerequisites(katana_tool)
    assert "go" in katana_prereqs
