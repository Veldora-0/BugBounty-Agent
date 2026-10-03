"""
Tests for Tool Capability Graph and Fallback Resolution.
"""

from framework.tools.capability import CapabilityGraph
from framework.tools.registry import ToolRegistry


def test_preferred_tool_resolution():
    graph = CapabilityGraph()

    pref_crawl = graph.get_preferred_tool("crawling")
    assert pref_crawl is not None
    assert pref_crawl.name == "katana"

    pref_sub = graph.get_preferred_tool("passive-subdomain-discovery")
    assert pref_sub is not None
    assert pref_sub.name == "subfinder"

    pref_fuzz = graph.get_preferred_tool("content-fuzzing")
    assert pref_fuzz is not None
    assert pref_fuzz.name == "ffuf"


def test_fallback_selection_with_installed_tools():
    graph = CapabilityGraph()

    # If subfinder is missing, but amass is installed -> should pick amass
    fb_sub = graph.get_fallback_tool("subfinder", installed_tool_names=["amass", "httpx"])
    assert fb_sub is not None
    assert fb_sub.name == "amass"

    # If katana is missing, but hakrawler is installed -> should pick hakrawler
    fb_crawl = graph.get_fallback_tool("katana", installed_tool_names=["hakrawler", "ffuf"])
    assert fb_crawl is not None
    assert fb_crawl.name == "hakrawler"

    # If ffuf is missing, but feroxbuster is installed -> should pick feroxbuster
    fb_fuzz = graph.get_fallback_tool("ffuf", installed_tool_names=["feroxbuster"])
    assert fb_fuzz is not None
    assert fb_fuzz.name == "feroxbuster"


def test_workflow_tooling_resolution():
    graph = CapabilityGraph()

    # Workflow requiring crawling and passive discovery
    res = graph.resolve_workflow_tooling(
        required_capabilities=["crawling", "passive-subdomain-discovery"],
        installed_tool_names=["katana", "subfinder"],
    )
    assert res["ready"] is True
    assert res["selected"]["crawling"] == "katana"
    assert res["selected"]["passive-subdomain-discovery"] == "subfinder"

    # Workflow where preferred is missing but fallback exists
    res_fb = graph.resolve_workflow_tooling(
        required_capabilities=["crawling"],
        installed_tool_names=["hakrawler"],
    )
    assert res_fb["ready"] is True
    assert res_fb["selected"]["crawling"] == "hakrawler"
    assert res_fb["fallbacks"]["katana"] == "hakrawler"

    # Workflow where required tool is completely missing
    res_miss = graph.resolve_workflow_tooling(
        required_capabilities=["port-scanning"],
        installed_tool_names=["katana"],
    )
    assert res_miss["ready"] is False
    assert len(res_miss["missing"]) > 0
