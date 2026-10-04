"""
JavaScript Intelligence Package for BugBounty-Agent.

Exposes JavaScriptIntelligenceEngine, JavaScriptAnalyzer, JavaScriptStateManager,
JavaScriptPolicy, and observation models.
"""

from framework.javascript.analyzer import JavaScriptAnalyzer
from framework.javascript.engine import JavaScriptIntelligenceEngine, JavaScriptPolicy
from framework.javascript.model import (
    DependencyObservation,
    DiscoveredEndpoint,
    DiscoveredRoute,
    InterestingString,
    JavaScriptResource,
    ParameterReference,
    SourceMapObservation,
    StringSensitivity,
    mask_sensitive_value,
)
from framework.javascript.state import JavaScriptStateManager

__all__ = [
    "JavaScriptIntelligenceEngine",
    "JavaScriptPolicy",
    "JavaScriptAnalyzer",
    "JavaScriptStateManager",
    "JavaScriptResource",
    "DiscoveredEndpoint",
    "DiscoveredRoute",
    "ParameterReference",
    "InterestingString",
    "DependencyObservation",
    "SourceMapObservation",
    "StringSensitivity",
    "mask_sensitive_value",
]
