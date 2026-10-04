"""
BugBounty-Agent Phase 7: XSS Intelligence & Validation Subsystem.

Provides context-aware Reflected XSS validation, DOM XSS source-to-sink intelligence,
stored candidate retrieval correlation, and false-positive elimination.
"""

from framework.xss.browser import BrowserConfirmationResult, BrowserXssAssistant
from framework.xss.context import ContextAnalysisResult, HtmlContextAnalyzer
from framework.xss.dom import DomXssEngine
from framework.xss.engine import XssIntelligenceEngine
from framework.xss.model import (
    ReflectionState,
    XssCandidate,
    XssCategory,
    XssConfidence,
    XssContextType,
    XssEvidence,
    XssSink,
    XssSource,
)
from framework.xss.state import XssStateManager
from framework.xss.stored import StoredXssEngine
from framework.xss.validator import (
    DomXssValidator,
    ReflectedXssContextValidator,
)

__all__ = [
    "BrowserConfirmationResult",
    "BrowserXssAssistant",
    "ContextAnalysisResult",
    "DomXssEngine",
    "DomXssValidator",
    "HtmlContextAnalyzer",
    "ReflectionState",
    "ReflectedXssContextValidator",
    "StoredXssEngine",
    "XssCandidate",
    "XssCategory",
    "XssConfidence",
    "XssContextType",
    "XssEvidence",
    "XssIntelligenceEngine",
    "XssSink",
    "XssSource",
    "XssStateManager",
]
