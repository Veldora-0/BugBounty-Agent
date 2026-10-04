"""
SSRF & Out-of-Band Interaction Intelligence Subsystem for BugBounty-Agent.

Provides comprehensive discovery, canary correlation, false-positive elimination,
and baseline verification for Server-Side Request Forgery vulnerabilities.
"""

from __future__ import annotations

from framework.ssrf.approval import HumanApprovalGate
from framework.ssrf.canary import CanaryManager, CanaryRecord
from framework.ssrf.comparator import SsrfComparator, SsrfComparisonResult
from framework.ssrf.engine import SsrfIntelligenceEngine
from framework.ssrf.intelligence import SsrfIntelligenceAnalyzer
from framework.ssrf.lab import LocalSsrfLab
from framework.ssrf.model import (
    OobInteractionType,
    OobProviderStatus,
    SsrfCandidate,
    SsrfCategory,
    SsrfConfidence,
    SsrfEvidence,
    SsrfInteraction,
    SsrfSink,
    SsrfSource,
)
from framework.ssrf.provider import (
    CollaboratorOobProvider,
    InteractshOobProvider,
    MockOobProvider,
    OobProvider,
    OobProviderFactory,
)
from framework.ssrf.state import SsrfStateManager

__all__ = [
    "HumanApprovalGate",
    "CanaryManager",
    "CanaryRecord",
    "SsrfComparator",
    "SsrfComparisonResult",
    "SsrfIntelligenceEngine",
    "SsrfIntelligenceAnalyzer",
    "LocalSsrfLab",
    "OobInteractionType",
    "OobProviderStatus",
    "SsrfCandidate",
    "SsrfCategory",
    "SsrfConfidence",
    "SsrfEvidence",
    "SsrfInteraction",
    "SsrfSink",
    "SsrfSource",
    "CollaboratorOobProvider",
    "InteractshOobProvider",
    "MockOobProvider",
    "OobProvider",
    "OobProviderFactory",
    "SsrfStateManager",
]
