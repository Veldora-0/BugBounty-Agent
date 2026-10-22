"""
XXE & Server-Side Parser Security Subsystem for BugBounty-Agent (Phase 18).
"""

from framework.xxe.model import (
    XxeCandidate,
    XxeCategory,
    XxeConfidence,
    XxeEvidence,
    XxeInteractionType,
    XxeSource,
)
from framework.xxe.state import XxeStateManager
from framework.xxe.engine import XxeIntelligenceEngine
from framework.xxe.lab import LocalXxeLab

__all__ = [
    "XxeCandidate",
    "XxeCategory",
    "XxeConfidence",
    "XxeEvidence",
    "XxeInteractionType",
    "XxeSource",
    "XxeStateManager",
    "XxeIntelligenceEngine",
    "LocalXxeLab",
]
