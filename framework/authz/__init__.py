"""
Authorization & Access-Control Intelligence Subsystem for BugBounty-Agent.

Provides comprehensive BOLA/IDOR, vertical privilege escalation, and
tenant boundary validation through rigorous 3-point comparative baseline analysis.
"""

from __future__ import annotations

from framework.authz.approval import HumanApprovalGate
from framework.authz.comparator import AccessControlComparator
from framework.authz.engine import AuthorizationIntelligenceEngine
from framework.authz.identifiers import ObjectIdentifierAnalyzer
from framework.authz.lab import LocalAuthzLab
from framework.authz.model import (
    AccessDecisionInferred,
    AuthorizationCategory,
    AuthorizationTestCase,
    AuthzComparisonResult,
    AuthzEvidence,
    ExpectedAccessDecision,
    ExpectedAccessPolicy,
    PrincipalProfile,
    ResourceAccessTarget,
    SessionProfile,
)
from framework.authz.state import AuthorizationStateManager

__all__ = [
    "AuthorizationIntelligenceEngine",
    "HumanApprovalGate",
    "AccessControlComparator",
    "LocalAuthzLab",
    "ObjectIdentifierAnalyzer",
    "AuthorizationStateManager",
    "AccessDecisionInferred",
    "AuthorizationCategory",
    "AuthorizationTestCase",
    "AuthzComparisonResult",
    "AuthzEvidence",
    "ExpectedAccessDecision",
    "ExpectedAccessPolicy",
    "PrincipalProfile",
    "ResourceAccessTarget",
    "SessionProfile",
]
