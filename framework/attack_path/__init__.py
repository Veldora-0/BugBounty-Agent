"""
Phase 22: Cross-Engine Attack-Path Correlation & Vulnerability Chaining.

Provides typed graph representation, evidence-driven capability normalization,
decoupled relationship and chain lifecycle state machines, zero-secret graph persistence,
and bounded correlation search.
"""

from __future__ import annotations

from framework.attack_path.correlator import (
    AttackPathCorrelator,
    CorrelationResult,
    FeasibilityResult,
)
from framework.attack_path.discovery import (
    CandidateRelationshipEngine,
    SUPPORTED_TENANT_ISOLATION_FLAWS,
)
from framework.attack_path.model import (
    AttackGraph,
    AttackGraphCapacityError,
    AttackGraphEdge,
    AttackGraphNode,
    AttackPath,
    CapabilityType,
    CausalityProofType,
    ChainState,
    EdgeType,
    ExtractedCapability,
    NodeType,
    RelationshipProvenance,
    RelationshipState,
    assert_no_raw_secrets,
)
from framework.attack_path.normalizer import (
    CapabilityExtractionError,
    FindingNormalizer,
)
from framework.attack_path.state import (
    AttackPathStateError,
    AttackPathStateManager,
)
from framework.attack_path.traversal import (
    BoundedTraversalEngine,
    TraversalResult,
)
from framework.attack_path.validator import (
    ApprovalSecurityError,
    ChainValidationPlan,
    DispatchSecurityError,
    EvidenceVerificationError,
    InvalidStateTransitionError,
    MethodSecurityError,
    PlanApproval,
    SafeChainValidationPlanner,
    ValidationAuditEvent,
    ValidationAuditEventType,
    ValidationExecutionResult,
    ValidationMethod,
    ValidationMethodRegistry,
    ValidationPlanningError,
    ValidationPlanStatus,
    ValidationRiskLevel,
)

__all__ = [
    "ApprovalSecurityError",
    "AttackGraph",
    "AttackGraphCapacityError",
    "AttackGraphEdge",
    "AttackGraphNode",
    "AttackPath",
    "AttackPathCorrelator",
    "AttackPathStateError",
    "AttackPathStateManager",
    "BoundedTraversalEngine",
    "CandidateRelationshipEngine",
    "CapabilityExtractionError",
    "CapabilityType",
    "CausalityProofType",
    "ChainState",
    "ChainValidationPlan",
    "CorrelationResult",
    "DispatchSecurityError",
    "EdgeType",
    "EvidenceVerificationError",
    "ExtractedCapability",
    "FeasibilityResult",
    "FindingNormalizer",
    "InvalidStateTransitionError",
    "MethodSecurityError",
    "NodeType",
    "PlanApproval",
    "RelationshipProvenance",
    "RelationshipState",
    "SUPPORTED_TENANT_ISOLATION_FLAWS",
    "SafeChainValidationPlanner",
    "TraversalResult",
    "ValidationAuditEvent",
    "ValidationAuditEventType",
    "ValidationExecutionResult",
    "ValidationMethod",
    "ValidationMethodRegistry",
    "ValidationPlanningError",
    "ValidationPlanStatus",
    "ValidationRiskLevel",
    "assert_no_raw_secrets",
]
