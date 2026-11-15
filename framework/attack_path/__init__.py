"""
Phase 22: Cross-Engine Attack-Path Correlation & Vulnerability Chaining.

Provides typed graph representation, evidence-driven capability normalization,
decoupled relationship and chain lifecycle state machines, zero-secret graph persistence,
and bounded correlation search.
"""

from __future__ import annotations

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

__all__ = [
    "AttackGraph",
    "AttackGraphCapacityError",
    "AttackGraphEdge",
    "AttackGraphNode",
    "AttackPath",
    "AttackPathStateError",
    "AttackPathStateManager",
    "CapabilityExtractionError",
    "CapabilityType",
    "CausalityProofType",
    "ChainState",
    "EdgeType",
    "ExtractedCapability",
    "FindingNormalizer",
    "NodeType",
    "RelationshipProvenance",
    "RelationshipState",
    "assert_no_raw_secrets",
]
