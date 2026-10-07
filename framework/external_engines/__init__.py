"""
External Pentesting Engine Integration Subsystem (Phase 12 / 12.1 Hardening).

Exports generic pentest engine contracts, Xalgorix adapter, Strix adapter,
engine selector, independent finding correlator, and job lifecycles.
"""

from framework.external_engines.base import (
    EngineCapability,
    ExternalEngineStatus,
    ExternalFinding,
    ExternalJob,
    ExternalPentestEngine,
    safe_join_artifact_path,
)
from framework.external_engines.correlator import (
    EngineSelectionDecision,
    ExternalEngineSelector,
    ExternalFindingCorrelator,
    IndependentValidator,
    compute_actor_context_fingerprint,
    compute_attack_surface_fingerprint,
    compute_resource_fingerprint,
    compute_root_cause_fingerprint,
)
from framework.external_engines.strix import StrixAdapter
from framework.external_engines.xalgorix import XalgorixAdapter

__all__ = [
    "EngineCapability",
    "ExternalEngineStatus",
    "ExternalFinding",
    "ExternalJob",
    "ExternalPentestEngine",
    "safe_join_artifact_path",
    "EngineSelectionDecision",
    "ExternalEngineSelector",
    "ExternalFindingCorrelator",
    "IndependentValidator",
    "compute_actor_context_fingerprint",
    "compute_attack_surface_fingerprint",
    "compute_resource_fingerprint",
    "compute_root_cause_fingerprint",
    "XalgorixAdapter",
    "StrixAdapter",
]
