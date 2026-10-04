"""
Injection Intelligence & Controlled Validation Subsystem (Phase 10).

Exposes models, prioritizer, error signatures, payloads, differential comparators,
bounded validators, local security lab, approval gate, and orchestration engine.
"""

from framework.injection.approval import HumanApprovalGate
from framework.injection.comparator import (
    InjectionComparator,
    InjectionComparisonResult,
)
from framework.injection.engine import InjectionIntelligenceEngine
from framework.injection.lab import LocalInjectionLab
from framework.injection.model import (
    InjectionCandidate,
    InjectionConfidence,
    InjectionContext,
    InjectionEvidence,
    InjectionType,
)
from framework.injection.payloads import (
    INJECTION_PAYLOADS,
    InjectionPayloadDefinition,
    InjectionPayloadRegistry,
    is_destructive_payload,
)
from framework.injection.prioritization import InjectionPrioritizer
from framework.injection.signatures import (
    ErrorSignature,
    ErrorSignatureMatcher,
    SIGNATURE_CATALOG,
)
from framework.injection.state import InjectionStateManager
from framework.injection.validator import (
    BaseInjectionValidator,
    CommandInjectionValidator,
    InjectionValidatorFactory,
    NoSqlInjectionValidator,
    SqlInjectionValidator,
    SstiValidator,
)

__all__ = [
    "InjectionType",
    "InjectionContext",
    "InjectionConfidence",
    "InjectionCandidate",
    "InjectionEvidence",
    "InjectionPrioritizer",
    "ErrorSignature",
    "SIGNATURE_CATALOG",
    "ErrorSignatureMatcher",
    "InjectionPayloadDefinition",
    "INJECTION_PAYLOADS",
    "InjectionPayloadRegistry",
    "is_destructive_payload",
    "InjectionComparator",
    "InjectionComparisonResult",
    "BaseInjectionValidator",
    "SqlInjectionValidator",
    "NoSqlInjectionValidator",
    "SstiValidator",
    "CommandInjectionValidator",
    "InjectionValidatorFactory",
    "LocalInjectionLab",
    "HumanApprovalGate",
    "InjectionStateManager",
    "InjectionIntelligenceEngine",
]
