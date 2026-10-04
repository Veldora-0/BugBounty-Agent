"""
HTTP / Header Trust & Protocol Security Subsystem (Phase 11).

Provides hypothesis-driven validation for Host header injection,
X-Forwarded-Host/Forwarded proxy trust, scheme trust, CORS trust boundaries,
HTTP parameter pollution (HPP), and cache-poisoning foundations.
"""

from framework.http_trust.approval import HumanApprovalGate
from framework.http_trust.comparator import (
    HttpTrustComparator,
    HttpTrustComparisonResult,
)
from framework.http_trust.engine import HttpTrustEngine
from framework.http_trust.lab import LocalHttpTrustLab
from framework.http_trust.model import (
    HeaderTrustCandidate,
    HeaderTrustEvidence,
    HttpTrustCategory,
    HttpTrustConfidence,
    HttpTrustTestCase,
    TrustClassification,
    TrustSource,
    generate_canary_host,
)
from framework.http_trust.prioritization import HttpTrustPrioritizer
from framework.http_trust.state import HttpTrustStateManager
from framework.http_trust.validator import (
    BaseHttpTrustValidator,
    CorsValidator,
    ForwardedValidator,
    HostInjectionValidator,
    HppValidator,
    HttpTrustValidatorFactory,
    SchemeValidator,
)

__all__ = [
    "HumanApprovalGate",
    "HttpTrustComparator",
    "HttpTrustComparisonResult",
    "HttpTrustEngine",
    "LocalHttpTrustLab",
    "HeaderTrustCandidate",
    "HeaderTrustEvidence",
    "HttpTrustCategory",
    "HttpTrustConfidence",
    "HttpTrustTestCase",
    "TrustClassification",
    "TrustSource",
    "generate_canary_host",
    "HttpTrustPrioritizer",
    "HttpTrustStateManager",
    "BaseHttpTrustValidator",
    "HostInjectionValidator",
    "ForwardedValidator",
    "SchemeValidator",
    "CorsValidator",
    "HppValidator",
    "HttpTrustValidatorFactory",
]
