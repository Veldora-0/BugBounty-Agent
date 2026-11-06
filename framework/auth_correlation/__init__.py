"""
Phase 21: Authentication & Authorization Correlation Engine.

Integrates multi-session lifecycle, pre-MFA state transitions, and multi-tenant
cross-correlation into a unified correlation layer without altering existing
authentication or authorization core engines.
"""

from framework.auth_correlation.model import (
    CorrelationLifecycle,
    ProbeStatus,
    CorrelatedPrincipalContext,
    CorrelatedSessionContext,
    CorrelationHypothesis,
    CorrelationFinding,
    SerializationSecurityError,
    StateSecurityValidationError,
)
from framework.auth_correlation.cvss import (
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    CIAImpact,
    CVSS31Metrics,
    CVSS31Calculator,
    CVSSMetricValidationError,
)
from framework.auth_correlation.preflight import (
    DualControlPreflightValidator,
)
from framework.auth_correlation.revocation import (
    PostRevocationResourceValidator,
    ApprovalSecurityError,
)

__all__ = [
    "CorrelationLifecycle",
    "ProbeStatus",
    "CorrelatedPrincipalContext",
    "CorrelatedSessionContext",
    "CorrelationHypothesis",
    "CorrelationFinding",
    "SerializationSecurityError",
    "StateSecurityValidationError",
    "AttackVector",
    "AttackComplexity",
    "PrivilegesRequired",
    "UserInteraction",
    "Scope",
    "CIAImpact",
    "CVSS31Metrics",
    "CVSS31Calculator",
    "CVSSMetricValidationError",
    "DualControlPreflightValidator",
    "PostRevocationResourceValidator",
    "ApprovalSecurityError",
]
