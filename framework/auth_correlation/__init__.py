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
    ControlledExecutionResult,
    CorrelationHypothesis,
    CorrelationFinding,
    SerializationSecurityError,
    StateSecurityValidationError,
    EvidencePersistenceError,
    AttestationSecurityError,
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
    get_or_create_attestation_key,
    create_controlled_invalidation_attestation,
    create_operator_invalidation_attestation,
)
from framework.auth_correlation.pre_mfa import (
    PreMfaPrivilegeValidator,
)
from framework.auth_correlation.tenant import (
    MultiTenantDesyncValidator,
)
from framework.auth_correlation.state import (
    AuthCorrelationStateManager,
    KeySecurityError,
    validate_state_schema,
    SUPPORTED_SCHEMA_ID,
)
from framework.auth_correlation.lab import (
    LocalAuthCorrelationLab,
    SimulationTransport,
    SecurityBoundaryViolationError,
)
from framework.auth_correlation.engine import (
    AuthCorrelationEngine,
)

__all__ = [
    "CorrelationLifecycle",
    "ProbeStatus",
    "CorrelatedPrincipalContext",
    "CorrelatedSessionContext",
    "ControlledExecutionResult",
    "CorrelationHypothesis",
    "CorrelationFinding",
    "SerializationSecurityError",
    "StateSecurityValidationError",
    "EvidencePersistenceError",
    "AttestationSecurityError",
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
    "get_or_create_attestation_key",
    "create_controlled_invalidation_attestation",
    "create_operator_invalidation_attestation",
    "PreMfaPrivilegeValidator",
    "MultiTenantDesyncValidator",
    "AuthCorrelationStateManager",
    "KeySecurityError",
    "validate_state_schema",
    "SUPPORTED_SCHEMA_ID",
    "LocalAuthCorrelationLab",
    "SimulationTransport",
    "SecurityBoundaryViolationError",
    "AuthCorrelationEngine",
]
