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

__all__ = [
    "CorrelationLifecycle",
    "ProbeStatus",
    "CorrelatedPrincipalContext",
    "CorrelatedSessionContext",
    "CorrelationHypothesis",
    "CorrelationFinding",
    "SerializationSecurityError",
    "StateSecurityValidationError",
]
