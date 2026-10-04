"""
Security Validation & Vulnerability Analysis Foundation for BugBounty-Agent.

Provides structured security test cases, empirical baseline comparison,
proof-of-concept validators (Reflected XSS, Open Redirect), authorization modeling,
sanitized evidence capture, and non-destructive verification.
"""

from framework.validation.authorization import (
    AuthorizationComparisonResult,
    ExpectedAccessPolicy,
    Principal,
    ResourceIdentifier,
    SessionContext,
    compare_dual_principal_access,
)
from framework.validation.baseline import (
    BaselineComparison,
    BaselineObservation,
    compare_with_baseline,
)
from framework.validation.engine import (
    ScopeViolationError,
    SecurityValidationEngine,
)
from framework.validation.model import (
    RiskLevel,
    SecurityTestCase,
    ValidationResult,
    VulnerabilityFamily,
)
from framework.validation.payload import (
    MutationType,
    Payload,
    PayloadRegistry,
)
from framework.validation.policy import (
    PolicyViolationError,
    SecurityTestPolicy,
)
from framework.validation.request import (
    ControlledRequest,
    ControlledResponse,
    RequestBuilder,
)
from framework.validation.state import (
    SecurityStateManager,
)
from framework.validation.validator import (
    BaseValidator,
    OpenRedirectValidator,
    ReflectedXSSValidator,
)

__all__ = [
    "AuthorizationComparisonResult",
    "BaseValidator",
    "BaselineComparison",
    "BaselineObservation",
    "ControlledRequest",
    "ControlledResponse",
    "ExpectedAccessPolicy",
    "MutationType",
    "OpenRedirectValidator",
    "Payload",
    "PayloadRegistry",
    "PolicyViolationError",
    "Principal",
    "ReflectedXSSValidator",
    "RequestBuilder",
    "ResourceIdentifier",
    "RiskLevel",
    "ScopeViolationError",
    "SecurityStateManager",
    "SecurityTestCase",
    "SecurityTestPolicy",
    "SecurityValidationEngine",
    "SessionContext",
    "ValidationResult",
    "VulnerabilityFamily",
    "compare_dual_principal_access",
    "compare_with_baseline",
]
