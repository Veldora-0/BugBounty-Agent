"""
Authentication, Session & Identity Security Intelligence Engine (Phase 14).

Exports models, analyzers, validators, lab, and primary orchestrator.
"""

from framework.authentication.discovery import AuthenticationSurfaceDiscoverer
from framework.authentication.engine import AuthenticationSecurityEngine
from framework.authentication.evidence import AuthenticationEvidenceManager
from framework.authentication.hypotheses import AuthenticationHypothesisEngine
from framework.authentication.identity import IdentityManager
from framework.authentication.lab import LocalAuthenticationSecurityLab
from framework.authentication.mfa import MFAAnalyzer
from framework.authentication.models import (
    AccountEnumerationSignal,
    AuthenticationFindingCandidate,
    AuthenticationFindingFamily,
    AuthenticationFlow,
    AuthenticationFlowType,
    AuthenticationHypothesis,
    AuthenticationState,
    AuthenticationStep,
    AuthenticationTransition,
    HypothesisValidationStatus,
    IdentityProfile,
    MFAState,
    PrincipalType,
    SessionLifecycle,
    SessionProfile,
    TokenMetadata,
)
from framework.authentication.password_reset import PasswordResetAnalyzer
from framework.authentication.policy import (
    AuthenticationApprovalGate,
    AuthenticationSecurityPolicy,
)
from framework.authentication.prioritization import AuthenticationPrioritizer
from framework.authentication.sessions import SessionAnalyzer
from framework.authentication.storage import AuthenticationStateManager
from framework.authentication.tokens import TokenAnalyzer
from framework.authentication.validators import (
    AuthenticationFalsePositiveClassifier,
    SafeAuthenticationValidator,
)

__all__ = [
    "AccountEnumerationSignal",
    "AuthenticationApprovalGate",
    "AuthenticationEvidenceManager",
    "AuthenticationFalsePositiveClassifier",
    "AuthenticationFindingCandidate",
    "AuthenticationFindingFamily",
    "AuthenticationFlow",
    "AuthenticationFlowType",
    "AuthenticationHypothesis",
    "AuthenticationHypothesisEngine",
    "AuthenticationPrioritizer",
    "AuthenticationSecurityEngine",
    "AuthenticationSecurityPolicy",
    "AuthenticationState",
    "AuthenticationStateManager",
    "AuthenticationStep",
    "AuthenticationSurfaceDiscoverer",
    "AuthenticationTransition",
    "HypothesisValidationStatus",
    "IdentityManager",
    "IdentityProfile",
    "LocalAuthenticationSecurityLab",
    "MFAAnalyzer",
    "MFAState",
    "PasswordResetAnalyzer",
    "PasswordResetFlow",
    "PrincipalType",
    "SafeAuthenticationValidator",
    "SessionAnalyzer",
    "SessionLifecycle",
    "SessionProfile",
    "TokenAnalyzer",
    "TokenMetadata",
]
