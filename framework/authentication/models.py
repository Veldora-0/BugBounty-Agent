"""
Data Models for Authentication, Session & Identity Security Intelligence Engine (Phase 14).

Defines structured models for identities, authentication states, flows, transitions,
session lifecycles, tokens, MFA, password reset, hypotheses, evidence, and finding candidates.
Adheres strictly to credential protection: NEVER stores actual passwords, raw bearer tokens,
or raw session cookies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional, Set


# ==============================================================================
# 1. Enums
# ==============================================================================

class AuthenticationState(str, Enum):
    """Lifecycle states of an identity or session in the authentication state machine."""
    UNKNOWN = "UNKNOWN"
    ANONYMOUS = "ANONYMOUS"
    AUTHENTICATED = "AUTHENTICATED"
    PARTIALLY_AUTHENTICATED = "PARTIALLY_AUTHENTICATED"
    MFA_REQUIRED = "MFA_REQUIRED"
    MFA_VERIFIED = "MFA_VERIFIED"
    EXPIRED = "EXPIRED"
    LOCKED = "LOCKED"
    RECOVERY = "RECOVERY"
    LOGGED_OUT = "LOGGED_OUT"


class PrincipalType(str, Enum):
    """Classification of security principals participating in authentication."""
    ANONYMOUS = "ANONYMOUS"
    USER = "USER"
    PRIVILEGED_USER = "PRIVILEGED_USER"
    ADMIN = "ADMIN"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    UNKNOWN = "UNKNOWN"


class AuthenticationFlowType(str, Enum):
    """Categorization of authentication flows and state transitions."""
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    REGISTRATION = "REGISTRATION"
    ACCOUNT_VERIFICATION = "ACCOUNT_VERIFICATION"
    PASSWORD_CHANGE = "PASSWORD_CHANGE"
    PASSWORD_RESET = "PASSWORD_RESET"
    MFA_ENROLLMENT = "MFA_ENROLLMENT"
    MFA_VERIFICATION = "MFA_VERIFICATION"
    DEVICE_TRUST = "DEVICE_TRUST"
    TOKEN_REFRESH = "TOKEN_REFRESH"


class SessionLifecycle(str, Enum):
    """Lifecycle observation states of a session identifier."""
    NOT_OBSERVED = "NOT_OBSERVED"
    CREATED = "CREATED"
    ROTATED = "ROTATED"
    ACTIVE = "ACTIVE"
    REFRESHED = "REFRESHED"
    LOGGED_OUT = "LOGGED_OUT"
    INVALIDATED = "INVALIDATED"
    EXPIRED = "EXPIRED"
    REUSABLE = "REUSABLE"
    UNKNOWN = "UNKNOWN"


class MFAState(str, Enum):
    """Multi-Factor Authentication state of a session or identity."""
    NOT_DETECTED = "NOT_DETECTED"
    NOT_REQUIRED = "NOT_REQUIRED"
    REQUIRED = "REQUIRED"
    CHALLENGE_ACTIVE = "CHALLENGE_ACTIVE"
    VERIFIED = "VERIFIED"
    REMEMBERED_DEVICE = "REMEMBERED_DEVICE"
    RECOVERY = "RECOVERY"


class AccountEnumerationSignal(str, Enum):
    """Classification of differential signals in account existence testing."""
    NO_ENUMERATION_SIGNAL = "NO_ENUMERATION_SIGNAL"
    WEAK_ENUMERATION_SIGNAL = "WEAK_ENUMERATION_SIGNAL"
    STRONG_ENUMERATION_SIGNAL = "STRONG_ENUMERATION_SIGNAL"
    VALIDATED_ENUMERATION = "VALIDATED_ENUMERATION"


class HypothesisValidationStatus(str, Enum):
    """Validation lifecycle status for authentication hypotheses."""
    UNTESTED = "UNTESTED"
    PLANNED = "PLANNED"
    TESTING = "TESTING"
    OBSERVED = "OBSERVED"
    CANDIDATE = "CANDIDATE"
    VALIDATED = "VALIDATED"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    SKIPPED = "SKIPPED"
    DUPLICATE = "DUPLICATE"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"
    INFORMATIONAL = "INFORMATIONAL"


# Controlled Finding Families Registry
class AuthenticationFindingFamily:
    AUTHENTICATION_BYPASS = "AUTHENTICATION_BYPASS"
    PRE_AUTH_PRIVILEGE_EXPOSURE = "PRE_AUTH_PRIVILEGE_EXPOSURE"
    SESSION_FIXATION = "SESSION_FIXATION"
    SESSION_NOT_INVALIDATED = "SESSION_NOT_INVALIDATED"
    SESSION_NOT_ROTATED = "SESSION_NOT_ROTATED"
    PASSWORD_RESET_TOKEN_REUSE = "PASSWORD_RESET_TOKEN_REUSE"
    PASSWORD_RESET_STATE_CONFUSION = "PASSWORD_RESET_STATE_CONFUSION"
    ACCOUNT_ENUMERATION = "ACCOUNT_ENUMERATION"
    MFA_BYPASS = "MFA_BYPASS"
    MFA_STATE_CONFUSION = "MFA_STATE_CONFUSION"
    REFRESH_TOKEN_REUSE = "REFRESH_TOKEN_REUSE"
    TOKEN_TRANSPORT_EXPOSURE = "TOKEN_TRANSPORT_EXPOSURE"
    AUTHENTICATION_STATE_INCONSISTENCY = "AUTHENTICATION_STATE_INCONSISTENCY"
    AUTHENTICATION_CONFIGURATION_WEAKNESS = "AUTHENTICATION_CONFIGURATION_WEAKNESS"

    ALL_FAMILIES = {
        AUTHENTICATION_BYPASS,
        PRE_AUTH_PRIVILEGE_EXPOSURE,
        SESSION_FIXATION,
        SESSION_NOT_INVALIDATED,
        SESSION_NOT_ROTATED,
        PASSWORD_RESET_TOKEN_REUSE,
        PASSWORD_RESET_STATE_CONFUSION,
        ACCOUNT_ENUMERATION,
        MFA_BYPASS,
        MFA_STATE_CONFUSION,
        REFRESH_TOKEN_REUSE,
        TOKEN_TRANSPORT_EXPOSURE,
        AUTHENTICATION_STATE_INCONSISTENCY,
        AUTHENTICATION_CONFIGURATION_WEAKNESS,
    }


# ==============================================================================
# 2. Identity & Profile Models
# ==============================================================================

@dataclass
class IdentityProfile:
    """
    Structured model for an identity or researcher-controlled principal.
    Strictly redacted: NEVER stores raw passwords, API tokens, or credentials.
    """
    identity_id: str
    username: str
    display_name: str = ""
    role: str = "USER"
    tenant: Optional[str] = None
    authentication_state: AuthenticationState = AuthenticationState.UNKNOWN
    source: str = "CONFIG"
    confidence: float = 1.0
    evidence_refs: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identity_id": self.identity_id,
            "username": self.username,
            "display_name": self.display_name,
            "role": self.role,
            "tenant": self.tenant,
            "authentication_state": self.authentication_state.value,
            "source": self.source,
            "confidence": round(self.confidence, 3),
            "evidence_refs": list(self.evidence_refs),
            "attributes": {k: v for k, v in self.attributes.items() if not any(s in k.lower() for s in ["pass", "token", "secret", "key"])},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> IdentityProfile:
        state_str = data.get("authentication_state", "UNKNOWN")
        try:
            state = AuthenticationState(state_str)
        except ValueError:
            state = AuthenticationState.UNKNOWN

        return cls(
            identity_id=data["identity_id"],
            username=data.get("username", ""),
            display_name=data.get("display_name", ""),
            role=data.get("role", "USER"),
            tenant=data.get("tenant"),
            authentication_state=state,
            source=data.get("source", "CONFIG"),
            confidence=float(data.get("confidence", 1.0)),
            evidence_refs=data.get("evidence_refs", []),
            attributes=data.get("attributes", {}),
        )


# ==============================================================================
# 3. Authentication Flow & Step Models
# ==============================================================================

@dataclass
class AuthenticationStep:
    """A single request/response step within an authentication flow."""
    step_id: str
    flow_type: AuthenticationFlowType
    method: str
    endpoint: str
    parameter_names: List[str] = field(default_factory=list)
    request_source: str = "HTTP"
    response_indicators: List[str] = field(default_factory=list)
    state_before: AuthenticationState = AuthenticationState.UNKNOWN
    state_after: AuthenticationState = AuthenticationState.UNKNOWN
    evidence_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "flow_type": self.flow_type.value,
            "method": self.method.upper(),
            "endpoint": self.endpoint,
            "parameter_names": self.parameter_names,
            "request_source": self.request_source,
            "response_indicators": self.response_indicators,
            "state_before": self.state_before.value,
            "state_after": self.state_after.value,
            "evidence_refs": self.evidence_refs,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuthenticationStep:
        return cls(
            step_id=data["step_id"],
            flow_type=AuthenticationFlowType(data.get("flow_type", "LOGIN")),
            method=data.get("method", "GET"),
            endpoint=data.get("endpoint", ""),
            parameter_names=data.get("parameter_names", []),
            request_source=data.get("request_source", "HTTP"),
            response_indicators=data.get("response_indicators", []),
            state_before=AuthenticationState(data.get("state_before", "UNKNOWN")),
            state_after=AuthenticationState(data.get("state_after", "UNKNOWN")),
            evidence_refs=data.get("evidence_refs", []),
        )


@dataclass
class AuthenticationTransition:
    """Represents a state machine transition between authentication states."""
    transition_id: str
    from_state: AuthenticationState
    to_state: AuthenticationState
    trigger_step: str
    requires_approval: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transition_id": self.transition_id,
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "trigger_step": self.trigger_step,
            "requires_approval": self.requires_approval,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuthenticationTransition:
        return cls(
            transition_id=data["transition_id"],
            from_state=AuthenticationState(data.get("from_state", "UNKNOWN")),
            to_state=AuthenticationState(data.get("to_state", "UNKNOWN")),
            trigger_step=data.get("trigger_step", ""),
            requires_approval=data.get("requires_approval", False),
        )


@dataclass
class AuthenticationFlow:
    """Structured representation of a complete authentication workflow."""
    flow_id: str
    flow_type: AuthenticationFlowType
    steps: List[AuthenticationStep] = field(default_factory=list)
    transitions: List[AuthenticationTransition] = field(default_factory=list)
    endpoint: str = ""
    description: str = ""
    success_indicators: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "flow_type": self.flow_type.value,
            "steps": [s.to_dict() for s in self.steps],
            "transitions": [t.to_dict() for t in self.transitions],
            "endpoint": self.endpoint,
            "description": self.description,
            "success_indicators": self.success_indicators,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuthenticationFlow:
        return cls(
            flow_id=data["flow_id"],
            flow_type=AuthenticationFlowType(data.get("flow_type", "LOGIN")),
            steps=[AuthenticationStep.from_dict(s) for s in data.get("steps", [])],
            transitions=[AuthenticationTransition.from_dict(t) for t in data.get("transitions", [])],
            endpoint=data.get("endpoint", ""),
            description=data.get("description", ""),
            success_indicators=data.get("success_indicators", []),
        )


# ==============================================================================
# 4. Session & Token Models
# ==============================================================================

@dataclass
class SessionProfile:
    """
    Session identifier metadata model.
    Stores masked or SHA-256 fingerprint reference only, NEVER raw session secret.
    """
    session_id: str  # Masked ref or hash: e.g. "sess_sha256_ab12..."
    identity_id: str
    cookie_names: List[str] = field(default_factory=list)
    token_type: str = "COOKIE"  # COOKIE, BEARER, HEADER, CUSTOM
    creation_observation: Optional[str] = None
    rotation_observation: Optional[str] = None
    invalidation_observation: Optional[str] = None
    expiry_observation: Optional[str] = None
    refresh_observation: Optional[str] = None
    transport_observation: Optional[str] = None
    lifecycle: SessionLifecycle = SessionLifecycle.ACTIVE
    confidence: float = 1.0
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "identity_id": self.identity_id,
            "cookie_names": self.cookie_names,
            "token_type": self.token_type,
            "creation_observation": self.creation_observation,
            "rotation_observation": self.rotation_observation,
            "invalidation_observation": self.invalidation_observation,
            "expiry_observation": self.expiry_observation,
            "refresh_observation": self.refresh_observation,
            "transport_observation": self.transport_observation,
            "lifecycle": self.lifecycle.value,
            "confidence": round(self.confidence, 3),
            "attributes": self.attributes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SessionProfile:
        return cls(
            session_id=data["session_id"],
            identity_id=data.get("identity_id", ""),
            cookie_names=data.get("cookie_names", []),
            token_type=data.get("token_type", "COOKIE"),
            creation_observation=data.get("creation_observation"),
            rotation_observation=data.get("rotation_observation"),
            invalidation_observation=data.get("invalidation_observation"),
            expiry_observation=data.get("expiry_observation"),
            refresh_observation=data.get("refresh_observation"),
            transport_observation=data.get("transport_observation"),
            lifecycle=SessionLifecycle(data.get("lifecycle", "ACTIVE")),
            confidence=float(data.get("confidence", 1.0)),
            attributes=data.get("attributes", {}),
        )


@dataclass
class TokenMetadata:
    """Metadata extracted structurally from authentication tokens (JWT or opaque)."""
    token_type: str  # JWT, OPAQUE_BEARER, SESSION_ID, REFRESH_TOKEN
    is_jwt: bool = False
    jwt_algorithm: Optional[str] = None
    jwt_issuer: Optional[str] = None
    jwt_subject_present: bool = False
    jwt_audience_present: bool = False
    jwt_expiry_present: bool = False
    jwt_not_before_present: bool = False
    jwt_issued_at_present: bool = False
    privilege_claims: List[str] = field(default_factory=list)
    transport_locations: List[str] = field(default_factory=list)  # HEADER, QUERY, COOKIE, BODY
    is_reusable: bool = False
    has_rotation: bool = False
    observations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_type": self.token_type,
            "is_jwt": self.is_jwt,
            "jwt_algorithm": self.jwt_algorithm,
            "jwt_issuer": self.jwt_issuer,
            "jwt_subject_present": self.jwt_subject_present,
            "jwt_audience_present": self.jwt_audience_present,
            "jwt_expiry_present": self.jwt_expiry_present,
            "jwt_not_before_present": self.jwt_not_before_present,
            "jwt_issued_at_present": self.jwt_issued_at_present,
            "privilege_claims": self.privilege_claims,
            "transport_locations": self.transport_locations,
            "is_reusable": self.is_reusable,
            "has_rotation": self.has_rotation,
            "observations": self.observations,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TokenMetadata:
        return cls(
            token_type=data.get("token_type", "OPAQUE_BEARER"),
            is_jwt=data.get("is_jwt", False),
            jwt_algorithm=data.get("jwt_algorithm"),
            jwt_issuer=data.get("jwt_issuer"),
            jwt_subject_present=data.get("jwt_subject_present", False),
            jwt_audience_present=data.get("jwt_audience_present", False),
            jwt_expiry_present=data.get("jwt_expiry_present", False),
            jwt_not_before_present=data.get("jwt_not_before_present", False),
            jwt_issued_at_present=data.get("jwt_issued_at_present", False),
            privilege_claims=data.get("privilege_claims", []),
            transport_locations=data.get("transport_locations", []),
            is_reusable=data.get("is_reusable", False),
            has_rotation=data.get("has_rotation", False),
            observations=data.get("observations", []),
        )


@dataclass
class PasswordResetFlow:
    """Structured model of a password reset lifecycle."""
    flow_id: str
    identity_id: str
    request_endpoint: str
    reset_endpoint: str
    token_param: str = "token"
    token_reusable: bool = False
    invalidated_after_reset: bool = True
    expired_token_rejected: bool = True
    enumeration_signal: AccountEnumerationSignal = AccountEnumerationSignal.NO_ENUMERATION_SIGNAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "identity_id": self.identity_id,
            "request_endpoint": self.request_endpoint,
            "reset_endpoint": self.reset_endpoint,
            "token_param": self.token_param,
            "token_reusable": self.token_reusable,
            "invalidated_after_reset": self.invalidated_after_reset,
            "expired_token_rejected": self.expired_token_rejected,
            "enumeration_signal": self.enumeration_signal.value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PasswordResetFlow:
        return cls(
            flow_id=data["flow_id"],
            identity_id=data.get("identity_id", ""),
            request_endpoint=data.get("request_endpoint", ""),
            reset_endpoint=data.get("reset_endpoint", ""),
            token_param=data.get("token_param", "token"),
            token_reusable=data.get("token_reusable", False),
            invalidated_after_reset=data.get("invalidated_after_reset", True),
            expired_token_rejected=data.get("expired_token_rejected", True),
            enumeration_signal=AccountEnumerationSignal(data.get("enumeration_signal", "NO_ENUMERATION_SIGNAL")),
        )


# ==============================================================================
# 5. Hypotheses & Findings Models
# ==============================================================================

@dataclass
class AuthenticationHypothesis:
    """Structured hypothesis regarding an authentication or session security property."""
    hypothesis_id: str
    family: str  # from AuthenticationFindingFamily
    endpoint: str
    principal: str
    required_state: AuthenticationState
    observed_state: AuthenticationState
    expected_behavior: str
    observed_behavior: str
    confidence: float
    impact_hint: str
    evidence_refs: List[str] = field(default_factory=list)
    validation_status: HypothesisValidationStatus = HypothesisValidationStatus.UNTESTED
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "family": self.family,
            "endpoint": self.endpoint,
            "principal": self.principal,
            "required_state": self.required_state.value,
            "observed_state": self.observed_state.value,
            "expected_behavior": self.expected_behavior,
            "observed_behavior": self.observed_behavior,
            "confidence": round(self.confidence, 3),
            "impact_hint": self.impact_hint,
            "evidence_refs": list(self.evidence_refs),
            "validation_status": self.validation_status.value,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuthenticationHypothesis:
        return cls(
            hypothesis_id=data["hypothesis_id"],
            family=data["family"],
            endpoint=data.get("endpoint", ""),
            principal=data.get("principal", "ANONYMOUS"),
            required_state=AuthenticationState(data.get("required_state", "AUTHENTICATED")),
            observed_state=AuthenticationState(data.get("observed_state", "UNKNOWN")),
            expected_behavior=data.get("expected_behavior", ""),
            observed_behavior=data.get("observed_behavior", ""),
            confidence=float(data.get("confidence", 0.5)),
            impact_hint=data.get("impact_hint", "LOW"),
            evidence_refs=data.get("evidence_refs", []),
            validation_status=HypothesisValidationStatus(data.get("validation_status", "UNTESTED")),
            rationale=data.get("rationale", ""),
        )


@dataclass
class AuthenticationFindingCandidate:
    """Validated authentication finding candidate prepared for global reporting."""
    finding_id: str
    title: str
    family: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    confidence: str  # CONFIRMED, HIGH, MEDIUM, LOW
    endpoint: str
    identity_id: str
    description: str
    evidence_chain: List[Dict[str, Any]]
    cvss_score: float
    remediation: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "family": self.family,
            "severity": self.severity,
            "confidence": self.confidence,
            "endpoint": self.endpoint,
            "identity_id": self.identity_id,
            "description": self.description,
            "evidence_chain": self.evidence_chain,
            "cvss_score": self.cvss_score,
            "remediation": self.remediation,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuthenticationFindingCandidate:
        return cls(
            finding_id=data["finding_id"],
            title=data.get("title", ""),
            family=data.get("family", "AUTHENTICATION_BYPASS"),
            severity=data.get("severity", "MEDIUM"),
            confidence=data.get("confidence", "HIGH"),
            endpoint=data.get("endpoint", ""),
            identity_id=data.get("identity_id", ""),
            description=data.get("description", ""),
            evidence_chain=data.get("evidence_chain", []),
            cvss_score=float(data.get("cvss_score", 5.0)),
            remediation=data.get("remediation", ""),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )

    def to_native_finding(self, scope_ref: str, is_validated: bool = False):
        """
        Converts the candidate into a native Finding object complying with FindingLifecycle.
        Candidates do NOT automatically become VALIDATED without explicit verification proof.
        """
        from framework.findings.schema import Finding, VALID_SEVERITIES, VALID_CONFIDENCES
        from framework.findings.lifecycle import FindingLifecycle
        from framework.authentication.evidence import AuthenticationEvidenceManager
        from urllib.parse import urlparse

        obs_only_families = {
            AuthenticationFindingFamily.SESSION_NOT_ROTATED,
            AuthenticationFindingFamily.TOKEN_TRANSPORT_EXPOSURE,
            AuthenticationFindingFamily.AUTHENTICATION_CONFIGURATION_WEAKNESS,
        }

        clean_endpoint = AuthenticationEvidenceManager.sanitize_url(self.endpoint or "/auth")
        clean_title = AuthenticationEvidenceManager.sanitize(self.title or f"Authentication Security Issue: {self.family}")
        clean_desc = AuthenticationEvidenceManager.sanitize(self.description or f"Identified {self.family} on {clean_endpoint}")
        clean_summary = AuthenticationEvidenceManager.sanitize(self.description[:200] if self.description else self.title)
        clean_remediation = AuthenticationEvidenceManager.sanitize(self.remediation or "Follow authentication hardening best practices.")
        clean_identity = AuthenticationEvidenceManager.sanitize(self.identity_id or "ANONYMOUS")

        evidence_items = []
        for ev in self.evidence_chain:
            if isinstance(ev, dict):
                raw_content = ev.get("response_redacted") or ev.get("request_redacted") or str(ev)
                clean_content = AuthenticationEvidenceManager.sanitize(raw_content)
                meta = ev.get("metadata", {})
                clean_meta = AuthenticationEvidenceManager.sanitize_dict(meta) if isinstance(meta, dict) else {}
                clean_meta["sha256"] = ev.get("sha256_digest", clean_meta.get("sha256", ""))
                clean_meta["status_code"] = ev.get("status_code", clean_meta.get("status_code", 0))
                clean_meta["endpoint"] = AuthenticationEvidenceManager.sanitize_url(ev.get("endpoint", clean_endpoint))

                evidence_items.append({
                    "type": "http_interaction",
                    "content": clean_content,
                    "metadata": clean_meta,
                    "timestamp": ev.get("timestamp", self.timestamp),
                })

        has_evidence = len(evidence_items) > 0
        if is_validated and self.family not in obs_only_families and has_evidence:
            lifecycle = FindingLifecycle.VALIDATED
        elif self.family in obs_only_families:
            lifecycle = FindingLifecycle.INFORMATIONAL
        else:
            lifecycle = FindingLifecycle.CANDIDATE

        # Normalize severity and confidence
        sev = self.severity.upper() if self.severity.upper() in VALID_SEVERITIES else "MEDIUM"
        conf = self.confidence.upper() if self.confidence.upper() in VALID_CONFIDENCES else "HIGH"

        # Determine asset
        asset = "authentication-service"
        if "://" in clean_endpoint:
            p = urlparse(clean_endpoint)
            asset = p.netloc or p.hostname or "authentication-service"
        elif clean_endpoint:
            parts = [seg for seg in clean_endpoint.split("/") if seg]
            asset = parts[0] if parts else "authentication-service"

        repro_steps = [
            f"Navigate to target endpoint: {clean_endpoint}",
            f"Execute authentication/session test under context identity: {clean_identity}",
            f"Observe application response for vulnerability family: {self.family}",
        ]

        return Finding(
            finding_id=self.finding_id,
            title=clean_title,
            summary=clean_summary,
            affected_asset=asset,
            affected_endpoint=clean_endpoint,
            vulnerability_type=self.family,
            severity=sev,
            confidence=conf,
            description=clean_desc,
            root_cause=f"Inadequate authentication/session controls for {self.family}",
            prerequisites=f"Access to endpoint under context {clean_identity}",
            reproduction_steps=repro_steps,
            expected_result="Endpoint enforces strict authentication and session boundaries.",
            observed_result=clean_desc,
            security_impact=f"Potential authentication/session compromise: CVSS {self.cvss_score}",
            remediation=clean_remediation,
            scope_reference=scope_ref,
            lifecycle_state=lifecycle,
            evidence=evidence_items,
        )
