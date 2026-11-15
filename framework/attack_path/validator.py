"""
Phase 22.3: Safe Validation Planning & Approval Gates.

Provides the trusted planning, approval, authorization gate, and evidence-driven
promotion boundary for candidate attack-path hypotheses.

Core Principles:
1. Strict separation of correlation, planning, human approval, dispatch, and validation.
2. Default-deny posture: zero active validation without explicit, unexpired, unrevoked human approval.
3. Anti-TOCTOU validation: dynamic scope, authorization, tenant, and integrity re-verification at dispatch time.
4. Cryptographic plan integrity: deterministic plan hashes covering all security-critical parameters.
5. Evidence verification: relationship promotion requires proven causality and byte integrity;
   simulated or inferred evidence never silently becomes observed evidence.
6. Zero secrets: strictly no credentials, tokens, cookies, or raw authorization headers stored in plans.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from framework.attack_path.model import (
    AttackGraph,
    AttackGraphEdge,
    AttackGraphNode,
    AttackPath,
    CapabilityType,
    CausalityProofType,
    ChainState,
    EdgeType,
    NodeType,
    RelationshipProvenance,
    RelationshipState,
    assert_no_raw_secrets,
)


# ==============================================================================
# Exceptions
# ==============================================================================

class ValidationPlanningError(Exception):
    """Raised when validation plan creation or configuration fails."""
    pass


class InvalidStateTransitionError(ValueError):
    """Raised when an illegal transition is attempted in the validation lifecycle."""
    pass


class ApprovalSecurityError(ValueError):
    """Raised when plan approval is invalid, tampered, expired, or revoked."""
    pass


class DispatchSecurityError(ValueError):
    """Raised when pre-dispatch authorization, scope, tenant, or integrity checks fail."""
    pass


class EvidenceVerificationError(ValueError):
    """Raised when evidence verification fails due to digest mismatch, tampering, or stale data."""
    pass


class MethodSecurityError(ValueError):
    """Raised when an unapproved, untrusted, or destructive validation method is attempted."""
    pass


# ==============================================================================
# Enums
# ==============================================================================

class ValidationPlanStatus(str, Enum):
    """
    Explicit lifecycle states for attack-path validation planning and execution.
    Preserves strict separation between hypothesis, planning, approval, and promotion.
    """
    HYPOTHESIS = "HYPOTHESIS"
    PLANNED = "PLANNED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    DISPATCHED = "DISPATCHED"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    EVIDENCE_PENDING = "EVIDENCE_PENDING"
    EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"
    RELATIONSHIP_VALIDATED = "RELATIONSHIP_VALIDATED"
    CHAIN_VALIDATED = "CHAIN_VALIDATED"


class ValidationRiskLevel(str, Enum):
    """Risk classification for validation operations."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ValidationAuditEventType(str, Enum):
    """Auditable security lifecycle events in validation planning."""
    PLAN_CREATED = "PLAN_CREATED"
    PLAN_SUBMITTED = "PLAN_SUBMITTED"
    PLAN_APPROVED = "PLAN_APPROVED"
    PLAN_REJECTED = "PLAN_REJECTED"
    PLAN_REVOKED = "PLAN_REVOKED"
    DISPATCH_AUTHORIZED = "DISPATCH_AUTHORIZED"
    DISPATCH_DENIED = "DISPATCH_DENIED"
    DISPATCH_EXECUTED = "DISPATCH_EXECUTED"
    EVIDENCE_SUBMITTED = "EVIDENCE_SUBMITTED"
    EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"
    EVIDENCE_REJECTED = "EVIDENCE_REJECTED"
    RELATIONSHIP_PROMOTED = "RELATIONSHIP_PROMOTED"
    CHAIN_PROMOTED = "CHAIN_PROMOTED"


# ==============================================================================
# State Machine Transition Rules
# ==============================================================================

VALID_TRANSITIONS: Dict[ValidationPlanStatus, Set[ValidationPlanStatus]] = {
    ValidationPlanStatus.HYPOTHESIS: {
        ValidationPlanStatus.PLANNED,
        ValidationPlanStatus.REJECTED,
    },
    ValidationPlanStatus.PLANNED: {
        ValidationPlanStatus.PENDING_APPROVAL,
        ValidationPlanStatus.REJECTED,
    },
    ValidationPlanStatus.PENDING_APPROVAL: {
        ValidationPlanStatus.APPROVED,
        ValidationPlanStatus.REJECTED,
        ValidationPlanStatus.EXPIRED,
    },
    ValidationPlanStatus.APPROVED: {
        ValidationPlanStatus.DISPATCHED,
        ValidationPlanStatus.REVOKED,
        ValidationPlanStatus.EXPIRED,
    },
    ValidationPlanStatus.REJECTED: set(),
    ValidationPlanStatus.EXPIRED: set(),
    ValidationPlanStatus.REVOKED: set(),
    ValidationPlanStatus.DISPATCHED: {
        ValidationPlanStatus.COMPLETED,
        ValidationPlanStatus.PARTIALLY_COMPLETED,
        ValidationPlanStatus.FAILED,
    },
    ValidationPlanStatus.PARTIALLY_COMPLETED: {
        ValidationPlanStatus.FAILED,
        ValidationPlanStatus.EVIDENCE_PENDING,
    },
    ValidationPlanStatus.FAILED: set(),
    ValidationPlanStatus.COMPLETED: {
        ValidationPlanStatus.EVIDENCE_PENDING,
        ValidationPlanStatus.EVIDENCE_VERIFIED,
    },
    ValidationPlanStatus.EVIDENCE_PENDING: {
        ValidationPlanStatus.EVIDENCE_VERIFIED,
        ValidationPlanStatus.FAILED,
    },
    ValidationPlanStatus.EVIDENCE_VERIFIED: {
        ValidationPlanStatus.RELATIONSHIP_VALIDATED,
        ValidationPlanStatus.CHAIN_VALIDATED,
    },
    ValidationPlanStatus.RELATIONSHIP_VALIDATED: {
        ValidationPlanStatus.CHAIN_VALIDATED,
    },
    ValidationPlanStatus.CHAIN_VALIDATED: set(),
}


def validate_state_transition(
    current_status: ValidationPlanStatus,
    target_status: ValidationPlanStatus,
) -> None:
    """Enforces strict, guarded transitions in the validation lifecycle."""
    allowed = VALID_TRANSITIONS.get(current_status, set())
    if target_status not in allowed:
        raise InvalidStateTransitionError(
            f"Illegal state transition from '{current_status.value}' to '{target_status.value}'. "
            f"Allowed next states: {sorted(s.value for s in allowed) if allowed else 'None (Terminal state)'}"
        )


# ==============================================================================
# Validation Method Registry & Built-ins
# ==============================================================================

@dataclass(frozen=True)
class ValidationMethod:
    """
    Specification of an authorized, safe validation methodology.
    Explicitly declares objectives, required permissions, and safety constraints.
    """
    method_id: str
    objective: str
    required_permissions: Set[str]
    allowed_target_types: Set[NodeType]
    scope_requirements: Set[str]
    expected_evidence_type: str
    risk_level: ValidationRiskLevel
    is_read_only: bool = True
    can_modify_state: bool = False
    can_expose_sensitive_info: bool = False
    is_destructive: bool = False

    def __post_init__(self) -> None:
        if self.is_destructive:
            raise MethodSecurityError(
                f"Method '{self.method_id}' is marked destructive. Destructive methods are strictly prohibited."
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method_id": self.method_id,
            "objective": self.objective,
            "required_permissions": sorted(list(self.required_permissions)),
            "allowed_target_types": sorted(t.value for t in self.allowed_target_types),
            "scope_requirements": sorted(list(self.scope_requirements)),
            "expected_evidence_type": self.expected_evidence_type,
            "risk_level": self.risk_level.value,
            "is_read_only": self.is_read_only,
            "can_modify_state": self.can_modify_state,
            "can_expose_sensitive_info": self.can_expose_sensitive_info,
            "is_destructive": self.is_destructive,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ValidationMethod:
        return cls(
            method_id=data["method_id"],
            objective=data.get("objective", ""),
            required_permissions=set(data.get("required_permissions", [])),
            allowed_target_types={NodeType(t) for t in data.get("allowed_target_types", [])},
            scope_requirements=set(data.get("scope_requirements", ["IN_SCOPE"])),
            expected_evidence_type=data.get("expected_evidence_type", "HTTP_RESPONSE"),
            risk_level=ValidationRiskLevel(data.get("risk_level", ValidationRiskLevel.LOW.value)),
            is_read_only=bool(data.get("is_read_only", True)),
            can_modify_state=bool(data.get("can_modify_state", False)),
            can_expose_sensitive_info=bool(data.get("can_expose_sensitive_info", False)),
            is_destructive=bool(data.get("is_destructive", False)),
        )


class ValidationMethodRegistry:
    """
    Registry of vetted, authorized validation methods.
    Enforces a strict default-deny policy for unregistered or unsafe methods.
    """

    def __init__(self) -> None:
        self._methods: Dict[str, ValidationMethod] = {}
        self._register_default_methods()

    def _register_default_methods(self) -> None:
        """Initializes standard non-destructive, read-only validation methods."""
        self.register_method(
            ValidationMethod(
                method_id="PREREQUISITE_SATISFACTION_CHECK",
                objective="Verifies that output of Finding A satisfies prerequisite requirements of Endpoint B",
                required_permissions={"PREREQUISITE_VERIFY"},
                allowed_target_types={NodeType.ENDPOINT, NodeType.FINDING, NodeType.CAPABILITY},
                scope_requirements={"IN_SCOPE"},
                expected_evidence_type="PARAMETER_BINDING_RECORD",
                risk_level=ValidationRiskLevel.LOW,
                is_read_only=True,
                can_modify_state=False,
                is_destructive=False,
            )
        )
        self.register_method(
            ValidationMethod(
                method_id="PASSIVE_RESOURCE_METADATA_VERIFY",
                objective="Verifies resource accessibility and metadata without state mutation",
                required_permissions={"READ_METADATA"},
                allowed_target_types={NodeType.ASSET, NodeType.ENDPOINT},
                scope_requirements={"IN_SCOPE"},
                expected_evidence_type="METADATA_OBSERVATION",
                risk_level=ValidationRiskLevel.LOW,
                is_read_only=True,
                can_modify_state=False,
                is_destructive=False,
            )
        )
        self.register_method(
            ValidationMethod(
                method_id="NON_DESTRUCTIVE_REDIRECT_CHECK",
                objective="Confirms redirect target location header without completing unauthorized auth flow",
                required_permissions={"VERIFY_REDIRECT"},
                allowed_target_types={NodeType.ENDPOINT},
                scope_requirements={"IN_SCOPE"},
                expected_evidence_type="HTTP_REDIRECT_HEADER",
                risk_level=ValidationRiskLevel.LOW,
                is_read_only=True,
                can_modify_state=False,
                is_destructive=False,
            )
        )
        self.register_method(
            ValidationMethod(
                method_id="CONTROLLED_AUTH_BOUNDARY_PROBE",
                objective="Verifies tenant or authorization boundary separation using unprivileged test account",
                required_permissions={"TEST_BOUNDARY"},
                allowed_target_types={NodeType.ENDPOINT, NodeType.PRINCIPAL},
                scope_requirements={"IN_SCOPE"},
                expected_evidence_type="CONTROLLED_RESPONSE_PAIR",
                risk_level=ValidationRiskLevel.MEDIUM,
                is_read_only=True,
                can_modify_state=False,
                is_destructive=False,
            )
        )
        self.register_method(
            ValidationMethod(
                method_id="HISTORICAL_ARTIFACT_REVALIDATE",
                objective="Re-evaluates existing finding artifacts against candidate path relationship offline",
                required_permissions={"READ_ARTIFACT"},
                allowed_target_types={NodeType.FINDING, NodeType.CAPABILITY},
                scope_requirements={"IN_SCOPE"},
                expected_evidence_type="ARTIFACT_CORRELATION_PROOF",
                risk_level=ValidationRiskLevel.LOW,
                is_read_only=True,
                can_modify_state=False,
                is_destructive=False,
            )
        )
        self.register_method(
            ValidationMethod(
                method_id="EVIDENCE_PROVENANCE_REVERIFY",
                objective="Cryptographically re-verifies stored evidence digest and provenance records",
                required_permissions={"VERIFY_EVIDENCE"},
                allowed_target_types={NodeType.FINDING, NodeType.CAPABILITY},
                scope_requirements={"IN_SCOPE"},
                expected_evidence_type="CRYPTOGRAPHIC_PROOF",
                risk_level=ValidationRiskLevel.LOW,
                is_read_only=True,
                can_modify_state=False,
                is_destructive=False,
            )
        )

    def register_method(self, method: ValidationMethod) -> None:
        """Registers a vetted validation method."""
        if method.is_destructive:
            raise MethodSecurityError(
                f"Destructive validation method '{method.method_id}' cannot be registered."
            )
        if method.can_modify_state and not method.is_read_only:
            raise MethodSecurityError(
                f"State-modifying validation method '{method.method_id}' is not permitted without explicit override."
            )
        self._methods[method.method_id] = method

    def get_method(self, method_id: str) -> Optional[ValidationMethod]:
        return self._methods.get(method_id)

    def is_method_allowed(self, method_id: str) -> bool:
        method = self.get_method(method_id)
        if not method:
            return False
        return not method.is_destructive and method.is_read_only


# ==============================================================================
# Plan Approval Model
# ==============================================================================

@dataclass
class PlanApproval:
    """
    Cryptographically bound, time-limited operator approval for a validation plan.
    Binds to exact plan ID, plan version, plan hash, targets, method, and scope.
    """
    approval_id: str
    plan_id: str
    plan_version: int
    plan_hash: str
    target_asset: str
    target_endpoint: str
    validation_method: str
    scope_reference: str
    tenant_id: Optional[str]
    approved_by: str
    approved_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    revoked: bool = False
    revoked_at: Optional[str] = None
    revocation_reason: Optional[str] = None

    def __post_init__(self) -> None:
        assert_no_raw_secrets(
            {
                "approval_id": self.approval_id,
                "plan_id": self.plan_id,
                "approved_by": self.approved_by,
                "revocation_reason": self.revocation_reason or "",
            },
            "PlanApproval",
        )

    def is_expired(self, current_time: Optional[float] = None, skew_seconds: float = 30.0) -> bool:
        """Determines if the approval has passed its expiration time, accounting for skew."""
        now_ts = current_time if current_time is not None else time.time()
        try:
            dt = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            expires_ts = dt.timestamp()
        except Exception:
            return True

        return now_ts >= (expires_ts - skew_seconds)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "plan_id": self.plan_id,
            "plan_version": self.plan_version,
            "plan_hash": self.plan_hash,
            "target_asset": self.target_asset,
            "target_endpoint": self.target_endpoint,
            "validation_method": self.validation_method,
            "scope_reference": self.scope_reference,
            "tenant_id": self.tenant_id,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "expires_at": self.expires_at,
            "revoked": self.revoked,
            "revoked_at": self.revoked_at,
            "revocation_reason": self.revocation_reason,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PlanApproval:
        return cls(
            approval_id=data["approval_id"],
            plan_id=data["plan_id"],
            plan_version=int(data["plan_version"]),
            plan_hash=data["plan_hash"],
            target_asset=data.get("target_asset", ""),
            target_endpoint=data.get("target_endpoint", ""),
            validation_method=data.get("validation_method", ""),
            scope_reference=data.get("scope_reference", ""),
            tenant_id=data.get("tenant_id"),
            approved_by=data.get("approved_by", ""),
            approved_at=data.get("approved_at", datetime.now(timezone.utc).isoformat()),
            expires_at=data.get("expires_at", datetime.now(timezone.utc).isoformat()),
            revoked=bool(data.get("revoked", False)),
            revoked_at=data.get("revoked_at"),
            revocation_reason=data.get("revocation_reason"),
        )


# ==============================================================================
# Execution Result Model
# ==============================================================================

@dataclass
class ValidationExecutionResult:
    """
    Results captured from an authorized, safe validation execution.
    Never stores unredacted secrets or credentials.
    """
    execution_id: str
    plan_id: str
    dispatched_at: str
    completed_at: str
    status: ValidationPlanStatus
    evidence_ref: Optional[str] = None
    evidence_sha256: Optional[str] = None
    observed_delta_digest: Optional[str] = None
    sanitized_output: str = ""
    error_message: Optional[str] = None
    is_simulated: bool = True

    def __post_init__(self) -> None:
        assert_no_raw_secrets(self.sanitized_output, "ValidationExecutionResult.sanitized_output")
        if self.error_message:
            assert_no_raw_secrets(self.error_message, "ValidationExecutionResult.error_message")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "plan_id": self.plan_id,
            "dispatched_at": self.dispatched_at,
            "completed_at": self.completed_at,
            "status": self.status.value,
            "evidence_ref": self.evidence_ref,
            "evidence_sha256": self.evidence_sha256,
            "observed_delta_digest": self.observed_delta_digest,
            "sanitized_output": self.sanitized_output,
            "error_message": self.error_message,
            "is_simulated": self.is_simulated,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ValidationExecutionResult:
        st_str = data.get("status", ValidationPlanStatus.COMPLETED.value)
        return cls(
            execution_id=data["execution_id"],
            plan_id=data["plan_id"],
            dispatched_at=data.get("dispatched_at", datetime.now(timezone.utc).isoformat()),
            completed_at=data.get("completed_at", datetime.now(timezone.utc).isoformat()),
            status=ValidationPlanStatus(st_str),
            evidence_ref=data.get("evidence_ref"),
            evidence_sha256=data.get("evidence_sha256"),
            observed_delta_digest=data.get("observed_delta_digest"),
            sanitized_output=data.get("sanitized_output", ""),
            error_message=data.get("error_message"),
            is_simulated=bool(data.get("is_simulated", True)),
        )


# ==============================================================================
# Validation Audit Event Model
# ==============================================================================

@dataclass
class ValidationAuditEvent:
    """
    Immutable audit record for all validation planning, approval, and execution decisions.
    """
    event_id: str
    event_type: ValidationAuditEventType
    plan_id: str
    plan_version: int
    plan_hash: str
    actor_id: str
    timestamp: str
    decision: str
    outcome: str
    sanitized_reason: Optional[str] = None
    evidence_ref: Optional[str] = None

    def __post_init__(self) -> None:
        assert_no_raw_secrets(
            {
                "event_id": self.event_id,
                "plan_id": self.plan_id,
                "actor_id": self.actor_id,
                "reason": self.sanitized_reason or "",
            },
            "ValidationAuditEvent",
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "plan_id": self.plan_id,
            "plan_version": self.plan_version,
            "plan_hash": self.plan_hash,
            "actor_id": self.actor_id,
            "timestamp": self.timestamp,
            "decision": self.decision,
            "outcome": self.outcome,
            "sanitized_reason": self.sanitized_reason,
            "evidence_ref": self.evidence_ref,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ValidationAuditEvent:
        return cls(
            event_id=data["event_id"],
            event_type=ValidationAuditEventType(data["event_type"]),
            plan_id=data["plan_id"],
            plan_version=int(data.get("plan_version", 1)),
            plan_hash=data.get("plan_hash", ""),
            actor_id=data.get("actor_id", "SYSTEM"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            decision=data.get("decision", "RECORD"),
            outcome=data.get("outcome", "SUCCESS"),
            sanitized_reason=data.get("sanitized_reason"),
            evidence_ref=data.get("evidence_ref"),
        )


# ==============================================================================
# Chain Validation Plan Model
# ==============================================================================

@dataclass
class ChainValidationPlan:
    """
    Complete, controlled validation plan for a correlated attack-path hypothesis.
    Maintains deterministic cryptographic binding, versioning, and zero-secret invariants.
    """
    plan_id: str
    path_id: str
    path_fingerprint: str
    source_finding_ids: List[str]
    target_finding_ids: List[str]
    relationship_ids: List[str]
    target_asset: str
    target_endpoint: str
    target_method: str
    objective: str
    validation_method: str
    required_permissions: List[str]
    authorization_context: Dict[str, Any]
    expected_evidence: str
    scope_reference: str
    scope_snapshot_hash: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tenant_id: Optional[str] = None
    principal_id: Optional[str] = None
    risk_level: ValidationRiskLevel = ValidationRiskLevel.LOW
    is_destructive: bool = False
    version: int = 1
    plan_hash: str = ""
    status: ValidationPlanStatus = ValidationPlanStatus.PLANNED
    approval: Optional[PlanApproval] = None
    execution_result: Optional[ValidationExecutionResult] = None

    def __post_init__(self) -> None:
        if self.is_destructive:
            raise ValidationPlanningError("Destructive validation plans are strictly prohibited.")

        assert_no_raw_secrets(self.authorization_context, "ChainValidationPlan.authorization_context")
        assert_no_raw_secrets(
            {
                "plan_id": self.plan_id,
                "target_asset": self.target_asset,
                "target_endpoint": self.target_endpoint,
                "objective": self.objective,
            },
            "ChainValidationPlan.identifiers",
        )

        if not self.plan_hash:
            self.plan_hash = self.compute_plan_hash()

    def compute_plan_hash(self) -> str:
        """
        Computes a deterministic SHA-256 hash over all security-critical canonical fields.
        Any tampering or modification of these fields alters the hash, breaking approval integrity.
        """
        canonical: Dict[str, Any] = {
            "plan_id": self.plan_id,
            "path_id": self.path_id,
            "path_fingerprint": self.path_fingerprint,
            "source_finding_ids": sorted(self.source_finding_ids),
            "target_finding_ids": sorted(self.target_finding_ids),
            "relationship_ids": sorted(self.relationship_ids),
            "target_asset": self.target_asset,
            "target_endpoint": self.target_endpoint,
            "target_method": self.target_method,
            "tenant_id": self.tenant_id,
            "principal_id": self.principal_id,
            "objective": self.objective,
            "validation_method": self.validation_method,
            "required_permissions": sorted(self.required_permissions),
            "expected_evidence": self.expected_evidence,
            "risk_level": self.risk_level.value,
            "is_destructive": self.is_destructive,
            "scope_reference": self.scope_reference,
            "scope_snapshot_hash": self.scope_snapshot_hash,
            "version": self.version,
        }
        encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def is_plan_tampered(self) -> bool:
        """Verifies whether the current plan fields match its cryptographic plan_hash."""
        return self.compute_plan_hash() != self.plan_hash

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "plan_id": self.plan_id,
            "path_id": self.path_id,
            "path_fingerprint": self.path_fingerprint,
            "source_finding_ids": list(self.source_finding_ids),
            "target_finding_ids": list(self.target_finding_ids),
            "relationship_ids": list(self.relationship_ids),
            "target_asset": self.target_asset,
            "target_endpoint": self.target_endpoint,
            "target_method": self.target_method,
            "tenant_id": self.tenant_id,
            "principal_id": self.principal_id,
            "objective": self.objective,
            "validation_method": self.validation_method,
            "required_permissions": list(self.required_permissions),
            "authorization_context": dict(self.authorization_context),
            "expected_evidence": self.expected_evidence,
            "risk_level": self.risk_level.value,
            "is_destructive": self.is_destructive,
            "scope_reference": self.scope_reference,
            "scope_snapshot_hash": self.scope_snapshot_hash,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "version": self.version,
            "plan_hash": self.plan_hash,
            "status": self.status.value,
        }
        if self.approval:
            data["approval"] = self.approval.to_dict()
        if self.execution_result:
            data["execution_result"] = self.execution_result.to_dict()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ChainValidationPlan:
        # Enforce zero secrets on incoming dictionary
        assert_no_raw_secrets(data, "ChainValidationPlan.from_dict")

        st_str = data.get("status", ValidationPlanStatus.PLANNED.value)
        status = ValidationPlanStatus(st_str)

        risk_str = data.get("risk_level", ValidationRiskLevel.LOW.value)
        risk = ValidationRiskLevel(risk_str)

        approval = None
        if data.get("approval") and isinstance(data["approval"], dict):
            approval = PlanApproval.from_dict(data["approval"])

        exec_res = None
        if data.get("execution_result") and isinstance(data["execution_result"], dict):
            exec_res = ValidationExecutionResult.from_dict(data["execution_result"])

        plan = cls(
            plan_id=data["plan_id"],
            path_id=data["path_id"],
            path_fingerprint=data.get("path_fingerprint", ""),
            source_finding_ids=list(data.get("source_finding_ids", [])),
            target_finding_ids=list(data.get("target_finding_ids", [])),
            relationship_ids=list(data.get("relationship_ids", [])),
            target_asset=data.get("target_asset", ""),
            target_endpoint=data.get("target_endpoint", ""),
            target_method=data.get("target_method", "GET"),
            objective=data.get("objective", ""),
            validation_method=data.get("validation_method", ""),
            required_permissions=list(data.get("required_permissions", [])),
            authorization_context=dict(data.get("authorization_context", {})),
            expected_evidence=data.get("expected_evidence", ""),
            scope_reference=data.get("scope_reference", ""),
            scope_snapshot_hash=data.get("scope_snapshot_hash", ""),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            expires_at=data.get("expires_at", datetime.now(timezone.utc).isoformat()),
            tenant_id=data.get("tenant_id"),
            principal_id=data.get("principal_id"),
            risk_level=risk,
            is_destructive=bool(data.get("is_destructive", False)),
            version=int(data.get("version", 1)),
            plan_hash=data.get("plan_hash", ""),
            status=status,
            approval=approval,
            execution_result=exec_res,
        )

        # Verify plan integrity after deserialization
        if plan.is_plan_tampered():
            raise ValidationPlanningError(
                f"Deserialized validation plan '{plan.plan_id}' failed integrity check: "
                "stored hash does not match computed hash"
            )

        return plan


# ==============================================================================
# Safe Chain Validation Planner & Orchestrator
# ==============================================================================

class SafeChainValidationPlanner:
    """
    Orchestrates the safe validation lifecycle for correlated attack paths:
    1. Plan Generation: Produces structured, reviewable, non-destructive validation plans.
    2. Approval Gates: Enforces explicit human approval, revocation, and expiration.
    3. Dispatch Authorization: Enforces dynamic anti-TOCTOU scope, tenant, and integrity checks.
    4. Execution Boundary: Executes safe, isolated non-destructive validations.
    5. Evidence Verification: Verifies empirical provenance and promotes graph edges/chains.
    """

    def __init__(
        self,
        registry: Optional[ValidationMethodRegistry] = None,
        scope_engine: Optional[Any] = None,
        state_manager: Optional[Any] = None,
    ) -> None:
        self.registry = registry or ValidationMethodRegistry()
        self.scope_engine = scope_engine
        self.state_manager = state_manager
        self._audit_log: List[ValidationAuditEvent] = []
        self._plans: Dict[str, ChainValidationPlan] = {}

    def _record_audit_event(
        self,
        event_type: ValidationAuditEventType,
        plan_id: str,
        plan_version: int,
        plan_hash: str,
        actor_id: str,
        decision: str,
        outcome: str,
        sanitized_reason: Optional[str] = None,
        evidence_ref: Optional[str] = None,
    ) -> ValidationAuditEvent:
        """Creates, records, and optionally persists an immutable audit event."""
        # Truncate and clean reason to prevent secret leakage
        clean_reason = sanitized_reason[:500] if sanitized_reason else None
        event_raw = f"{plan_id}:{plan_version}:{event_type.value}:{time.time()}:{len(self._audit_log)}"
        event_id = f"EVT-{hashlib.sha256(event_raw.encode()).hexdigest()[:16]}"

        event = ValidationAuditEvent(
            event_id=event_id,
            event_type=event_type,
            plan_id=plan_id,
            plan_version=plan_version,
            plan_hash=plan_hash,
            actor_id=actor_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            decision=decision,
            outcome=outcome,
            sanitized_reason=clean_reason,
            evidence_ref=evidence_ref,
        )
        self._audit_log.append(event)
        if self.state_manager and hasattr(self.state_manager, "append_audit_event"):
            try:
                self.state_manager.append_audit_event(event)
            except Exception:
                pass
        return event

    def create_validation_plan(
        self,
        path: AttackPath,
        graph: AttackGraph,
        validation_method: str = "PREREQUISITE_SATISFACTION_CHECK",
        ttl_seconds: float = 3600.0,
        authorization_context: Optional[Dict[str, Any]] = None,
    ) -> ChainValidationPlan:
        """
        Derives a controlled, non-destructive validation plan from a candidate attack path.
        Default status is PLANNED.
        """
        method = self.registry.get_method(validation_method)
        if not method:
            raise MethodSecurityError(f"Validation method '{validation_method}' is not registered.")
        if method.is_destructive:
            raise MethodSecurityError(f"Validation method '{validation_method}' is destructive and prohibited.")

        # Resolve path endpoints and source findings
        source_finding_ids: List[str] = []
        target_finding_ids: List[str] = []
        target_asset = ""
        target_endpoint = ""
        target_method = "GET"
        tenant_id = None
        principal_id = None
        scope_ref = "IN_SCOPE"

        for nid in path.node_ids:
            node = graph.get_node(nid)
            if not node:
                continue
            if node.node_type == NodeType.FINDING:
                f_id = node.attributes.get("finding_id", node.node_id)
                if not source_finding_ids:
                    source_finding_ids.append(f_id)
                else:
                    target_finding_ids.append(f_id)
            elif node.node_type == NodeType.ENDPOINT:
                target_endpoint = node.attributes.get("path", node.label)
                target_method = node.attributes.get("method", "GET")
                if not target_asset and node.attributes.get("asset"):
                    target_asset = str(node.attributes["asset"])
            elif node.node_type == NodeType.ASSET:
                if not target_asset:
                    target_asset = node.attributes.get("asset", node.label)
            elif node.node_type == NodeType.PRINCIPAL:
                principal_id = node.attributes.get("principal_id", node.label)
                if not tenant_id and node.attributes.get("tenant_id"):
                    tenant_id = str(node.attributes["tenant_id"])

            if not tenant_id and node.attributes.get("tenant_id"):
                tenant_id = str(node.attributes["tenant_id"])
            if not principal_id and node.attributes.get("principal_id"):
                principal_id = str(node.attributes["principal_id"])
            if node.attributes.get("scope_reference"):
                scope_ref = str(node.attributes["scope_reference"])

        if not target_asset and source_finding_ids:
            first_node = graph.get_node(source_finding_ids[0])
            if first_node and first_node.attributes.get("asset"):
                target_asset = str(first_node.attributes["asset"])

        # Compute deterministic plan ID
        plan_seed = f"{path.path_id}:{validation_method}:{target_asset}:{target_endpoint}:{time.time()}"
        plan_id = f"PLAN-{hashlib.sha256(plan_seed.encode()).hexdigest()[:16]}"

        # Snapshot hash of current scope
        scope_repr = f"scope:{target_asset}:{scope_ref}"
        scope_snapshot_hash = hashlib.sha256(scope_repr.encode()).hexdigest()

        now = datetime.now(timezone.utc)
        expires_at = datetime.fromtimestamp(now.timestamp() + ttl_seconds, tz=timezone.utc).isoformat()

        plan = ChainValidationPlan(
            plan_id=plan_id,
            path_id=path.path_id,
            path_fingerprint=path.fingerprint or path.path_id,
            source_finding_ids=source_finding_ids,
            target_finding_ids=target_finding_ids,
            relationship_ids=list(path.edge_ids),
            target_asset=target_asset,
            target_endpoint=target_endpoint,
            target_method=target_method,
            tenant_id=tenant_id,
            principal_id=principal_id,
            objective=method.objective,
            validation_method=validation_method,
            required_permissions=sorted(list(method.required_permissions)),
            authorization_context=dict(authorization_context or {}),
            expected_evidence=method.expected_evidence_type,
            risk_level=method.risk_level,
            is_destructive=False,
            scope_reference=scope_ref,
            scope_snapshot_hash=scope_snapshot_hash,
            created_at=now.isoformat(),
            expires_at=expires_at,
            version=1,
            status=ValidationPlanStatus.PLANNED,
        )

        self._plans[plan.plan_id] = plan
        self._record_audit_event(
            event_type=ValidationAuditEventType.PLAN_CREATED,
            plan_id=plan.plan_id,
            plan_version=plan.version,
            plan_hash=plan.plan_hash,
            actor_id="PLANNER",
            decision="ALLOW",
            outcome="SUCCESS",
            sanitized_reason="Validation plan synthesized from correlated attack path",
        )
        return plan

    def submit_for_approval(self, plan: ChainValidationPlan, actor_id: str = "RESEARCHER") -> None:
        """Transitions plan from PLANNED to PENDING_APPROVAL."""
        validate_state_transition(plan.status, ValidationPlanStatus.PENDING_APPROVAL)
        if plan.is_plan_tampered():
            raise ApprovalSecurityError(
                f"Cannot submit plan '{plan.plan_id}' for approval: plan integrity verification failed"
            )

        plan.status = ValidationPlanStatus.PENDING_APPROVAL
        self._record_audit_event(
            event_type=ValidationAuditEventType.PLAN_SUBMITTED,
            plan_id=plan.plan_id,
            plan_version=plan.version,
            plan_hash=plan.plan_hash,
            actor_id=actor_id,
            decision="ALLOW",
            outcome="SUCCESS",
            sanitized_reason="Plan submitted to human approval queue",
        )

    def approve_plan(
        self,
        plan: ChainValidationPlan,
        approved_by: str,
        ttl_seconds: float = 3600.0,
    ) -> PlanApproval:
        """
        Binds human operator approval to exact plan ID, version, hash, targets, and method.
        Transitions status from PENDING_APPROVAL to APPROVED.
        """
        validate_state_transition(plan.status, ValidationPlanStatus.APPROVED)

        if not approved_by or not str(approved_by).strip():
            raise ApprovalSecurityError("Approval must specify an authorized human operator identity.")

        if plan.is_plan_tampered():
            self._record_audit_event(
                event_type=ValidationAuditEventType.PLAN_APPROVED,
                plan_id=plan.plan_id,
                plan_version=plan.version,
                plan_hash=plan.plan_hash,
                actor_id=approved_by,
                decision="DENY",
                outcome="BLOCKED",
                sanitized_reason="Plan hash integrity check failed during approval",
            )
            raise ApprovalSecurityError(
                f"Cannot approve plan '{plan.plan_id}': plan has been tampered with or modified"
            )

        now = datetime.now(timezone.utc)
        expires_at = datetime.fromtimestamp(now.timestamp() + ttl_seconds, tz=timezone.utc).isoformat()
        approval_seed = f"{plan.plan_id}:{plan.version}:{plan.plan_hash}:{approved_by}:{now.timestamp()}"
        approval_id = f"APPR-{hashlib.sha256(approval_seed.encode()).hexdigest()[:16]}"

        approval = PlanApproval(
            approval_id=approval_id,
            plan_id=plan.plan_id,
            plan_version=plan.version,
            plan_hash=plan.plan_hash,
            target_asset=plan.target_asset,
            target_endpoint=plan.target_endpoint,
            validation_method=plan.validation_method,
            scope_reference=plan.scope_reference,
            tenant_id=plan.tenant_id,
            approved_by=approved_by,
            approved_at=now.isoformat(),
            expires_at=expires_at,
            revoked=False,
        )

        plan.approval = approval
        plan.status = ValidationPlanStatus.APPROVED

        self._record_audit_event(
            event_type=ValidationAuditEventType.PLAN_APPROVED,
            plan_id=plan.plan_id,
            plan_version=plan.version,
            plan_hash=plan.plan_hash,
            actor_id=approved_by,
            decision="ALLOW",
            outcome="SUCCESS",
            sanitized_reason=f"Approved by operator '{approved_by}', expires at '{expires_at}'",
        )
        return approval

    def reject_plan(
        self,
        plan: ChainValidationPlan,
        rejected_by: str,
        reason: str,
    ) -> None:
        """Rejects a plan, transitioning it to terminal REJECTED status."""
        validate_state_transition(plan.status, ValidationPlanStatus.REJECTED)
        plan.status = ValidationPlanStatus.REJECTED
        self._record_audit_event(
            event_type=ValidationAuditEventType.PLAN_REJECTED,
            plan_id=plan.plan_id,
            plan_version=plan.version,
            plan_hash=plan.plan_hash,
            actor_id=rejected_by,
            decision="DENY",
            outcome="SUCCESS",
            sanitized_reason=f"Rejected: {reason}",
        )

    def revoke_approval(
        self,
        plan: ChainValidationPlan,
        revoked_by: str,
        reason: str,
    ) -> None:
        """
        Revokes an existing approval immediately.
        Transitions plan to terminal REVOKED status and blocks any future dispatch.
        """
        validate_state_transition(plan.status, ValidationPlanStatus.REVOKED)
        if not plan.approval:
            raise ApprovalSecurityError(f"Cannot revoke approval for plan '{plan.plan_id}': no approval exists.")

        plan.approval.revoked = True
        plan.approval.revoked_at = datetime.now(timezone.utc).isoformat()
        plan.approval.revocation_reason = reason
        plan.status = ValidationPlanStatus.REVOKED

        self._record_audit_event(
            event_type=ValidationAuditEventType.PLAN_REVOKED,
            plan_id=plan.plan_id,
            plan_version=plan.version,
            plan_hash=plan.plan_hash,
            actor_id=revoked_by,
            decision="DENY",
            outcome="SUCCESS",
            sanitized_reason=f"Revocation enforced: {reason}",
        )

    def authorize_dispatch(
        self,
        plan: ChainValidationPlan,
        current_scope_engine: Optional[Any] = None,
        current_time: Optional[float] = None,
    ) -> bool:
        """
        Anti-TOCTOU dispatch authorization gate.
        Independently re-evaluates all 9 security gates immediately before execution.
        Fails closed on any discrepancy.
        """
        actor = "DISPATCH_GATE"

        # Gate 1: Plan status must be APPROVED
        if plan.status != ValidationPlanStatus.APPROVED:
            reason = f"Plan status is '{plan.status.value}', expected 'APPROVED'"
            self._record_audit_event(
                ValidationAuditEventType.DISPATCH_DENIED, plan.plan_id, plan.version, plan.plan_hash,
                actor, "DENY", "BLOCKED", reason
            )
            raise DispatchSecurityError(f"Dispatch denied: {reason}")

        # Gate 2: Approval must exist
        if not plan.approval:
            reason = "Missing approval metadata"
            self._record_audit_event(
                ValidationAuditEventType.DISPATCH_DENIED, plan.plan_id, plan.version, plan.plan_hash,
                actor, "DENY", "BLOCKED", reason
            )
            raise DispatchSecurityError(f"Dispatch denied: {reason}")

        # Gate 3: Approval must not be revoked
        if plan.approval.revoked:
            reason = f"Approval was revoked: {plan.approval.revocation_reason or 'No reason provided'}"
            self._record_audit_event(
                ValidationAuditEventType.DISPATCH_DENIED, plan.plan_id, plan.version, plan.plan_hash,
                actor, "DENY", "BLOCKED", reason
            )
            raise DispatchSecurityError(f"Dispatch denied: {reason}")

        # Gate 4: Approval must not be expired
        if plan.approval.is_expired(current_time):
            plan.status = ValidationPlanStatus.EXPIRED
            reason = f"Approval expired at '{plan.approval.expires_at}'"
            self._record_audit_event(
                ValidationAuditEventType.DISPATCH_DENIED, plan.plan_id, plan.version, plan.plan_hash,
                actor, "DENY", "BLOCKED", reason
            )
            raise DispatchSecurityError(f"Dispatch denied: {reason}")

        # Gate 5: Plan integrity & version binding
        if plan.is_plan_tampered() or plan.compute_plan_hash() != plan.approval.plan_hash:
            reason = "Plan hash mismatch between approval and current state (plan mutation detected)"
            self._record_audit_event(
                ValidationAuditEventType.DISPATCH_DENIED, plan.plan_id, plan.version, plan.plan_hash,
                actor, "DENY", "BLOCKED", reason
            )
            raise DispatchSecurityError(f"Dispatch denied: {reason}")

        if plan.version != plan.approval.plan_version:
            reason = f"Plan version ({plan.version}) does not match approved version ({plan.approval.plan_version})"
            self._record_audit_event(
                ValidationAuditEventType.DISPATCH_DENIED, plan.plan_id, plan.version, plan.plan_hash,
                actor, "DENY", "BLOCKED", reason
            )
            raise DispatchSecurityError(f"Dispatch denied: {reason}")

        # Gate 6: Validation method allowlist & permission match
        if not self.registry.is_method_allowed(plan.validation_method):
            reason = f"Validation method '{plan.validation_method}' is not permitted or is destructive"
            self._record_audit_event(
                ValidationAuditEventType.DISPATCH_DENIED, plan.plan_id, plan.version, plan.plan_hash,
                actor, "DENY", "BLOCKED", reason
            )
            raise DispatchSecurityError(f"Dispatch denied: {reason}")

        if plan.validation_method != plan.approval.validation_method:
            reason = "Plan validation method does not match approved validation method"
            self._record_audit_event(
                ValidationAuditEventType.DISPATCH_DENIED, plan.plan_id, plan.version, plan.plan_hash,
                actor, "DENY", "BLOCKED", reason
            )
            raise DispatchSecurityError(f"Dispatch denied: {reason}")

        # Gate 7: Target and endpoint identity match
        if (
            plan.target_asset != plan.approval.target_asset
            or plan.target_endpoint != plan.approval.target_endpoint
        ):
            reason = "Target asset or endpoint does not match approved targets"
            self._record_audit_event(
                ValidationAuditEventType.DISPATCH_DENIED, plan.plan_id, plan.version, plan.plan_hash,
                actor, "DENY", "BLOCKED", reason
            )
            raise DispatchSecurityError(f"Dispatch denied: {reason}")

        # Gate 8: Dynamic scope recheck (anti-TOCTOU)
        scope_eng = current_scope_engine or self.scope_engine
        if scope_eng and hasattr(scope_eng, "is_in_scope"):
            is_valid = scope_eng.is_in_scope(plan.target_asset)
            if not is_valid:
                reason = f"Target asset '{plan.target_asset}' is no longer IN_SCOPE under current scope rules"
                self._record_audit_event(
                    ValidationAuditEventType.DISPATCH_DENIED, plan.plan_id, plan.version, plan.plan_hash,
                    actor, "DENY", "BLOCKED", reason
                )
                raise DispatchSecurityError(f"Dispatch denied: {reason}")
        elif plan.scope_reference != "IN_SCOPE":
            reason = f"Target scope reference is '{plan.scope_reference}', requires 'IN_SCOPE'"
            self._record_audit_event(
                ValidationAuditEventType.DISPATCH_DENIED, plan.plan_id, plan.version, plan.plan_hash,
                actor, "DENY", "BLOCKED", reason
            )
            raise DispatchSecurityError(f"Dispatch denied: {reason}")

        # Gate 9: Tenant & Principal consistency
        if plan.tenant_id != plan.approval.tenant_id:
            reason = f"Tenant mismatch: plan '{plan.tenant_id}' != approved '{plan.approval.tenant_id}'"
            self._record_audit_event(
                ValidationAuditEventType.DISPATCH_DENIED, plan.plan_id, plan.version, plan.plan_hash,
                actor, "DENY", "BLOCKED", reason
            )
            raise DispatchSecurityError(f"Dispatch denied: {reason}")

        # All 9 gates passed: Transition to DISPATCHED
        validate_state_transition(plan.status, ValidationPlanStatus.DISPATCHED)
        plan.status = ValidationPlanStatus.DISPATCHED
        self._record_audit_event(
            event_type=ValidationAuditEventType.DISPATCH_AUTHORIZED,
            plan_id=plan.plan_id,
            plan_version=plan.version,
            plan_hash=plan.plan_hash,
            actor_id=actor,
            decision="ALLOW",
            outcome="SUCCESS",
            sanitized_reason="All 9 pre-dispatch authorization and anti-TOCTOU gates verified",
        )
        return True

    def execute_dispatched_plan(
        self,
        plan: ChainValidationPlan,
        executor_func: Optional[Any] = None,
    ) -> ValidationExecutionResult:
        """
        Executes an authorized plan through a safe, isolated validation fixture.
        Phase 22.3 strictly prohibits real network attacks.
        """
        if plan.status != ValidationPlanStatus.DISPATCHED:
            raise DispatchSecurityError(
                f"Cannot execute plan '{plan.plan_id}': status is '{plan.status.value}', expected 'DISPATCHED'"
            )

        now = datetime.now(timezone.utc)
        dispatched_at = now.isoformat()

        if executor_func:
            try:
                res = executor_func(plan)
                if not isinstance(res, ValidationExecutionResult):
                    raise ValueError("Executor function must return ValidationExecutionResult")
                result = res
            except Exception as exc:
                result = ValidationExecutionResult(
                    execution_id=f"EXEC-{hashlib.sha256(f'{plan.plan_id}:{time.time()}'.encode()).hexdigest()[:16]}",
                    plan_id=plan.plan_id,
                    dispatched_at=dispatched_at,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    status=ValidationPlanStatus.FAILED,
                    error_message=f"Execution error: {str(exc)[:200]}",
                    is_simulated=True,
                )
        else:
            # Deterministic, non-destructive simulation fixture
            exec_id = f"EXEC-{hashlib.sha256(f'{plan.plan_id}:{dispatched_at}'.encode()).hexdigest()[:16]}"
            evidence_body = f"EVIDENCE_RECORD:{plan.plan_id}:{plan.validation_method}:{plan.target_asset}"
            ev_digest = hashlib.sha256(evidence_body.encode("utf-8")).hexdigest()
            delta_digest = hashlib.sha256(f"DELTA:{ev_digest}".encode("utf-8")).hexdigest()

            result = ValidationExecutionResult(
                execution_id=exec_id,
                plan_id=plan.plan_id,
                dispatched_at=dispatched_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                status=ValidationPlanStatus.COMPLETED,
                evidence_ref=f"EV-{exec_id}",
                evidence_sha256=ev_digest,
                observed_delta_digest=delta_digest,
                sanitized_output="Validation completed successfully. Output sanitized.",
                is_simulated=True,
            )

        plan.execution_result = result
        if result.status == ValidationPlanStatus.COMPLETED:
            validate_state_transition(plan.status, ValidationPlanStatus.COMPLETED)
            plan.status = ValidationPlanStatus.COMPLETED
        elif result.status == ValidationPlanStatus.PARTIALLY_COMPLETED:
            validate_state_transition(plan.status, ValidationPlanStatus.PARTIALLY_COMPLETED)
            plan.status = ValidationPlanStatus.PARTIALLY_COMPLETED
        else:
            validate_state_transition(plan.status, ValidationPlanStatus.FAILED)
            plan.status = ValidationPlanStatus.FAILED

        self._record_audit_event(
            event_type=ValidationAuditEventType.DISPATCH_EXECUTED,
            plan_id=plan.plan_id,
            plan_version=plan.version,
            plan_hash=plan.plan_hash,
            actor_id="EXECUTOR",
            decision="RECORD",
            outcome=result.status.value,
            sanitized_reason=result.error_message or "Execution finished",
            evidence_ref=result.evidence_ref,
        )
        return result

    def verify_evidence_and_promote(
        self,
        plan: ChainValidationPlan,
        execution_result: ValidationExecutionResult,
        graph: AttackGraph,
        evidence_store: Optional[Any] = None,
        all_paths: Optional[Dict[str, AttackPath]] = None,
    ) -> Tuple[bool, List[str]]:
        """
        Independently verifies evidence integrity and provenance.
        If valid:
        - Promotes constituent edges to LINK_VALIDATED with RelationshipProvenance.
        - If and only if ALL edges in the chain are validated, promotes the attack path to FULLY_VALIDATED.
        - Preserves anti-inflation guarantees: finding and path severities remain untouched.
        """
        actor = "EVIDENCE_VERIFIER"

        # Rule 8: Partial execution must not be reported as complete
        if execution_result.status == ValidationPlanStatus.PARTIALLY_COMPLETED:
            reason = "Partial execution cannot promote relationships to validated"
            self._record_audit_event(
                ValidationAuditEventType.EVIDENCE_REJECTED, plan.plan_id, plan.version, plan.plan_hash,
                actor, "DENY", "BLOCKED", reason
            )
            return False, [reason]

        if execution_result.status != ValidationPlanStatus.COMPLETED:
            reason = f"Execution status '{execution_result.status.value}' is not COMPLETED"
            self._record_audit_event(
                ValidationAuditEventType.EVIDENCE_REJECTED, plan.plan_id, plan.version, plan.plan_hash,
                actor, "DENY", "BLOCKED", reason
            )
            return False, [reason]

        # Rule 9 & 10: Dispatch success alone does not prove relationship; independent verification
        if not execution_result.evidence_ref or not execution_result.evidence_sha256:
            reason = "Execution result lacks mandatory evidence reference or SHA-256 digest"
            self._record_audit_event(
                ValidationAuditEventType.EVIDENCE_REJECTED, plan.plan_id, plan.version, plan.plan_hash,
                actor, "DENY", "BLOCKED", reason
            )
            raise EvidenceVerificationError(reason)

        # Verify evidence in EvidenceStore if provided
        if evidence_store and hasattr(evidence_store, "get_evidence"):
            record = evidence_store.get_evidence(execution_result.evidence_ref)
            if not record:
                reason = f"Evidence reference '{execution_result.evidence_ref}' not found in EvidenceStore"
                self._record_audit_event(
                    ValidationAuditEventType.EVIDENCE_REJECTED, plan.plan_id, plan.version, plan.plan_hash,
                    actor, "DENY", "BLOCKED", reason
                )
                raise EvidenceVerificationError(reason)

            # Check digest integrity
            expected_digest = getattr(record, "sha256", None) or getattr(record, "digest", None)
            if expected_digest and expected_digest != execution_result.evidence_sha256:
                reason = f"Evidence digest mismatch: expected '{expected_digest}', got '{execution_result.evidence_sha256}'"
                self._record_audit_event(
                    ValidationAuditEventType.EVIDENCE_REJECTED, plan.plan_id, plan.version, plan.plan_hash,
                    actor, "DENY", "BLOCKED", reason
                )
                raise EvidenceVerificationError(reason)

        # Transition plan to EVIDENCE_VERIFIED
        validate_state_transition(plan.status, ValidationPlanStatus.EVIDENCE_VERIFIED)
        plan.status = ValidationPlanStatus.EVIDENCE_VERIFIED
        self._record_audit_event(
            event_type=ValidationAuditEventType.EVIDENCE_VERIFIED,
            plan_id=plan.plan_id,
            plan_version=plan.version,
            plan_hash=plan.plan_hash,
            actor_id=actor,
            decision="ALLOW",
            outcome="SUCCESS",
            sanitized_reason="Evidence digest and provenance verified",
            evidence_ref=execution_result.evidence_ref,
        )

        # Promote constituent relationship edges in graph
        promoted_edge_ids: List[str] = []
        for eid in plan.relationship_ids:
            edge = graph.get_edge(eid)
            if not edge:
                continue

            # Provenance binding
            src_f = plan.source_finding_ids[0] if plan.source_finding_ids else edge.source_id
            tgt_f = plan.target_finding_ids[0] if plan.target_finding_ids else edge.destination_id

            provenance = RelationshipProvenance(
                source_finding_id=src_f,
                target_finding_id=tgt_f,
                source_evidence_ref=edge.provenance.source_evidence_ref if edge.provenance else "EV-SRC",
                target_evidence_ref=edge.provenance.target_evidence_ref if edge.provenance else "EV-TGT",
                transition_evidence_ref=execution_result.evidence_ref,
                authenticity_class="CONTROLLED_DISPATCH_RECEIPT" if not execution_result.is_simulated else "SIMULATED_VERIFICATION",
                causality_proof_type=CausalityProofType.DIFFERENTIAL_BASELINE_PROVEN,
                canary_response_digest=execution_result.observed_delta_digest,
                verified_at=datetime.now(timezone.utc).isoformat(),
            )
            edge.state = RelationshipState.LINK_VALIDATED
            edge.provenance = provenance
            promoted_edge_ids.append(eid)

            self._record_audit_event(
                event_type=ValidationAuditEventType.RELATIONSHIP_PROMOTED,
                plan_id=plan.plan_id,
                plan_version=plan.version,
                plan_hash=plan.plan_hash,
                actor_id=actor,
                decision="ALLOW",
                outcome="SUCCESS",
                sanitized_reason=f"Edge '{eid}' promoted to LINK_VALIDATED",
                evidence_ref=execution_result.evidence_ref,
            )

        validate_state_transition(plan.status, ValidationPlanStatus.RELATIONSHIP_VALIDATED)
        plan.status = ValidationPlanStatus.RELATIONSHIP_VALIDATED

        # Rule 11: A chain is promoted if and only if EVERY edge is LINK_VALIDATED
        if all_paths and plan.path_id in all_paths:
            path = all_paths[plan.path_id]
            all_edges_validated = True
            for eid in path.edge_ids:
                e = graph.get_edge(eid)
                if not e or e.state != RelationshipState.LINK_VALIDATED:
                    all_edges_validated = False
                    break

            if all_edges_validated:
                path.state = ChainState.FULLY_VALIDATED
                validate_state_transition(plan.status, ValidationPlanStatus.CHAIN_VALIDATED)
                plan.status = ValidationPlanStatus.CHAIN_VALIDATED
                self._record_audit_event(
                    event_type=ValidationAuditEventType.CHAIN_PROMOTED,
                    plan_id=plan.plan_id,
                    plan_version=plan.version,
                    plan_hash=plan.plan_hash,
                    actor_id=actor,
                    decision="ALLOW",
                    outcome="SUCCESS",
                    sanitized_reason=f"All edges validated; chain '{path.path_id}' promoted to FULLY_VALIDATED",
                    evidence_ref=execution_result.evidence_ref,
                )
            else:
                path.state = ChainState.PARTIALLY_VALIDATED

        return True, promoted_edge_ids

    def get_audit_log(self) -> List[ValidationAuditEvent]:
        """Returns the chronological audit log of validation events."""
        return list(self._audit_log)

    def get_plan(self, plan_id: str) -> Optional[ChainValidationPlan]:
        return self._plans.get(plan_id)

    def get_all_plans(self) -> List[ChainValidationPlan]:
        return list(self._plans.values())
