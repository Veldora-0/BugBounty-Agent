"""
Data Models for Business Logic & Workflow Intelligence (Phase 12).

Defines structured models for workflows, steps, transitions, states, invariants,
actors, resources, parameters, hypotheses, test cases, evidence, and findings.
Adheres strictly to deterministic IDs, sanitized evidence, and state machine models.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Set
import uuid

from framework.authz.model import PrincipalProfile
from framework.common.evidence import sanitize_sensitive_data
from framework.findings.lifecycle import FindingLifecycle


class WorkflowActorType(str, Enum):
    """Actors and roles participating in business workflows."""
    ANONYMOUS = "ANONYMOUS"
    USER_A = "USER_A"
    USER_B = "USER_B"
    LOW_PRIVILEGE = "LOW_PRIVILEGE"
    HIGH_PRIVILEGE = "HIGH_PRIVILEGE"
    ADMIN = "ADMIN"
    TENANT_A = "TENANT_A"
    TENANT_B = "TENANT_B"
    CUSTOM = "CUSTOM"

    @classmethod
    def from_string(cls, val: str) -> WorkflowActorType:
        clean = (val or "").strip().upper()
        for member in cls:
            if member.value == clean or member.name == clean:
                return member
        return cls.CUSTOM


class WorkflowState(str, Enum):
    """Generic lifecycle states in application state machines."""
    INITIAL = "INITIAL"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    REGISTERED = "REGISTERED"
    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    AUTHENTICATED = "AUTHENTICATED"
    RESOURCE_DRAFT = "RESOURCE_DRAFT"
    RESOURCE_CREATED = "RESOURCE_CREATED"
    RESOURCE_ACTIVE = "RESOURCE_ACTIVE"
    RESOURCE_LOCKED = "RESOURCE_LOCKED"
    RESOURCE_DELETED = "RESOURCE_DELETED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    CHECKOUT_INITIATED = "CHECKOUT_INITIATED"
    PAYMENT_PENDING = "PAYMENT_PENDING"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    CUSTOM = "CUSTOM"

    @classmethod
    def from_string(cls, val: str) -> WorkflowState:
        clean = (val or "").strip().upper()
        for member in cls:
            if member.value == clean or member.name == clean:
                return member
        return cls.CUSTOM


class InvariantStatus(str, Enum):
    """Evaluation status for business logic invariants."""
    INVARIANT_EXPECTED = "INVARIANT_EXPECTED"
    INVARIANT_OBSERVED = "INVARIANT_OBSERVED"
    INVARIANT_VIOLATED = "INVARIANT_VIOLATED"

    @classmethod
    def from_string(cls, val: str) -> InvariantStatus:
        clean = (val or "").strip().upper()
        for member in cls:
            if member.value == clean:
                return member
        return cls.INVARIANT_EXPECTED


class BusinessLogicCategory(str, Enum):
    """Taxonomy of business logic test classes."""
    STEP_SKIPPING = "step_skipping"
    STEP_REORDERING = "step_reordering"
    REPLAY_ACTION = "replay_action"
    REPLAY_TOKEN = "replay_token"
    DUPLICATE_ACTION = "duplicate_action"
    STATE_TAMPERING = "state_tampering"
    PARAMETER_TAMPERING = "parameter_tampering"
    OWNERSHIP_MISMATCH = "ownership_mismatch"
    ROLE_TRANSITION_ABUSE = "role_transition_abuse"
    TENANT_BOUNDARY_VIOLATION = "tenant_boundary_violation"
    QUANTITY_MANIPULATION = "quantity_manipulation"
    PRICE_MANIPULATION = "price_manipulation"
    NEGATIVE_QUANTITY = "negative_quantity"
    BOUNDARY_VALUE_ABUSE = "boundary_value_abuse"
    DISCOUNT_COUPON_ABUSE = "discount_coupon_abuse"
    RESOURCE_LIFECYCLE_ABUSE = "resource_lifecycle_abuse"
    INVITATION_ABUSE = "invitation_abuse"
    VERIFICATION_ABUSE = "verification_abuse"
    ACCOUNT_RECOVERY_ABUSE = "account_recovery_abuse"
    APPROVAL_BYPASS = "approval_bypass"
    RACE_CONDITION = "race_condition"
    TOCTOU = "toctou"
    MISSING_PREREQUISITE = "missing_prerequisite"
    POST_COMPLETION_ABUSE = "post_completion_abuse"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, val: str) -> BusinessLogicCategory:
        clean = (val or "").strip().lower()
        for member in cls:
            if member.value == clean or member.name.lower() == clean:
                return member
        return cls.UNKNOWN


class WorkflowConfidence(str, Enum):
    """Confidence levels for workflow candidates and findings."""
    CANDIDATE = "CANDIDATE"
    SUSPECTED = "SUSPECTED"
    OBSERVED = "OBSERVED"
    VALIDATED = "VALIDATED"

    @classmethod
    def from_string(cls, val: str) -> WorkflowConfidence:
        clean = (val or "").strip().upper()
        for member in cls:
            if member.value == clean:
                return member
        return cls.CANDIDATE


class WorkflowActor:
    """Actor profile wrapper for business logic workflows."""

    def __init__(
        self,
        actor_id: str,
        actor_type: WorkflowActorType | str = WorkflowActorType.ANONYMOUS,
        role: str = "USER",
        tenant_id: Optional[str] = None,
        principal_ref: Optional[str] = None,
        session_token_ref: Optional[str] = None,
        privilege_level: int = 10,
    ):
        self.actor_id = actor_id.strip()
        self.actor_type = (
            actor_type
            if isinstance(actor_type, WorkflowActorType)
            else WorkflowActorType.from_string(actor_type)
        )
        self.role = role.strip().upper()
        self.tenant_id = tenant_id.strip() if tenant_id else None
        self.principal_ref = principal_ref or self.actor_id
        self.session_token_ref = session_token_ref
        self.privilege_level = int(privilege_level)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "actor_type": self.actor_type.value,
            "role": self.role,
            "tenant_id": self.tenant_id,
            "principal_ref": self.principal_ref,
            "session_token_ref": self.session_token_ref,
            "privilege_level": self.privilege_level,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WorkflowActor:
        return cls(
            actor_id=data.get("actor_id", str(uuid.uuid4())),
            actor_type=data.get("actor_type", WorkflowActorType.ANONYMOUS),
            role=data.get("role", "USER"),
            tenant_id=data.get("tenant_id"),
            principal_ref=data.get("principal_ref"),
            session_token_ref=data.get("session_token_ref"),
            privilege_level=data.get("privilege_level", 10),
        )


class WorkflowResource:
    """Entity or asset manipulated within a business workflow."""

    def __init__(
        self,
        resource_id: str,
        resource_type: str,
        owner_actor_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        initial_state: str = "INITIAL",
        attributes: Optional[Dict[str, Any]] = None,
    ):
        self.resource_id = resource_id.strip()
        self.resource_type = resource_type.strip()
        self.owner_actor_id = owner_actor_id
        self.tenant_id = tenant_id
        self.current_state = initial_state
        self.attributes = dict(attributes or {})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "owner_actor_id": self.owner_actor_id,
            "tenant_id": self.tenant_id,
            "current_state": self.current_state,
            "attributes": self.attributes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WorkflowResource:
        return cls(
            resource_id=data.get("resource_id", ""),
            resource_type=data.get("resource_type", "GENERIC"),
            owner_actor_id=data.get("owner_actor_id"),
            tenant_id=data.get("tenant_id"),
            initial_state=data.get("current_state", "INITIAL"),
            attributes=data.get("attributes", {}),
        )


class WorkflowParameter:
    """Security-sensitive parameter in a workflow transition."""

    def __init__(
        self,
        name: str,
        location: str = "body",
        inferred_type: str = "string",
        semantic_role: str = "general",
        default_value: Any = None,
        is_security_sensitive: bool = False,
    ):
        self.name = name.strip()
        self.location = location.lower()
        self.inferred_type = inferred_type
        self.semantic_role = semantic_role.lower()
        self.default_value = default_value
        self.is_security_sensitive = is_security_sensitive

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "inferred_type": self.inferred_type,
            "semantic_role": self.semantic_role,
            "default_value": self.default_value,
            "is_security_sensitive": self.is_security_sensitive,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WorkflowParameter:
        return cls(
            name=data.get("name", ""),
            location=data.get("location", "body"),
            inferred_type=data.get("inferred_type", "string"),
            semantic_role=data.get("semantic_role", "general"),
            default_value=data.get("default_value"),
            is_security_sensitive=data.get("is_security_sensitive", False),
        )


class WorkflowStep:
    """Discrete operational step within a structured workflow."""

    def __init__(
        self,
        step_id: str,
        name: str,
        endpoint: str,
        method: str = "GET",
        expected_actor: str = "USER_A",
        from_state: str = "INITIAL",
        to_state: str = "COMPLETED",
        required_preconditions: Optional[List[str]] = None,
        parameters: Optional[List[WorkflowParameter]] = None,
        is_optional: bool = False,
        is_terminal: bool = False,
    ):
        self.step_id = step_id.strip()
        self.name = name.strip()
        self.endpoint = endpoint.strip()
        self.method = method.upper().strip()
        self.expected_actor = expected_actor
        self.from_state = from_state
        self.to_state = to_state
        self.required_preconditions = list(required_preconditions or [])
        self.parameters = list(parameters or [])
        self.is_optional = is_optional
        self.is_terminal = is_terminal

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "name": self.name,
            "endpoint": self.endpoint,
            "method": self.method,
            "expected_actor": self.expected_actor,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "required_preconditions": self.required_preconditions,
            "parameters": [p.to_dict() for p in self.parameters],
            "is_optional": self.is_optional,
            "is_terminal": self.is_terminal,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WorkflowStep:
        params = [WorkflowParameter.from_dict(p) for p in data.get("parameters", [])]
        return cls(
            step_id=data.get("step_id", str(uuid.uuid4())),
            name=data.get("name", ""),
            endpoint=data.get("endpoint", ""),
            method=data.get("method", "GET"),
            expected_actor=data.get("expected_actor", "USER_A"),
            from_state=data.get("from_state", "INITIAL"),
            to_state=data.get("to_state", "COMPLETED"),
            required_preconditions=data.get("required_preconditions", []),
            parameters=params,
            is_optional=data.get("is_optional", False),
            is_terminal=data.get("is_terminal", False),
        )


class WorkflowTransition:
    """State transition edge in a workflow state machine."""

    def __init__(
        self,
        transition_id: str,
        from_state: str,
        to_state: str,
        step_id: str,
        allowed_actors: Optional[List[str]] = None,
        guard_condition: str = "",
    ):
        self.transition_id = transition_id.strip()
        self.from_state = from_state.strip()
        self.to_state = to_state.strip()
        self.step_id = step_id.strip()
        self.allowed_actors = list(allowed_actors or ["USER_A"])
        self.guard_condition = guard_condition

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transition_id": self.transition_id,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "step_id": self.step_id,
            "allowed_actors": self.allowed_actors,
            "guard_condition": self.guard_condition,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WorkflowTransition:
        return cls(
            transition_id=data.get("transition_id", str(uuid.uuid4())),
            from_state=data.get("from_state", ""),
            to_state=data.get("to_state", ""),
            step_id=data.get("step_id", ""),
            allowed_actors=data.get("allowed_actors", ["USER_A"]),
            guard_condition=data.get("guard_condition", ""),
        )


class WorkflowInvariant:
    """A business logic rule that must never be violated."""

    def __init__(
        self,
        invariant_id: str,
        rule_name: str,
        description: str,
        category: BusinessLogicCategory | str,
        status: InvariantStatus | str = InvariantStatus.INVARIANT_EXPECTED,
        violation_details: str = "",
    ):
        self.invariant_id = invariant_id.strip()
        self.rule_name = rule_name.strip()
        self.description = description.strip()
        self.category = (
            category
            if isinstance(category, BusinessLogicCategory)
            else BusinessLogicCategory.from_string(category)
        )
        self.status = (
            status
            if isinstance(status, InvariantStatus)
            else InvariantStatus.from_string(status)
        )
        self.violation_details = violation_details

    def to_dict(self) -> Dict[str, Any]:
        return {
            "invariant_id": self.invariant_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "category": self.category.value,
            "status": self.status.value,
            "violation_details": self.violation_details,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WorkflowInvariant:
        return cls(
            invariant_id=data.get("invariant_id", str(uuid.uuid4())),
            rule_name=data.get("rule_name", ""),
            description=data.get("description", ""),
            category=data.get("category", BusinessLogicCategory.UNKNOWN),
            status=data.get("status", InvariantStatus.INVARIANT_EXPECTED),
            violation_details=data.get("violation_details", ""),
        )


class Workflow:
    """Structured representation of an end-to-end multi-step business workflow."""

    def __init__(
        self,
        workflow_id: str,
        program: str,
        application: str,
        name: str,
        description: str = "",
        steps: Optional[List[WorkflowStep]] = None,
        transitions: Optional[List[WorkflowTransition]] = None,
        invariants: Optional[List[WorkflowInvariant]] = None,
        provenance: Optional[Dict[str, Any]] = None,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
    ):
        self.workflow_id = workflow_id.strip()
        self.program = program.strip()
        self.application = application.strip()
        self.name = name.strip()
        self.description = description
        self.steps = list(steps or [])
        self.transitions = list(transitions or [])
        self.invariants = list(invariants or [])
        self.provenance = dict(provenance or {})
        now_iso = datetime.now(timezone.utc).isoformat()
        self.created_at = created_at or now_iso
        self.updated_at = updated_at or now_iso

    def compute_fingerprint(self) -> str:
        step_sig = "|".join(f"{s.method}:{s.endpoint}" for s in self.steps)
        raw = f"{self.application.lower()}|{self.name.lower()}|{step_sig}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "program": self.program,
            "application": self.application,
            "name": self.name,
            "description": self.description,
            "steps": [s.to_dict() for s in self.steps],
            "transitions": [t.to_dict() for t in self.transitions],
            "invariants": [i.to_dict() for i in self.invariants],
            "fingerprint": self.compute_fingerprint(),
            "provenance": self.provenance,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Workflow:
        steps = [WorkflowStep.from_dict(s) for s in data.get("steps", [])]
        trans = [WorkflowTransition.from_dict(t) for t in data.get("transitions", [])]
        invs = [WorkflowInvariant.from_dict(i) for i in data.get("invariants", [])]
        return cls(
            workflow_id=data.get("workflow_id", str(uuid.uuid4())),
            program=data.get("program", "default"),
            application=data.get("application", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            steps=steps,
            transitions=trans,
            invariants=invs,
            provenance=data.get("provenance", {}),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
        )


class WorkflowEvidence:
    """Sanitized evidence capture for business logic test results."""

    def __init__(
        self,
        evidence_id: str,
        workflow_id: str,
        test_case_id: str,
        category: BusinessLogicCategory | str,
        endpoint: str,
        actor_id: str,
        baseline_status: int,
        tampered_status: int,
        baseline_headers: Dict[str, str],
        tampered_headers: Dict[str, str],
        match_signals: List[str],
        body_snippet: str = "",
        violated_invariant: str = "",
        timestamp: Optional[str] = None,
    ):
        self.evidence_id = evidence_id.strip()
        self.workflow_id = workflow_id.strip()
        self.test_case_id = test_case_id.strip()
        self.category = (
            category
            if isinstance(category, BusinessLogicCategory)
            else BusinessLogicCategory.from_string(category)
        )
        self.endpoint = endpoint
        self.actor_id = actor_id
        self.baseline_status = baseline_status
        self.tampered_status = tampered_status
        self.baseline_headers = {
            str(k): sanitize_sensitive_data(f"{k}: {v}").split(": ", 1)[-1]
            for k, v in (baseline_headers or {}).items()
        }
        self.tampered_headers = {
            str(k): sanitize_sensitive_data(f"{k}: {v}").split(": ", 1)[-1]
            for k, v in (tampered_headers or {}).items()
        }
        self.match_signals = list(match_signals)
        self.body_snippet = sanitize_sensitive_data(body_snippet[:1500])
        self.violated_invariant = violated_invariant
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.integrity_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        serialized = json.dumps(
            {
                "evidence_id": self.evidence_id,
                "workflow_id": self.workflow_id,
                "test_case_id": self.test_case_id,
                "category": self.category.value,
                "endpoint": self.endpoint,
                "actor_id": self.actor_id,
                "tampered_status": self.tampered_status,
                "signals": sorted(self.match_signals),
                "body_snippet": self.body_snippet,
            },
            sort_keys=True,
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "workflow_id": self.workflow_id,
            "test_case_id": self.test_case_id,
            "category": self.category.value,
            "endpoint": self.endpoint,
            "actor_id": self.actor_id,
            "baseline_status": self.baseline_status,
            "tampered_status": self.tampered_status,
            "baseline_headers": self.baseline_headers,
            "tampered_headers": self.tampered_headers,
            "match_signals": self.match_signals,
            "body_snippet": self.body_snippet,
            "violated_invariant": self.violated_invariant,
            "timestamp": self.timestamp,
            "integrity_hash": self.integrity_hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WorkflowEvidence:
        ev = cls(
            evidence_id=data.get("evidence_id", str(uuid.uuid4())),
            workflow_id=data.get("workflow_id", ""),
            test_case_id=data.get("test_case_id", ""),
            category=data.get("category", BusinessLogicCategory.UNKNOWN),
            endpoint=data.get("endpoint", ""),
            actor_id=data.get("actor_id", "ANONYMOUS"),
            baseline_status=data.get("baseline_status", 0),
            tampered_status=data.get("tampered_status", 0),
            baseline_headers=data.get("baseline_headers", {}),
            tampered_headers=data.get("tampered_headers", {}),
            match_signals=data.get("match_signals", []),
            body_snippet=data.get("body_snippet", ""),
            violated_invariant=data.get("violated_invariant", ""),
            timestamp=data.get("timestamp"),
        )
        if "integrity_hash" in data:
            ev.integrity_hash = data["integrity_hash"]
        return ev


class WorkflowHypothesis:
    """Security hypothesis targeting a specific workflow invariant."""

    def __init__(
        self,
        hypothesis_id: str,
        workflow_id: str,
        category: BusinessLogicCategory | str,
        title: str,
        description: str,
        target_step_id: str,
        test_strategy: str,
        target_actor: str = "USER_A",
        priority: int = 50,
        confidence: WorkflowConfidence | str = WorkflowConfidence.CANDIDATE,
        lifecycle: FindingLifecycle | str = FindingLifecycle.CANDIDATE,
    ):
        self.hypothesis_id = hypothesis_id.strip()
        self.workflow_id = workflow_id.strip()
        self.category = (
            category
            if isinstance(category, BusinessLogicCategory)
            else BusinessLogicCategory.from_string(category)
        )
        self.title = title.strip()
        self.description = description.strip()
        self.target_step_id = target_step_id.strip()
        self.test_strategy = test_strategy
        self.target_actor = target_actor
        self.priority = max(0, min(100, int(priority)))
        self.confidence = (
            confidence
            if isinstance(confidence, WorkflowConfidence)
            else WorkflowConfidence.from_string(confidence)
        )
        if isinstance(lifecycle, FindingLifecycle):
            self.lifecycle = lifecycle
        else:
            clean_l = str(lifecycle).upper().strip()
            self.lifecycle = FindingLifecycle[clean_l] if clean_l in FindingLifecycle.__members__ else FindingLifecycle.CANDIDATE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "workflow_id": self.workflow_id,
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "target_step_id": self.target_step_id,
            "test_strategy": self.test_strategy,
            "target_actor": self.target_actor,
            "priority": self.priority,
            "confidence": self.confidence.value,
            "lifecycle": self.lifecycle.value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WorkflowHypothesis:
        return cls(
            hypothesis_id=data.get("hypothesis_id", str(uuid.uuid4())),
            workflow_id=data.get("workflow_id", ""),
            category=data.get("category", BusinessLogicCategory.UNKNOWN),
            title=data.get("title", ""),
            description=data.get("description", ""),
            target_step_id=data.get("target_step_id", ""),
            test_strategy=data.get("test_strategy", ""),
            target_actor=data.get("target_actor", "USER_A"),
            priority=data.get("priority", 50),
            confidence=data.get("confidence", WorkflowConfidence.CANDIDATE),
            lifecycle=data.get("lifecycle", FindingLifecycle.CANDIDATE),
        )


class WorkflowTestCase:
    """Execution plan and empirical outcome for a business logic hypothesis."""

    def __init__(
        self,
        test_case_id: str,
        hypothesis_id: str,
        workflow_id: str,
        category: BusinessLogicCategory | str,
        step_id: str,
        endpoint: str,
        method: str = "GET",
        actor_id: str = "USER_A",
        mutated_parameters: Optional[Dict[str, Any]] = None,
        tampered_state: Optional[str] = None,
        result: str = "PENDING",
        evidence: Optional[WorkflowEvidence] = None,
        confidence: WorkflowConfidence | str = WorkflowConfidence.CANDIDATE,
        priority: int = 50,
        lifecycle: FindingLifecycle | str = FindingLifecycle.CANDIDATE,
    ):
        self.test_case_id = test_case_id.strip()
        self.hypothesis_id = hypothesis_id.strip()
        self.workflow_id = workflow_id.strip()
        self.category = (
            category
            if isinstance(category, BusinessLogicCategory)
            else BusinessLogicCategory.from_string(category)
        )
        self.step_id = step_id.strip()
        self.endpoint = endpoint.strip()
        self.method = method.upper().strip()
        self.actor_id = actor_id
        self.mutated_parameters = dict(mutated_parameters or {})
        self.tampered_state = tampered_state
        self.result = result
        self.evidence = evidence
        self.confidence = (
            confidence
            if isinstance(confidence, WorkflowConfidence)
            else WorkflowConfidence.from_string(confidence)
        )
        self.priority = max(0, min(100, int(priority)))
        if isinstance(lifecycle, FindingLifecycle):
            self.lifecycle = lifecycle
        else:
            clean_l = str(lifecycle).upper().strip()
            self.lifecycle = FindingLifecycle[clean_l] if clean_l in FindingLifecycle.__members__ else FindingLifecycle.CANDIDATE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_case_id": self.test_case_id,
            "hypothesis_id": self.hypothesis_id,
            "workflow_id": self.workflow_id,
            "category": self.category.value,
            "step_id": self.step_id,
            "endpoint": self.endpoint,
            "method": self.method,
            "actor_id": self.actor_id,
            "mutated_parameters": self.mutated_parameters,
            "tampered_state": self.tampered_state,
            "result": self.result,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "confidence": self.confidence.value,
            "priority": self.priority,
            "lifecycle": self.lifecycle.value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WorkflowTestCase:
        ev_data = data.get("evidence")
        ev = WorkflowEvidence.from_dict(ev_data) if ev_data else None
        return cls(
            test_case_id=data.get("test_case_id", str(uuid.uuid4())),
            hypothesis_id=data.get("hypothesis_id", ""),
            workflow_id=data.get("workflow_id", ""),
            category=data.get("category", BusinessLogicCategory.UNKNOWN),
            step_id=data.get("step_id", ""),
            endpoint=data.get("endpoint", ""),
            method=data.get("method", "GET"),
            actor_id=data.get("actor_id", "USER_A"),
            mutated_parameters=data.get("mutated_parameters", {}),
            tampered_state=data.get("tampered_state"),
            result=data.get("result", "PENDING"),
            evidence=ev,
            confidence=data.get("confidence", WorkflowConfidence.CANDIDATE),
            priority=data.get("priority", 50),
            lifecycle=data.get("lifecycle", FindingLifecycle.CANDIDATE),
        )


class WorkflowFinding:
    """Validated business logic vulnerability finding."""

    def __init__(
        self,
        finding_id: str,
        workflow_id: str,
        test_case_id: str,
        title: str,
        category: BusinessLogicCategory | str,
        severity: str,
        endpoint: str,
        actor: str,
        violated_invariant: str,
        description: str,
        remediation: str,
        evidence_id: str,
        confidence: WorkflowConfidence | str = WorkflowConfidence.VALIDATED,
        lifecycle: FindingLifecycle | str = FindingLifecycle.VALIDATED,
    ):
        self.finding_id = finding_id.strip()
        self.workflow_id = workflow_id.strip()
        self.test_case_id = test_case_id.strip()
        self.title = title.strip()
        self.category = (
            category
            if isinstance(category, BusinessLogicCategory)
            else BusinessLogicCategory.from_string(category)
        )
        self.severity = severity.upper().strip()
        self.endpoint = endpoint
        self.actor = actor
        self.violated_invariant = violated_invariant
        self.description = description
        self.remediation = remediation
        self.evidence_id = evidence_id
        self.confidence = (
            confidence
            if isinstance(confidence, WorkflowConfidence)
            else WorkflowConfidence.from_string(confidence)
        )
        if isinstance(lifecycle, FindingLifecycle):
            self.lifecycle = lifecycle
        else:
            clean_l = str(lifecycle).upper().strip()
            self.lifecycle = FindingLifecycle[clean_l] if clean_l in FindingLifecycle.__members__ else FindingLifecycle.VALIDATED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "workflow_id": self.workflow_id,
            "test_case_id": self.test_case_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "actor": self.actor,
            "violated_invariant": self.violated_invariant,
            "description": self.description,
            "remediation": self.remediation,
            "evidence_id": self.evidence_id,
            "confidence": self.confidence.value,
            "lifecycle": self.lifecycle.value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WorkflowFinding:
        return cls(
            finding_id=data.get("finding_id", str(uuid.uuid4())),
            workflow_id=data.get("workflow_id", ""),
            test_case_id=data.get("test_case_id", ""),
            title=data.get("title", ""),
            category=data.get("category", BusinessLogicCategory.UNKNOWN),
            severity=data.get("severity", "MEDIUM"),
            endpoint=data.get("endpoint", ""),
            actor=data.get("actor", "USER_A"),
            violated_invariant=data.get("violated_invariant", ""),
            description=data.get("description", ""),
            remediation=data.get("remediation", ""),
            evidence_id=data.get("evidence_id", ""),
            confidence=data.get("confidence", WorkflowConfidence.VALIDATED),
            lifecycle=data.get("lifecycle", FindingLifecycle.VALIDATED),
        )
