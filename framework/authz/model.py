"""
Data Models for Authorization & Access-Control Intelligence (Phase 8).

Defines structured models for security principals, secure session references,
resource targets, access control policies, comparative test cases, and cryptographic evidence.
Never persists raw secrets or credentials.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional, Set
import uuid

from framework.common.evidence import sanitize_sensitive_data


class ExpectedAccessDecision(str, Enum):
    """Expected authorization decision under a formal security policy."""
    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"


class AccessDecisionInferred(str, Enum):
    """Observed authorization decision inferred from empirical response comparison."""
    ALLOW = "ALLOW"
    DENY = "DENY"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


class AuthorizationCategory(str, Enum):
    """Taxonomy of authorization & privilege escalation testing."""
    HORIZONTAL = "horizontal"                      # BOLA/IDOR between peers (User A vs User B)
    VERTICAL = "vertical"                          # Privilege escalation (User vs Admin)
    TENANT = "tenant"                              # Cross-tenant data isolation failure
    UNAUTHENTICATED = "unauthenticated"            # Access to protected resource without auth
    FUNCTION_LEVEL = "function_level"              # BFLA / Administrative route access
    METHOD_INCONSISTENCY = "method_inconsistency"  # Authorization discrepancies across HTTP verbs


class PrincipalProfile:
    """
    Represents an authorized or unauthenticated security principal.
    Never contains raw credentials; stores masked identifier references only.
    """

    def __init__(
        self,
        principal_id: str,
        role: str = "USER",
        tenant_id: Optional[str] = None,
        auth_profile_ref: Optional[str] = None,
        session_id: Optional[str] = None,
        privilege_level: int = 10,  # 0=anonymous, 10=user, 50=privileged, 100=admin
        ownership_context: Optional[List[str]] = None,
        provenance: Optional[Dict[str, Any]] = None,
        masked_metadata: Optional[Dict[str, str]] = None,
    ):
        self.principal_id = principal_id.strip()
        self.role = role.strip().upper()
        self.tenant_id = tenant_id.strip() if tenant_id else None
        self.auth_profile_ref = auth_profile_ref or f"auth-profile-{self.principal_id}"
        self.session_id = session_id
        self.privilege_level = int(privilege_level)
        self.ownership_context: List[str] = list(ownership_context or [])
        self.provenance = provenance or {}
        # Clean any values passed in metadata
        clean_meta = {}
        for k, v in (masked_metadata or {}).items():
            val_str = str(v)
            cleaned = sanitize_sensitive_data(f"{k}: {val_str}").replace(f"{k}: ", "")
            if cleaned == val_str:
                cleaned = sanitize_sensitive_data(val_str)
            clean_meta[k] = cleaned
        self.masked_metadata = clean_meta

    def owns_resource(self, resource_id: str) -> bool:
        """Checks if this principal is the documented owner of resource_id."""
        return str(resource_id) in self.ownership_context

    def to_dict(self) -> Dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "role": self.role,
            "tenant_id": self.tenant_id,
            "auth_profile_ref": self.auth_profile_ref,
            "session_id": self.session_id,
            "privilege_level": self.privilege_level,
            "ownership_context": self.ownership_context,
            "provenance": self.provenance,
            "masked_metadata": self.masked_metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PrincipalProfile:
        return cls(
            principal_id=data.get("principal_id", ""),
            role=data.get("role", "USER"),
            tenant_id=data.get("tenant_id"),
            auth_profile_ref=data.get("auth_profile_ref"),
            session_id=data.get("session_id"),
            privilege_level=data.get("privilege_level", 10),
            ownership_context=data.get("ownership_context", []),
            provenance=data.get("provenance", {}),
            masked_metadata=data.get("masked_metadata", {}),
        )


class SessionProfile:
    """
    Secure authenticated session abstraction.
    Headers and cookies store reference keys or masked formats.
    Tokens are injected only at dispatch time from volatile memory/environment.
    """

    def __init__(
        self,
        session_id: str,
        principal_id: str,
        headers_ref: Optional[Dict[str, str]] = None,
        cookies_ref: Optional[Dict[str, str]] = None,
        csrf_token_ref: Optional[str] = None,
        expires_at: Optional[str] = None,
        is_authenticated: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.session_id = session_id.strip()
        self.principal_id = principal_id.strip()

        # Sanitize references for storage
        self.headers_ref: Dict[str, str] = {}
        for k, v in (headers_ref or {}).items():
            val_str = str(v)
            cleaned = sanitize_sensitive_data(f"{k}: {val_str}").replace(f"{k}: ", "")
            if cleaned == val_str:
                cleaned = sanitize_sensitive_data(val_str)
            self.headers_ref[k] = cleaned

        self.cookies_ref: Dict[str, str] = {}
        for k, v in (cookies_ref or {}).items():
            val_str = str(v)
            cleaned = sanitize_sensitive_data(f"{k}={val_str}").replace(f"{k}=", "")
            if cleaned == val_str:
                cleaned = sanitize_sensitive_data(val_str)
            self.cookies_ref[k] = cleaned

        self.csrf_token_ref = sanitize_sensitive_data(csrf_token_ref or "") if csrf_token_ref else None
        self.expires_at = expires_at
        self.is_authenticated = bool(is_authenticated)
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "principal_id": self.principal_id,
            "headers_ref": self.headers_ref,
            "cookies_ref": self.cookies_ref,
            "csrf_token_ref": self.csrf_token_ref,
            "expires_at": self.expires_at,
            "is_authenticated": self.is_authenticated,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SessionProfile:
        return cls(
            session_id=data.get("session_id", ""),
            principal_id=data.get("principal_id", ""),
            headers_ref=data.get("headers_ref", {}),
            cookies_ref=data.get("cookies_ref", {}),
            csrf_token_ref=data.get("csrf_token_ref"),
            expires_at=data.get("expires_at"),
            is_authenticated=data.get("is_authenticated", True),
            metadata=data.get("metadata", {}),
        )


class ResourceAccessTarget:
    """
    Represents an identifiable application resource subject to access control.
    """

    def __init__(
        self,
        resource_id: str,
        resource_type: str,
        endpoint: str,
        method: str = "GET",
        tenant_id: Optional[str] = None,
        owner_principal_id: Optional[str] = None,
        param_location: str = "PATH",  # "PATH", "QUERY", "BODY"
        identifier_type: str = "NUMERIC",  # "NUMERIC", "UUID", "SLUG", "OPAQUE"
        confidence: str = "MEDIUM",  # "CONFIRMED", "HIGH", "MEDIUM", "LOW"
        target_id: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ):
        self.target_id = target_id or f"res-{uuid.uuid4().hex[:8]}"
        self.resource_id = str(resource_id).strip()
        self.resource_type = resource_type.strip().lower()
        self.endpoint = endpoint.strip()
        self.method = method.strip().upper()
        self.tenant_id = tenant_id.strip() if tenant_id else None
        self.owner_principal_id = owner_principal_id.strip() if owner_principal_id else None
        self.param_location = param_location.strip().upper()
        self.identifier_type = identifier_type.strip().upper()
        self.confidence = confidence.strip().upper()
        self.provenance = provenance or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_id": self.target_id,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "endpoint": self.endpoint,
            "method": self.method,
            "tenant_id": self.tenant_id,
            "owner_principal_id": self.owner_principal_id,
            "param_location": self.param_location,
            "identifier_type": self.identifier_type,
            "confidence": self.confidence,
            "provenance": self.provenance,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ResourceAccessTarget:
        return cls(
            target_id=data.get("target_id"),
            resource_id=data.get("resource_id", ""),
            resource_type=data.get("resource_type", "generic"),
            endpoint=data.get("endpoint", ""),
            method=data.get("method", "GET"),
            tenant_id=data.get("tenant_id"),
            owner_principal_id=data.get("owner_principal_id"),
            param_location=data.get("param_location", "PATH"),
            identifier_type=data.get("identifier_type", "NUMERIC"),
            confidence=data.get("confidence", "MEDIUM"),
            provenance=data.get("provenance", {}),
        )


class ExpectedAccessPolicy:
    """
    Formal policy model specifying whether access is ALLOWED, DENIED, or UNKNOWN
    for a principal accessing a target resource.
    """

    def __init__(
        self,
        principal_id: str = "ANONYMOUS",
        role: str = "ANONYMOUS",
        tenant_id: Optional[str] = None,
        resource_owner_id: Optional[str] = None,
        resource_tenant_id: Optional[str] = None,
        operation: str = "READ",
        expected_decision: ExpectedAccessDecision | str = ExpectedAccessDecision.UNKNOWN,
        confidence: str = "MEDIUM",
        source: str = "HEURISTIC",
    ):
        self.principal_id = principal_id
        self.role = role.upper()
        self.tenant_id = tenant_id
        self.resource_owner_id = resource_owner_id
        self.resource_tenant_id = resource_tenant_id
        self.operation = operation.upper()
        self.expected_decision = (
            expected_decision
            if isinstance(expected_decision, ExpectedAccessDecision)
            else ExpectedAccessDecision(str(expected_decision).upper())
        )
        self.confidence = confidence.upper()
        self.source = source

    @classmethod
    def evaluate(
        cls,
        principal: PrincipalProfile,
        resource: ResourceAccessTarget,
        operation: str = "READ",
    ) -> ExpectedAccessPolicy:
        """
        Infers the default expected authorization decision based on ownership and roles.
        """
        # Anonymous principal accessing protected resource
        if principal.role == "ANONYMOUS" or principal.privilege_level == 0:
            return cls(
                principal_id=principal.principal_id,
                role=principal.role,
                tenant_id=principal.tenant_id,
                resource_owner_id=resource.owner_principal_id,
                resource_tenant_id=resource.tenant_id,
                operation=operation,
                expected_decision=ExpectedAccessDecision.DENY,
                confidence="HIGH",
                source="UNAUTHENTICATED_CHECK",
            )

        # Admin principal
        if principal.role == "ADMIN" or principal.privilege_level >= 100:
            return cls(
                principal_id=principal.principal_id,
                role=principal.role,
                tenant_id=principal.tenant_id,
                resource_owner_id=resource.owner_principal_id,
                resource_tenant_id=resource.tenant_id,
                operation=operation,
                expected_decision=ExpectedAccessDecision.ALLOW,
                confidence="HIGH",
                source="ADMIN_ROLE",
            )

        # Cross-tenant check: if tenant IDs exist and differ
        if principal.tenant_id and resource.tenant_id and principal.tenant_id != resource.tenant_id:
            return cls(
                principal_id=principal.principal_id,
                role=principal.role,
                tenant_id=principal.tenant_id,
                resource_owner_id=resource.owner_principal_id,
                resource_tenant_id=resource.tenant_id,
                operation=operation,
                expected_decision=ExpectedAccessDecision.DENY,
                confidence="HIGH",
                source="CROSS_TENANT_ISOLATION",
            )

        # Ownership check: if owner ID exists
        if resource.owner_principal_id:
            if principal.principal_id == resource.owner_principal_id or principal.owns_resource(resource.resource_id):
                return cls(
                    principal_id=principal.principal_id,
                    role=principal.role,
                    tenant_id=principal.tenant_id,
                    resource_owner_id=resource.owner_principal_id,
                    resource_tenant_id=resource.tenant_id,
                    operation=operation,
                    expected_decision=ExpectedAccessDecision.ALLOW,
                    confidence="HIGH",
                    source="OWNER_MATCH",
                )
            else:
                return cls(
                    principal_id=principal.principal_id,
                    role=principal.role,
                    tenant_id=principal.tenant_id,
                    resource_owner_id=resource.owner_principal_id,
                    resource_tenant_id=resource.tenant_id,
                    operation=operation,
                    expected_decision=ExpectedAccessDecision.DENY,
                    confidence="HIGH",
                    source="HORIZONTAL_IDOR_BOUNDARY",
                )

        return cls(
            principal_id=principal.principal_id,
            role=principal.role,
            tenant_id=principal.tenant_id,
            resource_owner_id=resource.owner_principal_id,
            resource_tenant_id=resource.tenant_id,
            operation=operation,
            expected_decision=ExpectedAccessDecision.UNKNOWN,
            confidence="LOW",
            source="DEFAULT_UNKNOWN",
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "role": self.role,
            "tenant_id": self.tenant_id,
            "resource_owner_id": self.resource_owner_id,
            "resource_tenant_id": self.resource_tenant_id,
            "operation": self.operation,
            "expected_decision": self.expected_decision.value,
            "confidence": self.confidence,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExpectedAccessPolicy:
        return cls(
            principal_id=data.get("principal_id", ""),
            role=data.get("role", "USER"),
            tenant_id=data.get("tenant_id"),
            resource_owner_id=data.get("resource_owner_id"),
            resource_tenant_id=data.get("resource_tenant_id"),
            operation=data.get("operation", "READ"),
            expected_decision=data.get("expected_decision", ExpectedAccessDecision.UNKNOWN),
            confidence=data.get("confidence", "MEDIUM"),
            source=data.get("source", "MANUAL"),
        )

    # Classmethod alias
    infer_default = evaluate


class AuthzComparisonResult:
    """
    Detailed comparison between baseline access and testing principal access.
    """

    def __init__(
        self,
        decision_inferred: AccessDecisionInferred | str,
        status_code: int,
        body_similarity: float,
        is_vulnerable: bool = False,
        semantic_matches: Optional[List[str]] = None,
        ownership_identifier_found: bool = False,
        generic_error_page: bool = False,
        soft_404: bool = False,
        signals: Optional[List[str]] = None,
        evidence_summary: str = "",
    ):
        self.decision_inferred = (
            decision_inferred
            if isinstance(decision_inferred, AccessDecisionInferred)
            else AccessDecisionInferred(str(decision_inferred).upper())
        )
        self.status_code = int(status_code)
        self.body_similarity = float(body_similarity)
        self.is_vulnerable = bool(is_vulnerable)
        self.semantic_matches = list(semantic_matches or [])
        self.ownership_identifier_found = bool(ownership_identifier_found)
        self.generic_error_page = bool(generic_error_page)
        self.soft_404 = bool(soft_404)
        self.signals = list(signals or [])
        self.evidence_summary = evidence_summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_inferred": self.decision_inferred.value,
            "status_code": self.status_code,
            "body_similarity": round(self.body_similarity, 4),
            "is_vulnerable": self.is_vulnerable,
            "semantic_matches": self.semantic_matches,
            "ownership_identifier_found": self.ownership_identifier_found,
            "generic_error_page": self.generic_error_page,
            "soft_404": self.soft_404,
            "signals": self.signals,
            "evidence_summary": self.evidence_summary,
        }


class AuthzEvidence:
    """Cryptographic evidence record for authorization validation."""

    def __init__(
        self,
        test_id: str,
        baseline_owner_status: int,
        test_principal_status: int,
        baseline_invalid_status: int,
        evidence_summary: str,
        evidence_hash: Optional[str] = None,
        captured_at: Optional[str] = None,
        request_summary: Optional[Dict[str, Any]] = None,
        response_summary: Optional[Dict[str, Any]] = None,
    ):
        self.test_id = test_id
        self.baseline_owner_status = baseline_owner_status
        self.test_principal_status = test_principal_status
        self.baseline_invalid_status = baseline_invalid_status
        self.evidence_summary = evidence_summary
        self.captured_at = captured_at or datetime.now(timezone.utc).isoformat()
        self.request_summary = request_summary or {}
        self.response_summary = response_summary or {}
        self.evidence_hash = evidence_hash or self._compute_hash()

    def _compute_hash(self) -> str:
        payload = f"{self.test_id}|{self.baseline_owner_status}|{self.test_principal_status}|{self.captured_at}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_id": self.test_id,
            "baseline_owner_status": self.baseline_owner_status,
            "test_principal_status": self.test_principal_status,
            "baseline_invalid_status": self.baseline_invalid_status,
            "evidence_summary": self.evidence_summary,
            "evidence_hash": self.evidence_hash,
            "captured_at": self.captured_at,
            "request_summary": self.request_summary,
            "response_summary": self.response_summary,
        }


class AuthorizationTestCase:
    """
    Controlled authorization test specification.
    Includes human approval lifecycle status and differential comparison outcome.
    """

    def __init__(
        self,
        category: AuthorizationCategory | str,
        endpoint: str,
        resource: ResourceAccessTarget,
        testing_principal: PrincipalProfile,
        source_principal: Optional[PrincipalProfile] = None,
        substitute_identifier: Optional[str] = None,
        method: str = "GET",
        test_id: Optional[str] = None,
        expected_decision: ExpectedAccessDecision | str = ExpectedAccessDecision.DENY,
        policy_context: Optional[Dict[str, Any]] = None,
        approval_status: str = "PENDING",  # "PENDING", "APPROVED", "REJECTED"
        lifecycle_state: str = "CANDIDATE",
        severity: str = "HIGH",
        confidence: str = "MEDIUM",
        comparison_result: Optional[AuthzComparisonResult] = None,
        evidence: Optional[AuthzEvidence] = None,
        notes: str = "",
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
    ):
        self.test_id = test_id or f"authz-tc-{uuid.uuid4().hex[:10]}"
        self.category = category if isinstance(category, AuthorizationCategory) else AuthorizationCategory(category)
        self.endpoint = endpoint
        self.resource = resource
        self.testing_principal = testing_principal
        self.source_principal = source_principal
        self.substitute_identifier = substitute_identifier or resource.resource_id
        self.method = method.upper()
        self.expected_decision = (
            expected_decision
            if isinstance(expected_decision, ExpectedAccessDecision)
            else ExpectedAccessDecision(str(expected_decision).upper())
        )
        self.policy_context = policy_context or {}
        self.approval_status = approval_status.upper()
        self.lifecycle_state = lifecycle_state
        self.severity = severity
        self.confidence = confidence
        self.comparison_result = comparison_result
        self.evidence = evidence
        self.notes = notes
        now = datetime.now(timezone.utc).isoformat()
        self.created_at = created_at or now
        self.updated_at = updated_at or now

    def is_approved_for_execution(self) -> bool:
        """Enforces human approval requirement before live request dispatch."""
        return self.approval_status == "APPROVED"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_id": self.test_id,
            "category": self.category.value,
            "endpoint": self.endpoint,
            "resource": self.resource.to_dict(),
            "testing_principal": self.testing_principal.to_dict(),
            "source_principal": self.source_principal.to_dict() if self.source_principal else None,
            "substitute_identifier": self.substitute_identifier,
            "method": self.method,
            "expected_decision": self.expected_decision.value,
            "policy_context": self.policy_context,
            "approval_status": self.approval_status,
            "lifecycle_state": self.lifecycle_state,
            "severity": self.severity,
            "confidence": self.confidence,
            "comparison_result": self.comparison_result.to_dict() if self.comparison_result else None,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuthorizationTestCase:
        res_data = data.get("resource", {})
        test_prin_data = data.get("testing_principal", {})
        src_prin_data = data.get("source_principal")
        comp_data = data.get("comparison_result")

        return cls(
            test_id=data.get("test_id"),
            category=data.get("category", AuthorizationCategory.HORIZONTAL),
            endpoint=data.get("endpoint", ""),
            resource=ResourceAccessTarget.from_dict(res_data),
            testing_principal=PrincipalProfile.from_dict(test_prin_data),
            source_principal=PrincipalProfile.from_dict(src_prin_data) if src_prin_data else None,
            substitute_identifier=data.get("substitute_identifier"),
            method=data.get("method", "GET"),
            expected_decision=data.get("expected_decision", ExpectedAccessDecision.DENY),
            policy_context=data.get("policy_context", {}),
            approval_status=data.get("approval_status", "PENDING"),
            lifecycle_state=data.get("lifecycle_state", "CANDIDATE"),
            severity=data.get("severity", "HIGH"),
            confidence=data.get("confidence", "MEDIUM"),
            comparison_result=AuthzComparisonResult(**comp_data) if comp_data else None,
            notes=data.get("notes", ""),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
        )
