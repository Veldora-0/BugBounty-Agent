"""
Data Models for XXE & XML Parser Security Intelligence (Phase 18).

Defines structured models for XXE candidates, harmless synthetic canaries,
evidence classification, and conservative lifecycle states.
Strictly prohibits sensitive file reads (file://, /etc/passwd) and cloud metadata probing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional
import uuid

from framework.common.evidence import sanitize_sensitive_data


class XxeCategory(str, Enum):
    """Taxonomy of XML External Entity & parser vulnerability classes."""
    INTERNAL_ENTITY_REFLECTION = "internal_entity_reflection"  # In-band reflection of internal DTD entity (proves DTD processing, not XXE)
    SYNTHETIC_REFLECTION = "synthetic_reflection"              # Alias for internal entity reflection
    PARAMETER_ENTITY = "parameter_entity"                      # Non-egress parameter entity expansion evaluation
    ERROR_BASED = "error_based"                                # Safe syntax / parser error revealing XML parsing mechanism
    BLIND_OOB = "blind_oob"                                    # Out-of-band canary interaction


class XxeConfidence(str, Enum):
    """Confidence level assigned to an XXE candidate or finding."""
    CANDIDATE = "CANDIDATE"    # Endpoint accepts XML or has XML parameter (heuristic)
    SUSPECTED = "SUSPECTED"    # Parser error or syntax anomaly suggests active XML parser
    OBSERVED = "OBSERVED"      # Safe internal entity reflection or DNS interaction observed (XXE unconfirmed)
    SIMULATED = "SIMULATED"    # Local test harness or mock OOB verification
    VALIDATED = "VALIDATED"    # Direct, attributable external entity resolution (live OOB callback)


class XxeInteractionType(str, Enum):
    """Type of signal observed during XML validation."""
    NO_INTERACTION = "NO_INTERACTION"
    PARSER_ERROR = "PARSER_ERROR"
    INTERNAL_ENTITY_REFLECTED = "INTERNAL_ENTITY_REFLECTED"
    SYNTHETIC_REFLECTION = "SYNTHETIC_REFLECTION"
    DNS_CALLBACK = "DNS_CALLBACK"
    HTTP_CALLBACK = "HTTP_CALLBACK"
    SIMULATED_CALLBACK = "SIMULATED_CALLBACK"
    UNKNOWN = "UNKNOWN"


class XxeSource:
    """Identifies the input location where XML parsing behavior was discovered."""

    def __init__(
        self,
        source_type: str,  # "XML_BODY", "FORM_BODY", "API_ENDPOINT", "SITEMAP", "FILE_UPLOAD"
        parameter_name: str,
        original_value: Optional[str] = None,
        context: Optional[str] = None,
    ):
        self.source_type = source_type.upper().strip()
        self.parameter_name = parameter_name.strip()
        self.original_value = sanitize_sensitive_data(str(original_value)) if original_value else None
        self.context = context or ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_type": self.source_type,
            "parameter_name": self.parameter_name,
            "original_value": self.original_value,
            "context": self.context,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> XxeSource:
        return cls(
            source_type=data.get("source_type", "XML_BODY"),
            parameter_name=data.get("parameter_name", ""),
            original_value=data.get("original_value"),
            context=data.get("context"),
        )


class XxeEvidence:
    """Cryptographic and contextual evidence proving XML parser vulnerability."""

    def __init__(
        self,
        test_id: str,
        canary_token: str,
        category: XxeCategory | str,
        interaction_type: XxeInteractionType | str,
        status_code: int = 0,
        reflected_marker: Optional[str] = None,
        evidence_summary: str = "",
        captured_at: Optional[str] = None,
        evidence_hash: Optional[str] = None,
    ):
        self.test_id = test_id
        self.canary_token = canary_token
        self.category = (
            category if isinstance(category, XxeCategory) else XxeCategory(str(category).lower())
        )
        self.interaction_type = (
            interaction_type
            if isinstance(interaction_type, XxeInteractionType)
            else XxeInteractionType(str(interaction_type).upper())
        )
        self.status_code = int(status_code)
        self.reflected_marker = reflected_marker
        self.evidence_summary = evidence_summary
        self.captured_at = captured_at or datetime.now(timezone.utc).isoformat()
        self.evidence_hash = evidence_hash or self._compute_hash()

    def _compute_hash(self) -> str:
        payload = f"{self.test_id}|{self.canary_token}|{self.category.value}|{self.interaction_type.value}|{self.status_code}|{self.captured_at}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_id": self.test_id,
            "canary_token": self.canary_token,
            "category": self.category.value,
            "interaction_type": self.interaction_type.value,
            "status_code": self.status_code,
            "reflected_marker": self.reflected_marker,
            "evidence_summary": self.evidence_summary,
            "captured_at": self.captured_at,
            "evidence_hash": self.evidence_hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> XxeEvidence:
        return cls(
            test_id=data.get("test_id", ""),
            canary_token=data.get("canary_token", ""),
            category=data.get("category", XxeCategory.SYNTHETIC_REFLECTION),
            interaction_type=data.get("interaction_type", XxeInteractionType.UNKNOWN),
            status_code=data.get("status_code", 0),
            reflected_marker=data.get("reflected_marker"),
            evidence_summary=data.get("evidence_summary", ""),
            captured_at=data.get("captured_at"),
            evidence_hash=data.get("evidence_hash"),
        )


class XxeCandidate:
    """Structured XXE candidate tracking discovery, payload mutation, and verification."""

    def __init__(
        self,
        application: str,
        endpoint: str,
        parameter: str = "xml",
        candidate_id: Optional[str] = None,
        param_location: str = "XML_BODY",  # "XML_BODY", "FORM_BODY", "QUERY", "FILE_UPLOAD"
        method: str = "POST",
        category: XxeCategory | str = XxeCategory.SYNTHETIC_REFLECTION,
        source_intel: Optional[XxeSource] = None,
        callback_token: Optional[str] = None,
        confidence: XxeConfidence | str = XxeConfidence.CANDIDATE,
        severity: str = "HIGH",
        lifecycle_state: str = "CANDIDATE",  # CANDIDATE, TESTING, OBSERVED, VALIDATED, REJECTED
        approval_status: str = "PENDING",    # PENDING, APPROVED, REJECTED
        evidence: Optional[XxeEvidence] = None,
        provenance: Optional[Dict[str, Any]] = None,
        notes: str = "",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
    ):
        self.candidate_id = candidate_id or f"xxe-{uuid.uuid4().hex[:10]}"
        self.application = application.strip()
        self.endpoint = endpoint.strip()
        self.parameter = parameter.strip()
        self.param_location = param_location.upper().strip()
        self.method = method.upper().strip()
        self.category = (
            category if isinstance(category, XxeCategory) else XxeCategory(str(category).lower())
        )
        self.source_intel = source_intel or XxeSource(
            source_type=self.param_location, parameter_name=self.parameter
        )
        self.callback_token = callback_token
        self.confidence = (
            confidence
            if isinstance(confidence, XxeConfidence)
            else XxeConfidence(str(confidence).upper())
        )
        self.severity = severity.upper()
        self.lifecycle_state = lifecycle_state
        self.approval_status = approval_status.upper()
        self.evidence = evidence
        self.provenance = provenance or {}
        self.notes = notes
        self.headers: Dict[str, str] = (
            dict(headers or {}) if headers is not None else dict(self.provenance.get("headers", {}))
        )
        self.body: Optional[str] = body if body is not None else (
            self.provenance.get("body")
            or self.provenance.get("sample_body")
            or self.provenance.get("original_body")
        )
        now = datetime.now(timezone.utc).isoformat()
        self.created_at = created_at or now
        self.updated_at = updated_at or now

    def is_approved_for_execution(self) -> bool:
        """Enforces human approval before executing active canary tests."""
        return self.approval_status == "APPROVED"

    def compute_fingerprint(self) -> str:
        """Generates stable deduplication fingerprint."""
        raw = f"{self.application}|{self.endpoint}|{self.parameter}|{self.param_location}|{self.category.value}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "application": self.application,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "param_location": self.param_location,
            "method": self.method,
            "category": self.category.value,
            "source_intel": self.source_intel.to_dict() if self.source_intel else None,
            "callback_token": self.callback_token,
            "confidence": self.confidence.value,
            "severity": self.severity,
            "lifecycle_state": self.lifecycle_state,
            "approval_status": self.approval_status,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "provenance": self.provenance,
            "notes": self.notes,
            "headers": self.headers,
            "body": self.body,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> XxeCandidate:
        src = XxeSource.from_dict(data["source_intel"]) if data.get("source_intel") else None
        ev = XxeEvidence.from_dict(data["evidence"]) if data.get("evidence") else None

        return cls(
            candidate_id=data.get("candidate_id"),
            application=data.get("application", ""),
            endpoint=data.get("endpoint", ""),
            parameter=data.get("parameter", "xml"),
            param_location=data.get("param_location", "XML_BODY"),
            method=data.get("method", "POST"),
            category=data.get("category", XxeCategory.SYNTHETIC_REFLECTION),
            source_intel=src,
            callback_token=data.get("callback_token"),
            confidence=data.get("confidence", XxeConfidence.CANDIDATE),
            severity=data.get("severity", "HIGH"),
            lifecycle_state=data.get("lifecycle_state", "CANDIDATE"),
            approval_status=data.get("approval_status", "PENDING"),
            evidence=ev,
            provenance=data.get("provenance"),
            notes=data.get("notes", ""),
            headers=data.get("headers"),
            body=data.get("body"),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
        )
