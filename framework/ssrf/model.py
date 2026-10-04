"""
Data Models for SSRF & Out-of-Band Interaction Intelligence (Phase 9).

Defines structured models for SSRF candidates, sink intelligence,
out-of-band canary tokens, interaction events, comparative evidence,
and finding classification.
Never persists sensitive OOB credentials or target authorization tokens.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional, Set
import uuid

from framework.common.evidence import sanitize_sensitive_data


class SsrfCategory(str, Enum):
    """Taxonomy of Server-Side Request Forgery & server interaction categories."""
    DIRECT = "direct"                        # Direct URL fetch parameter reflected or processed
    BLIND = "blind"                          # Blind server-side interaction confirmed via OOB callback
    REDIRECT_MEDIATED = "redirect_mediated"  # Target follows controlled redirect to canary
    DNS_ONLY = "dns_only"                    # Target resolves canary hostname without making HTTP request
    HTTP_CALLBACK = "http_callback"          # Server-side HTTP request made to canary URL
    WEBHOOK = "webhook"                      # Webhook / notification delivery callback endpoint
    URL_FETCH = "url_fetch"                  # General URL fetcher / proxy endpoint
    IMPORTER = "importer"                    # Remote document / image / metadata importer


class SsrfConfidence(str, Enum):
    """Confidence level assigned to an SSRF candidate or finding."""
    CANDIDATE = "CANDIDATE"                  # Parameter or feature identified (heuristic only)
    SUSPECTED = "SUSPECTED"                  # Indirect evidence or unconfirmed timing anomaly
    OBSERVED = "OBSERVED"                    # Verified server-side DNS resolution or unauthenticated callback
    VALIDATED = "VALIDATED"                  # Reproducible server-side HTTP callback with matching token correlation


class OobInteractionType(str, Enum):
    """Type of interaction observed by the out-of-band callback provider."""
    NO_INTERACTION = "NO_INTERACTION"
    DNS_ONLY = "DNS_ONLY"
    HTTP_INTERACTION = "HTTP_INTERACTION"
    HTTPS_INTERACTION = "HTTPS_INTERACTION"
    TCP_INTERACTION = "TCP_INTERACTION"
    UNKNOWN = "UNKNOWN"


class OobProviderStatus(str, Enum):
    """Operational status of the OOB interaction provider."""
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    CONFIG_REQUIRED = "CONFIG_REQUIRED"
    ERROR = "ERROR"


class SsrfSource:
    """
    Identifies the input location where a URL or remote host candidate was discovered.
    """

    def __init__(
        self,
        source_type: str,  # "QUERY", "PATH", "JSON_BODY", "FORM_BODY", "HEADER", "API_SCHEMA", "JS_FETCH", etc.
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
    def from_dict(cls, data: Dict[str, Any]) -> SsrfSource:
        return cls(
            source_type=data.get("source_type", "QUERY"),
            parameter_name=data.get("parameter_name", ""),
            original_value=data.get("original_value"),
            context=data.get("context"),
        )


class SsrfSink:
    """
    Hypothesized backend URL consumer or server-side fetch mechanism.
    """

    def __init__(
        self,
        sink_type: str,  # "URL_FETCHER", "WEBHOOK_DISPATCHER", "IMAGE_PROXY", "PDF_GENERATOR", etc.
        description: str = "",
        expected_protocol: str = "HTTP",
        is_authenticated: bool = False,
    ):
        self.sink_type = sink_type.upper().strip()
        self.description = description
        self.expected_protocol = expected_protocol.upper()
        self.is_authenticated = bool(is_authenticated)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sink_type": self.sink_type,
            "description": self.description,
            "expected_protocol": self.expected_protocol,
            "is_authenticated": self.is_authenticated,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SsrfSink:
        return cls(
            sink_type=data.get("sink_type", "URL_FETCHER"),
            description=data.get("description", ""),
            expected_protocol=data.get("expected_protocol", "HTTP"),
            is_authenticated=data.get("is_authenticated", False),
        )


class SsrfInteraction:
    """
    Normalized out-of-band interaction event recorded by the OOB provider.
    Never persists unredacted tokens or arbitrary request bodies indiscriminately.
    """

    def __init__(
        self,
        interaction_id: str,
        canary_token: str,
        protocol: str = "HTTP",
        timestamp: Optional[str] = None,
        source_ip_metadata: Optional[str] = None,
        observed_hostname: Optional[str] = None,
        observed_method: Optional[str] = "GET",
        observed_path: Optional[str] = "/",
        bounded_headers: Optional[Dict[str, str]] = None,
        interaction_type: OobInteractionType | str = OobInteractionType.HTTP_INTERACTION,
        confidence: SsrfConfidence | str = SsrfConfidence.OBSERVED,
    ):
        self.interaction_id = interaction_id
        self.canary_token = canary_token
        self.protocol = protocol.upper()
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.source_ip_metadata = source_ip_metadata or "unknown"
        self.observed_hostname = observed_hostname or ""
        self.observed_method = (observed_method or "GET").upper()
        self.observed_path = observed_path or "/"

        # Sanitize headers to ensure no leaked tokens or session cookies
        clean_headers: Dict[str, str] = {}
        for k, v in (bounded_headers or {}).items():
            val_str = str(v)
            combined = f"{k}: {val_str}"
            sanitized = sanitize_sensitive_data(combined)
            if sanitized.startswith(f"{k}: "):
                clean_headers[k] = sanitized[len(f"{k}: "):]
            else:
                clean_headers[k] = sanitize_sensitive_data(val_str)
        self.bounded_headers = clean_headers

        self.interaction_type = (
            interaction_type
            if isinstance(interaction_type, OobInteractionType)
            else OobInteractionType(str(interaction_type).upper())
        )
        self.confidence = (
            confidence
            if isinstance(confidence, SsrfConfidence)
            else SsrfConfidence(str(confidence).upper())
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "interaction_id": self.interaction_id,
            "canary_token": self.canary_token,
            "protocol": self.protocol,
            "timestamp": self.timestamp,
            "source_ip_metadata": self.source_ip_metadata,
            "observed_hostname": self.observed_hostname,
            "observed_method": self.observed_method,
            "observed_path": self.observed_path,
            "bounded_headers": self.bounded_headers,
            "interaction_type": self.interaction_type.value,
            "confidence": self.confidence.value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SsrfInteraction:
        return cls(
            interaction_id=data.get("interaction_id", ""),
            canary_token=data.get("canary_token", ""),
            protocol=data.get("protocol", "HTTP"),
            timestamp=data.get("timestamp"),
            source_ip_metadata=data.get("source_ip_metadata"),
            observed_hostname=data.get("observed_hostname"),
            observed_method=data.get("observed_method"),
            observed_path=data.get("observed_path"),
            bounded_headers=data.get("bounded_headers"),
            interaction_type=data.get("interaction_type", OobInteractionType.HTTP_INTERACTION),
            confidence=data.get("confidence", SsrfConfidence.OBSERVED),
        )


class SsrfEvidence:
    """
    Cryptographic and correlation evidence proving server-side network interaction.
    """

    def __init__(
        self,
        test_id: str,
        canary_token: str,
        provider_name: str,
        interaction_type: OobInteractionType | str,
        interactions: List[SsrfInteraction],
        baseline_status: int = 0,
        test_status: int = 0,
        evidence_summary: str = "",
        captured_at: Optional[str] = None,
        evidence_hash: Optional[str] = None,
    ):
        self.test_id = test_id
        self.canary_token = canary_token
        self.provider_name = provider_name
        self.interaction_type = (
            interaction_type
            if isinstance(interaction_type, OobInteractionType)
            else OobInteractionType(str(interaction_type).upper())
        )
        self.interactions = list(interactions or [])
        self.baseline_status = int(baseline_status)
        self.test_status = int(test_status)
        self.evidence_summary = evidence_summary
        self.captured_at = captured_at or datetime.now(timezone.utc).isoformat()
        self.evidence_hash = evidence_hash or self._compute_hash()

    def _compute_hash(self) -> str:
        payload = f"{self.test_id}|{self.canary_token}|{self.provider_name}|{self.interaction_type.value}|{len(self.interactions)}|{self.captured_at}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_id": self.test_id,
            "canary_token": self.canary_token,
            "provider_name": self.provider_name,
            "interaction_type": self.interaction_type.value,
            "interactions": [i.to_dict() for i in self.interactions],
            "baseline_status": self.baseline_status,
            "test_status": self.test_status,
            "evidence_summary": self.evidence_summary,
            "captured_at": self.captured_at,
            "evidence_hash": self.evidence_hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SsrfEvidence:
        raw_ints = data.get("interactions", [])
        ints = [SsrfInteraction.from_dict(i) for i in raw_ints]
        return cls(
            test_id=data.get("test_id", ""),
            canary_token=data.get("canary_token", ""),
            provider_name=data.get("provider_name", "mock"),
            interaction_type=data.get("interaction_type", OobInteractionType.UNKNOWN),
            interactions=ints,
            baseline_status=data.get("baseline_status", 0),
            test_status=data.get("test_status", 0),
            evidence_summary=data.get("evidence_summary", ""),
            captured_at=data.get("captured_at"),
            evidence_hash=data.get("evidence_hash"),
        )


class SsrfCandidate:
    """
    Structured SSRF candidate model tracking discovery, canary testing,
    correlation, and validation status across the research lifecycle.
    """

    def __init__(
        self,
        application: str,
        endpoint: str,
        parameter: str,
        candidate_id: Optional[str] = None,
        param_location: str = "QUERY",  # "QUERY", "PATH", "JSON_BODY", "FORM_BODY", "HEADER"
        method: str = "GET",
        category: SsrfCategory | str = SsrfCategory.DIRECT,
        source_intel: Optional[SsrfSource] = None,
        sink_intel: Optional[SsrfSink] = None,
        url_type: str = "ABSOLUTE_URL",  # "ABSOLUTE_URL", "HOSTNAME", "IP", "RELATIVE"
        callback_token: Optional[str] = None,
        confidence: SsrfConfidence | str = SsrfConfidence.CANDIDATE,
        severity: str = "HIGH",
        lifecycle_state: str = "CANDIDATE",  # CANDIDATE, TESTING, OBSERVED, VALIDATED, REJECTED
        approval_status: str = "PENDING",    # PENDING, APPROVED, REJECTED
        evidence: Optional[SsrfEvidence] = None,
        provenance: Optional[Dict[str, Any]] = None,
        notes: str = "",
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
    ):
        self.candidate_id = candidate_id or f"ssrf-{uuid.uuid4().hex[:10]}"
        self.application = application.strip()
        self.endpoint = endpoint.strip()
        self.parameter = parameter.strip()
        self.param_location = param_location.upper().strip()
        self.method = method.upper().strip()
        self.category = (
            category
            if isinstance(category, SsrfCategory)
            else SsrfCategory(str(category).lower())
        )
        self.source_intel = source_intel or SsrfSource(source_type=self.param_location, parameter_name=self.parameter)
        self.sink_intel = sink_intel or SsrfSink(sink_type="URL_FETCHER")
        self.url_type = url_type
        self.callback_token = callback_token
        self.confidence = (
            confidence
            if isinstance(confidence, SsrfConfidence)
            else SsrfConfidence(str(confidence).upper())
        )
        self.severity = severity.upper()
        self.lifecycle_state = lifecycle_state
        self.approval_status = approval_status.upper()
        self.evidence = evidence
        self.provenance = provenance or {}
        self.notes = notes
        now = datetime.now(timezone.utc).isoformat()
        self.created_at = created_at or now
        self.updated_at = updated_at or now

    def is_approved_for_execution(self) -> bool:
        """Enforces human approval before dispatching active canary tests."""
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
            "sink_intel": self.sink_intel.to_dict() if self.sink_intel else None,
            "url_type": self.url_type,
            "callback_token": self.callback_token,
            "confidence": self.confidence.value,
            "severity": self.severity,
            "lifecycle_state": self.lifecycle_state,
            "approval_status": self.approval_status,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "provenance": self.provenance,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SsrfCandidate:
        src = SsrfSource.from_dict(data["source_intel"]) if data.get("source_intel") else None
        snk = SsrfSink.from_dict(data["sink_intel"]) if data.get("sink_intel") else None
        ev = SsrfEvidence.from_dict(data["evidence"]) if data.get("evidence") else None

        return cls(
            candidate_id=data.get("candidate_id"),
            application=data.get("application", ""),
            endpoint=data.get("endpoint", ""),
            parameter=data.get("parameter", ""),
            param_location=data.get("param_location", "QUERY"),
            method=data.get("method", "GET"),
            category=data.get("category", SsrfCategory.DIRECT),
            source_intel=src,
            sink_intel=snk,
            url_type=data.get("url_type", "ABSOLUTE_URL"),
            callback_token=data.get("callback_token"),
            confidence=data.get("confidence", SsrfConfidence.CANDIDATE),
            severity=data.get("severity", "HIGH"),
            lifecycle_state=data.get("lifecycle_state", "CANDIDATE"),
            approval_status=data.get("approval_status", "PENDING"),
            evidence=ev,
            provenance=data.get("provenance", {}),
            notes=data.get("notes", ""),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
        )
