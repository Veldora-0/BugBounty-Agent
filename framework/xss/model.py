"""
Data Models for XSS Intelligence & Validation in BugBounty-Agent.

Defines structured representations for XSS candidates, reflection contexts,
DOM sources and sinks, transformation states, evidence records, and confidence lifecycles.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional
import uuid


class XssCategory(str, Enum):
    """Category of Cross-Site Scripting vulnerability."""
    REFLECTED = "reflected"
    DOM = "dom"
    STORED = "stored"


class XssContextType(str, Enum):
    """Context in which input is reflected or rendered."""
    HTML_BODY = "HTML_BODY"
    HTML_ATTRIBUTE = "HTML_ATTRIBUTE"
    HTML_ATTRIBUTE_NAME = "HTML_ATTRIBUTE_NAME"
    SCRIPT_BLOCK = "SCRIPT_BLOCK"
    EVENT_HANDLER = "EVENT_HANDLER"
    URL_ATTRIBUTE = "URL_ATTRIBUTE"
    JSON_STRING = "JSON_STRING"
    STYLE_BLOCK = "STYLE_BLOCK"
    HTML_COMMENT = "HTML_COMMENT"
    UNKNOWN = "UNKNOWN"


class ReflectionState(str, Enum):
    """State of input reflection relative to context defenses."""
    UNFILTERED = "UNFILTERED"                     # Reflected verbatim with active characters intact
    ENCODED = "ENCODED"                           # Defended: properly entity/URL/JS encoded for context
    INSUFFICIENTLY_ENCODED = "INSUFFICIENTLY_ENCODED" # Partially encoded but insufficient (e.g. HTML encoded in JS string)
    FILTERED = "FILTERED"                         # Characters stripped or sanitized
    ABSENT = "ABSENT"                             # Not reflected


class XssConfidence(str, Enum):
    """
    Confidence assessment for XSS candidate.
    Reflection alone is NEVER marked VALIDATED without verified execution context.
    """
    OBSERVED = "OBSERVED"     # Input reflected or sink detected, but exploitability unproven
    SUSPECTED = "SUSPECTED"   # Unencoded reflection in dangerous context or direct source-to-sink flow
    VALIDATED = "VALIDATED"   # Non-destructive proof-of-concept executed in verified context
    REJECTED = "REJECTED"     # Properly encoded, sanitized, or not reproducible


class XssSource:
    """Represents a DOM-based untrusted input source."""

    def __init__(
        self,
        source_type: str,
        name: str,
        file_path: Optional[str] = None,
        line_number: Optional[int] = None,
        snippet: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.source_type = source_type
        self.name = name
        self.file_path = file_path
        self.line_number = line_number
        self.snippet = snippet
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_type": self.source_type,
            "name": self.name,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "snippet": self.snippet,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> XssSource:
        return cls(
            source_type=data.get("source_type", "unknown"),
            name=data.get("name", ""),
            file_path=data.get("file_path"),
            line_number=data.get("line_number"),
            snippet=data.get("snippet"),
            details=data.get("details", {}),
        )


class XssSink:
    """Represents a DOM-based code or markup execution sink."""

    def __init__(
        self,
        sink_type: str,
        name: str,
        framework: Optional[str] = None,
        file_path: Optional[str] = None,
        line_number: Optional[int] = None,
        snippet: Optional[str] = None,
        is_framework_dangerous: bool = False,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.sink_type = sink_type
        self.name = name
        self.framework = framework
        self.file_path = file_path
        self.line_number = line_number
        self.snippet = snippet
        self.is_framework_dangerous = is_framework_dangerous
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sink_type": self.sink_type,
            "name": self.name,
            "framework": self.framework,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "snippet": self.snippet,
            "is_framework_dangerous": self.is_framework_dangerous,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> XssSink:
        return cls(
            sink_type=data.get("sink_type", "unknown"),
            name=data.get("name", ""),
            framework=data.get("framework"),
            file_path=data.get("file_path"),
            line_number=data.get("line_number"),
            snippet=data.get("snippet"),
            is_framework_dangerous=data.get("is_framework_dangerous", False),
            details=data.get("details", {}),
        )


class XssEvidence:
    """Cryptographically verifiable evidence record for an XSS test or observation."""

    def __init__(
        self,
        canary_token: str,
        context_snippet: str,
        evidence_hash: Optional[str] = None,
        request_summary: Optional[Dict[str, Any]] = None,
        response_summary: Optional[Dict[str, Any]] = None,
        transformations_observed: Optional[Dict[str, str]] = None,
        browser_signals: Optional[List[str]] = None,
        captured_at: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.canary_token = canary_token
        self.context_snippet = context_snippet
        self.request_summary = request_summary or {}
        self.response_summary = response_summary or {}
        self.transformations_observed = transformations_observed or {}
        self.browser_signals = browser_signals or []
        self.captured_at = captured_at or datetime.now(timezone.utc).isoformat()
        self.details = details or {}
        self.evidence_hash = evidence_hash or self._compute_hash()

    def _compute_hash(self) -> str:
        payload = f"{self.canary_token}|{self.context_snippet}|{self.captured_at}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "canary_token": self.canary_token,
            "context_snippet": self.context_snippet,
            "evidence_hash": self.evidence_hash,
            "request_summary": self.request_summary,
            "response_summary": self.response_summary,
            "transformations_observed": self.transformations_observed,
            "browser_signals": self.browser_signals,
            "details": self.details,
            "captured_at": self.captured_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> XssEvidence:
        return cls(
            canary_token=data.get("canary_token", ""),
            context_snippet=data.get("context_snippet", ""),
            evidence_hash=data.get("evidence_hash"),
            request_summary=data.get("request_summary", {}),
            response_summary=data.get("response_summary", {}),
            transformations_observed=data.get("transformations_observed", {}),
            browser_signals=data.get("browser_signals", []),
            captured_at=data.get("captured_at"),
        )


class XssCandidate:
    """
    Structured candidate model tracking potential XSS vulnerabilities
    across reflected, DOM, and stored workflows.
    """

    def __init__(
        self,
        candidate_id: Optional[str] = None,
        category: XssCategory | str = XssCategory.REFLECTED,
        target_asset: str = "",
        endpoint: str = "",
        parameter: Optional[str] = None,
        method: str = "GET",
        context_type: XssContextType | str = XssContextType.UNKNOWN,
        reflection_state: ReflectionState | str = ReflectionState.ABSENT,
        confidence: XssConfidence | str = XssConfidence.OBSERVED,
        lifecycle_state: str = "OBSERVED",
        severity: str = "INFORMATIONAL",
        source: Optional[XssSource] = None,
        sink: Optional[XssSink] = None,
        evidence: Optional[XssEvidence] = None,
        canary_token: Optional[str] = None,
        retrieval_endpoint: Optional[str] = None,
        retrieval_method: Optional[str] = None,
        remediation: Optional[str] = None,
        notes: Optional[str] = None,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
    ):
        self.candidate_id = candidate_id or f"xss-{uuid.uuid4().hex[:10]}"
        self.category = category if isinstance(category, XssCategory) else XssCategory(category)
        self.target_asset = target_asset
        self.endpoint = endpoint
        self.parameter = parameter
        self.method = method.upper()
        self.context_type = context_type if isinstance(context_type, XssContextType) else XssContextType(context_type)
        self.reflection_state = reflection_state if isinstance(reflection_state, ReflectionState) else ReflectionState(reflection_state)
        self.confidence = confidence if isinstance(confidence, XssConfidence) else XssConfidence(confidence)
        self.lifecycle_state = lifecycle_state
        self.severity = severity
        self.source = source
        self.sink = sink
        self.evidence = evidence
        self.canary_token = canary_token
        self.retrieval_endpoint = retrieval_endpoint
        self.retrieval_method = retrieval_method
        self.remediation = remediation or self._default_remediation()
        self.notes = notes or ""
        now = datetime.now(timezone.utc).isoformat()
        self.created_at = created_at or now
        self.updated_at = updated_at or now

    def _default_remediation(self) -> str:
        if self.category == XssCategory.DOM:
            return "Avoid passing untrusted data directly to DOM sinks; use textContent or an audited sanitization library (e.g. DOMPurify)."
        elif self.category == XssCategory.STORED:
            return "Validate and sanitize input on ingestion, and apply context-aware HTML entity encoding upon retrieval and rendering."
        else:
            return "Implement context-sensitive output encoding and enforce a restrictive Content-Security-Policy."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "category": self.category.value,
            "target_asset": self.target_asset,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "method": self.method,
            "context_type": self.context_type.value,
            "reflection_state": self.reflection_state.value,
            "confidence": self.confidence.value,
            "lifecycle_state": self.lifecycle_state,
            "severity": self.severity,
            "source": self.source.to_dict() if self.source else None,
            "sink": self.sink.to_dict() if self.sink else None,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "canary_token": self.canary_token,
            "retrieval_endpoint": self.retrieval_endpoint,
            "retrieval_method": self.retrieval_method,
            "remediation": self.remediation,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> XssCandidate:
        source_dict = data.get("source")
        sink_dict = data.get("sink")
        evidence_dict = data.get("evidence")

        return cls(
            candidate_id=data.get("candidate_id"),
            category=data.get("category", XssCategory.REFLECTED),
            target_asset=data.get("target_asset", ""),
            endpoint=data.get("endpoint", ""),
            parameter=data.get("parameter"),
            method=data.get("method", "GET"),
            context_type=data.get("context_type", XssContextType.UNKNOWN),
            reflection_state=data.get("reflection_state", ReflectionState.ABSENT),
            confidence=data.get("confidence", XssConfidence.OBSERVED),
            lifecycle_state=data.get("lifecycle_state", "OBSERVED"),
            severity=data.get("severity", "INFORMATIONAL"),
            source=XssSource.from_dict(source_dict) if source_dict else None,
            sink=XssSink.from_dict(sink_dict) if sink_dict else None,
            evidence=XssEvidence.from_dict(evidence_dict) if evidence_dict else None,
            canary_token=data.get("canary_token"),
            retrieval_endpoint=data.get("retrieval_endpoint"),
            retrieval_method=data.get("retrieval_method"),
            remediation=data.get("remediation"),
            notes=data.get("notes"),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
        )
