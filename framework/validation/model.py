"""
Security Test Case and Validation Models for BugBounty-Agent.

Provides structured models for security test cases, validation results,
risk classification, and lifecycle states.
Never permits unrestricted exploitation or unbounded payloads.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional
import uuid

from framework.findings.lifecycle import FindingLifecycle


class VulnerabilityFamily(str, Enum):
    """Standard vulnerability classifications."""
    XSS = "XSS"
    SQL_INJECTION = "SQL_INJECTION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    SSRF = "SSRF"
    AUTHORIZATION = "AUTHORIZATION"
    AUTHENTICATION = "AUTHENTICATION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    FILE_UPLOAD = "FILE_UPLOAD"
    OPEN_REDIRECT = "OPEN_REDIRECT"
    TEMPLATE_INJECTION = "TEMPLATE_INJECTION"
    BUSINESS_LOGIC = "BUSINESS_LOGIC"
    CORS = "CORS"
    UNKNOWN = "UNKNOWN"


class RiskLevel(str, Enum):
    """Safety and risk classification for validation operations."""
    SAFE = "SAFE"
    INFORMATIVE = "INFORMATIVE"
    POTENTIALLY_DISRUPTIVE = "POTENTIALLY_DISRUPTIVE"


class SecurityTestCase:
    """
    Structured model for a controlled, hypothesis-driven security test.
    Defines target, mutated parameter, payload ID, risk level, and expected signals.
    """

    def __init__(
        self,
        vulnerability_family: VulnerabilityFamily | str,
        target: str,
        endpoint: str,
        method: str = "GET",
        parameter: Optional[str] = None,
        payload_identifier: str = "DEFAULT",
        test_strategy: str = "baseline_comparison",
        preconditions: Optional[Dict[str, Any]] = None,
        risk_level: RiskLevel | str = RiskLevel.SAFE,
        request_budget: int = 3,
        expected_signals: Optional[List[str]] = None,
        provenance: Optional[Dict[str, Any]] = None,
        test_id: Optional[str] = None,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
    ):
        if isinstance(vulnerability_family, str):
            try:
                self.vulnerability_family = VulnerabilityFamily(vulnerability_family)
            except ValueError:
                self.vulnerability_family = VulnerabilityFamily.UNKNOWN
        else:
            self.vulnerability_family = vulnerability_family

        self.target = target.strip().lower()
        self.endpoint = endpoint.strip()
        self.method = method.strip().upper()
        self.parameter = parameter.strip() if parameter else None
        self.payload_identifier = payload_identifier.strip()
        self.test_strategy = test_strategy.strip()
        self.preconditions = preconditions or {}

        if isinstance(risk_level, str):
            try:
                self.risk_level = RiskLevel(risk_level.upper())
            except ValueError:
                self.risk_level = RiskLevel.SAFE
        else:
            self.risk_level = risk_level

        self.request_budget = max(1, int(request_budget))
        self.expected_signals = list(expected_signals or [])
        self.provenance = provenance or {}

        now_str = datetime.now(timezone.utc).isoformat()
        self.created_at = created_at or now_str
        self.updated_at = updated_at or now_str

        # Generate deterministic test ID if not provided
        if test_id:
            self.test_id = test_id
        else:
            fp = self.compute_fingerprint()
            self.test_id = f"STC-{fp[:10].upper()}"

    def compute_fingerprint(self) -> str:
        """Computes a stable SHA-256 fingerprint for deduplication and resume tracking."""
        components = [
            self.vulnerability_family.value,
            self.target,
            self.endpoint.lower(),
            self.method,
            self.parameter.lower() if self.parameter else "",
            self.payload_identifier,
            self.test_strategy,
        ]
        raw = "|".join(components)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Serializes test case to dictionary."""
        return {
            "test_id": self.test_id,
            "vulnerability_family": self.vulnerability_family.value,
            "target": self.target,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "payload_identifier": self.payload_identifier,
            "test_strategy": self.test_strategy,
            "preconditions": self.preconditions,
            "risk_level": self.risk_level.value,
            "request_budget": self.request_budget,
            "expected_signals": self.expected_signals,
            "provenance": self.provenance,
            "fingerprint": self.compute_fingerprint(),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SecurityTestCase:
        """Deserializes test case from dictionary."""
        return cls(
            test_id=data.get("test_id"),
            vulnerability_family=data.get("vulnerability_family", VulnerabilityFamily.UNKNOWN),
            target=data.get("target", ""),
            endpoint=data.get("endpoint", ""),
            method=data.get("method", "GET"),
            parameter=data.get("parameter"),
            payload_identifier=data.get("payload_identifier", "DEFAULT"),
            test_strategy=data.get("test_strategy", "baseline_comparison"),
            preconditions=data.get("preconditions", {}),
            risk_level=data.get("risk_level", RiskLevel.SAFE),
            request_budget=data.get("request_budget", 3),
            expected_signals=data.get("expected_signals", []),
            provenance=data.get("provenance", {}),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
        )


class ValidationResult:
    """Represents the outcome of a controlled security test execution."""

    def __init__(
        self,
        test_id: str,
        lifecycle_state: FindingLifecycle | str,
        signals_observed: Optional[List[str]] = None,
        evidence_summary: str = "",
        request_metadata: Optional[Dict[str, Any]] = None,
        response_metadata: Optional[Dict[str, Any]] = None,
        confidence: str = "LOW",
        severity: str = "INFORMATIONAL",
        evidence_reference: Optional[str] = None,
        timestamp: Optional[str] = None,
    ):
        self.test_id = test_id
        if isinstance(lifecycle_state, str):
            try:
                self.lifecycle_state = FindingLifecycle(lifecycle_state.upper())
            except ValueError:
                self.lifecycle_state = FindingLifecycle.CANDIDATE
        else:
            self.lifecycle_state = lifecycle_state

        self.signals_observed = list(signals_observed or [])
        self.evidence_summary = evidence_summary
        self.request_metadata = request_metadata or {}
        self.response_metadata = response_metadata or {}
        self.confidence = confidence.upper()
        self.severity = severity.upper()
        self.evidence_reference = evidence_reference
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Serializes result to dictionary."""
        return {
            "test_id": self.test_id,
            "lifecycle_state": self.lifecycle_state.value,
            "signals_observed": self.signals_observed,
            "evidence_summary": self.evidence_summary,
            "request_metadata": self.request_metadata,
            "response_metadata": self.response_metadata,
            "confidence": self.confidence,
            "severity": self.severity,
            "evidence_reference": self.evidence_reference,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ValidationResult:
        """Deserializes result from dictionary."""
        return cls(
            test_id=data.get("test_id", ""),
            lifecycle_state=data.get("lifecycle_state", FindingLifecycle.CANDIDATE),
            signals_observed=data.get("signals_observed", []),
            evidence_summary=data.get("evidence_summary", ""),
            request_metadata=data.get("request_metadata", {}),
            response_metadata=data.get("response_metadata", {}),
            confidence=data.get("confidence", "LOW"),
            severity=data.get("severity", "INFORMATIONAL"),
            evidence_reference=data.get("evidence_reference"),
            timestamp=data.get("timestamp"),
        )
