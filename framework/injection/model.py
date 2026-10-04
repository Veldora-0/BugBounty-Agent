"""
Data Models for Injection Intelligence & Controlled Validation (Phase 10).

Defines structured models for injection candidates, context inference,
bounded evidence captures, prioritization scores, and findings.
Supports SQLi, NoSQLi, SSTI, and Command Injection foundation.
Never stores unredacted credentials or destructive payloads.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional, Set
import uuid

from framework.common.evidence import sanitize_sensitive_data
from framework.findings.lifecycle import FindingLifecycle


class InjectionType(str, Enum):
    """Taxonomy of injection vulnerability families."""
    SQL = "sql"
    NOSQL = "nosql"
    SSTI = "ssti"
    COMMAND = "command"
    LDAP = "ldap"
    EXPRESSION = "expression"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, val: str) -> InjectionType:
        clean = (val or "").strip().lower()
        for member in cls:
            if member.value == clean or member.name.lower() == clean:
                return member
        return cls.UNKNOWN


class InjectionContext(str, Enum):
    """Contextual role of the injected parameter in the target interpreter."""
    SQL_STRING = "SQL_STRING"
    SQL_NUMERIC = "SQL_NUMERIC"
    SQL_ORDER_BY = "SQL_ORDER_BY"
    SQL_LIMIT = "SQL_LIMIT"
    SQL_FILTER = "SQL_FILTER"

    NOSQL_QUERY = "NOSQL_QUERY"
    NOSQL_OPERATOR = "NOSQL_OPERATOR"
    NOSQL_JSON = "NOSQL_JSON"

    TEMPLATE_EXPRESSION = "TEMPLATE_EXPRESSION"
    TEMPLATE_VARIABLE = "TEMPLATE_VARIABLE"
    TEMPLATE_ATTRIBUTE = "TEMPLATE_ATTRIBUTE"

    COMMAND_ARGUMENT = "COMMAND_ARGUMENT"
    COMMAND_OPTION = "COMMAND_OPTION"
    COMMAND_PATH = "COMMAND_PATH"

    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_string(cls, val: str) -> InjectionContext:
        clean = (val or "").strip().upper()
        for member in cls:
            if member.value == clean:
                return member
        return cls.UNKNOWN


class InjectionConfidence(str, Enum):
    """Confidence level assigned to an injection candidate or finding."""
    CANDIDATE = "CANDIDATE"      # Discovered via heuristic, schema, or route
    SUSPECTED = "SUSPECTED"      # Single anomaly or potential syntax distortion
    OBSERVED = "OBSERVED"        # Verified error signature or unconfirmed differential
    VALIDATED = "VALIDATED"      # Deterministic differential or mathematical proof

    @classmethod
    def from_string(cls, val: str) -> InjectionConfidence:
        clean = (val or "").strip().upper()
        for member in cls:
            if member.value == clean:
                return member
        return cls.CANDIDATE


class InjectionCandidate:
    """
    Structured model for an injection testing candidate parameter.
    Includes test prioritization score (0-100), inferred context, and lifecycle tracking.
    """

    def __init__(
        self,
        candidate_id: str,
        family: InjectionType | str,
        application: str,
        endpoint: str,
        parameter: str,
        parameter_location: str = "QUERY",  # "QUERY", "PATH", "JSON", "FORM", "HEADER"
        method: str = "GET",
        inferred_input_type: str = "STRING",  # "STRING", "INTEGER", "JSON_OBJECT", etc.
        backend_context: InjectionContext | str = InjectionContext.UNKNOWN,
        source_intelligence: Optional[Dict[str, Any]] = None,
        confidence: InjectionConfidence | str = InjectionConfidence.CANDIDATE,
        priority_score: int = 50,
        priority_reasons: Optional[List[str]] = None,
        lifecycle: FindingLifecycle | str = FindingLifecycle.CANDIDATE,
        evidence_refs: Optional[List[str]] = None,
        provenance: Optional[Dict[str, Any]] = None,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
    ):
        self.candidate_id = candidate_id.strip()
        self.family = (
            family if isinstance(family, InjectionType)
            else InjectionType.from_string(str(family))
        )
        self.application = application.strip()
        self.endpoint = endpoint.strip()
        self.parameter = parameter.strip()
        self.parameter_location = parameter_location.upper().strip()
        self.method = method.upper().strip()
        self.inferred_input_type = inferred_input_type.upper().strip()
        self.backend_context = (
            backend_context if isinstance(backend_context, InjectionContext)
            else InjectionContext.from_string(str(backend_context))
        )
        self.source_intelligence = dict(source_intelligence or {})
        self.confidence = (
            confidence if isinstance(confidence, InjectionConfidence)
            else InjectionConfidence.from_string(str(confidence))
        )
        # Clamped priority score: 0 to 100
        self.priority_score = max(0, min(100, int(priority_score)))
        self.priority_reasons = list(priority_reasons or [])
        self.lifecycle = (
            lifecycle if isinstance(lifecycle, FindingLifecycle)
            else FindingLifecycle(str(lifecycle).upper())
        )
        self.evidence_refs = list(evidence_refs or [])
        self.provenance = dict(provenance or {})
        now = datetime.now(timezone.utc).isoformat()
        self.created_at = created_at or now
        self.updated_at = updated_at or now

    def compute_fingerprint(self) -> str:
        """Computes deterministic hash for candidate deduplication."""
        raw = f"{self.application}|{self.endpoint}|{self.parameter}|{self.parameter_location}|{self.family.value}|{self.backend_context.value}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "family": self.family.value,
            "application": self.application,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "parameter_location": self.parameter_location,
            "method": self.method,
            "inferred_input_type": self.inferred_input_type,
            "backend_context": self.backend_context.value,
            "source_intelligence": self.source_intelligence,
            "confidence": self.confidence.value,
            "priority_score": self.priority_score,
            "priority_reasons": self.priority_reasons,
            "lifecycle": self.lifecycle.value,
            "evidence_refs": self.evidence_refs,
            "provenance": self.provenance,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> InjectionCandidate:
        return cls(
            candidate_id=data.get("candidate_id", ""),
            family=data.get("family", "unknown"),
            application=data.get("application", ""),
            endpoint=data.get("endpoint", ""),
            parameter=data.get("parameter", ""),
            parameter_location=data.get("parameter_location", "QUERY"),
            method=data.get("method", "GET"),
            inferred_input_type=data.get("inferred_input_type", "STRING"),
            backend_context=data.get("backend_context", "UNKNOWN"),
            source_intelligence=data.get("source_intelligence", {}),
            confidence=data.get("confidence", "CANDIDATE"),
            priority_score=data.get("priority_score", 50),
            priority_reasons=data.get("priority_reasons", []),
            lifecycle=data.get("lifecycle", "CANDIDATE"),
            evidence_refs=data.get("evidence_refs", []),
            provenance=data.get("provenance", {}),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
        )


class InjectionEvidence:
    """
    Evidence record for an injection validation trial.
    Captures baseline, control, test responses, differential signals,
    and error signatures with SHA-256 integrity hash.
    """

    def __init__(
        self,
        evidence_id: str,
        candidate_id: str,
        test_id: str,
        family: InjectionType | str,
        endpoint: str,
        parameter: str,
        payload_id: str,
        baseline_request: Dict[str, Any],
        baseline_response: Dict[str, Any],
        test_request: Dict[str, Any],
        test_response: Dict[str, Any],
        control_request: Optional[Dict[str, Any]] = None,
        control_response: Optional[Dict[str, Any]] = None,
        differential_signals: Optional[List[str]] = None,
        error_signature: Optional[Dict[str, Any]] = None,
        timing_metadata: Optional[Dict[str, Any]] = None,
        technology_context: Optional[str] = None,
        confidence: InjectionConfidence | str = InjectionConfidence.SUSPECTED,
        created_at: Optional[str] = None,
    ):
        self.evidence_id = evidence_id.strip()
        self.candidate_id = candidate_id.strip()
        self.test_id = test_id.strip()
        self.family = (
            family if isinstance(family, InjectionType)
            else InjectionType.from_string(str(family))
        )
        self.endpoint = endpoint.strip()
        self.parameter = parameter.strip()
        self.payload_id = payload_id.strip()

        # Sanitize sensitive headers and tokens in requests/responses
        self.baseline_request = self._sanitize_dict(baseline_request)
        self.baseline_response = self._sanitize_dict(baseline_response)
        self.test_request = self._sanitize_dict(test_request)
        self.test_response = self._sanitize_dict(test_response)
        self.control_request = self._sanitize_dict(control_request) if control_request else None
        self.control_response = self._sanitize_dict(control_response) if control_response else None

        self.differential_signals = list(differential_signals or [])
        self.error_signature = dict(error_signature or {}) if error_signature else None
        self.timing_metadata = dict(timing_metadata or {}) if timing_metadata else None
        self.technology_context = technology_context or ""
        self.confidence = (
            confidence if isinstance(confidence, InjectionConfidence)
            else InjectionConfidence.from_string(str(confidence))
        )
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.evidence_hash = self._compute_evidence_hash()

    @staticmethod
    def _sanitize_dict(d: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not d:
            return {}
        clean = {}
        for k, v in d.items():
            if isinstance(v, str):
                combined = f"{k}: {v}"
                sanitized = sanitize_sensitive_data(combined)
                if sanitized.startswith(f"{k}: "):
                    clean[k] = sanitized[len(f"{k}: "):]
                else:
                    clean[k] = sanitize_sensitive_data(v)
            elif isinstance(v, dict):
                clean[k] = InjectionEvidence._sanitize_dict(v)
            else:
                clean[k] = v
        return clean

    def _compute_evidence_hash(self) -> str:
        body = json.dumps(
            {
                "test_id": self.test_id,
                "candidate_id": self.candidate_id,
                "family": self.family.value,
                "endpoint": self.endpoint,
                "parameter": self.parameter,
                "payload_id": self.payload_id,
                "signals": self.differential_signals,
                "error": self.error_signature,
            },
            sort_keys=True,
        )
        return hashlib.sha256(body.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "candidate_id": self.candidate_id,
            "test_id": self.test_id,
            "family": self.family.value,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "payload_id": self.payload_id,
            "baseline_request": self.baseline_request,
            "baseline_response": self.baseline_response,
            "control_request": self.control_request,
            "control_response": self.control_response,
            "test_request": self.test_request,
            "test_response": self.test_response,
            "differential_signals": self.differential_signals,
            "error_signature": self.error_signature,
            "timing_metadata": self.timing_metadata,
            "technology_context": self.technology_context,
            "confidence": self.confidence.value,
            "evidence_hash": self.evidence_hash,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> InjectionEvidence:
        ev = cls(
            evidence_id=data.get("evidence_id", ""),
            candidate_id=data.get("candidate_id", ""),
            test_id=data.get("test_id", ""),
            family=data.get("family", "unknown"),
            endpoint=data.get("endpoint", ""),
            parameter=data.get("parameter", ""),
            payload_id=data.get("payload_id", ""),
            baseline_request=data.get("baseline_request", {}),
            baseline_response=data.get("baseline_response", {}),
            test_request=data.get("test_request", {}),
            test_response=data.get("test_response", {}),
            control_request=data.get("control_request"),
            control_response=data.get("control_response"),
            differential_signals=data.get("differential_signals", []),
            error_signature=data.get("error_signature"),
            timing_metadata=data.get("timing_metadata"),
            technology_context=data.get("technology_context"),
            confidence=data.get("confidence", "SUSPECTED"),
            created_at=data.get("created_at"),
        )
        if "evidence_hash" in data:
            ev.evidence_hash = data["evidence_hash"]
        return ev
