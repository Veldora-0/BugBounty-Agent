"""
Data Models for HTTP / Header Trust & Protocol Security Subsystem (Phase 11).

Defines structured models for header trust candidates, trust classification,
controlled test cases, evidence recording, and multi-signal findings.
Never stores unredacted credentials or destructive payloads.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Set
import uuid

from framework.common.evidence import sanitize_sensitive_data
from framework.findings.lifecycle import FindingLifecycle


class TrustClassification(str, Enum):
    """Deterministic trust state of a supplied HTTP header."""
    UNUSED = "UNUSED"
    ACCEPTED = "ACCEPTED"
    REFLECTED = "REFLECTED"
    USED_FOR_ROUTING = "USED_FOR_ROUTING"
    USED_FOR_URL_GENERATION = "USED_FOR_URL_GENERATION"
    USED_FOR_REDIRECT = "USED_FOR_REDIRECT"
    USED_FOR_SECURITY_DECISION = "USED_FOR_SECURITY_DECISION"
    USED_FOR_CACHE_KEY = "USED_FOR_CACHE_KEY"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_string(cls, val: str) -> TrustClassification:
        clean = (val or "").strip().upper()
        for member in cls:
            if member.value == clean:
                return member
        return cls.UNKNOWN


class TrustSource(str, Enum):
    """Source level responsible for interpreting/trusting the header."""
    DIRECT_APPLICATION_TRUST = "DIRECT_APPLICATION_TRUST"
    PROXY_TRUST = "PROXY_TRUST"
    FRAMEWORK_TRUST = "FRAMEWORK_TRUST"
    UNKNOWN_TRUST_SOURCE = "UNKNOWN_TRUST_SOURCE"

    @classmethod
    def from_string(cls, val: str) -> TrustSource:
        clean = (val or "").strip().upper()
        for member in cls:
            if member.value == clean:
                return member
        return cls.UNKNOWN_TRUST_SOURCE


class HttpTrustCategory(str, Enum):
    """Categories of HTTP / Header trust testing."""
    HOST_INJECTION = "host"
    FORWARDED_TRUST = "forwarded"
    SCHEME_TRUST = "scheme"
    REDIRECT_POISONING = "redirect"
    URL_POISONING = "url_poisoning"
    CORS_TRUST = "cors"
    HPP = "hpp"
    CACHE_POISONING = "cache"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, val: str) -> HttpTrustCategory:
        clean = (val or "").strip().lower()
        for member in cls:
            if member.value == clean or member.name.lower() == clean:
                return member
        return cls.UNKNOWN


class HttpTrustConfidence(str, Enum):
    """Confidence level assigned to an HTTP trust candidate or finding."""
    CANDIDATE = "CANDIDATE"      # Discovered via routing, schema, or endpoint semantics
    SUSPECTED = "SUSPECTED"      # Single anomaly or header acceptance
    OBSERVED = "OBSERVED"        # Reflection or differential response observed
    VALIDATED = "VALIDATED"      # Security-sensitive effect deterministically confirmed

    @classmethod
    def from_string(cls, val: str) -> HttpTrustConfidence:
        clean = (val or "").strip().upper()
        for member in cls:
            if member.value == clean:
                return member
        return cls.CANDIDATE


def generate_canary_host(program: str, test_id: str = "", lab_mode: bool = False) -> str:
    """
    Generates a researcher-controlled canary domain for host/proxy header injection.
    Bounded length, no credentials, safe domain.
    """
    clean_prog = re.sub(r"[^a-zA-Z0-9-]", "", program.lower()) or "lab"
    if lab_mode:
        return "bb11-lab-canary.researcher-controlled.example"
    tid = test_id[:8] if test_id else uuid.uuid4().hex[:8]
    return f"bb11-{clean_prog}-{tid}.researcher-controlled.example"


class HeaderTrustCandidate:
    """
    Structured model for an HTTP header trust testing candidate.
    Includes priority score (0-100), trust classification, and lifecycle tracking.
    """

    def __init__(
        self,
        candidate_id: str,
        header_name: str,
        endpoint: str,
        application: str,
        method: str = "GET",
        supplied_value: str = "",
        observed_behavior: str = "",
        trust_classification: TrustClassification | str = TrustClassification.UNKNOWN,
        trust_source: TrustSource | str = TrustSource.UNKNOWN_TRUST_SOURCE,
        security_sensitive_effect: str = "",
        category: HttpTrustCategory | str = HttpTrustCategory.HOST_INJECTION,
        source: str = "PASSIVE_ENDPOINT",
        confidence: HttpTrustConfidence | str = HttpTrustConfidence.CANDIDATE,
        severity: str = "LOW",
        priority: int = 10,
        lifecycle: FindingLifecycle | str = FindingLifecycle.CANDIDATE,
        evidence_references: Optional[List[str]] = None,
        provenance: Optional[Dict[str, Any]] = None,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
    ):
        self.candidate_id = candidate_id
        self.header_name = header_name.strip()
        self.endpoint = endpoint.strip()
        self.application = application.strip()
        self.method = method.upper().strip()
        self.supplied_value = supplied_value
        self.observed_behavior = observed_behavior
        self.trust_classification = (
            trust_classification
            if isinstance(trust_classification, TrustClassification)
            else TrustClassification.from_string(trust_classification)
        )
        self.trust_source = (
            trust_source
            if isinstance(trust_source, TrustSource)
            else TrustSource.from_string(trust_source)
        )
        self.security_sensitive_effect = security_sensitive_effect
        self.category = (
            category
            if isinstance(category, HttpTrustCategory)
            else HttpTrustCategory.from_string(category)
        )
        self.source = source
        self.confidence = (
            confidence
            if isinstance(confidence, HttpTrustConfidence)
            else HttpTrustConfidence.from_string(confidence)
        )
        self.severity = severity.upper().strip()
        self.priority = max(0, min(100, int(priority)))
        if isinstance(lifecycle, FindingLifecycle):
            self.lifecycle = lifecycle
        else:
            clean_l = str(lifecycle).upper().strip()
            self.lifecycle = FindingLifecycle[clean_l] if clean_l in FindingLifecycle.__members__ else FindingLifecycle.CANDIDATE
        self.evidence_references = list(evidence_references or [])
        self.provenance = dict(provenance or {})
        now_iso = datetime.now(timezone.utc).isoformat()
        self.created_at = created_at or now_iso
        self.updated_at = updated_at or now_iso

    def compute_fingerprint(self) -> str:
        """Computes stable SHA-256 fingerprint for deduplication."""
        norm_url = self.endpoint.split("?")[0].rstrip("/").lower()
        key = f"{self.application.lower()}|{norm_url}|{self.method}|{self.header_name.lower()}|{self.category.value}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "header_name": self.header_name,
            "endpoint": self.endpoint,
            "application": self.application,
            "method": self.method,
            "supplied_value": self.supplied_value,
            "observed_behavior": self.observed_behavior,
            "trust_classification": self.trust_classification.value,
            "trust_source": self.trust_source.value,
            "security_sensitive_effect": self.security_sensitive_effect,
            "category": self.category.value,
            "source": self.source,
            "confidence": self.confidence.value,
            "severity": self.severity,
            "priority": self.priority,
            "lifecycle": self.lifecycle.value,
            "evidence_references": self.evidence_references,
            "provenance": self.provenance,
            "fingerprint": self.compute_fingerprint(),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> HeaderTrustCandidate:
        return cls(
            candidate_id=data.get("candidate_id", str(uuid.uuid4())),
            header_name=data.get("header_name", ""),
            endpoint=data.get("endpoint", ""),
            application=data.get("application", ""),
            method=data.get("method", "GET"),
            supplied_value=data.get("supplied_value", ""),
            observed_behavior=data.get("observed_behavior", ""),
            trust_classification=data.get("trust_classification", TrustClassification.UNKNOWN),
            trust_source=data.get("trust_source", TrustSource.UNKNOWN_TRUST_SOURCE),
            security_sensitive_effect=data.get("security_sensitive_effect", ""),
            category=data.get("category", HttpTrustCategory.HOST_INJECTION),
            source=data.get("source", "PASSIVE_ENDPOINT"),
            confidence=data.get("confidence", HttpTrustConfidence.CANDIDATE),
            severity=data.get("severity", "LOW"),
            priority=data.get("priority", 10),
            lifecycle=data.get("lifecycle", FindingLifecycle.CANDIDATE),
            evidence_references=data.get("evidence_references", []),
            provenance=data.get("provenance", {}),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
        )


class HeaderTrustEvidence:
    """
    Evidence record for an HTTP header trust test case.
    Sanitizes secrets/cookies and computes SHA-256 integrity hash.
    """

    def __init__(
        self,
        evidence_id: str,
        candidate_id: str,
        category: HttpTrustCategory | str,
        header_name: str,
        supplied_value: str,
        baseline_status: int,
        test_status: int,
        baseline_headers: Dict[str, str],
        test_headers: Dict[str, str],
        match_signals: List[str],
        body_snippet: str = "",
        security_effect_summary: str = "",
        timestamp: Optional[str] = None,
    ):
        self.evidence_id = evidence_id
        self.candidate_id = candidate_id
        self.category = (
            category
            if isinstance(category, HttpTrustCategory)
            else HttpTrustCategory.from_string(category)
        )
        self.header_name = header_name
        self.supplied_value = supplied_value
        self.baseline_status = baseline_status
        self.test_status = test_status
        self.baseline_headers = {
            str(k): sanitize_sensitive_data(f"{k}: {v}").split(": ", 1)[-1]
            for k, v in (baseline_headers or {}).items()
        }
        self.test_headers = {
            str(k): sanitize_sensitive_data(f"{k}: {v}").split(": ", 1)[-1]
            for k, v in (test_headers or {}).items()
        }
        self.match_signals = list(match_signals)
        self.body_snippet = sanitize_sensitive_data(body_snippet[:1500])
        self.security_effect_summary = security_effect_summary
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.integrity_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        serialized = json.dumps(
            {
                "evidence_id": self.evidence_id,
                "candidate_id": self.candidate_id,
                "category": self.category.value,
                "header_name": self.header_name,
                "supplied_value": self.supplied_value,
                "test_status": self.test_status,
                "signals": sorted(self.match_signals),
                "body_snippet": self.body_snippet,
            },
            sort_keys=True,
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "candidate_id": self.candidate_id,
            "category": self.category.value,
            "header_name": self.header_name,
            "supplied_value": self.supplied_value,
            "baseline_status": self.baseline_status,
            "test_status": self.test_status,
            "baseline_headers": self.baseline_headers,
            "test_headers": self.test_headers,
            "match_signals": self.match_signals,
            "body_snippet": self.body_snippet,
            "security_effect_summary": self.security_effect_summary,
            "timestamp": self.timestamp,
            "integrity_hash": self.integrity_hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> HeaderTrustEvidence:
        ev = cls(
            evidence_id=data.get("evidence_id", str(uuid.uuid4())),
            candidate_id=data.get("candidate_id", ""),
            category=data.get("category", HttpTrustCategory.HOST_INJECTION),
            header_name=data.get("header_name", ""),
            supplied_value=data.get("supplied_value", ""),
            baseline_status=data.get("baseline_status", 0),
            test_status=data.get("test_status", 0),
            baseline_headers=data.get("baseline_headers", {}),
            test_headers=data.get("test_headers", {}),
            match_signals=data.get("match_signals", []),
            body_snippet=data.get("body_snippet", ""),
            security_effect_summary=data.get("security_effect_summary", ""),
            timestamp=data.get("timestamp"),
        )
        if "integrity_hash" in data:
            ev.integrity_hash = data["integrity_hash"]
        return ev


class HttpTrustTestCase:
    """
    Structured execution plan and result for an individual HTTP trust test case.
    Integrates base request, mutated header, observed differential, and evidence.
    """

    def __init__(
        self,
        test_id: str,
        candidate_id: str,
        endpoint: str,
        mutated_header: str,
        mutation_value: str,
        expected_effect: str,
        security_sensitive_purpose: str,
        category: HttpTrustCategory | str = HttpTrustCategory.HOST_INJECTION,
        method: str = "GET",
        baseline_summary: Optional[Dict[str, Any]] = None,
        test_summary: Optional[Dict[str, Any]] = None,
        result: str = "PENDING",
        evidence: Optional[HeaderTrustEvidence] = None,
        confidence: HttpTrustConfidence | str = HttpTrustConfidence.CANDIDATE,
        severity: str = "LOW",
        priority: int = 10,
        lifecycle: FindingLifecycle | str = FindingLifecycle.CANDIDATE,
    ):
        self.test_id = test_id
        self.candidate_id = candidate_id
        self.endpoint = endpoint
        self.mutated_header = mutated_header
        self.mutation_value = mutation_value
        self.expected_effect = expected_effect
        self.security_sensitive_purpose = security_sensitive_purpose
        self.category = (
            category
            if isinstance(category, HttpTrustCategory)
            else HttpTrustCategory.from_string(category)
        )
        self.method = method.upper().strip()
        self.baseline_summary = dict(baseline_summary or {})
        self.test_summary = dict(test_summary or {})
        self.result = result
        self.evidence = evidence
        self.confidence = (
            confidence
            if isinstance(confidence, HttpTrustConfidence)
            else HttpTrustConfidence.from_string(confidence)
        )
        self.severity = severity.upper().strip()
        self.priority = max(0, min(100, int(priority)))
        if isinstance(lifecycle, FindingLifecycle):
            self.lifecycle = lifecycle
        else:
            clean_l = str(lifecycle).upper().strip()
            self.lifecycle = FindingLifecycle[clean_l] if clean_l in FindingLifecycle.__members__ else FindingLifecycle.CANDIDATE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_id": self.test_id,
            "candidate_id": self.candidate_id,
            "endpoint": self.endpoint,
            "mutated_header": self.mutated_header,
            "mutation_value": self.mutation_value,
            "expected_effect": self.expected_effect,
            "security_sensitive_purpose": self.security_sensitive_purpose,
            "category": self.category.value,
            "method": self.method,
            "baseline_summary": self.baseline_summary,
            "test_summary": self.test_summary,
            "result": self.result,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "confidence": self.confidence.value,
            "severity": self.severity,
            "priority": self.priority,
            "lifecycle": self.lifecycle.value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> HttpTrustTestCase:
        ev_data = data.get("evidence")
        ev = HeaderTrustEvidence.from_dict(ev_data) if ev_data else None
        return cls(
            test_id=data.get("test_id", str(uuid.uuid4())),
            candidate_id=data.get("candidate_id", ""),
            endpoint=data.get("endpoint", ""),
            mutated_header=data.get("mutated_header", ""),
            mutation_value=data.get("mutation_value", ""),
            expected_effect=data.get("expected_effect", ""),
            security_sensitive_purpose=data.get("security_sensitive_purpose", ""),
            category=data.get("category", HttpTrustCategory.HOST_INJECTION),
            method=data.get("method", "GET"),
            baseline_summary=data.get("baseline_summary", {}),
            test_summary=data.get("test_summary", {}),
            result=data.get("result", "PENDING"),
            evidence=ev,
            confidence=data.get("confidence", HttpTrustConfidence.CANDIDATE),
            severity=data.get("severity", "LOW"),
            priority=data.get("priority", 10),
            lifecycle=data.get("lifecycle", FindingLifecycle.CANDIDATE),
        )
