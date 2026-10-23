"""
Data Models and Enums for Race Conditions & Distributed Workflows Intelligence.

Defines taxonomy for concurrent invariant testing, check-then-act race windows,
bounded microsecond barrier dispatch plans, and structured test outcomes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional

from framework.findings.lifecycle import FindingLifecycle


class RaceCategory(str, Enum):
    """Taxonomy of race condition and distributed workflow failure modes."""
    LIMIT_OVERRUN = "LIMIT_OVERRUN"
    TOCTOU = "TOCTOU"
    DOUBLE_SPEND = "DOUBLE_SPEND"
    IDEMPOTENCY_BYPASS = "IDEMPOTENCY_BYPASS"
    PARTIAL_EXECUTION_DESYNC = "PARTIAL_EXECUTION_DESYNC"
    CONCURRENT_STATE_MUTATION = "CONCURRENT_STATE_MUTATION"

    @classmethod
    def from_string(cls, val: str) -> RaceCategory:
        clean = (val or "").strip().upper()
        for member in cls:
            if member.value == clean or member.name == clean:
                return member
        return cls.LIMIT_OVERRUN


class RaceConfidence(str, Enum):
    """Confidence levels for concurrency findings and observations."""
    CONFIRMED = "CONFIRMED"
    SUSPECTED = "SUSPECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    CONCURRENCY_CONTROLLED = "CONCURRENCY_CONTROLLED"


@dataclass
class SingleProbeExecution:
    """Telemetry and response summary from an individual concurrent probe thread."""
    request_index: int
    status_code: int
    response_time_ms: float
    body_snippet: str
    headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_index": self.request_index,
            "status_code": self.status_code,
            "response_time_ms": round(self.response_time_ms, 2),
            "body_snippet": self.body_snippet,
            "headers": self.headers,
            "error": self.error,
        }


@dataclass
class ConcurrencyProbePlan:
    """Pre-armed execution plan for a bounded barrier-synchronized burst."""
    target_url: str
    method: str = "POST"
    category: RaceCategory = RaceCategory.LIMIT_OVERRUN
    burst_size: int = 4
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    allowed_limit: int = 1
    expected_status_code: int = 200
    timeout: float = 5.0

    def __post_init__(self):
        # Bound burst size between 2 and 10 to prevent denial of service
        self.burst_size = max(2, min(10, int(self.burst_size)))
        self.timeout = max(1.0, min(30.0, float(self.timeout)))


@dataclass
class RaceConditionHypothesis:
    """Structured hypothesis for concurrency-sensitive state transition testing."""
    hypothesis_id: str
    program: str
    category: RaceCategory
    endpoint: str
    method: str = "POST"
    description: str = ""
    allowed_limit: int = 1
    burst_size: int = 4
    lifecycle_state: FindingLifecycle = FindingLifecycle.HYPOTHESIS
    approval_status: str = "PENDING"
    notes: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def compute_fingerprint(self) -> str:
        cat_val = self.category.value if isinstance(self.category, RaceCategory) else str(self.category)
        raw = f"{self.endpoint.strip().lower()}::{self.method.upper()}::{cat_val}::{self.allowed_limit}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "program": self.program,
            "category": self.category.value if isinstance(self.category, RaceCategory) else str(self.category),
            "endpoint": self.endpoint,
            "method": self.method,
            "description": self.description,
            "allowed_limit": self.allowed_limit,
            "burst_size": self.burst_size,
            "lifecycle_state": self.lifecycle_state.value if isinstance(self.lifecycle_state, FindingLifecycle) else str(self.lifecycle_state),
            "approval_status": self.approval_status,
            "notes": self.notes,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RaceConditionHypothesis:
        cat_str = data.get("category", "LIMIT_OVERRUN")
        category = RaceCategory.from_string(cat_str)
        state_str = data.get("lifecycle_state", "HYPOTHESIS")
        try:
            state = FindingLifecycle(state_str)
        except ValueError:
            state = FindingLifecycle.HYPOTHESIS
        return cls(
            hypothesis_id=data["hypothesis_id"],
            program=data.get("program", "default"),
            category=category,
            endpoint=data.get("endpoint", ""),
            method=data.get("method", "POST"),
            description=data.get("description", ""),
            allowed_limit=int(data.get("allowed_limit", 1)),
            burst_size=int(data.get("burst_size", 4)),
            lifecycle_state=state,
            approval_status=data.get("approval_status", "PENDING"),
            notes=data.get("notes"),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class RaceConditionTestResult:
    """Outcome of bounded concurrent probe execution against target endpoint."""
    hypothesis_id: str
    category: RaceCategory
    confidence: RaceConfidence
    lifecycle_state: FindingLifecycle
    severity: str
    is_vulnerable: bool
    burst_size: int
    success_count: int
    failure_count: int
    reasons: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    executions: List[SingleProbeExecution] = field(default_factory=list)
    sanitized_excerpt: str = ""
    evidence_fingerprint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "category": self.category.value if isinstance(self.category, RaceCategory) else str(self.category),
            "confidence": self.confidence.value if isinstance(self.confidence, RaceConfidence) else str(self.confidence),
            "lifecycle_state": self.lifecycle_state.value if isinstance(self.lifecycle_state, FindingLifecycle) else str(self.lifecycle_state),
            "severity": self.severity,
            "is_vulnerable": self.is_vulnerable,
            "burst_size": self.burst_size,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "reasons": self.reasons,
            "evidence": self.evidence,
            "executions": [e.to_dict() for e in self.executions],
            "sanitized_excerpt": self.sanitized_excerpt,
            "evidence_fingerprint": self.evidence_fingerprint,
        }
