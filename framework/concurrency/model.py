"""
Data Models and Enums for Race Conditions & Distributed Workflows Intelligence.

Defines taxonomy for concurrent invariant testing, check-then-act race windows,
bounded microsecond barrier dispatch plans, evidence provenance contracts,
isolated request-budget contexts, and structured test outcomes.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import threading
from typing import Any, Dict, List, Optional, Tuple

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


class WorkerLifecycleState(str, Enum):
    """State and outcome classification for individual concurrent probe worker threads."""
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT_UNRESOLVED = "TIMED_OUT_UNRESOLVED"
    CANCELLED = "CANCELLED"


class EvidenceSource(str, Enum):
    """Provenance and trust boundary classification for post-state evidence."""
    UNTRUSTED_CALLER_CLAIM = "UNTRUSTED_CALLER_CLAIM"
    DIRECT_TRANSPORT_OBSERVATION = "DIRECT_TRANSPORT_OBSERVATION"
    INDEPENDENT_STATE_QUERY = "INDEPENDENT_STATE_QUERY"
    LAB_FIXTURE_AUTHORITATIVE = "LAB_FIXTURE_AUTHORITATIVE"


CURRENT_EVIDENCE_SCHEMA_VERSION = "concurrency-evidence-v1"


def canonical_serialize_envelope(envelope_data: Dict[str, Any]) -> bytes:
    """
    Deterministically and canonically serializes the complete evidence envelope for HMAC signing.

    Enforces strict canonical properties:
    - Root and nested dictionaries have keys sorted lexicographically.
    - Dict keys must be strings.
    - Supported types: None, bool, int, float, str, dict, list.
    - Unsupported types (sets, custom objects, etc.) raise TypeError to fail closed.
    - Deterministic JSON separators (',', ':'), ensure_ascii=False, UTF-8 encoded.
    """
    def _validate_types(val: Any) -> None:
        if val is None or isinstance(val, (bool, int, float, str)):
            return
        if isinstance(val, dict):
            for k, v in val.items():
                if not isinstance(k, str):
                    raise TypeError(f"Dictionary keys must be strings, got: {type(k).__name__}")
                _validate_types(v)
            return
        if isinstance(val, (list, tuple)):
            for item in val:
                _validate_types(item)
            return
        raise TypeError(f"Unsupported type in evidence envelope: {type(val).__name__}")

    if not isinstance(envelope_data, dict):
        raise TypeError("Envelope data must be a dictionary.")

    _validate_types(envelope_data)
    serialized = json.dumps(
        envelope_data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return serialized.encode("utf-8")


@dataclass
class EvidenceEnvelope:
    """
    Canonical, versioned envelope binding every decision-relevant field of post-state evidence.
    Authenticated cryptographically via HMAC-SHA256 to prevent tampering or elevation.
    """
    schema_version: str
    observation_id: str
    source: str
    endpoint: str
    verified_at: str
    pre_state: Optional[Dict[str, Any]]
    post_state: Optional[Dict[str, Any]]
    delta_metrics: Dict[str, Any]
    provenance_details: str
    has_overlap: bool = False

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "delta_metrics": self.delta_metrics or {},
            "endpoint": self.endpoint or "",
            "has_overlap": bool(self.has_overlap),
            "observation_id": self.observation_id or "",
            "post_state": self.post_state or {},
            "pre_state": self.pre_state or {},
            "provenance_details": self.provenance_details or "",
            "schema_version": self.schema_version or "",
            "source": self.source or "",
            "verified_at": self.verified_at or "",
        }


@dataclass
class PostStateEvidence:
    """
    Formal evidence contract tracking origin and validation for post-state mutation claims.
    Distinguishes untrusted caller assertions from independently verified server datastore queries.
    Enforces a genuine cryptographic attestation trust boundary over a canonical envelope:
    external or deserialized dictionaries cannot elevate themselves into authoritative evidence.
    """
    source: EvidenceSource = EvidenceSource.UNTRUSTED_CALLER_CLAIM
    schema_version: str = CURRENT_EVIDENCE_SCHEMA_VERSION
    observation_id: str = ""
    pre_state: Optional[Dict[str, Any]] = None
    post_state: Optional[Dict[str, Any]] = None
    verified_endpoint: Optional[str] = None
    verified_at: Optional[str] = None
    delta_metrics: Dict[str, Any] = field(default_factory=dict)
    provenance_details: str = ""
    has_overlap: bool = False
    _attestation_token: Optional[str] = field(default=None, repr=False)

    def is_authoritative(self, expected_observation_id: Optional[str] = None) -> bool:
        """
        Returns True if and only if evidence originates from an authenticated, trusted source
        and has passed cryptographic HMAC-SHA256 envelope verification.
        Requires:
        1. source == LAB_FIXTURE_AUTHORITATIVE
        2. Valid attestation token present (hex SHA-256)
        3. Schema version matches CURRENT_EVIDENCE_SCHEMA_VERSION
        4. Valid endpoint matching an active LocalConcurrencyLab instance
        5. If expected_observation_id is provided, observation_id must match
        6. Cryptographic HMAC-SHA256 signature over the full canonical envelope matches.
        """
        if self.source != EvidenceSource.LAB_FIXTURE_AUTHORITATIVE:
            return False
        if not self._attestation_token:
            return False
        if self.schema_version != CURRENT_EVIDENCE_SCHEMA_VERSION:
            return False
        if expected_observation_id and self.observation_id != expected_observation_id:
            return False
        try:
            from framework.concurrency.lab import LocalConcurrencyLab
            return LocalConcurrencyLab.verify_attestation(self, expected_observation_id=expected_observation_id)
        except Exception:
            return False

    def validate_consistency(self) -> Tuple[bool, Optional[str]]:
        """
        Validates internal consistency and field constraints for post-state evidence.
        Fails closed when pre-state and post-state contradict the mutation claim,
        or when required fields are malformed or missing.
        """
        if self.source == EvidenceSource.LAB_FIXTURE_AUTHORITATIVE:
            if not self.post_state or not isinstance(self.post_state, dict):
                return False, "Authoritative evidence missing post_state dictionary."
            if not self.verified_endpoint:
                return False, "Authoritative evidence missing verified_endpoint."
            if not self.observation_id:
                return False, "Authoritative evidence missing observation_id."

        if self.pre_state is not None and not isinstance(self.pre_state, dict):
            return False, "Malformed non-dictionary pre_state."

        if self.post_state is not None and not isinstance(self.post_state, dict):
            return False, "Malformed non-dictionary post_state."

        if self.pre_state and self.post_state:
            counter_keys = (
                "count", "redemptions", "total_votes", "voting_count",
                "order_count", "counter", "coupon_redemptions", "safe_mutex_counter", "rate_limit_hits"
            )
            for k in counter_keys:
                if k in self.pre_state and k in self.post_state:
                    try:
                        pre_v = int(self.pre_state[k])
                        post_v = int(self.post_state[k])
                        if pre_v < 0 or post_v < 0:
                            return False, f"Negative counter value not permitted for '{k}': pre={pre_v}, post={post_v}"
                        if post_v < pre_v:
                            return False, f"Contradictory pre/post state: {k} decreased from {pre_v} to {post_v}"
                    except (ValueError, TypeError):
                        return False, f"Malformed non-numeric counter value for '{k}'"
        return True, None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "observation_id": self.observation_id,
            "has_overlap": bool(self.has_overlap),
            "source": self.source.value if isinstance(self.source, EvidenceSource) else str(self.source),
            "is_authoritative": self.is_authoritative(),
            "pre_state": copy.deepcopy(self.pre_state),
            "post_state": copy.deepcopy(self.post_state),
            "verified_endpoint": self.verified_endpoint,
            "verified_at": self.verified_at,
            "delta_metrics": copy.deepcopy(self.delta_metrics),
            "provenance_details": self.provenance_details,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PostStateEvidence:
        """
        Deserializes evidence from an untrusted dictionary (e.g. state JSON or caller data).
        CRITICAL TRUST BOUNDARY:
        Deserialized external data is ALWAYS assigned UNTRUSTED_CALLER_CLAIM and
        _attestation_token is stripped. Caller-supplied source labels, boolean flags,
        or tokens cannot promote themselves into authoritative evidence.
        """
        if not isinstance(data, dict):
            return cls(
                source=EvidenceSource.UNTRUSTED_CALLER_CLAIM,
                provenance_details="Malformed non-dictionary data received.",
            )

        pre_state = data.get("pre_state")
        if pre_state is not None and not isinstance(pre_state, dict):
            pre_state = None
        else:
            pre_state = copy.deepcopy(pre_state)

        post_state = data.get("post_state")
        if post_state is not None and not isinstance(post_state, dict):
            post_state = None
        else:
            post_state = copy.deepcopy(post_state)

        delta_metrics = data.get("delta_metrics")
        if not isinstance(delta_metrics, dict):
            delta_metrics = {}
        else:
            delta_metrics = copy.deepcopy(delta_metrics)

        endpoint = data.get("verified_endpoint")
        if endpoint is not None and not isinstance(endpoint, str):
            endpoint = str(endpoint)

        verified_at = data.get("verified_at")
        if verified_at is not None and not isinstance(verified_at, str):
            verified_at = str(verified_at)

        observation_id = data.get("observation_id", "")
        if not isinstance(observation_id, str):
            observation_id = str(observation_id)

        has_overlap = bool(data.get("has_overlap", False))

        schema_version = data.get("schema_version", CURRENT_EVIDENCE_SCHEMA_VERSION)
        if not isinstance(schema_version, str):
            schema_version = str(schema_version)

        prov_details = data.get("provenance_details", "")
        if not isinstance(prov_details, str):
            prov_details = str(prov_details)

        claimed_source = str(data.get("source", "UNKNOWN"))
        return cls(
            source=EvidenceSource.UNTRUSTED_CALLER_CLAIM,
            schema_version=schema_version,
            observation_id=observation_id,
            pre_state=pre_state,
            post_state=post_state,
            verified_endpoint=endpoint,
            verified_at=verified_at,
            delta_metrics=delta_metrics,
            has_overlap=has_overlap,
            provenance_details=f"Deserialized from untrusted dictionary (claimed source: {claimed_source}). {prov_details}".strip(),
            _attestation_token=None,
        )


class HypothesisBudgetContext:
    """
    Thread-safe request budget isolated to a specific hypothesis execution.
    Strictly caps dispatches at MAX_REQUESTS_PER_TEST = 15.
    """
    def __init__(self, hypothesis_id: str, max_requests: int = 15):
        self.hypothesis_id = hypothesis_id
        # Clamp configured limit: minimum 1, hard maximum 15
        self.max_requests = max(1, min(15, int(max_requests)))
        self._dispatched_count = 0
        self._lock = threading.Lock()

    def try_acquire_slot(self) -> Tuple[bool, int]:
        with self._lock:
            if self._dispatched_count >= self.max_requests:
                return False, self._dispatched_count
            self._dispatched_count += 1
            return True, self._dispatched_count

    @property
    def dispatched_count(self) -> int:
        with self._lock:
            return self._dispatched_count


@dataclass
class SingleProbeExecution:
    """Telemetry and response summary from an individual concurrent probe thread."""
    request_index: int
    status_code: int
    response_time_ms: float
    body_snippet: str
    headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    worker_state: WorkerLifecycleState = WorkerLifecycleState.COMPLETED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_index": self.request_index,
            "status_code": self.status_code,
            "response_time_ms": round(self.response_time_ms, 2),
            "body_snippet": self.body_snippet,
            "headers": self.headers,
            "error": self.error,
            "worker_state": self.worker_state.value if isinstance(self.worker_state, WorkerLifecycleState) else str(self.worker_state),
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
