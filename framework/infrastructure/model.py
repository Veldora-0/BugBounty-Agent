"""
Infrastructure and Configuration Exposure Data Models for BugBounty-Agent.

Defines the 8 exposure categories, candidate tracking, hypotheses, and evaluation results.
Never stores unredacted credentials or raw secret-bearing bodies.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional

from framework.findings.lifecycle import FindingLifecycle


class ExposureCategory(str, Enum):
    """The 8 high-value exposure classes for Phase 19."""
    ADMIN_INTERFACE = "ADMIN_INTERFACE"         # Administrative consoles, management dashboards, discovery endpoints
    VERSION_CONTROL = "VERSION_CONTROL"         # Exposed .git, .svn repositories and metadata
    CONFIG_FILE = "CONFIG_FILE"                 # Exposed .env, web.config, settings, configuration files
    BACKUP_ARCHIVE = "BACKUP_ARCHIVE"           # Backup and archive files (.bak, .tar.gz, .zip, .sql)
    DEPLOYMENT_MANIFEST = "DEPLOYMENT_MANIFEST" # Build and dependency manifests (composer.json, package.json, Dockerfile)
    SOURCE_MAP = "SOURCE_MAP"                   # Frontend JavaScript source maps (.js.map)
    DIRECTORY_LISTING = "DIRECTORY_LISTING"     # Open web server directory indices (Index of /)
    DEBUG_INTERFACE = "DEBUG_INTERFACE"         # Diagnostic endpoints (/actuator/health, /metrics, verbose stack traces)


def generate_candidate_id(endpoint: str, category: ExposureCategory | str, program_id: Optional[str] = None) -> str:
    """
    Generates a deterministic candidate ID based strictly on endpoint URL and category.
    Never incorporates credentials, response bodies, or sensitive parameters into the hash.
    """
    cat_str = category.value if isinstance(category, ExposureCategory) else str(category)
    norm_ep = endpoint.strip().lower()
    raw_key = f"{norm_ep}::{cat_str.upper()}"
    digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:12]
    prefix = f"EXP-{program_id.strip()}" if program_id else "EXP"
    return f"{prefix}-{digest}"


@dataclass
class ExposureCandidate:
    """Represents a potential exposure candidate discovered from recon or crawling."""
    candidate_id: str
    application: str
    endpoint: str
    category: ExposureCategory
    confidence: str = "LOW"
    lifecycle_state: FindingLifecycle = FindingLifecycle.CANDIDATE
    approval_status: str = "PENDING"
    evidence_fingerprint: Optional[str] = None
    notes: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def compute_fingerprint(self) -> str:
        """Stable test fingerprint for candidate deduplication."""
        cat_val = self.category.value if isinstance(self.category, ExposureCategory) else str(self.category)
        return hashlib.sha256(f"{self.endpoint.strip().lower()}::{cat_val}".encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "application": self.application,
            "endpoint": self.endpoint,
            "category": self.category.value if isinstance(self.category, ExposureCategory) else str(self.category),
            "confidence": self.confidence,
            "lifecycle_state": self.lifecycle_state.value if isinstance(self.lifecycle_state, FindingLifecycle) else str(self.lifecycle_state),
            "approval_status": self.approval_status,
            "evidence_fingerprint": self.evidence_fingerprint,
            "notes": self.notes,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExposureCandidate:
        cat_str = data.get("category", "ADMIN_INTERFACE")
        category = ExposureCategory(cat_str) if cat_str in ExposureCategory.__members__ else ExposureCategory.ADMIN_INTERFACE
        state_str = data.get("lifecycle_state", "CANDIDATE")
        try:
            state = FindingLifecycle(state_str)
        except ValueError:
            state = FindingLifecycle.CANDIDATE
        return cls(
            candidate_id=data["candidate_id"],
            application=data.get("application", ""),
            endpoint=data.get("endpoint", ""),
            category=category,
            confidence=data.get("confidence", "LOW"),
            lifecycle_state=state,
            approval_status=data.get("approval_status", "PENDING"),
            evidence_fingerprint=data.get("evidence_fingerprint"),
            notes=data.get("notes"),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class ExposureHypothesis:
    """Hypothesis linking passive/crawled observation to active exposure test."""
    hypothesis_id: str
    candidate_id: str
    application: str
    endpoint: str
    category: ExposureCategory
    rationale: str
    expected_signals: List[str]
    severity_hint: str = "MEDIUM"
    status: str = "PENDING"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "candidate_id": self.candidate_id,
            "application": self.application,
            "endpoint": self.endpoint,
            "category": self.category.value if isinstance(self.category, ExposureCategory) else str(self.category),
            "rationale": self.rationale,
            "expected_signals": self.expected_signals,
            "severity_hint": self.severity_hint,
            "status": self.status,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExposureHypothesis:
        cat_str = data.get("category", "ADMIN_INTERFACE")
        category = ExposureCategory(cat_str) if cat_str in ExposureCategory.__members__ else ExposureCategory.ADMIN_INTERFACE
        return cls(
            hypothesis_id=data["hypothesis_id"],
            candidate_id=data.get("candidate_id", ""),
            application=data.get("application", ""),
            endpoint=data.get("endpoint", ""),
            category=category,
            rationale=data.get("rationale", ""),
            expected_signals=data.get("expected_signals", []),
            severity_hint=data.get("severity_hint", "MEDIUM"),
            status=data.get("status", "PENDING"),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class ExposureEvaluationResult:
    """Outcome of an active exposure evaluation against target endpoint."""
    is_exposed: bool
    confidence: str
    lifecycle_state: FindingLifecycle
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)
    is_soft_404: bool = False
    bytes_consumed: int = 0
    stopping_rule_triggered: bool = False
    sanitized_excerpt: str = ""
    evidence_fingerprint: str = ""
