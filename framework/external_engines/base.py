"""
Generic External Pentesting Engine Contract & Abstraction (Phase 12).

Defines standard interfaces for detecting, checking, invoking, and parsing findings
from external autonomous pentesting tools (Xalgorix, Strix, etc.).
External engines NEVER become the source of truth and are bounded by ScopeEngine,
traffic budgets, and human operator approval.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional
import uuid

from framework.common.evidence import sanitize_sensitive_data
from framework.findings.lifecycle import FindingLifecycle
from framework.scope.engine import ScopeEngine


class ExternalEngineStatus(str, Enum):
    """Lifecycle / availability status of an external pentest engine."""
    INSTALLED = "INSTALLED"
    NOT_INSTALLED = "NOT_INSTALLED"
    MISCONFIGURED = "MISCONFIGURED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class ExternalFinding:
    """Normalized finding emitted by an external pentesting engine."""

    def __init__(
        self,
        finding_id: str,
        engine: str,
        engine_version: str,
        run_id: str,
        target: str,
        vulnerability_class: str,
        title: str,
        severity: str,
        confidence: str,
        endpoint: str,
        parameter: Optional[str] = None,
        actor: Optional[str] = None,
        description: str = "",
        evidence: Optional[Dict[str, Any]] = None,
        reproduction: Optional[Dict[str, Any]] = None,
        raw_reference: Optional[str] = None,
        verification_status: str = "NEEDS_INDEPENDENT_VERIFICATION",
        source_timestamp: Optional[str] = None,
    ):
        self.finding_id = finding_id.strip()
        self.engine = engine.strip().lower()
        self.engine_version = engine_version.strip()
        self.run_id = run_id.strip()
        self.target = target.strip()
        self.vulnerability_class = vulnerability_class.strip()
        self.title = title.strip()
        self.severity = severity.strip().upper()
        self.confidence = confidence.strip().upper()
        self.endpoint = endpoint.strip()
        self.parameter = parameter
        self.actor = actor
        self.description = description
        self.evidence = dict(evidence or {})
        self.reproduction = dict(reproduction or {})
        self.raw_reference = raw_reference
        self.verification_status = verification_status
        self.source_timestamp = source_timestamp or datetime.now(timezone.utc).isoformat()

    def compute_fingerprint(self) -> str:
        raw = f"{self.vulnerability_class.lower()}|{self.endpoint.lower()}|{str(self.parameter).lower()}|{str(self.actor).lower()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "engine": self.engine,
            "engine_version": self.engine_version,
            "run_id": self.run_id,
            "target": self.target,
            "vulnerability_class": self.vulnerability_class,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "actor": self.actor,
            "description": self.description,
            "evidence": self.evidence,
            "reproduction": self.reproduction,
            "raw_reference": self.raw_reference,
            "verification_status": self.verification_status,
            "source_timestamp": self.source_timestamp,
            "fingerprint": self.compute_fingerprint(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExternalFinding:
        return cls(
            finding_id=data.get("finding_id", str(uuid.uuid4())),
            engine=data.get("engine", "generic"),
            engine_version=data.get("engine_version", "unknown"),
            run_id=data.get("run_id", "default"),
            target=data.get("target", ""),
            vulnerability_class=data.get("vulnerability_class", "unknown"),
            title=data.get("title", ""),
            severity=data.get("severity", "MEDIUM"),
            confidence=data.get("confidence", "CANDIDATE"),
            endpoint=data.get("endpoint", ""),
            parameter=data.get("parameter"),
            actor=data.get("actor"),
            description=data.get("description", ""),
            evidence=data.get("evidence", {}),
            reproduction=data.get("reproduction", {}),
            raw_reference=data.get("raw_reference"),
            verification_status=data.get("verification_status", "NEEDS_INDEPENDENT_VERIFICATION"),
            source_timestamp=data.get("source_timestamp"),
        )


class ExternalPentestEngine(ABC):
    """Abstract Base Class for external autonomous pentesting engines."""

    def __init__(self, name: str, repo_url: str):
        self.name = name
        self.repo_url = repo_url

    @abstractmethod
    def detect(self) -> Dict[str, Any]:
        """Detects if engine CLI or container is present on host."""
        pass

    @abstractmethod
    def health_check(self) -> Dict[str, Any]:
        """Checks runtime prerequisites, API keys, and configurations."""
        pass

    @abstractmethod
    def prepare_job(
        self,
        program_dir: str,
        target_urls: List[str],
        scope_engine: ScopeEngine,
        budget_requests: int = 100,
        timeout_seconds: int = 300,
    ) -> Dict[str, Any]:
        """Generates bounded configuration for an external test run."""
        pass

    @abstractmethod
    def parse_results(self, output_dir_or_file: str) -> List[ExternalFinding]:
        """Parses raw engine artifacts into normalized ExternalFinding records."""
        pass
