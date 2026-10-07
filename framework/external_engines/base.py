"""
Generic External Pentesting Engine Contract & Abstraction (Phase 12 / 12.1).

Defines standard interfaces for detecting, checking, preparing, executing, monitoring,
and parsing findings from external autonomous pentesting tools (Xalgorix, Strix, etc.).

Architectural Invariants:
1. External engines NEVER become the primary OpenCode agent.
2. Every target URL must pass ScopeEngine verification before any execution.
3. Safe argv-based process invocation only: shell execution, eval, exec, and os.system are forbidden.
4. Artifact file ingestion prevents path traversal, symlink escape, and absolute path escapes.
5. Findings start as EXTERNAL_UNVERIFIED and require independent empirical reproduction.
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
from typing import Any, Dict, List, Optional, Set
import uuid

from framework.common.evidence import sanitize_sensitive_data
from framework.findings.lifecycle import FindingLifecycle
from framework.scope.engine import ScopeEngine


class ExternalEngineStatus(str, Enum):
    """Lifecycle / availability status of an external pentest engine."""
    INSTALLED = "INSTALLED"
    NOT_INSTALLED = "NOT_INSTALLED"
    VERSION_MISMATCH = "VERSION_MISMATCH"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    READY = "READY"
    MISSING_CONFIGURATION = "MISSING_CONFIGURATION"
    UNHEALTHY = "UNHEALTHY"
    PREPARING = "PREPARING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    STOPPED = "STOPPED"
    UNKNOWN = "UNKNOWN"


class EngineCapability(str, Enum):
    """Specific capabilities supported by external pentesting engines."""
    BROWSER = "browser"
    WEB = "web"
    API = "api"
    SOURCE = "source"
    AUTHENTICATED = "authenticated"
    WORKFLOW = "workflow"
    REPORT = "report"
    STRUCTURED_OUTPUT = "structured_output"
    BUDGET_CONTROL = "budget_control"
    TIMEOUT_CONTROL = "timeout_control"
    SANDBOX = "sandbox"
    LOCAL_ONLY = "local_only"


def safe_join_artifact_path(base_dir: str, untrusted_filename: str) -> str:
    """
    Safely resolves a path inside base_dir, strictly preventing directory traversal,
    absolute path escapes, and symlink escapes.
    """
    clean_base = os.path.abspath(base_dir)
    norm = untrusted_filename.replace("\\", "/")

    # Check for path traversal components
    parts = norm.split("/")
    if ".." in parts:
        raise ValueError(f"Path traversal detected: {untrusted_filename} escapes {base_dir}")

    # Check for absolute path escape
    if os.path.isabs(untrusted_filename) or (len(untrusted_filename) > 1 and untrusted_filename[1] == ":"):
        raise ValueError(f"Absolute path escape detected: {untrusted_filename}")

    resolved_path = os.path.abspath(os.path.join(clean_base, untrusted_filename))

    try:
        common = os.path.commonpath([clean_base, resolved_path])
        if common != clean_base:
            raise ValueError(f"Path traversal detected: {untrusted_filename} escapes {base_dir}")
    except ValueError as e:
        raise ValueError(f"Invalid path {untrusted_filename}: {e}")

    if os.path.islink(resolved_path):
        real_target = os.path.realpath(resolved_path)
        if os.path.commonpath([clean_base, real_target]) != clean_base:
            raise ValueError(f"Symlink traversal detected: {untrusted_filename} points outside base directory")

    return resolved_path



class ExternalJob:
    """Represents a bounded external engine test execution lifecycle."""

    def __init__(
        self,
        job_id: str,
        program: str,
        engine: str,
        engine_version: str,
        tested_commit: str,
        target_set: List[str],
        scope_snapshot: Dict[str, Any],
        capabilities: List[str],
        approval_status: str = "PENDING_APPROVAL",
        agent_budget: int = 100,
        time_budget_seconds: int = 300,
        concurrency_budget: int = 1,
        artifact_directory: str = "",
        status: str = ExternalEngineStatus.PREPARING.value,
        process_id: Optional[int] = None,
        started_at: Optional[str] = None,
        finished_at: Optional[str] = None,
        failure_reason: Optional[str] = None,
        budget_notes: Optional[str] = None,
    ):
        self.job_id = job_id.strip()
        self.program = program.strip()
        self.engine = engine.strip().lower()
        self.engine_version = engine_version.strip()
        self.tested_commit = tested_commit.strip()
        self.target_set = list(target_set)
        self.scope_snapshot = dict(scope_snapshot)
        self.capabilities = list(capabilities)
        self.approval_status = approval_status
        self.agent_budget = agent_budget
        self.time_budget_seconds = time_budget_seconds
        self.concurrency_budget = concurrency_budget
        self.artifact_directory = artifact_directory
        self.status = status
        self.process_id = process_id
        self.started_at = started_at
        self.finished_at = finished_at
        self.failure_reason = failure_reason
        self.budget_notes = budget_notes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "program": self.program,
            "engine": self.engine,
            "engine_version": self.engine_version,
            "tested_commit": self.tested_commit,
            "target_set": self.target_set,
            "scope_snapshot": self.scope_snapshot,
            "capabilities": self.capabilities,
            "approval_status": self.approval_status,
            "agent_budget": self.agent_budget,
            "time_budget_seconds": self.time_budget_seconds,
            "concurrency_budget": self.concurrency_budget,
            "artifact_directory": self.artifact_directory,
            "status": self.status,
            "process_id": self.process_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "failure_reason": self.failure_reason,
            "budget_notes": self.budget_notes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExternalJob:
        return cls(
            job_id=data.get("job_id", str(uuid.uuid4())),
            program=data.get("program", "default"),
            engine=data.get("engine", "generic"),
            engine_version=data.get("engine_version", "unknown"),
            tested_commit=data.get("tested_commit", "unknown"),
            target_set=data.get("target_set", []),
            scope_snapshot=data.get("scope_snapshot", {}),
            capabilities=data.get("capabilities", []),
            approval_status=data.get("approval_status", "PENDING_APPROVAL"),
            agent_budget=data.get("agent_budget", 100),
            time_budget_seconds=data.get("time_budget_seconds", 300),
            concurrency_budget=data.get("concurrency_budget", 1),
            artifact_directory=data.get("artifact_directory", ""),
            status=data.get("status", ExternalEngineStatus.PREPARING.value),
            process_id=data.get("process_id"),
            started_at=data.get("started_at"),
            finished_at=data.get("finished_at"),
            failure_reason=data.get("failure_reason"),
            budget_notes=data.get("budget_notes"),
        )


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
        method: str = "GET",
        parameter: Optional[str] = None,
        actor: Optional[str] = None,
        tenant: Optional[str] = None,
        resource_id: Optional[str] = None,
        description: str = "",
        evidence: Optional[Dict[str, Any]] = None,
        reproduction: Optional[Dict[str, Any]] = None,
        raw_reference: Optional[str] = None,
        verification_status: str = "EXTERNAL_UNVERIFIED",
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
        self.method = method.strip().upper()
        self.parameter = parameter.strip() if parameter else None
        self.actor = actor.strip() if actor else None
        self.tenant = tenant.strip() if tenant else None
        self.resource_id = resource_id.strip() if resource_id else None
        self.description = description
        self.evidence = sanitize_sensitive_data(dict(evidence or {}))
        self.reproduction = sanitize_sensitive_data(dict(reproduction or {}))
        self.raw_reference = raw_reference
        self.verification_status = verification_status
        self.source_timestamp = source_timestamp or datetime.now(timezone.utc).isoformat()

    def compute_attack_surface_fingerprint(self) -> str:
        norm_ep = self.endpoint.lower().split("?")[0].rstrip("/")
        raw = f"{self.method}|{norm_ep}|{str(self.parameter).lower()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def compute_root_cause_fingerprint(self) -> str:
        raw = f"{self.vulnerability_class.lower()}|{self.title.lower().split(':')[0]}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def compute_claim_fingerprint(self) -> str:
        raw = (
            f"{self.vulnerability_class.lower()}|"
            f"{self.method}|{self.endpoint.lower()}|"
            f"{str(self.parameter).lower()}|{str(self.actor).lower()}|"
            f"{str(self.resource_id).lower()}"
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def compute_fingerprint(self) -> str:
        return self.compute_claim_fingerprint()

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
            "method": self.method,
            "parameter": self.parameter,
            "actor": self.actor,
            "tenant": self.tenant,
            "resource_id": self.resource_id,
            "description": self.description,
            "evidence": self.evidence,
            "reproduction": self.reproduction,
            "raw_reference": self.raw_reference,
            "verification_status": self.verification_status,
            "source_timestamp": self.source_timestamp,
            "attack_surface_fingerprint": self.compute_attack_surface_fingerprint(),
            "root_cause_fingerprint": self.compute_root_cause_fingerprint(),
            "claim_fingerprint": self.compute_claim_fingerprint(),
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
            method=data.get("method", "GET"),
            parameter=data.get("parameter"),
            actor=data.get("actor"),
            tenant=data.get("tenant"),
            resource_id=data.get("resource_id"),
            description=data.get("description", ""),
            evidence=data.get("evidence", {}),
            reproduction=data.get("reproduction", {}),
            raw_reference=data.get("raw_reference"),
            verification_status=data.get("verification_status", "EXTERNAL_UNVERIFIED"),
            source_timestamp=data.get("source_timestamp"),
        )


class ExternalPentestEngine(ABC):
    """
    Abstract Base Class for external autonomous pentesting engines.
    Enforces a truthful, fully observable execution lifecycle:
    detect -> health_check -> prepare -> start -> status -> stop -> collect -> parse_results -> cleanup
    """

    def __init__(
        self,
        name: str,
        repo_url: str,
        tested_release: str,
        tested_commit: str,
        min_supported_release: str,
        capabilities: List[EngineCapability],
    ):
        self.name = name.lower().strip()
        self.repo_url = repo_url
        self.tested_release = tested_release
        self.tested_commit = tested_commit
        self.min_supported_release = min_supported_release
        self.capabilities = capabilities
        self._active_processes: Dict[str, subprocess.Popen] = {}

    @abstractmethod
    def detect(self) -> Dict[str, Any]:
        """Detects if engine CLI is present and inspects its truthful version."""
        pass

    @abstractmethod
    def health_check(self) -> Dict[str, Any]:
        """Checks runtime prerequisites, configuration files, and authentication."""
        pass

    @abstractmethod
    def prepare_job(
        self,
        program_dir: str,
        target_urls: List[str],
        scope_engine: ScopeEngine,
        budget_requests: int = 100,
        timeout_seconds: int = 300,
        concurrency: int = 1,
        approval_granted: bool = False,
    ) -> ExternalJob:
        """Constructs and persists an ExternalJob instance after scope verification."""
        pass

    @abstractmethod
    def start(self, job: ExternalJob) -> ExternalJob:
        """Launches the external engine via safe argv-based subprocess."""
        pass

    @abstractmethod
    def status(self, job: ExternalJob) -> Dict[str, Any]:
        """Polls process status and runtime progress without blocking."""
        pass

    @abstractmethod
    def stop(self, job: ExternalJob) -> bool:
        """Gracefully terminates running external process."""
        pass

    @abstractmethod
    def collect(self, job: ExternalJob) -> List[str]:
        """Collects generated artifact file paths safely within job artifact directory."""
        pass

    @abstractmethod
    def parse_results(
        self,
        output_dir_or_file: str,
        run_id: Optional[str] = None,
    ) -> List[ExternalFinding]:
        """Parses machine-readable artifacts into normalized ExternalFinding records."""
        pass

    @abstractmethod
    def cleanup(self, job: ExternalJob) -> bool:
        """Cleans up temporary working directories, stopping any orphaned processes."""
        pass
