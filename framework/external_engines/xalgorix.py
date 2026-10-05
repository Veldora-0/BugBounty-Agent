"""
Xalgorix External Pentest Engine Adapter (Phase 12).

Official repository: https://github.com/xalgorix/xalgorix
Self-hosted autonomous AI pentesting platform.
Provides detection, health checks, bounded job preparation, result ingestion,
and independent finding normalization.
Xalgorix is executed strictly as a bounded worker; never as an OpenCode custom agent.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional
import uuid

from framework.external_engines.base import (
    ExternalEngineStatus,
    ExternalFinding,
    ExternalPentestEngine,
)
from framework.scope.engine import ScopeEngine


class XalgorixAdapter(ExternalPentestEngine):
    """Adapter for Xalgorix autonomous AI pentesting engine."""

    PINNED_UPSTREAM_RELEASE = "v0.4.0-stable"
    REPO_URL = "https://github.com/xalgorix/xalgorix"

    def __init__(self):
        super().__init__(name="xalgorix", repo_url=self.REPO_URL)

    def detect(self) -> Dict[str, Any]:
        """Detects whether Xalgorix CLI or Docker container is available on the system."""
        # Check CLI in PATH
        cli_path = shutil.which("xalgorix")
        docker_path = shutil.which("docker")

        detected = bool(cli_path)
        docker_available = bool(docker_path)

        version = "unknown"
        if cli_path:
            try:
                out = subprocess.run([cli_path, "--version"], capture_output=True, text=True, timeout=5)
                if out.returncode == 0:
                    version = out.stdout.strip().split()[-1]
            except Exception:
                pass

        return {
            "name": self.name,
            "status": ExternalEngineStatus.INSTALLED.value if detected else ExternalEngineStatus.NOT_INSTALLED.value,
            "installed": detected,
            "executable_path": cli_path,
            "version": version if detected else self.PINNED_UPSTREAM_RELEASE,
            "pinned_version": self.PINNED_UPSTREAM_RELEASE,
            "docker_available": docker_available,
            "repo_url": self.repo_url,
        }

    def health_check(self) -> Dict[str, Any]:
        """Verifies environment readiness for running Xalgorix."""
        det = self.detect()
        if not det["installed"]:
            return {
                "healthy": False,
                "status": "NOT_INSTALLED",
                "message": "Xalgorix is not installed in system PATH. Install via 'pipx install xalgorix' or docker.",
                "details": det,
            }

        # Check required LLM or API keys
        has_llm_key = bool(os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("GEMINI_API_KEY"))
        return {
            "healthy": has_llm_key,
            "status": "READY" if has_llm_key else "MISSING_LLM_KEY",
            "message": "Xalgorix is ready" if has_llm_key else "Xalgorix requires an LLM provider key (OPENAI_API_KEY / ANTHROPIC_API_KEY / GEMINI_API_KEY)",
            "details": det,
        }

    def prepare_job(
        self,
        program_dir: str,
        target_urls: List[str],
        scope_engine: ScopeEngine,
        budget_requests: int = 100,
        timeout_seconds: int = 300,
    ) -> Dict[str, Any]:
        """Generates bounded configuration for a scoped Xalgorix test run."""
        # Strictly filter targets through BugBounty ScopeEngine
        scoped_targets = [u for u in target_urls if scope_engine.is_in_scope(u)]

        job_id = f"xalgorix-job-{uuid.uuid4().hex[:8]}"
        job_dir = os.path.join(program_dir, "external", "xalgorix", job_id)
        os.makedirs(job_dir, exist_ok=True)

        job_config = {
            "job_id": job_id,
            "engine": "xalgorix",
            "version": self.PINNED_UPSTREAM_RELEASE,
            "scoped_targets": scoped_targets,
            "max_requests": max(10, min(1000, budget_requests)),
            "timeout_seconds": max(30, min(1800, timeout_seconds)),
            "disallow_destructive": True,
            "disallow_dos": True,
            "output_dir": job_dir,
            "created_at": str(os.path.basename(program_dir)),
        }

        cfg_path = os.path.join(job_dir, "config.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(job_config, f, indent=2)

        return job_config

    def parse_results(self, output_dir_or_file: str) -> List[ExternalFinding]:
        """Parses Xalgorix structured JSON report into normalized ExternalFinding records."""
        findings: List[ExternalFinding] = []
        if not os.path.exists(output_dir_or_file):
            return findings

        target_file = output_dir_or_file
        if os.path.isdir(output_dir_or_file):
            candidate_files = ["findings.json", "report.json", "results.json"]
            for cf in candidate_files:
                candidate_path = os.path.join(output_dir_or_file, cf)
                if os.path.isfile(candidate_path):
                    target_file = candidate_path
                    break

        if not os.path.isfile(target_file):
            return findings

        try:
            with open(target_file, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
                items = raw_data if isinstance(raw_data, list) else raw_data.get("findings", [])
                for item in items:
                    f = ExternalFinding(
                        finding_id=f"xf-{uuid.uuid4().hex[:8]}",
                        engine="xalgorix",
                        engine_version=self.PINNED_UPSTREAM_RELEASE,
                        run_id=item.get("run_id", "run-1"),
                        target=item.get("target") or item.get("endpoint", ""),
                        vulnerability_class=item.get("vulnerability_class") or item.get("type", "unknown"),
                        title=item.get("title", "External Finding"),
                        severity=item.get("severity", "MEDIUM"),
                        confidence=item.get("confidence", "CANDIDATE"),
                        endpoint=item.get("endpoint", ""),
                        parameter=item.get("parameter"),
                        actor=item.get("actor"),
                        description=item.get("description", ""),
                        evidence=item.get("evidence", {}),
                        reproduction=item.get("reproduction", {}),
                        verification_status="NEEDS_INDEPENDENT_VERIFICATION",
                    )
                    findings.append(f)
        except Exception:
            pass

        return findings
