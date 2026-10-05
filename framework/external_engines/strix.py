"""
Strix Generic Pentest Engine Adapter (Phase 12).

Official repository: https://github.com/usestrix/strix
Self-hosted CLI providing autonomous pentesting.
Integrated as an OPTIONAL engine; NOT a hard dependency.
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


class StrixAdapter(ExternalPentestEngine):
    """Adapter for Strix autonomous CLI pentest engine."""

    PINNED_UPSTREAM_RELEASE = "v0.3.2-stable"
    REPO_URL = "https://github.com/usestrix/strix"

    def __init__(self):
        super().__init__(name="strix", repo_url=self.REPO_URL)

    def detect(self) -> Dict[str, Any]:
        """Detects whether Strix CLI is present."""
        cli_path = shutil.which("strix")
        detected = bool(cli_path)

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
            "repo_url": self.repo_url,
        }

    def health_check(self) -> Dict[str, Any]:
        det = self.detect()
        return {
            "healthy": det["installed"],
            "status": "READY" if det["installed"] else "NOT_INSTALLED",
            "message": "Strix is available" if det["installed"] else "Strix is optional / not installed",
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
        scoped_targets = [u for u in target_urls if scope_engine.is_in_scope(u)]
        job_id = f"strix-job-{uuid.uuid4().hex[:8]}"
        job_dir = os.path.join(program_dir, "external", "strix", job_id)
        os.makedirs(job_dir, exist_ok=True)

        job_config = {
            "job_id": job_id,
            "engine": "strix",
            "version": self.PINNED_UPSTREAM_RELEASE,
            "scoped_targets": scoped_targets,
            "max_requests": budget_requests,
            "timeout_seconds": timeout_seconds,
            "output_dir": job_dir,
        }
        return job_config

    def parse_results(self, output_dir_or_file: str) -> List[ExternalFinding]:
        findings: List[ExternalFinding] = []
        if not os.path.exists(output_dir_or_file):
            return findings

        target_file = output_dir_or_file
        if os.path.isdir(output_dir_or_file):
            candidate_files = ["strix-report.json", "findings.json", "results.json"]
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
                        finding_id=f"strix-f-{uuid.uuid4().hex[:8]}",
                        engine="strix",
                        engine_version=self.PINNED_UPSTREAM_RELEASE,
                        run_id=item.get("run_id", "strix-1"),
                        target=item.get("target") or item.get("endpoint", ""),
                        vulnerability_class=item.get("type", "unknown"),
                        title=item.get("title", "Strix Finding"),
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
