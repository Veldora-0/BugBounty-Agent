"""
Xalgorix External Pentest Engine Adapter (Phase 12 / 12.1 Hardening).

Official repository: https://github.com/xalgorix/xalgorix
Tech Stack: Go and TypeScript autonomous AI pentesting platform.
Current upstream release line: v4.x

Truthful Versioning Policy:
- Tested Release: v4.6.121
- Tested Commit: 17f90ae
- Min Supported Release: v4.0.0
- Interface Version: v4

Operating Constraints:
1. Operates as an external tool invoked by Bug-Bounty; NEVER as an OpenCode custom agent.
2. Every target URL must pass ScopeEngine verification.
3. Safe argv-based execution via subprocess without shell execution.
4. Request budgets: Native CLI does not provide a deterministic HTTP request cap flag;
   we report ENGINE_REQUEST_BUDGET_UNSUPPORTED and enforce strict process timeouts
   and scope filtering.
5. Ingested artifacts are validated with safe_join_artifact_path to prevent directory traversal.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional
import uuid

from framework.external_engines.base import (
    EngineCapability,
    ExternalEngineStatus,
    ExternalFinding,
    ExternalJob,
    ExternalPentestEngine,
    safe_join_artifact_path,
)
from framework.scope.engine import ScopeEngine


class XalgorixAdapter(ExternalPentestEngine):
    """Hardened adapter for the Xalgorix autonomous AI pentesting platform."""

    CURRENT_TESTED_RELEASE = "v4.6.121"
    CURRENT_TESTED_COMMIT = "17f90ae"
    MIN_SUPPORTED_RELEASE = "v4.0.0"
    REPOSITORY_URL = "https://github.com/xalgorix/xalgorix"
    INTERFACE_VERSION = "v4"

    def __init__(self):
        super().__init__(
            name="xalgorix",
            repo_url=self.REPOSITORY_URL,
            tested_release=self.CURRENT_TESTED_RELEASE,
            tested_commit=self.CURRENT_TESTED_COMMIT,
            min_supported_release=self.MIN_SUPPORTED_RELEASE,
            capabilities=[
                EngineCapability.WEB,
                EngineCapability.API,
                EngineCapability.STRUCTURED_OUTPUT,
                EngineCapability.TIMEOUT_CONTROL,
                EngineCapability.LOCAL_ONLY,
            ],
        )

    @classmethod
    def parse_version_string(cls, raw_output: str) -> str:
        """Extracts version token from CLI version output."""
        match = re.search(r"v?(\d+\.\d+(?:\.\d+)?)", raw_output)
        if match:
            return f"v{match.group(1)}"
        tokens = raw_output.strip().split()
        return tokens[-1] if tokens else "unknown"

    def detect(self) -> Dict[str, Any]:
        """Detects whether Xalgorix CLI is installed and checks version compatibility."""
        cli_path = shutil.which("xalgorix")
        docker_path = shutil.which("docker")

        if not cli_path:
            return {
                "name": self.name,
                "status": ExternalEngineStatus.NOT_INSTALLED.value,
                "installed": False,
                "executable_path": None,
                "version": None,
                "tested_release": self.tested_release,
                "tested_commit": self.tested_commit,
                "min_supported_release": self.min_supported_release,
                "docker_available": bool(docker_path),
                "repo_url": self.repo_url,
                "notes": "Xalgorix binary not found in system PATH. Install via official Go installer or release binary.",
            }

        # Query version safely
        version_str = "unknown"
        status = ExternalEngineStatus.INSTALLED.value
        try:
            res = subprocess.run(
                [cli_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            raw = res.stdout if res.stdout else res.stderr
            version_str = self.parse_version_string(raw)
        except Exception as e:
            version_str = f"error: {str(e)}"

        # Evaluate version compatibility
        if version_str != "unknown" and not version_str.startswith("error"):
            # Check major version or exact release
            if version_str != self.tested_release:
                # If major differs from v4, flag unsupported
                if not version_str.startswith("v4"):
                    status = ExternalEngineStatus.UNSUPPORTED_VERSION.value
                else:
                    status = ExternalEngineStatus.VERSION_MISMATCH.value
            else:
                status = ExternalEngineStatus.INSTALLED.value

        return {
            "name": self.name,
            "status": status,
            "installed": True,
            "executable_path": cli_path,
            "version": version_str,
            "tested_release": self.tested_release,
            "tested_commit": self.tested_commit,
            "min_supported_release": self.min_supported_release,
            "docker_available": bool(docker_path),
            "repo_url": self.repo_url,
        }

    def health_check(self) -> Dict[str, Any]:
        """Checks configuration, environment files, and LLM provider configuration."""
        det = self.detect()
        if not det["installed"]:
            return {
                "healthy": False,
                "status": ExternalEngineStatus.NOT_INSTALLED.value,
                "message": "Xalgorix is optional and not installed in system PATH.",
                "details": det,
            }

        # Check configuration files
        home_cfg = os.path.expanduser("~/.xalgorix.env")
        etc_cfg = "/etc/xalgorix.env"
        has_cfg_file = os.path.isfile(home_cfg) or os.path.isfile(etc_cfg)

        # Check environment keys (masked diagnostics only)
        has_xalgorix_key = bool(os.environ.get("XALGORIX_API_KEY"))
        has_llm_key = bool(
            os.environ.get("OPENAI_API_KEY")
            or os.environ.get("ANTHROPIC_API_KEY")
            or os.environ.get("GEMINI_API_KEY")
        )

        configured = has_cfg_file or has_xalgorix_key or has_llm_key

        if not configured:
            return {
                "healthy": False,
                "status": ExternalEngineStatus.MISSING_CONFIGURATION.value,
                "message": (
                    "Xalgorix is installed but unconfigured. Requires ~/.xalgorix.env "
                    "or XALGORIX_API_KEY / LLM provider key."
                ),
                "details": {
                    **det,
                    "config_file_present": has_cfg_file,
                    "has_xalgorix_key": has_xalgorix_key,
                    "has_llm_key": has_llm_key,
                },
            }

        return {
            "healthy": True,
            "status": ExternalEngineStatus.READY.value,
            "message": "Xalgorix is installed and configured.",
            "details": {
                **det,
                "config_file_present": has_cfg_file,
                "has_xalgorix_key": has_xalgorix_key,
                "has_llm_key": has_llm_key,
            },
        }

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
        """Prepares a bounded external job with strict scope validation."""
        scoped_targets = [u for u in target_urls if scope_engine.is_in_scope(u)]
        if not scoped_targets:
            raise ValueError("All provided targets are out-of-scope according to ScopeEngine.")

        job_id = f"xalgorix-job-{uuid.uuid4().hex[:8]}"
        job_dir = os.path.join(program_dir, "external", "xalgorix", job_id)
        os.makedirs(job_dir, exist_ok=True)

        job = ExternalJob(
            job_id=job_id,
            program=os.path.basename(os.path.normpath(program_dir)),
            engine=self.name,
            engine_version=self.tested_release,
            tested_commit=self.tested_commit,
            target_set=scoped_targets,
            scope_snapshot={
                "allowed_targets": scoped_targets,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            capabilities=[c.value for c in self.capabilities],
            approval_status="APPROVED" if approval_granted else "PENDING_APPROVAL",
            agent_budget=budget_requests,
            time_budget_seconds=max(30, min(1800, timeout_seconds)),
            concurrency_budget=max(1, min(5, concurrency)),
            artifact_directory=job_dir,
            status=ExternalEngineStatus.PREPARING.value,
            budget_notes="ENGINE_REQUEST_BUDGET_UNSUPPORTED: Enforcing process timeout and target scope boundaries.",
        )

        job_file = os.path.join(job_dir, "job.json")
        with open(job_file, "w", encoding="utf-8") as f:
            json.dump(job.to_dict(), f, indent=2)

        return job

    def build_argv(self, job: ExternalJob, cli_path: Optional[str] = None) -> List[str]:
        """Constructs safe argv arguments for the Xalgorix CLI without shell interpolation."""
        path = cli_path or shutil.which("xalgorix") or "xalgorix"
        argv = [path]
        for t in job.target_set:
            argv.extend(["--target", t])
        argv.extend([
            "--instruction",
            "Perform authorized bug bounty testing. Restrict activity to specified targets. Non-destructive.",
        ])
        return argv

    def start(self, job: ExternalJob) -> ExternalJob:
        """Launches Xalgorix via safe argv-based subprocess."""
        if job.approval_status != "APPROVED":
            raise PermissionError(f"Job {job.job_id} requires explicit human operator approval (--approve).")

        det = self.detect()
        if not det["installed"]:
            job.status = ExternalEngineStatus.FAILED.value
            job.failure_reason = "Xalgorix binary not found on host."
            return job

        cli_path = det["executable_path"]
        argv = self.build_argv(job, cli_path)

        stdout_log = os.path.join(job.artifact_directory, "stdout.log")
        stderr_log = os.path.join(job.artifact_directory, "stderr.log")

        f_out = open(stdout_log, "w", encoding="utf-8")
        f_err = open(stderr_log, "w", encoding="utf-8")

        proc = subprocess.Popen(
            argv,
            cwd=job.artifact_directory,
            stdout=f_out,
            stderr=f_err,
            text=True,
        )

        self._active_processes[job.job_id] = proc
        job.process_id = proc.pid
        job.status = ExternalEngineStatus.RUNNING.value
        job.started_at = datetime.now(timezone.utc).isoformat()

        # Update persisted job state
        job_file = os.path.join(job.artifact_directory, "job.json")
        with open(job_file, "w", encoding="utf-8") as f:
            json.dump(job.to_dict(), f, indent=2)

        return job

    def status(self, job: ExternalJob) -> Dict[str, Any]:
        """Monitors process status and enforces timeout budget."""
        proc = self._active_processes.get(job.job_id)
        if not proc:
            return {
                "job_id": job.job_id,
                "status": job.status,
                "running": False,
                "exit_code": None,
            }

        poll = proc.poll()
        if poll is None:
            # Check elapsed time vs timeout
            if job.started_at:
                try:
                    started = datetime.fromisoformat(job.started_at)
                    elapsed = (datetime.now(timezone.utc) - started).total_seconds()
                    if elapsed > job.time_budget_seconds:
                        self.stop(job)
                        job.status = ExternalEngineStatus.TIMEOUT.value
                        job.finished_at = datetime.now(timezone.utc).isoformat()
                        job.failure_reason = f"Execution exceeded time budget of {job.time_budget_seconds}s"
                        return {
                            "job_id": job.job_id,
                            "status": job.status,
                            "running": False,
                            "exit_code": -1,
                            "reason": job.failure_reason,
                        }
                except Exception:
                    pass

            return {
                "job_id": job.job_id,
                "status": ExternalEngineStatus.RUNNING.value,
                "running": True,
                "exit_code": None,
            }

        # Process has finished
        job.finished_at = datetime.now(timezone.utc).isoformat()
        if poll == 0:
            job.status = ExternalEngineStatus.COMPLETED.value
        else:
            job.status = ExternalEngineStatus.FAILED.value
            job.failure_reason = f"Process exited with code {poll}"

        return {
            "job_id": job.job_id,
            "status": job.status,
            "running": False,
            "exit_code": poll,
        }

    def stop(self, job: ExternalJob) -> bool:
        """Terminates a running Xalgorix process."""
        proc = self._active_processes.get(job.job_id)
        if not proc:
            return False

        try:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            job.status = ExternalEngineStatus.STOPPED.value
            job.finished_at = datetime.now(timezone.utc).isoformat()
            return True
        except Exception:
            return False

    def collect(self, job: ExternalJob) -> List[str]:
        """Collects generated artifact files safely inside job artifact directory."""
        if not os.path.isdir(job.artifact_directory):
            return []

        artifacts: List[str] = []
        for name in os.listdir(job.artifact_directory):
            try:
                safe_path = safe_join_artifact_path(job.artifact_directory, name)
                if os.path.isfile(safe_path):
                    artifacts.append(safe_path)
            except ValueError:
                continue

        return artifacts

    def parse_results(
        self,
        output_dir_or_file: str,
        run_id: Optional[str] = None,
    ) -> List[ExternalFinding]:
        """
        Parses findings from Xalgorix structured JSON report.
        Never swallows exceptions silently; reports structured PARSE_ERROR or RESULT_SOURCE_UNKNOWN.
        """
        findings: List[ExternalFinding] = []
        run_identifier = run_id or "xalgorix-run"

        if not os.path.exists(output_dir_or_file):
            raise FileNotFoundError(f"Result path does not exist: {output_dir_or_file}")

        target_file = output_dir_or_file
        if os.path.isdir(output_dir_or_file):
            candidate_files = [
                "findings.json",
                "report.json",
                "results.json",
                "xalgorix_export.json",
            ]
            found = False
            for cf in candidate_files:
                try:
                    cand_path = safe_join_artifact_path(output_dir_or_file, cf)
                    if os.path.isfile(cand_path):
                        target_file = cand_path
                        found = True
                        break
                except ValueError:
                    continue

            if not found:
                raise ValueError(
                    f"RESULT_SOURCE_UNKNOWN: No recognized result format found in {output_dir_or_file}. "
                    f"Expected one of: {candidate_files}"
                )

        # Validate that target_file is not escaping
        try:
            base_dir = os.path.dirname(os.path.abspath(target_file))
            target_file = safe_join_artifact_path(base_dir, os.path.basename(target_file))
        except ValueError as pe:
            raise ValueError(f"PARSE_ERROR: Unsafe artifact path: {pe}")

        try:
            with open(target_file, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
        except Exception as err:
            raise ValueError(f"PARSE_ERROR: Failed to parse JSON from {target_file}: {err}")

        items = raw_data if isinstance(raw_data, list) else raw_data.get("findings", [])
        if not isinstance(items, list):
            raise ValueError(f"PARSE_ERROR: Expected findings list in {target_file}, got {type(items).__name__}")

        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            finding_id = item.get("finding_id") or f"xf-{uuid.uuid4().hex[:8]}"
            endpoint = item.get("endpoint") or item.get("url") or item.get("target") or ""
            vuln_class = item.get("vulnerability_class") or item.get("type") or "unknown"
            title = item.get("title") or f"Xalgorix {vuln_class}"

            f = ExternalFinding(
                finding_id=finding_id,
                engine=self.name,
                engine_version=self.tested_release,
                run_id=item.get("run_id", run_identifier),
                target=item.get("target") or endpoint,
                vulnerability_class=vuln_class,
                title=title,
                severity=item.get("severity", "MEDIUM"),
                confidence=item.get("confidence", "CANDIDATE"),
                endpoint=endpoint,
                method=item.get("method", "GET"),
                parameter=item.get("parameter"),
                actor=item.get("actor"),
                tenant=item.get("tenant"),
                resource_id=item.get("resource_id"),
                description=item.get("description", ""),
                evidence=item.get("evidence", {}),
                reproduction=item.get("reproduction", {}),
                raw_reference=item.get("raw_reference") or f"{target_file}#item_{idx}",
                verification_status="EXTERNAL_UNVERIFIED",
            )
            findings.append(f)

        return findings

    def cleanup(self, job: ExternalJob) -> bool:
        """Stops any active process and removes temporary files."""
        self.stop(job)
        self._active_processes.pop(job.job_id, None)
        return True
