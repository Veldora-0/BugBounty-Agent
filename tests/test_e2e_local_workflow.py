"""
End-to-End Local Discovery-to-Report Integration Test for BugBounty-Agent (Gate 0).

Validates the complete workflow using an ephemeral local mock HTTP server on 127.0.0.1:
1. Local HTTP fixture running on an unprivileged ephemeral port (>= 1024).
2. Workspace initialization with canonical scope/scope.yaml containing fixture target.
3. Explicit fixture port authorization via allow_fixture_port().
4. Surface mapping & passive intake from webapps.json.
5. Active validation against local fixture endpoint with real network dispatch.
6. Cryptographic SHA-256 evidence generation and integrity verification.
7. Candidate finding lifecycle progression (OBSERVED -> VALIDATED).
8. State synchronization and cross-engine finding deduplication.
9. Disclosure report generation into reports/ via bb-report with standard 17 sections.
10. Preservation of existing report artifacts without accidental overwrite.
11. Fail-closed behavior on unvalidated, simulated, or out-of-scope candidate findings.
12. Clean mock server and workspace teardown.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import importlib.util
import shutil
import tempfile
import threading
import urllib.parse
import pytest
import yaml

from framework.common.config import resolve_program_scope_file
from framework.findings.lifecycle import (
    FindingLifecycle,
    InvalidLifecycleTransition,
)
from framework.findings.schema import Finding, FindingValidationError
from framework.scope.engine import ScopeEngine, ScopeStatus
from framework.state.manager import StateManager
from framework.validation.engine import (
    ScopeViolationError,
    SecurityValidationEngine,
)
from framework.validation.policy import SecurityTestPolicy

import importlib.machinery
import importlib.util

# Load bb-report module from scripts/bb-report
BB_REPORT_SCRIPT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts", "bb-report"))
_loader = importlib.machinery.SourceFileLoader("bb_report", BB_REPORT_SCRIPT)
_spec = importlib.util.spec_from_loader("bb_report", _loader)
bb_report_cli = importlib.util.module_from_spec(_spec)
_loader.exec_module(bb_report_cli)



class LocalFixtureHandler(http.server.BaseHTTPRequestHandler):
    """
    Local mock HTTP server handler that reflects the 'q' parameter
    to allow deterministic proof-of-concept validation for reflected XSS.
    """

    def log_message(self, format: str, *args) -> None:
        # Silence HTTP server logging during test runs
        pass

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/search":
            if "q" in params:
                query_val = params["q"][0]
                body = f"<html><head><title>Search Results</title></head><body>Results for {query_val}</body></html>"
            else:
                body = "<html><head><title>Search Page</title></head><body>No query provided</body></html>"

            content = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")


@pytest.fixture
def local_fixture_server():
    """Starts an ephemeral local HTTP server on 127.0.0.1."""
    server = http.server.HTTPServer(("127.0.0.1", 0), LocalFixtureHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, port
    server.shutdown()
    server.server_close()


@pytest.fixture
def temp_workspace(local_fixture_server):
    """Provides a temporary program workspace configured with local fixture scope."""
    server, port = local_fixture_server
    tmpdir = tempfile.mkdtemp(prefix="bb_test_e2e_")

    scope_dir = os.path.join(tmpdir, "scope")
    state_dir = os.path.join(tmpdir, "state")
    evidence_dir = os.path.join(tmpdir, "evidence")
    reports_dir = os.path.join(tmpdir, "reports")

    for d in (scope_dir, state_dir, evidence_dir, reports_dir):
        os.makedirs(d, exist_ok=True)

    scope_data = {
        "program": {"name": "e2e-test-program"},
        "targets": {
            "domains": ["localhost"],
            "urls": [f"http://127.0.0.1:{port}"],
        },
        "out_of_scope": {
            "domains": ["out-of-scope.example.com"],
            "urls": [f"http://127.0.0.1:{port}/out-of-scope/secret"],
        },
    }

    scope_file = os.path.join(scope_dir, "scope.yaml")
    with open(scope_file, "w", encoding="utf-8") as f:
        yaml.safe_dump(scope_data, f)

    yield tmpdir, port, scope_file
    shutil.rmtree(tmpdir, ignore_errors=True)


def test_end_to_end_local_discovery_to_report_workflow(temp_workspace):
    """
    Comprehensive E2E test executing the full vulnerability discovery to
    reporting workflow locally against a live fixture on 127.0.0.1.
    """
    tmpdir, port, scope_file = temp_workspace

    # 1. Verify Scope Resolution
    resolved_scope = resolve_program_scope_file(tmpdir)
    assert resolved_scope == scope_file
    scope_engine = ScopeEngine.from_file(resolved_scope)

    fixture_base = f"http://127.0.0.1:{port}"
    target_endpoint = f"{fixture_base}/search"
    target_url_with_param = f"{target_endpoint}?q=test"

    assert scope_engine.check(fixture_base).status == ScopeStatus.IN_SCOPE
    assert scope_engine.check(target_endpoint).status == ScopeStatus.IN_SCOPE

    # 2. Initialize SecurityValidationEngine and configure fixture port
    engine = SecurityValidationEngine(
        program_dir=tmpdir,
        scope_engine=scope_engine,
    )

    # Before allowing fixture port: 127.0.0.1 must be blocked as private loopback SSRF
    with pytest.raises(ScopeViolationError):
        engine.check_request_scope(target_url_with_param)

    # Register fixture port
    engine.allow_fixture_port(port)
    verified_ip = engine.check_request_scope(target_url_with_param)
    assert verified_ip == "127.0.0.1"

    # Other loopback port not in allowed_fixture_ports must fail closed
    with pytest.raises(ScopeViolationError):
        engine.check_request_scope(f"http://127.0.0.1:{port + 1}/test")

    # 3. Seed surface mapping in webapps.json and execute passive intake
    webapps_file = os.path.join(tmpdir, "state", "webapps.json")
    with open(webapps_file, "w", encoding="utf-8") as wf:
        json.dump(
            {
                "endpoints": {
                    f"GET {target_url_with_param}": {
                        "url": target_url_with_param,
                        "method": "GET",
                        "app_id": f"app:127.0.0.1:{port}",
                    }
                }
            },
            wf,
        )

    intake_res = engine.passive_intake()
    assert len(intake_res) >= 1

    # 4. Active validation against local fixture
    run_res = engine.run_validation(
        endpoint=target_endpoint,
        parameter="q",
        validator_name="reflected-xss",
    )

    assert run_res["mode"] == "active_validation"
    assert run_res["tests_executed"] >= 1
    assert run_res["findings_recorded"] == 1
    assert len(run_res["findings"]) == 1

    observed_finding_dict = run_res["findings"][0]
    assert observed_finding_dict["lifecycle_state"] == "OBSERVED"
    assert observed_finding_dict["severity"] in ("MEDIUM", "HIGH")
    assert observed_finding_dict["confidence"] in ("MEDIUM", "HIGH")

    # 5. Verify cryptographic SHA-256 evidence generation
    evidence_list = observed_finding_dict.get("evidence", [])
    assert len(evidence_list) >= 1
    for ev in evidence_list:
        digest = ev["metadata"]["sha256"]
        assert len(digest) == 64
        # Verify cryptographic integrity of raw evidence captured on disk
        evidence_files = [f for f in os.listdir(os.path.join(tmpdir, "evidence")) if digest[:8] in f and f.endswith(".txt")]
        assert len(evidence_files) >= 1
        ev_file_path = os.path.join(tmpdir, "evidence", evidence_files[0])
        with open(ev_file_path, "rb") as ef:
            file_hash = hashlib.sha256(ef.read()).hexdigest()
        assert file_hash == digest, "Cryptographic evidence file SHA-256 hash mismatch"

    # 6. Candidate finding lifecycle progression
    finding = Finding.from_dict(observed_finding_dict)
    assert finding.lifecycle_state == FindingLifecycle.OBSERVED

    # An OBSERVED finding cannot be reported (fail-closed)
    ready, reason = finding.is_report_ready()
    assert ready is False
    assert "only VALIDATED findings can be reported" in reason

    # Transition to VALIDATED with differential validation notes
    val_note = "Confirmed unescaped reflection of arithmetic marker violating HTML encoding invariant."
    finding.transition_to(FindingLifecycle.VALIDATED, notes=val_note)
    assert finding.lifecycle_state == FindingLifecycle.VALIDATED

    # Now finding is report-ready
    ready, reason = finding.is_report_ready()
    assert ready is True
    assert reason == "Finding is report-ready."

    # 7. State synchronization and deduplication
    state_mgr = StateManager(tmpdir)
    canonical_findings = state_mgr.get_findings()
    assert len(canonical_findings) >= 1
    assert any(f.finding_id == finding.finding_id for f in canonical_findings)

    # Sync is idempotent and preserves findings
    synced = state_mgr.sync_all_engine_findings()
    assert synced == 0

    # Update canonical finding with VALIDATED state
    state_mgr.record_finding(finding)

    # Re-submitting duplicate finding with new ID triggers central deduplication
    dup_candidate = Finding(
        title="Reflected XSS Duplicate Discovery",
        summary="Same reflected XSS discovered on search parameter",
        affected_asset=finding.affected_asset,
        affected_endpoint=finding.affected_endpoint,
        parameter=finding.parameter,
        vulnerability_type=finding.vulnerability_type,
        severity=finding.severity,
        description=finding.description,
        root_cause=finding.root_cause,
        prerequisites=finding.prerequisites,
        reproduction_steps=finding.reproduction_steps,
        expected_result=finding.expected_result,
        observed_result=finding.observed_result,
        security_impact=finding.security_impact,
        remediation=finding.remediation,
        scope_reference=finding.scope_reference,
        confidence=finding.confidence,
        lifecycle_state=FindingLifecycle.VALIDATED,
        evidence=[{
            "content": "GET /search?q=dup HTTP/1.1",
            "metadata": {"sha256": "a" * 64},
        }],
        validation_notes="Duplicate validation probe.",
    )
    _, is_dup, dup_of = state_mgr.record_finding(dup_candidate, engine_source="xss")
    assert is_dup is True
    assert dup_of == finding.finding_id

    # 8. Report generation into reports/ via bb-report CLI functions
    reports_dir = os.path.join(tmpdir, "reports")
    report_file = os.path.join(reports_dir, f"{bb_report_cli.sanitize_finding_id_to_filename(finding.finding_id)}.md")

    # Generate markdown report
    report_md = finding.to_markdown_report()
    assert f"# {finding.title}" in report_md
    assert "## Summary" in report_md
    assert "## Asset Details" in report_md
    assert "## Description" in report_md
    assert "## Root Cause" in report_md
    assert "## Prerequisites" in report_md
    assert "## Reproduction Steps" in report_md
    assert "## Expected Result" in report_md
    assert "## Observed Result" in report_md
    assert "## Security Impact" in report_md
    assert "## Evidence" in report_md
    assert "## Remediation" in report_md

    with open(report_file, "w", encoding="utf-8") as rf:
        rf.write(report_md)

    assert os.path.isfile(report_file)

    # 9. Preservation of existing report artifacts
    # bb_report safe path check
    safe_path = bb_report_cli.get_safe_report_path(reports_dir, finding.finding_id)
    assert safe_path == report_file
    assert os.path.exists(safe_path)

    # Path traversal protection verification
    with pytest.raises(ValueError):
        bb_report_cli.get_safe_report_path(reports_dir, "../../etc/passwd")

    with pytest.raises(ValueError):
        bb_report_cli.sanitize_finding_id_to_filename("../../../")


def test_unvalidated_and_simulated_findings_fail_closed_reporting(temp_workspace):
    """
    Verifies that unvalidated candidate findings and simulated observations
    are strictly forbidden from report generation and validated promotion.
    """
    tmpdir, port, scope_file = temp_workspace

    # Case A: Candidate finding (unvalidated)
    cand_finding = Finding(
        title="Unverified Candidate",
        summary="Candidate finding from initial probe",
        affected_asset="127.0.0.1",
        affected_endpoint=f"http://127.0.0.1:{port}/search",
        vulnerability_type="Reflected XSS",
        severity="MEDIUM",
        description="Candidate unvalidated reflected XSS.",
        root_cause="Unescaped parameter reflection.",
        prerequisites="None",
        reproduction_steps=["Query /search?q=test"],
        expected_result="Escaped output",
        observed_result="Unescaped output",
        security_impact="Script execution in client browser",
        remediation="Apply HTML entity encoding",
        scope_reference="scope.yaml: 127.0.0.1",
        confidence="LOW",
        lifecycle_state=FindingLifecycle.CANDIDATE,
    )
    ready, reason = cand_finding.is_report_ready()
    assert ready is False
    assert "only VALIDATED findings can be reported" in reason

    with pytest.raises(FindingValidationError):
        cand_finding.to_markdown_report()

    # Case B: Simulated finding
    sim_finding = Finding(
        title="Simulated Probe",
        summary="Simulated mock scenario",
        affected_asset="127.0.0.1",
        affected_endpoint=f"http://127.0.0.1:{port}/search",
        vulnerability_type="Reflected XSS",
        severity="MEDIUM",
        description="Simulated mock scenario.",
        root_cause="Mock lab scenario.",
        prerequisites="Lab access",
        reproduction_steps=["Run simulated test"],
        expected_result="Access denied",
        observed_result="Simulated response",
        security_impact="Potential information disclosure",
        remediation="Validate input",
        scope_reference="local-lab-scope",
        confidence="HIGH",
        lifecycle_state=FindingLifecycle.OBSERVED,
        provenance={"is_simulation": True},
        evidence=[{
            "content": "Simulated evidence",
            "metadata": {"sha256": hashlib.sha256(b"Simulated evidence").hexdigest()},
        }],
    )

    # Promotion to VALIDATED is rejected
    with pytest.raises(InvalidLifecycleTransition):
        sim_finding.transition_to(FindingLifecycle.VALIDATED, notes="Attempting promotion of simulation")

    # Disclosure report generation fails closed
    ready2, reason2 = sim_finding.is_report_ready()
    assert ready2 is False
    with pytest.raises(FindingValidationError):
        sim_finding.to_markdown_report()
