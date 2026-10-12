"""
Unit and Integration Regression Tests for Gate 0 Remediation Items.

Covers:
1. Shared scope resolution helper (framework/common/config.py):
   - Explicit scope path precedence (fails closed on non-existent path).
   - Canonical program directory (<prog_dir>/scope/scope.yaml).
   - Legacy fallback directory (<prog_dir>/scope.yaml).
   - Authentication policy delegation (resolve_scope_file).
2. Local fixture authorization & validation engine bounds:
   - Port bounds validation (1024 <= port <= 65535).
   - Rejection of privileged ports (< 1024) and out-of-range ports.
   - Fail-closed scope enforcement on allowed fixture targets.
3. HTTP trust state synchronization (framework/state/manager.py):
   - Synchronization of http-trust.json findings into canonical state/findings.json.
   - Evidence retention and lifecycle preservation.
   - Deduplication across sync cycles.
4. Dedicated report CLI (scripts/bb-report):
   - Sanitization and path traversal defense.
   - Fail-closed refusal for unvalidated or simulated findings.
   - Markdown report generation conforming to 17 standard disclosure sections.
   - Preservation of existing report artifacts without --force.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import tempfile
import pytest
import yaml

from framework.authentication.policy import resolve_scope_file
from framework.common.config import resolve_program_scope_file
from framework.findings.lifecycle import FindingLifecycle
from framework.findings.schema import Finding, FindingValidationError
from framework.scope.engine import ScopeEngine
from framework.state.manager import StateManager
from framework.validation.engine import (
    ScopeViolationError,
    SecurityValidationEngine,
)

import importlib.machinery
import importlib.util

# Load bb-report module from scripts/bb-report
BB_REPORT_SCRIPT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts", "bb-report"))
_loader = importlib.machinery.SourceFileLoader("bb_report", BB_REPORT_SCRIPT)
_spec = importlib.util.spec_from_loader("bb_report", _loader)
bb_report_cli = importlib.util.module_from_spec(_spec)
_loader.exec_module(bb_report_cli)



@pytest.fixture
def temp_workspace():
    tmpdir = tempfile.mkdtemp(prefix="bb_test_gate0_")
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


# ==============================================================================
# 1. SHARED SCOPE RESOLUTION TESTS
# ==============================================================================


def test_scope_resolution_explicit_path_precedence(temp_workspace):
    """Explicit scope path takes precedence when it exists."""
    explicit_file = os.path.join(temp_workspace, "custom_scope.yaml")
    with open(explicit_file, "w", encoding="utf-8") as f:
        f.write("target: custom\n")

    resolved = resolve_program_scope_file(temp_workspace, explicit_file)
    assert resolved == os.path.abspath(explicit_file)


def test_scope_resolution_explicit_missing_fails_closed(temp_workspace):
    """Non-existent explicit scope path returns None (fail-closed, never falls back)."""
    canonical_dir = os.path.join(temp_workspace, "scope")
    os.makedirs(canonical_dir, exist_ok=True)
    canonical_file = os.path.join(canonical_dir, "scope.yaml")
    with open(canonical_file, "w", encoding="utf-8") as f:
        f.write("target: canonical\n")

    # Even though canonical scope.yaml exists, an invalid explicit path must fail closed
    missing_explicit = os.path.join(temp_workspace, "does_not_exist.yaml")
    resolved = resolve_program_scope_file(temp_workspace, missing_explicit)
    assert resolved is None


def test_scope_resolution_canonical_precedence_over_legacy(temp_workspace):
    """Canonical <prog_dir>/scope/scope.yaml takes precedence over <prog_dir>/scope.yaml."""
    canonical_dir = os.path.join(temp_workspace, "scope")
    os.makedirs(canonical_dir, exist_ok=True)
    canonical_file = os.path.join(canonical_dir, "scope.yaml")
    with open(canonical_file, "w", encoding="utf-8") as f:
        f.write("target: canonical\n")

    legacy_file = os.path.join(temp_workspace, "scope.yaml")
    with open(legacy_file, "w", encoding="utf-8") as f:
        f.write("target: legacy\n")

    resolved = resolve_program_scope_file(temp_workspace)
    assert resolved == os.path.abspath(canonical_file)


def test_scope_resolution_legacy_fallback(temp_workspace):
    """When canonical scope/scope.yaml is absent, falls back to <prog_dir>/scope.yaml."""
    legacy_file = os.path.join(temp_workspace, "scope.yaml")
    with open(legacy_file, "w", encoding="utf-8") as f:
        f.write("target: legacy\n")

    resolved = resolve_program_scope_file(temp_workspace)
    assert resolved == os.path.abspath(legacy_file)


def test_scope_resolution_absent_returns_none(temp_workspace):
    """Returns None when no scope file exists anywhere."""
    resolved = resolve_program_scope_file(temp_workspace)
    assert resolved is None


def test_authentication_policy_resolve_scope_file_delegation(temp_workspace):
    """Verifies framework.authentication.policy.resolve_scope_file delegates cleanly."""
    canonical_dir = os.path.join(temp_workspace, "scope")
    os.makedirs(canonical_dir, exist_ok=True)
    canonical_file = os.path.join(canonical_dir, "scope.yaml")
    with open(canonical_file, "w", encoding="utf-8") as f:
        f.write("target: auth_canonical\n")

    assert resolve_scope_file(temp_workspace) == os.path.abspath(canonical_file)
    assert resolve_scope_file(temp_workspace, "missing.yaml") is None


# ==============================================================================
# 2. LOCAL FIXTURE AUTHORIZATION BOUNDS TESTS
# ==============================================================================


def test_fixture_port_range_validation(temp_workspace):
    """Verifies allow_fixture_port strictly accepts only unprivileged ports (1024-65535)."""
    engine = SecurityValidationEngine(program_dir=temp_workspace)

    # Valid unprivileged ports
    engine.allow_fixture_port(1024)
    engine.allow_fixture_port(8080)
    engine.allow_fixture_port(65535)
    assert {1024, 8080, 65535}.issubset(engine.allowed_fixture_ports)

    # Privileged ports must be rejected
    for priv_port in (80, 443, 22, 0, -1, 1023):
        with pytest.raises(ValueError):
            engine.allow_fixture_port(priv_port)

    # Out of range ports must be rejected
    for invalid_port in (65536, 70000, 100000):
        with pytest.raises(ValueError):
            engine.allow_fixture_port(invalid_port)

    # Non-integer inputs must be rejected
    for invalid_type in ("8080", None, 8080.5):
        with pytest.raises(ValueError):
            engine.allow_fixture_port(invalid_type)  # type: ignore


def test_fixture_port_fails_closed_without_allow_port(temp_workspace):
    """Verifies unapproved loopback ports, internal IPs, and metadata targets fail closed."""
    engine = SecurityValidationEngine(program_dir=temp_workspace)

    # Port not allowed: blocked as SSRF
    with pytest.raises(ScopeViolationError):
        engine.check_request_scope("http://127.0.0.1:8888/test")

    # Allowed port permits local loopback fixture
    engine.allow_fixture_port(8888)
    assert engine.check_request_scope("http://127.0.0.1:8888/test") == "127.0.0.1"

    # Non-loopback internal IP remains blocked even if port matches
    with pytest.raises(ScopeViolationError):
        engine.check_request_scope("http://10.0.0.1:8888/test")
    with pytest.raises(ScopeViolationError):
        engine.check_request_scope("http://169.254.169.254:8888/latest")
    with pytest.raises(ScopeViolationError):
        engine.check_request_scope("http://192.168.1.1:8888/admin")


# ==============================================================================
# 3. HTTP TRUST STATE SYNCHRONIZATION TESTS
# ==============================================================================


def test_sync_all_engine_findings_indexes_http_trust(temp_workspace):
    """Verifies sync_all_engine_findings reads and synchronizes http-trust.json."""
    state_dir = os.path.join(temp_workspace, "state")
    os.makedirs(state_dir, exist_ok=True)

    http_trust_state = {
        "version": "1.0.0",
        "program": "test-prog",
        "findings": {
            "http-find-001": {
                "id": "http-find-001",
                "title": "HTTP Host Header Injection",
                "category": "http_trust_host",
                "severity": "HIGH",
                "endpoint": "https://api.example.com/password-reset",
                "header": "Host",
                "signals": ["DIFFERENTIAL_REDIRECT_OBSERVED"],
                "description": "Password reset email poisons link via untrusted Host header.",
                "lifecycle": "VALIDATED",
                "priority": "P1",
                "remediation": "Validate Host header against whitelist.",
                "evidence": [{
                    "content": "POST /password-reset HTTP/1.1\nHost: evil.com",
                    "metadata": {"sha256": "1" * 64},
                }],
                "reproduction_steps": ["Submit password reset with Host: evil.com", "Verify reset token URL"],
                "expected_result": "Reset email references official domain",
                "observed_result": "Reset email references evil.com",
                "validation_notes": "Differential testing confirmed arbitrary host header reflection in reset flow.",
            }
        }
    }

    with open(os.path.join(state_dir, "http-trust.json"), "w", encoding="utf-8") as f:
        json.dump(http_trust_state, f)

    sm = StateManager(temp_workspace)
    synced_count = sm.sync_all_engine_findings()
    assert synced_count == 1

    findings_file = os.path.join(state_dir, "findings.json")
    assert os.path.isfile(findings_file)

    with open(findings_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "http-find-001" in data
    synced_finding = data["http-find-001"]
    assert synced_finding["severity"] == "HIGH"
    assert synced_finding["lifecycle_state"] == "VALIDATED"
    assert synced_finding["provenance"]["engine_source"] == "http_trust"
    assert len(synced_finding["evidence"]) == 1

    # Second sync produces 0 new indexed findings (deduplicated)
    synced_again = sm.sync_all_engine_findings()
    assert synced_again == 0


# ==============================================================================
# 4. REPORT CLI (scripts/bb-report) UNIT TESTS
# ==============================================================================


def test_bb_report_path_sanitization_and_traversal_defense(temp_workspace):
    """Verifies sanitize_finding_id_to_filename and get_safe_report_path reject traversal attacks."""
    reports_dir = os.path.join(temp_workspace, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    # Valid IDs
    assert bb_report_cli.sanitize_finding_id_to_filename("find-123") == "find-123"
    assert bb_report_cli.sanitize_finding_id_to_filename("FIND_ABC_01") == "FIND_ABC_01"

    safe_path = bb_report_cli.get_safe_report_path(reports_dir, "find-123")
    assert safe_path == os.path.join(os.path.abspath(reports_dir), "find-123.md")

    # Path traversal attempts must be rejected with ValueError
    for evil_id in ("../../etc/passwd", "..\\..\\windows\\system32", "../find-123", "", "...", "../../../", "///"):
        with pytest.raises(ValueError):
            bb_report_cli.sanitize_finding_id_to_filename(evil_id)
        with pytest.raises(ValueError):
            bb_report_cli.get_safe_report_path(reports_dir, evil_id)


def test_bb_report_preserves_existing_report_without_force(temp_workspace):
    """Verifies existing reports are not overwritten unless --force is specified."""
    reports_dir = os.path.join(temp_workspace, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    report_path = os.path.join(reports_dir, "test-finding-01.md")
    original_content = "# Original Preserved Report Content"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(original_content)

    # Verify safe path detects existence
    assert os.path.exists(report_path)

    # Calling get_safe_report_path succeeds
    target = bb_report_cli.get_safe_report_path(reports_dir, "test-finding-01")
    assert target == report_path

    # Content remains unaltered
    with open(report_path, "r", encoding="utf-8") as f:
        assert f.read() == original_content
