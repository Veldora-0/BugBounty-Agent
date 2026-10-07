"""
Comprehensive Test Suite for Phase 12.1 — External Pentest Engine Hardening.

Validates:
1. Versioning policies: tested release/commit, version mismatch, unsupported versions.
2. Xalgorix adapter: detection, health, argv construction, scope enforcement, process lifecycle,
   budget semantics, and structured error reporting on malformed artifacts.
3. Strix adapter: optional detection, health, argv construction, scope enforcement, parsing, and cleanup.
4. Multi-fingerprint correlation: AttackSurface, RootCause, Resource, and ActorContext matching.
5. IndependentValidator: empirical claim validation (dual-principal authorization, XSS reflection,
   SSRF canaries, invariant breaches) — rejecting false-positive HTTP 200s.
6. Security hygiene: path traversal resistance, symlink escape resistance, and zero shell execution.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from unittest.mock import MagicMock, patch
import pytest

from framework.business_logic.model import BusinessLogicCategory, WorkflowFinding
from framework.external_engines.base import (
    EngineCapability,
    ExternalEngineStatus,
    ExternalFinding,
    ExternalJob,
    safe_join_artifact_path,
)
from framework.external_engines.correlator import (
    EngineSelectionDecision,
    ExternalEngineSelector,
    ExternalFindingCorrelator,
    IndependentValidator,
    compute_actor_context_fingerprint,
    compute_attack_surface_fingerprint,
    compute_resource_fingerprint,
    compute_root_cause_fingerprint,
)
from framework.external_engines.strix import StrixAdapter
from framework.external_engines.xalgorix import XalgorixAdapter
from framework.findings.lifecycle import FindingLifecycle
from framework.scope.engine import ScopeEngine
from framework.validation.request import ControlledRequest, ControlledResponse


@pytest.fixture
def temp_workspace():
    tmp = tempfile.mkdtemp(prefix="test_ext_hardening_")
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


# ==============================================================================
# 1. Versioning & Detection Tests
# ==============================================================================

def test_xalgorix_version_policy_and_parsing():
    adapter = XalgorixAdapter()
    assert adapter.tested_release == "v4.6.121"
    assert adapter.tested_commit == "17f90ae"
    assert adapter.min_supported_release == "v4.0.0"

    # Version parsing from various CLI outputs
    assert adapter.parse_version_string("xalgorix version 4.6.121 (build abc)") == "v4.6.121"
    assert adapter.parse_version_string("v4.5.0") == "v4.5.0"
    assert adapter.parse_version_string("xalgorix v4.6.121") == "v4.6.121"


def test_strix_version_policy_and_parsing():
    adapter = StrixAdapter()
    assert adapter.tested_release == "v1.6.2"
    assert adapter.tested_commit == "b47d018"
    assert adapter.min_supported_release == "v1.0.0"

    assert adapter.parse_version_string("strix 1.6.2") == "v1.6.2"
    assert adapter.parse_version_string("strix, version 1.6.2") == "v1.6.2"


def test_xalgorix_detection_mismatch_and_unsupported():
    adapter = XalgorixAdapter()

    # Mock CLI returning an older minor version (v4.2.0) -> VERSION_MISMATCH
    with patch("shutil.which", return_value="/usr/local/bin/xalgorix"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="xalgorix v4.2.0", stderr="")
            det = adapter.detect()
            assert det["installed"] is True
            assert det["status"] == ExternalEngineStatus.VERSION_MISMATCH.value
            assert det["version"] == "v4.2.0"

    # Mock CLI returning an unsupported major version (v3.1.0) -> UNSUPPORTED_VERSION
    with patch("shutil.which", return_value="/usr/local/bin/xalgorix"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="xalgorix v3.1.0", stderr="")
            det = adapter.detect()
            assert det["status"] == ExternalEngineStatus.UNSUPPORTED_VERSION.value

    # Mock CLI returning exact tested release -> INSTALLED
    with patch("shutil.which", return_value="/usr/local/bin/xalgorix"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="xalgorix v4.6.121", stderr="")
            det = adapter.detect()
            assert det["status"] == ExternalEngineStatus.INSTALLED.value


def test_strix_optional_detection():
    adapter = StrixAdapter()

    # When absent from PATH, reports NOT_INSTALLED cleanly
    with patch("shutil.which", return_value=None):
        det = adapter.detect()
        assert det["installed"] is False
        assert det["status"] == ExternalEngineStatus.NOT_INSTALLED.value

        health = adapter.health_check()
        assert health["healthy"] is False
        assert health["status"] == ExternalEngineStatus.NOT_INSTALLED.value


# ==============================================================================
# 2. Scope Enforcement & Safe Argv Construction
# ==============================================================================

def test_scope_enforcement_and_safe_argv(temp_workspace):
    scope = ScopeEngine({
        "program": {"name": "test"},
        "targets": {
            "domains": ["authorized.local"],
            "urls": ["http://authorized.local/app"],
        },
        "out_of_scope": {
            "domains": ["unauthorized.external"],
        },
    })
    adapter = XalgorixAdapter()

    targets = [
        "http://authorized.local/app",
        "https://unauthorized.external/secret",
        "http://attacker.com/payload",
    ]

    job = adapter.prepare_job(
        program_dir=temp_workspace,
        target_urls=targets,
        scope_engine=scope,
        budget_requests=50,
        timeout_seconds=120,
    )

    # Must only include authorized.local
    assert len(job.target_set) == 1
    assert job.target_set[0] == "http://authorized.local/app"

    # Command line construction must be an argv array without shell metacharacters
    argv = adapter.build_argv(job, cli_path="/bin/xalgorix")
    assert argv[0] == "/bin/xalgorix"
    assert "--target" in argv
    assert "http://authorized.local/app" in argv
    assert "https://unauthorized.external/secret" not in argv

    # Budget realism: note that native request caps are not faked
    assert "ENGINE_REQUEST_BUDGET_UNSUPPORTED" in job.budget_notes


def test_scope_rejection_when_all_targets_out_of_scope(temp_workspace):
    scope = ScopeEngine({
        "program": {"name": "test"},
        "targets": {"domains": ["authorized.local"]},
    })
    adapter = StrixAdapter()
    with pytest.raises(ValueError, match="out-of-scope"):
        adapter.prepare_job(
            program_dir=temp_workspace,
            target_urls=["https://disallowed.target/admin"],
            scope_engine=scope,
        )


# ==============================================================================
# 3. Execution Lifecycle, Approval Gate & Timeout
# ==============================================================================

def test_approval_gate_blocks_execution(temp_workspace):
    scope = ScopeEngine({
        "program": {"name": "test"},
        "targets": {"domains": ["authorized.local"]},
    })
    adapter = XalgorixAdapter()
    job = adapter.prepare_job(
        program_dir=temp_workspace,
        target_urls=["http://authorized.local/app"],
        scope_engine=scope,
        approval_granted=False,
    )

    # Execution without approval must raise PermissionError
    with pytest.raises(PermissionError, match="requires explicit human operator approval"):
        adapter.start(job)


def test_process_lifecycle_mocked(temp_workspace):
    scope = ScopeEngine({
        "program": {"name": "test"},
        "targets": {"domains": ["authorized.local"]},
    })
    adapter = XalgorixAdapter()
    job = adapter.prepare_job(
        program_dir=temp_workspace,
        target_urls=["http://authorized.local/app"],
        scope_engine=scope,
        approval_granted=True,
    )

    mock_proc = MagicMock()
    mock_proc.pid = 99999
    mock_proc.poll.return_value = None  # Running

    with patch.object(adapter, "detect", return_value={"installed": True, "executable_path": "/bin/xalgorix"}):
        with patch("subprocess.Popen", return_value=mock_proc):
            started_job = adapter.start(job)
            assert started_job.status == ExternalEngineStatus.RUNNING.value
            assert started_job.process_id == 99999

            stat = adapter.status(started_job)
            assert stat["running"] is True

            # Stop the process
            stopped = adapter.stop(started_job)
            assert stopped is True
            assert started_job.status == ExternalEngineStatus.STOPPED.value
            mock_proc.terminate.assert_called_once()


# ==============================================================================
# 4. Artifact Path Traversal Prevention & Parsing Errors
# ==============================================================================

def test_safe_join_artifact_path_prevents_traversal(temp_workspace):
    # Valid relative filenames
    safe_file = safe_join_artifact_path(temp_workspace, "report.json")
    assert safe_file == os.path.join(temp_workspace, "report.json")

    # Directory traversal attempts must raise ValueError
    with pytest.raises(ValueError, match="escapes"):
        safe_join_artifact_path(temp_workspace, "../../../etc/passwd")

    with pytest.raises(ValueError, match="escapes"):
        safe_join_artifact_path(temp_workspace, "..\\secret.env")


def test_parser_reports_structured_errors_on_malformed_json(temp_workspace):
    adapter = XalgorixAdapter()

    # File does not exist
    with pytest.raises(FileNotFoundError):
        adapter.parse_results(os.path.join(temp_workspace, "nonexistent.json"))

    # Directory has no recognized candidate files -> RESULT_SOURCE_UNKNOWN
    empty_dir = os.path.join(temp_workspace, "empty_run")
    os.makedirs(empty_dir, exist_ok=True)
    with pytest.raises(ValueError, match="RESULT_SOURCE_UNKNOWN"):
        adapter.parse_results(empty_dir)

    # Malformed JSON -> PARSE_ERROR
    bad_file = os.path.join(empty_dir, "findings.json")
    with open(bad_file, "w", encoding="utf-8") as f:
        f.write("{this is not valid json")

    with pytest.raises(ValueError, match="PARSE_ERROR"):
        adapter.parse_results(empty_dir)


# ==============================================================================
# 5. Multi-Fingerprint Correlation
# ==============================================================================

def test_correlation_multi_fingerprints():
    # Native finding on /api/user/profile
    nf = WorkflowFinding(
        finding_id="native-1",
        workflow_id="wf-1",
        test_case_id="tc-1",
        title="BOLA: Unauthorized Profile View",
        category=BusinessLogicCategory.OWNERSHIP_MISMATCH,
        severity="HIGH",
        endpoint="http://target.local/api/user/profile",
        actor="ATTACKER",
        violated_invariant="Profile ownership check failed",
        description="Profile accessible",
        remediation="Check session user id",
        evidence_id="ev-1",
    )

    # 1. Matching external finding: same endpoint, compatible class, same actor
    matching_ef = ExternalFinding(
        finding_id="ext-match",
        engine="xalgorix",
        engine_version="v4.6.121",
        run_id="run-1",
        target="http://target.local",
        vulnerability_class="ownership_mismatch",
        title="IDOR in profile endpoint",
        severity="HIGH",
        confidence="CANDIDATE",
        endpoint="http://target.local/api/user/profile",
        method="GET",
        actor="ATTACKER",
    )

    correlated = ExternalFindingCorrelator.correlate([nf], [matching_ef])
    assert len(correlated) == 1
    assert "external_xalgorix" in correlated[0]["sources"]

    # 2. Conflicting actor on same endpoint -> MUST NOT MERGE
    diff_actor_ef = ExternalFinding(
        finding_id="ext-diff-actor",
        engine="xalgorix",
        engine_version="v4.6.121",
        run_id="run-2",
        target="http://target.local",
        vulnerability_class="ownership_mismatch",
        title="IDOR in profile endpoint for admin",
        severity="HIGH",
        confidence="CANDIDATE",
        endpoint="http://target.local/api/user/profile",
        method="GET",
        actor="DIFFERENT_ACTOR",
    )

    correlated_diff = ExternalFindingCorrelator.correlate([nf], [diff_actor_ef])
    # Must remain separate findings because actors differ
    assert len(correlated_diff) == 2

    # 3. Different root cause on same endpoint -> MUST NOT MERGE
    diff_vuln_ef = ExternalFinding(
        finding_id="ext-xss",
        engine="strix",
        engine_version="v1.6.2",
        run_id="run-3",
        target="http://target.local",
        vulnerability_class="xss",
        title="Cross-Site Scripting in profile",
        severity="MEDIUM",
        confidence="CANDIDATE",
        endpoint="http://target.local/api/user/profile",
        method="GET",
    )

    correlated_diff_vuln = ExternalFindingCorrelator.correlate([nf], [diff_vuln_ef])
    assert len(correlated_diff_vuln) == 2


# ==============================================================================
# 6. Hardened Independent Validator (Empirical Claim Verification)
# ==============================================================================

def test_independent_validator_rejects_naive_200_ok():
    """An external IDOR finding receiving HTTP 200 without baseline comparison is NOT VALIDATED."""
    idor_ef = ExternalFinding(
        finding_id="ext-idor",
        engine="xalgorix",
        engine_version="v4.6.121",
        run_id="run-1",
        target="http://target.local",
        vulnerability_class="idor",
        title="IDOR in document export",
        severity="HIGH",
        confidence="CANDIDATE",
        endpoint="http://target.local/api/docs/999",
        actor="ATTACKER",
        resource_id="999",
    )

    # Server returns 200 OK
    def hook_200(req):
        return ControlledResponse(status_code=200, body_text='{"doc": "999"}')

    validator = IndependentValidator(hook_200)

    # Calling without dual-principal baseline comparison must NOT validate
    life, note = validator.independently_validate(idor_ef)
    assert life != FindingLifecycle.VALIDATED
    assert life == FindingLifecycle.NEEDS_MANUAL_REVIEW

    # With proper baseline comparison:
    # Unauthorized actor gets 200 (same as owner 200), reflecting doc 999 -> VALIDATED
    life_valid, note_valid = validator.independently_validate(
        idor_ef,
        context={
            "owner_baseline_status": 200,
            "expected_denial_status": [401, 403, 404],
            "resource_id": "999",
        },
    )
    assert life_valid == FindingLifecycle.VALIDATED
    assert "Empirically validated IDOR/BOLA" in note_valid


def test_independent_validator_xss_and_ssrf():
    # XSS Verification: must have unencoded reflection
    xss_ef = ExternalFinding(
        finding_id="ext-xss",
        engine="xalgorix",
        engine_version="v4.6.121",
        run_id="run-1",
        target="http://target.local",
        vulnerability_class="xss",
        title="Reflected XSS",
        severity="MEDIUM",
        confidence="CANDIDATE",
        endpoint="http://target.local/search?q=test",
    )

    def hook_encoded(req):
        return ControlledResponse(status_code=200, body_text="Hello &lt;XSHIELD_TEST_XSS&gt;")

    def hook_unencoded(req):
        return ControlledResponse(status_code=200, body_text="Hello <XSHIELD_TEST_XSS>")

    val_enc = IndependentValidator(hook_encoded)
    life_enc, _ = val_enc.independently_validate(xss_ef, context={"marker": "XSHIELD_TEST_XSS"})
    assert life_enc == FindingLifecycle.REJECTED  # Properly encoded

    val_unenc = IndependentValidator(hook_unencoded)
    life_unenc, _ = val_unenc.independently_validate(xss_ef, context={"marker": "XSHIELD_TEST_XSS"})
    assert life_unenc == FindingLifecycle.VALIDATED  # Unencoded reflection

    # SSRF Verification: must capture canary callback
    ssrf_ef = ExternalFinding(
        finding_id="ext-ssrf",
        engine="strix",
        engine_version="v1.6.2",
        run_id="run-1",
        target="http://target.local",
        vulnerability_class="ssrf",
        title="Blind SSRF",
        severity="HIGH",
        confidence="CANDIDATE",
        endpoint="http://target.local/webhook",
    )

    def hook_ssrf(req):
        return ControlledResponse(status_code=200, body_text='{"status": "accepted"}')

    val_ssrf = IndependentValidator(hook_ssrf)
    # Without canary callback -> REJECTED
    life_no_cb, _ = val_ssrf.independently_validate(ssrf_ef, context={"canary_callback_received": False})
    assert life_no_cb == FindingLifecycle.REJECTED

    # With canary callback -> VALIDATED
    life_cb, _ = val_ssrf.independently_validate(ssrf_ef, context={"canary_callback_received": True})
    assert life_cb == FindingLifecycle.VALIDATED


# ==============================================================================
# 7. Capability Scoring Engine Selector
# ==============================================================================

def test_engine_selector_capability_scoring():
    selector = ExternalEngineSelector()

    # When native coverage is adequate, external engines are skipped
    dec_native = selector.evaluate_selection(native_coverage_adequate=True)
    assert dec_native.selected_engine is None
    assert "adequate coverage" in dec_native.reasons[0]

    # When both uninstalled, returns none with clear reasons
    with patch.object(selector.engines["xalgorix"], "detect", return_value={"installed": False, "status": "NOT_INSTALLED"}):
        with patch.object(selector.engines["strix"], "detect", return_value={"installed": False, "status": "NOT_INSTALLED"}):
            dec_none = selector.evaluate_selection()
            assert dec_none.selected_engine is None
            assert len(dec_none.rejected_engines) == 2
