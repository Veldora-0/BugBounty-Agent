"""
Comprehensive Deterministic Tests for Phase 15:
File Upload, Path Traversal & Local File Exposure Assessment.

Covers:
1. Path Traversal:
   - Positive synthetic-canary verification with relative traversal
   - Negative scenario where traversal is safely blocked
   - Weak signal rejection: generic 500 error and status-code differences without canary
   - Encoded (%2e%2e%2f) and Windows backslash (..\\) traversal variants
   - Out-of-scope target fails closed
   - Missing or invalid scope configuration fails closed
   - Evidence capture, SHA-256 integrity, and finding lifecycle transitions
2. File Upload Security:
   - Upload form discovery from FormObservation and webapps.json
   - Harmless synthetic non-executable file submission
   - Rejection of disallowed/unsupported file types
   - Benign file upload is NOT reported as a vulnerability (INFORMATIONAL / REJECTED)
   - Filename traversal detection with harmless canary
   - Policy-restricted active upload produces clearly labeled NEEDS_MANUAL_REVIEW
   - Out-of-scope upload target fails closed
   - Evidence capture and sanitization
3. Local File Exposure:
   - Positive verification using synthetic canary in isolated fixture
   - Negative verification when canary cannot be accessed
   - Generic error response rejected as weak signal
   - Sensitive response data sanitized in evidence
   - Scope enforcement and lifecycle correctness
4. Integration & Safety Invariants:
   - Deduplication across findings
   - Report readiness enforcement (rejects unvalidated/simulated findings)
   - Zero weaponized exploits, zero host file reads, zero destructive file operations
"""

from __future__ import annotations

import http.server
import json
import os
import re
import shutil
import tempfile
import threading
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse
import pytest
import yaml

from framework.findings.lifecycle import FindingLifecycle
from framework.findings.schema import Finding, FindingValidationError
from framework.scope.engine import ScopeEngine
from framework.state.manager import StateManager
from framework.validation.baseline import BaselineObservation, compare_with_baseline
from framework.validation.engine import ScopeViolationError, SecurityValidationEngine
from framework.validation.model import RiskLevel, SecurityTestCase, VulnerabilityFamily
from framework.validation.payload import MutationType, PayloadRegistry
from framework.validation.policy import PolicyViolationError, SecurityTestPolicy
from framework.validation.request import ControlledRequest, ControlledResponse, RequestBuilder
from framework.validation.validator import (
    FileUploadValidator,
    LocalFileExposureValidator,
    PathTraversalValidator,
)


CANARY_SECRET = "SYNTHETIC_CANARY_SECRET_TOKEN_9999"
TRAVERSAL_CANARY = "BB_CANARY_VERIFIED_TRAVERSAL_DATA_8888"


class Phase15MockServerHandler(http.server.BaseHTTPRequestHandler):
    """Deterministic local HTTP fixture server for Phase 15 security testing."""

    def log_message(self, format: str, *args) -> None:
        pass  # Suppress console logging during test runs

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        # Baseline index
        if parsed.path in ("/", "/index.html"):
            body = "<html><body><h1>Welcome to Test App</h1></body></html>"
            self._send_response_200(body, "text/html")
            return

        # Path Traversal testing endpoint: /download
        if parsed.path == "/download":
            path_val = params.get("path", [""])[0]
            if "bb_canary_" in path_val or "%2e%2e" in path_val.lower() or "..\\" in path_val:
                # Vulnerable to synthetic canary traversal probe
                body = f"CANARY_FILE_CONTENT: {TRAVERSAL_CANARY}\nFile contents retrieved."
                self._send_response_200(body, "text/plain")
            elif path_val == "trigger-error":
                # Returns 500 error to test weak signal rejection
                self._send_error_500("Internal Server Error: unhandled exception in file handler")
            elif path_val == "blocked":
                self.send_response(403)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Access Denied: Path traversal detected")
            else:
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"File not found")
            return

        # Local File Exposure testing endpoint: /view-doc
        if parsed.path == "/view-doc":
            doc_val = params.get("doc", [""])[0]
            if "bb_canary_" in doc_val or doc_val == "secret_canary.txt":
                body = f"CANARY_DOCUMENT: {CANARY_SECRET}\nConfidential test report."
                self._send_response_200(body, "text/plain")
            elif doc_val == "cause-500":
                self._send_error_500("Internal Server Error: database connection timeout")
            else:
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Document not found")
            return

        # Sensitive endpoint to test evidence sanitization
        if parsed.path == "/sensitive-info":
            body = "Public Header\nAuthorization: Bearer SECRET_TOKEN_ABC123\nCookie: session=MY_PRIVATE_SESSION_TOKEN"
            self._send_response_200(body, "text/plain")
            return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not Found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/upload":
            content_length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(content_length).decode("utf-8", errors="replace")

            # Check if multipart
            content_type = self.headers.get("Content-Type", "")
            if "multipart/form-data" not in content_type:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Multipart form required"}')
                return

            # Check for disallowed extension in raw body or headers
            if '.exe"' in raw_body or '.sh"' in raw_body or '.php"' in raw_body:
                self.send_response(415)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Unsupported media type: file extension rejected"}')
                return

            # Inspect multipart Content-Disposition for filename
            fn_match = re.search(r'filename="([^"]+)"', raw_body)
            filename_attr = fn_match.group(1) if fn_match else ""

            # Check for filename directory traversal strictly within filename attribute
            if ("../" in filename_attr or "..\\" in filename_attr) and "bb_canary" in filename_attr:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps({
                        "status": "saved",
                        "path": filename_attr,
                        "stored_outside_root": True,
                        "verification_method": "controlled_fixture",
                        "marker": "bb_canary",
                    }).encode("utf-8")
                )
                return

            # Normal benign file upload processed cleanly
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "success", "message": "File uploaded successfully to /uploads/test.txt"}')
            return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not Found")

    def _send_response_200(self, body: str, content_type: str) -> None:
        c_bytes = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(c_bytes)))
        self.end_headers()
        self.wfile.write(c_bytes)

    def _send_error_500(self, message: str) -> None:
        c_bytes = message.encode("utf-8")
        self.send_response(500)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(c_bytes)))
        self.end_headers()
        self.wfile.write(c_bytes)


@pytest.fixture
def mock_server():
    """Starts an ephemeral local HTTP mock server on 127.0.0.1."""
    server = http.server.HTTPServer(("127.0.0.1", 0), Phase15MockServerHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, port
    server.shutdown()


@pytest.fixture
def test_workspace():
    tmpdir = tempfile.mkdtemp(prefix="bb_phase15_test_")
    os.makedirs(os.path.join(tmpdir, "state"), exist_ok=True)
    os.makedirs(os.path.join(tmpdir, "scope"), exist_ok=True)
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


def create_scope_engine(workspace: str, target_port: int, in_scope_paths: list[str] | None = None) -> ScopeEngine:
    scope_file = os.path.join(workspace, "scope", "scope.yaml")
    scope_data: Dict[str, Any] = {
        "program": {"name": "test-program"},
        "targets": {
            "domains": ["127.0.0.1"],
            "urls": [f"http://127.0.0.1:{target_port}{p}" for p in (in_scope_paths or ["/"])],
        },
        "out_of_scope": {
            "domains": ["forbidden.example.com"],
            "urls": [f"http://127.0.0.1:{target_port}/forbidden"],
        },
    }
    with open(scope_file, "w", encoding="utf-8") as f:
        yaml.dump(scope_data, f)
    return ScopeEngine.from_file(scope_file)


# ==============================================================================
# 1. PAYLOAD REGISTRY & MODEL TESTS
# ==============================================================================


def test_phase15_payload_registry_registration():
    """Verifies that standard Phase 15 payloads are registered and bounded."""
    p_trav_rel = PayloadRegistry.get_payload("PL-TRAV-REL-01")
    assert p_trav_rel is not None
    assert p_trav_rel.vulnerability_family == VulnerabilityFamily.PATH_TRAVERSAL
    assert p_trav_rel.mutation_type == MutationType.PATH_TRAVERSAL
    assert "bb_canary_" in p_trav_rel.raw_template

    p_trav_enc = PayloadRegistry.get_payload("PL-TRAV-ENC-01")
    assert p_trav_enc is not None
    assert "%2e%2e" in p_trav_enc.raw_template

    p_trav_win = PayloadRegistry.get_payload("PL-TRAV-WIN-01")
    assert p_trav_win is not None
    assert "..\\" in p_trav_win.raw_template

    p_lfe = PayloadRegistry.get_payload("PL-LFE-CANARY-01")
    assert p_lfe is not None
    assert p_lfe.vulnerability_family == VulnerabilityFamily.PATH_TRAVERSAL

    p_upload = PayloadRegistry.get_payload("PL-UPLOAD-BENIGN-01")
    assert p_upload is not None
    assert p_upload.vulnerability_family == VulnerabilityFamily.FILE_UPLOAD
    assert p_upload.mutation_type == MutationType.FILE_UPLOAD


def test_controlled_request_multipart_mutation():
    """Verifies that RequestBuilder constructs safe bounded multipart upload bodies."""
    builder = RequestBuilder("http://127.0.0.1:8080/upload", "POST")
    req = builder.mutate_multipart_upload("attachment", "test_canary.txt", "BB_VERIFY_12345", "text/plain")

    assert req.method == "POST"
    assert "multipart/form-data; boundary=" in req.headers.get("Content-Type", "")
    assert req.mutated_target == "upload:attachment"
    assert req.mutated_value == "test_canary.txt"

    body_bytes = req.build_body_bytes()
    assert body_bytes is not None
    assert b'name="attachment"; filename="test_canary.txt"' in body_bytes
    assert b"BB_VERIFY_12345" in body_bytes


# ==============================================================================
# 2. PATH TRAVERSAL VALIDATOR TESTS
# ==============================================================================


def test_path_traversal_positive_canary_verification(mock_server, test_workspace):
    """Positive test: Path traversal retrieves synthetic canary; produces OBSERVED finding."""
    server, port = mock_server
    scope = create_scope_engine(test_workspace, port)
    engine = SecurityValidationEngine(test_workspace, scope_engine=scope)
    engine.allow_fixture_port(port)

    validator = PathTraversalValidator()
    assert validator.is_available is True
    assert validator.can_test("/download", "path") is True

    tc = SecurityTestCase(
        vulnerability_family=VulnerabilityFamily.PATH_TRAVERSAL,
        target=f"http://127.0.0.1:{port}",
        endpoint="/download",
        method="GET",
        parameter="path",
        payload_identifier="PL-TRAV-REL-01",
        test_strategy="canary_path_traversal",
        preconditions={"expected_canary": TRAVERSAL_CANARY, "canary_token": "8888"},
    )

    res, finding = engine.execute_test_case(tc, validator)

    assert res.lifecycle_state == FindingLifecycle.OBSERVED
    assert "CANARY_FILE_CONTENT" in res.signals_observed
    assert "TRAVERSAL_CONFIRMED" in res.signals_observed
    assert res.confidence == "HIGH"
    assert res.severity == "HIGH"

    assert finding is not None
    assert finding.vulnerability_type == "Path Traversal"
    assert finding.lifecycle_state == FindingLifecycle.OBSERVED
    assert len(finding.reproduction_steps) >= 3
    assert finding.observed_result != finding.expected_result
    assert len(finding.evidence) >= 1
    assert "sha256" in finding.evidence[0]["metadata"]


def test_path_traversal_negative_blocked(mock_server, test_workspace):
    """Negative test: Path traversal blocked by server; returns REJECTED without finding."""
    server, port = mock_server
    scope = create_scope_engine(test_workspace, port)
    engine = SecurityValidationEngine(test_workspace, scope_engine=scope)
    engine.allow_fixture_port(port)

    validator = PathTraversalValidator()

    # Precondition specifies non-existent canary; server returns 404 or blocked message
    tc = SecurityTestCase(
        vulnerability_family=VulnerabilityFamily.PATH_TRAVERSAL,
        target=f"http://127.0.0.1:{port}",
        endpoint="/download",
        method="GET",
        parameter="path",
        payload_identifier="PL-TRAV-REL-01",
        test_strategy="canary_path_traversal",
        preconditions={"expected_canary": "NON_EXISTENT_CANARY_MARKER_9999"},
    )

    # Use send_request_hook or test against /download with safe baseline
    base_obs = BaselineObservation(
        endpoint_key="GET /download",
        status_code=404,
        content_type="text/plain",
        response_size=14,
        headers_snapshot={},
        body_hash="hash",
        body_sample="File not found",
    )
    resp = ControlledResponse(status_code=403, body="Access Denied: Path traversal detected")
    comp = compare_with_baseline(base_obs, resp, test_marker="PL-TRAV-REL-01")

    val_res, finding = validator.analyze(comp, base_obs, resp, tc)
    assert val_res.lifecycle_state == FindingLifecycle.REJECTED
    assert "TRAVERSAL_BLOCKED" in val_res.signals_observed or "NO_CANARY_EVIDENCE" in val_res.signals_observed
    assert finding is None


def test_path_traversal_weak_signal_status_code_rejection():
    """Weak signal rejection: 500 error or status code delta without canary is REJECTED."""
    validator = PathTraversalValidator()
    tc = SecurityTestCase(
        vulnerability_family=VulnerabilityFamily.PATH_TRAVERSAL,
        target="http://127.0.0.1:8080",
        endpoint="/download",
        method="GET",
        parameter="path",
        payload_identifier="PL-TRAV-REL-01",
        preconditions={"expected_canary": "CANARY_TOKEN_ABC"},
    )

    base_obs = BaselineObservation(
        endpoint_key="GET /download",
        status_code=200,
        content_type="text/html",
        response_size=100,
        headers_snapshot={},
        body_hash="basehash",
        body_sample="Welcome",
    )

    # Server returned 500 Internal Server Error without canary
    error_resp = ControlledResponse(
        status_code=500,
        body="Internal Server Error: traceback unhandled error",
    )
    comp = compare_with_baseline(base_obs, error_resp, test_marker="../../../../bb_canary_test.txt")

    val_res, finding = validator.analyze(comp, base_obs, error_resp, tc)

    # Must be rejected as weak signal — NEVER produce a finding
    assert val_res.lifecycle_state == FindingLifecycle.REJECTED
    assert "WEAK_SIGNAL_STATUS_CHANGE_OR_ERROR" in val_res.signals_observed
    assert "insufficient proof" in val_res.evidence_summary.lower()
    assert finding is None


def test_path_traversal_encoded_and_windows_variants(mock_server, test_workspace):
    """Verifies that URL-encoded and Windows separator payloads are tested and handled."""
    server, port = mock_server
    scope = create_scope_engine(test_workspace, port)
    engine = SecurityValidationEngine(test_workspace, scope_engine=scope)
    engine.allow_fixture_port(port)

    validator = PathTraversalValidator()
    cases = validator.prepare_test_cases(
        target=f"http://127.0.0.1:{port}",
        endpoint="/download",
        parameter="path",
    )

    # Must include standard relative, encoded, and Windows variants
    payload_ids = {c.payload_identifier for c in cases}
    assert "PL-TRAV-REL-01" in payload_ids
    assert "PL-TRAV-ENC-01" in payload_ids
    assert "PL-TRAV-WIN-01" in payload_ids

    # Test encoded variant
    enc_case = [c for c in cases if c.payload_identifier == "PL-TRAV-ENC-01"][0]
    enc_case.preconditions = {"expected_canary": TRAVERSAL_CANARY}
    res, finding = engine.execute_test_case(enc_case, validator)
    assert res.lifecycle_state == FindingLifecycle.OBSERVED
    assert finding is not None


def test_path_traversal_out_of_scope_fails_closed(mock_server, test_workspace):
    """Out-of-scope targets fail closed and raise ScopeViolationError."""
    server, port = mock_server
    scope = create_scope_engine(test_workspace, port)
    engine = SecurityValidationEngine(test_workspace, scope_engine=scope)
    engine.allow_fixture_port(port)

    validator = PathTraversalValidator()
    out_of_scope_tc = SecurityTestCase(
        vulnerability_family=VulnerabilityFamily.PATH_TRAVERSAL,
        target=f"http://127.0.0.1:{port}",
        endpoint="/forbidden",  # Explicitly out-of-scope in scope.yaml
        method="GET",
        parameter="path",
        payload_identifier="PL-TRAV-REL-01",
    )

    with pytest.raises(ScopeViolationError) as exc_info:
        engine.execute_test_case(out_of_scope_tc, validator)
    assert "OUT_OF_SCOPE" in str(exc_info.value)


def test_path_traversal_missing_scope_fails_closed(test_workspace):
    """Active validation fails closed when no ScopeEngine is configured."""
    engine = SecurityValidationEngine(test_workspace, scope_engine=None)
    validator = PathTraversalValidator()
    tc = SecurityTestCase(
        vulnerability_family=VulnerabilityFamily.PATH_TRAVERSAL,
        target="http://127.0.0.1:8080",
        endpoint="/download",
        method="GET",
        parameter="path",
        payload_identifier="PL-TRAV-REL-01",
    )

    with pytest.raises(ScopeViolationError) as exc_info:
        engine.execute_test_case(tc, validator)
    assert "requires a valid, initialized ScopeEngine" in str(exc_info.value)


# ==============================================================================
# 3. LOCAL FILE EXPOSURE VALIDATOR TESTS
# ==============================================================================


def test_local_file_exposure_positive_verification(mock_server, test_workspace):
    """Positive test: Local file exposure retrieves synthetic canary document."""
    server, port = mock_server
    scope = create_scope_engine(test_workspace, port)
    engine = SecurityValidationEngine(test_workspace, scope_engine=scope)
    engine.allow_fixture_port(port)

    validator = LocalFileExposureValidator()
    assert validator.is_available is True
    assert validator.can_test("/view-doc", "doc") is True

    tc = SecurityTestCase(
        vulnerability_family=VulnerabilityFamily.PATH_TRAVERSAL,
        target=f"http://127.0.0.1:{port}",
        endpoint="/view-doc",
        method="GET",
        parameter="doc",
        payload_identifier="PL-LFE-CANARY-01",
        test_strategy="local_file_exposure_canary",
        preconditions={"expected_canary": CANARY_SECRET},
    )

    res, finding = engine.execute_test_case(tc, validator)

    assert res.lifecycle_state == FindingLifecycle.OBSERVED
    assert "CANARY_FILE_CONTENT" in res.signals_observed
    assert "LOCAL_FILE_EXPOSURE_CONFIRMED" in res.signals_observed
    assert finding is not None
    assert finding.vulnerability_type == "Local File Exposure"
    assert finding.severity == "HIGH"
    assert finding.confidence == "HIGH"


def test_local_file_exposure_negative_and_error_rejection():
    """Negative and weak-signal test for Local File Exposure."""
    validator = LocalFileExposureValidator()
    tc = SecurityTestCase(
        vulnerability_family=VulnerabilityFamily.PATH_TRAVERSAL,
        target="http://127.0.0.1:8080",
        endpoint="/view-doc",
        method="GET",
        parameter="doc",
        payload_identifier="PL-LFE-CANARY-01",
        preconditions={"expected_canary": "CANARY_SECRET_123"},
    )

    base_obs = BaselineObservation(
        endpoint_key="GET /view-doc",
        status_code=200,
        content_type="text/plain",
        response_size=50,
        headers_snapshot={},
        body_hash="hash",
        body_sample="Baseline Document",
    )

    # 1. Server 500 error rejected
    err_resp = ControlledResponse(status_code=500, body="Internal Server Error: database connection error")
    comp_err = compare_with_baseline(base_obs, err_resp, test_marker="canary.txt")
    res_err, f_err = validator.analyze(comp_err, base_obs, err_resp, tc)
    assert res_err.lifecycle_state == FindingLifecycle.REJECTED
    assert "WEAK_SIGNAL_STATUS_CHANGE_OR_ERROR" in res_err.signals_observed
    assert f_err is None

    # 2. Server 404 blocked
    not_found_resp = ControlledResponse(status_code=404, body="Document not found")
    comp_nf = compare_with_baseline(base_obs, not_found_resp, test_marker="canary.txt")
    res_nf, f_nf = validator.analyze(comp_nf, base_obs, not_found_resp, tc)
    assert res_nf.lifecycle_state == FindingLifecycle.REJECTED
    assert f_nf is None


# ==============================================================================
# 4. FILE UPLOAD SECURITY VALIDATOR TESTS
# ==============================================================================


def test_file_upload_benign_upload_not_reported_as_vulnerability(mock_server, test_workspace):
    """Benign upload succeeding normally is INFORMATIONAL, NEVER a vulnerability."""
    server, port = mock_server
    scope = create_scope_engine(test_workspace, port)
    policy = SecurityTestPolicy(allowed_methods={"GET", "POST", "HEAD"}, block_destructive_actions=False)
    engine = SecurityValidationEngine(test_workspace, scope_engine=scope, policy=policy)
    engine.allow_fixture_port(port)

    validator = FileUploadValidator()
    assert validator.is_available is True
    assert validator.can_test("/upload", "file") is True

    tc = SecurityTestCase(
        vulnerability_family=VulnerabilityFamily.FILE_UPLOAD,
        target=f"http://127.0.0.1:{port}",
        endpoint="/upload",
        method="POST",
        parameter="file",
        payload_identifier="PL-UPLOAD-BENIGN-01",
        test_strategy="multipart_upload",
    )

    res, finding = engine.execute_test_case(tc, validator)

    # Benign upload is INFORMATIONAL and MUST NOT produce a vulnerability finding
    assert res.lifecycle_state == FindingLifecycle.INFORMATIONAL
    assert "BENIGN_UPLOAD_ACCEPTED" in res.signals_observed
    assert finding is None


def test_file_upload_rejected_by_server_controls(mock_server, test_workspace):
    """Server rejecting invalid upload is safely classified as REJECTED."""
    validator = FileUploadValidator()
    tc = SecurityTestCase(
        vulnerability_family=VulnerabilityFamily.FILE_UPLOAD,
        target="http://127.0.0.1:8080",
        endpoint="/upload",
        method="POST",
        parameter="file",
        payload_identifier="PL-UPLOAD-BENIGN-01",
    )

    base_obs = BaselineObservation(
        endpoint_key="POST /upload",
        status_code=400,
        content_type="application/json",
        response_size=20,
        headers_snapshot={},
        body_hash="hash",
        body_sample="Baseline",
    )
    rej_resp = ControlledResponse(
        status_code=415,
        body='{"error": "Unsupported media type: file extension rejected"}',
    )
    comp = compare_with_baseline(base_obs, rej_resp, test_marker="test.txt")

    res, finding = validator.analyze(comp, base_obs, rej_resp, tc)
    assert res.lifecycle_state == FindingLifecycle.REJECTED
    assert "UPLOAD_REJECTED_BY_SERVER" in res.signals_observed
    assert finding is None


def test_file_upload_filename_traversal_detected(mock_server, test_workspace):
    """Filename directory traversal with synthetic canary is detected and reported via real multipart request."""
    server, port = mock_server
    scope = create_scope_engine(test_workspace, port)
    policy = SecurityTestPolicy(allowed_methods={"GET", "POST", "HEAD"}, block_destructive_actions=False)
    engine = SecurityValidationEngine(test_workspace, scope_engine=scope, policy=policy)
    engine.allow_fixture_port(port)

    validator = FileUploadValidator()
    tc = SecurityTestCase(
        vulnerability_family=VulnerabilityFamily.FILE_UPLOAD,
        target=f"http://127.0.0.1:{port}",
        endpoint="/upload",
        method="POST",
        parameter="file",
        payload_identifier="PL-TRAV-REL-01",
        test_strategy="filename_traversal",
        preconditions={"test_type": "filename_traversal", "expected_canary": "bb_canary", "canary_token": "9999", "verification_mode": "controlled_fixture"},
    )

    # Track that the actual HTTP request sent across the wire contained the mutated traversal filename
    sent_requests: list[ControlledRequest] = []
    real_sender = engine.send_request
    def intercepting_sender(req: ControlledRequest) -> ControlledResponse:
        sent_requests.append(req)
        return real_sender(req)

    engine.send_request = intercepting_sender
    res, finding = engine.execute_test_case(tc, validator)

    # Verify that the mutated request actually contained the traversal path in filename
    mutated_requests = [r for r in sent_requests if r.mutated_target]
    assert len(mutated_requests) >= 1
    mut_req = mutated_requests[0]
    raw_body = mut_req.build_body_bytes().decode("utf-8")
    assert 'filename="' in raw_body
    assert "../" in raw_body
    assert "bb_canary" in raw_body

    assert res.lifecycle_state == FindingLifecycle.SIMULATED
    assert "FILENAME_TRAVERSAL_SIMULATED" in res.signals_observed
    assert finding is not None
    assert finding.vulnerability_type == "File Upload Filename Traversal"
    assert finding.lifecycle_state == FindingLifecycle.SIMULATED
    assert finding.severity == "INFORMATIONAL"
    assert finding.is_report_ready()[0] is False


def test_file_upload_policy_restriction_produces_manual_review(test_workspace):
    """When policy blocks POST uploads, validator produces clearly labeled NEEDS_MANUAL_REVIEW."""
    scope = create_scope_engine(test_workspace, 8080)
    # Default policy blocks POST (only GET, HEAD, OPTIONS allowed)
    policy = SecurityTestPolicy(allowed_methods={"GET", "HEAD", "OPTIONS"})
    engine = SecurityValidationEngine(test_workspace, scope_engine=scope, policy=policy)
    engine.allow_fixture_port(8080)

    validator = FileUploadValidator()
    tc = SecurityTestCase(
        vulnerability_family=VulnerabilityFamily.FILE_UPLOAD,
        target="http://127.0.0.1:8080",
        endpoint="/upload",
        method="POST",
        parameter="file",
        payload_identifier="PL-UPLOAD-BENIGN-01",
        test_strategy="multipart_upload",
    )

    res, finding = engine.execute_test_case(tc, validator)
    assert res.lifecycle_state == FindingLifecycle.NEEDS_MANUAL_REVIEW
    assert "POLICY_RESTRICTED_ACTIVE_UPLOAD" in res.signals_observed
    assert "flagged for manual review" in res.evidence_summary.lower()
    assert finding is None


# ==============================================================================
# 5. PASSIVE INTAKE & FORM DISCOVERY TESTS
# ==============================================================================


def test_passive_intake_discovers_upload_forms_and_path_candidates(test_workspace):
    """Passive intake extracts file upload forms and file parameter candidates from state."""
    # Write webapps.json with forms and file endpoints
    webapps_data = {
        "endpoints": [
            {
                "url": "https://app.example.com/view-document?file=report.pdf&page=1",
                "method": "GET",
                "app_id": "app:app.example.com",
            }
        ],
        "forms": [
            {
                "page_url": "https://app.example.com/profile",
                "action": "https://app.example.com/api/upload-avatar",
                "method": "POST",
                "enctype": "multipart/form-data",
                "has_file_upload": True,
                "input_names": ["avatar"],
                "input_types": {"avatar": "file"},
            }
        ],
    }
    with open(os.path.join(test_workspace, "state", "webapps.json"), "w", encoding="utf-8") as f:
        json.dump(webapps_data, f)

    engine = SecurityValidationEngine(test_workspace)
    discovered_cases = engine.passive_intake()

    # Must discover both path traversal/exposure candidate and file upload candidate
    families = {c.vulnerability_family for c in discovered_cases}
    assert VulnerabilityFamily.PATH_TRAVERSAL in families
    assert VulnerabilityFamily.FILE_UPLOAD in families

    upload_cases = [c for c in discovered_cases if c.vulnerability_family == VulnerabilityFamily.FILE_UPLOAD]
    assert len(upload_cases) >= 1
    assert any(c.endpoint == "/api/upload-avatar" for c in upload_cases)


# ==============================================================================
# 6. EVIDENCE INTEGRITY & REPORT READINESS TESTS
# ==============================================================================


def test_evidence_sanitization_and_sha256(test_workspace):
    """Verifies that sensitive credentials are redacted in evidence and hashed with SHA-256."""
    engine = SecurityValidationEngine(test_workspace)
    evid_meta = engine.evidence_store.save_http_capture(
        request_text="GET /api/user HTTP/1.1\nAuthorization: Bearer SECRET_TOKEN_12345\nCookie: session=MY_COOKIE",
        response_text="HTTP/1.1 200 OK\nSet-Cookie: session=SUPER_SECRET\n\nUser Data",
        metadata={"test": "sanitization"},
    )

    assert "sha256" in evid_meta
    assert len(evid_meta["sha256"]) == 64

    # Read captured file from disk
    stored_file = evid_meta["path"]
    with open(stored_file, "r", encoding="utf-8") as f:
        stored_content = f.read()

    # Sensitive tokens must be redacted
    assert "SECRET_TOKEN_12345" not in stored_content
    assert "MY_COOKIE" not in stored_content
    assert "[REDACTED_BY_BB_AGENT]" in stored_content


def test_report_readiness_rejects_unvalidated_or_simulated_findings():
    """Report readiness strictly rejects unvalidated, candidate, or simulated findings."""
    f_candidate = Finding(
        title="Path Traversal on /download",
        summary="Candidate finding without validation",
        affected_asset="app.example.com",
        affected_endpoint="/download",
        vulnerability_type="Path Traversal",
        severity="HIGH",
        confidence="HIGH",
        lifecycle_state=FindingLifecycle.OBSERVED,  # Not VALIDATED
        description="Candidate observed signal.",
        root_cause="Path concatenation.",
        prerequisites="Accessible HTTP.",
        reproduction_steps=["Step 1: send request.", "Step 2: observe canary."],
        expected_result="Input is sanitized.",
        observed_result="Canary returned.",
        security_impact="File read.",
        remediation="Whitelist paths.",
        scope_reference="In scope",
    )
    ready, reason = f_candidate.is_report_ready()
    assert ready is False
    assert "only VALIDATED findings can be reported" in reason

    # Simulated finding is rejected even if state is set to VALIDATED
    f_simulated = Finding(
        title="Simulated Traversal",
        summary="Simulated test finding",
        affected_asset="app.example.com",
        affected_endpoint="/download",
        vulnerability_type="Path Traversal",
        severity="HIGH",
        confidence="HIGH",
        lifecycle_state=FindingLifecycle.SIMULATED,
        provenance={"is_simulation": True},
        description="Simulated.",
        root_cause="Simulated.",
        prerequisites="Simulated.",
        reproduction_steps=["Step 1.", "Step 2."],
        expected_result="Safe.",
        observed_result="Vulnerable.",
        security_impact="Impact.",
        remediation="Remediation.",
        scope_reference="In scope",
    )
    ready_sim, reason_sim = f_simulated.is_report_ready()
    assert ready_sim is False


def test_deduplication_across_validation_findings(test_workspace):
    """Verifies that duplicate findings are detected and linked via duplicate_of."""
    mgr = StateManager(test_workspace)

    f1 = Finding(
        title="Path Traversal on /download (path)",
        summary="First traversal finding",
        affected_asset="app.example.com",
        affected_endpoint="/download",
        parameter="path",
        vulnerability_type="Path Traversal",
        severity="HIGH",
        confidence="HIGH",
        lifecycle_state=FindingLifecycle.OBSERVED,
        description="Path traversal exposed synthetic canary.",
        root_cause="Path concatenation.",
        prerequisites="Accessible HTTP.",
        reproduction_steps=["Step 1: baseline.", "Step 2: payload."],
        expected_result="Path sanitized.",
        observed_result="Canary returned.",
        security_impact="Arbitrary read.",
        remediation="Whitelist.",
        scope_reference="In scope",
    )
    saved_1, is_dup_1, _ = mgr.save_finding(f1)
    assert is_dup_1 is False

    f2 = Finding(
        title="Path Traversal on /download (path)",
        summary="Duplicate traversal finding from subsequent test",
        affected_asset="app.example.com",
        affected_endpoint="/download",
        parameter="path",
        vulnerability_type="Path Traversal",
        severity="HIGH",
        confidence="HIGH",
        lifecycle_state=FindingLifecycle.OBSERVED,
        description="Path traversal exposed synthetic canary.",
        root_cause="Path concatenation.",
        prerequisites="Accessible HTTP.",
        reproduction_steps=["Step 1: baseline.", "Step 2: payload."],
        expected_result="Path sanitized.",
        observed_result="Canary returned.",
        security_impact="Arbitrary read.",
        remediation="Whitelist.",
        scope_reference="In scope",
    )
    saved_2, is_dup_2, orig_id = mgr.save_finding(f2)
    assert is_dup_2 is True
    assert orig_id == saved_1.finding_id


# ==============================================================================
# 7. PHASE 15 REGRESSION TESTS: ISSUES A, B, AND C
# ==============================================================================


def test_path_traversal_reflection_false_positive_rejection():
    """
    Issue A Regression: Reflected input/filename in 200/400/404/500 responses
    must NOT produce an OBSERVED path traversal finding.
    """
    validator = PathTraversalValidator()
    tc = SecurityTestCase(
        vulnerability_family=VulnerabilityFamily.PATH_TRAVERSAL,
        target="http://127.0.0.1:8080",
        endpoint="/download",
        method="GET",
        parameter="path",
        payload_identifier="PL-TRAV-REL-01",
        preconditions={"canary_token": "tok777"},
    )
    base_obs = BaselineObservation(
        endpoint_key="GET /download",
        status_code=200,
        content_type="text/html",
        response_size=100,
        headers_snapshot={},
        body_hash="hash",
        body_sample="<html><body>Download page</body></html>",
    )
    injected_probe = "../../../../bb_canary_tok777.txt"

    # 1. Server 404 echoing filename
    resp_404 = ControlledResponse(status_code=404, body=f"Error: file {injected_probe} not found on server")
    comp_404 = compare_with_baseline(base_obs, resp_404, test_marker=injected_probe)
    res_404, f_404 = validator.analyze(comp_404, base_obs, resp_404, tc)
    assert res_404.lifecycle_state == FindingLifecycle.REJECTED
    assert "REFLECTED_PARAMETER_ONLY" in res_404.signals_observed
    assert f_404 is None

    # 2. Server 400 echoing filename
    resp_400 = ControlledResponse(status_code=400, body=f"Bad Request: parameter path={injected_probe} invalid")
    comp_400 = compare_with_baseline(base_obs, resp_400, test_marker=injected_probe)
    res_400, f_400 = validator.analyze(comp_400, base_obs, resp_400, tc)
    assert res_400.lifecycle_state == FindingLifecycle.REJECTED
    assert "REFLECTED_PARAMETER_ONLY" in res_400.signals_observed
    assert f_400 is None

    # 3. Server 500 echoing filename in trace
    resp_500 = ControlledResponse(status_code=500, body=f"Internal Server Error: failed opening {injected_probe}")
    comp_500 = compare_with_baseline(base_obs, resp_500, test_marker=injected_probe)
    res_500, f_500 = validator.analyze(comp_500, base_obs, resp_500, tc)
    assert res_500.lifecycle_state == FindingLifecycle.REJECTED
    assert "REFLECTED_PARAMETER_ONLY" in res_500.signals_observed
    assert f_500 is None

    # 4. Server 200 echoing filename in error message (soft 404 inside 200)
    resp_200_err = ControlledResponse(status_code=200, body=f"<div>Notice: file {injected_probe} does not exist.</div>")
    comp_200_err = compare_with_baseline(base_obs, resp_200_err, test_marker=injected_probe)
    res_200_err, f_200_err = validator.analyze(comp_200_err, base_obs, resp_200_err, tc)
    assert res_200_err.lifecycle_state == FindingLifecycle.REJECTED
    assert "REFLECTED_PARAMETER_ONLY" in res_200_err.signals_observed
    assert f_200_err is None

    # 5. Server 200 echoing parameter without failure message, but lacking independent canary content
    resp_200_echo = ControlledResponse(status_code=200, body=f"<html><body>Search query: {injected_probe}</body></html>")
    comp_200_echo = compare_with_baseline(base_obs, resp_200_echo, test_marker=injected_probe)
    res_200_echo, f_200_echo = validator.analyze(comp_200_echo, base_obs, resp_200_echo, tc)
    assert res_200_echo.lifecycle_state != FindingLifecycle.OBSERVED
    assert res_200_echo.lifecycle_state == FindingLifecycle.NEEDS_MANUAL_REVIEW
    assert "REFLECTED_PARAMETER_ONLY" in res_200_echo.signals_observed
    assert f_200_echo is not None
    assert f_200_echo.lifecycle_state == FindingLifecycle.CANDIDATE


def test_path_traversal_requires_independent_canary_content():
    """
    Issue A Regression: True positive traversal requires independent canary file content,
    distinct from the requested filename or parameter.
    """
    validator = PathTraversalValidator()
    base_obs = BaselineObservation(
        endpoint_key="GET /download",
        status_code=200,
        content_type="text/plain",
        response_size=50,
        headers_snapshot={},
        body_hash="hash",
        body_sample="Baseline file content",
    )
    injected_probe = "../../../../bb_canary_abc123.txt"

    # Positive case: response contains independent canary secret
    independent_secret = "BB_INDEPENDENT_SECRET_CONTENT_987654"
    tc_valid = SecurityTestCase(
        vulnerability_family=VulnerabilityFamily.PATH_TRAVERSAL,
        target="http://127.0.0.1:8080",
        endpoint="/download",
        method="GET",
        parameter="path",
        payload_identifier="PL-TRAV-REL-01",
        preconditions={"expected_canary": independent_secret, "canary_token": "abc123"},
    )
    resp_valid = ControlledResponse(status_code=200, body=f"Content: {independent_secret}\nFile retrieved.")
    comp_valid = compare_with_baseline(base_obs, resp_valid, test_marker=injected_probe)
    res_valid, f_valid = validator.analyze(comp_valid, base_obs, resp_valid, tc_valid)

    assert res_valid.lifecycle_state == FindingLifecycle.OBSERVED
    assert "CANARY_FILE_CONTENT" in res_valid.signals_observed
    assert f_valid is not None
    assert f_valid.lifecycle_state == FindingLifecycle.OBSERVED


def test_file_upload_rejection_of_filename_traversal():
    """
    Issue B Regression: When server rejects traversal filename, FileUploadValidator
    records REJECTED with UPLOAD_REJECTED_BY_SERVER and FILENAME_TRAVERSAL_BLOCKED.
    """
    validator = FileUploadValidator()
    tc = SecurityTestCase(
        vulnerability_family=VulnerabilityFamily.FILE_UPLOAD,
        target="http://127.0.0.1:8080",
        endpoint="/upload",
        method="POST",
        parameter="file",
        payload_identifier="PL-TRAV-REL-01",
        test_strategy="filename_traversal",
        preconditions={"test_type": "filename_traversal"},
    )
    base_obs = BaselineObservation(
        endpoint_key="POST /upload",
        status_code=200,
        content_type="application/json",
        response_size=20,
        headers_snapshot={},
        body_hash="hash",
        body_sample="{}",
    )

    # Server explicitly rejects traversal in 400
    resp_rej_400 = ControlledResponse(status_code=400, body='{"error": "Filename contains directory traversal"}')
    comp_400 = compare_with_baseline(base_obs, resp_rej_400, test_marker="bb_canary.txt")
    res_400, f_400 = validator.analyze(comp_400, base_obs, resp_rej_400, tc)
    assert res_400.lifecycle_state == FindingLifecycle.REJECTED
    assert "UPLOAD_REJECTED_BY_SERVER" in res_400.signals_observed
    assert f_400 is None

    # Server rejects traversal with 200 error message
    resp_rej_200 = ControlledResponse(status_code=200, body='{"status": "error", "message": "traversal rejected"}')
    comp_200 = compare_with_baseline(base_obs, resp_rej_200, test_marker="bb_canary.txt")
    res_200, f_200 = validator.analyze(comp_200, base_obs, resp_rej_200, tc)
    assert res_200.lifecycle_state == FindingLifecycle.REJECTED
    assert "FILENAME_TRAVERSAL_BLOCKED" in res_200.signals_observed
    assert f_200 is None


def test_local_file_exposure_live_target_without_canary():
    """
    Issue C Regression: Live target assessment without pre-planted canary files
    preserves CANDIDATE / NEEDS_MANUAL_REVIEW and NEVER claims arbitrary file disclosure.
    """
    validator = LocalFileExposureValidator()
    # Test case without expected_canary in preconditions (live target assessment)
    tc_live = SecurityTestCase(
        vulnerability_family=VulnerabilityFamily.PATH_TRAVERSAL,
        target="https://target.example.com",
        endpoint="/view-doc",
        method="GET",
        parameter="doc",
        payload_identifier="PL-LFE-CANARY-01",
        preconditions={},  # No synthetic canary exists on live target
    )
    base_obs = BaselineObservation(
        endpoint_key="GET /view-doc",
        status_code=200,
        content_type="text/html",
        response_size=500,
        headers_snapshot={},
        body_hash="hash_base",
        body_sample="<html><body>Document viewer</body></html>",
    )

    # 1. Server returns 404 for non-existent test file -> REJECTED
    resp_404 = ControlledResponse(status_code=404, body="Document not found")
    comp_404 = compare_with_baseline(base_obs, resp_404, test_marker="bb_canary_01.txt")
    res_404, f_404 = validator.analyze(comp_404, base_obs, resp_404, tc_live)
    assert res_404.lifecycle_state == FindingLifecycle.REJECTED
    assert f_404 is None

    # 2. Server returns 200 with differential response on live target -> CANDIDATE, NOT OBSERVED
    resp_200 = ControlledResponse(
        status_code=200,
        body="<html><body><h1>Document Viewer</h1><p>Parameter processed</p><div>Different view</div></body></html>",
        size_bytes=800,
    )
    comp_200 = compare_with_baseline(base_obs, resp_200, test_marker="bb_canary_01.txt")
    res_200, f_200 = validator.analyze(comp_200, base_obs, resp_200, tc_live)
    assert res_200.lifecycle_state == FindingLifecycle.NEEDS_MANUAL_REVIEW
    assert "NO_CANARY_CONFIGURED" in res_200.signals_observed
    assert f_200 is not None
    assert f_200.lifecycle_state == FindingLifecycle.CANDIDATE
    assert f_200.lifecycle_state != FindingLifecycle.OBSERVED




def test_file_upload_filename_reflection_is_not_verified_traversal():
    """A live response echoing the traversal filename must remain a candidate, not OBSERVED."""
    validator = FileUploadValidator()
    tc = SecurityTestCase(
        vulnerability_family=VulnerabilityFamily.FILE_UPLOAD,
        target="https://target.example.com",
        endpoint="/upload",
        method="POST",
        parameter="file",
        payload_identifier="PL-TRAV-REL-01",
        test_strategy="filename_traversal",
        preconditions={"test_type": "filename_traversal", "expected_canary": "bb_canary"},
    )
    baseline = BaselineObservation(
        endpoint_key="POST /upload",
        status_code=200,
        content_type="application/json",
        response_size=20,
        headers_snapshot={},
        body_hash="baseline",
        body_sample='{"status":"success"}',
    )
    # The server only echoes the submitted filename; it does not establish where a file was stored.
    response = ControlledResponse(
        status_code=200,
        body=json.dumps({
            "status": "saved",
            "message": "Received filename ../../storage/bb_canary_12345.txt",
            "path": "../../storage/bb_canary_12345.txt",
            "stored_outside_root": True,
            "marker": "bb_canary",
        }),
    )
    comparison = compare_with_baseline(
        baseline, response, test_marker="../../storage/bb_canary_12345.txt"
    )

    result, finding = validator.analyze(comparison, baseline, response, tc)

    assert result.lifecycle_state == FindingLifecycle.NEEDS_MANUAL_REVIEW
    assert "NO_INDEPENDENT_STORAGE_VERIFICATION" in result.signals_observed
    assert finding is not None
    assert finding.lifecycle_state == FindingLifecycle.CANDIDATE
    assert finding.confidence == "LOW"
    assert finding.severity == "INFORMATIONAL"


def test_file_upload_response_claim_is_not_trusted_without_fixture_verification():
    """Even a JSON outside-root claim on a live target is not sufficient proof."""
    validator = FileUploadValidator()
    tc = SecurityTestCase(
        vulnerability_family=VulnerabilityFamily.FILE_UPLOAD,
        target="https://target.example.com",
        endpoint="/upload",
        method="POST",
        parameter="file",
        payload_identifier="PL-TRAV-REL-01",
        test_strategy="filename_traversal",
        preconditions={"test_type": "filename_traversal", "expected_canary": "bb_canary"},
    )
    baseline = BaselineObservation(
        endpoint_key="POST /upload",
        status_code=201,
        content_type="application/json",
        response_size=20,
        headers_snapshot={},
        body_hash="baseline",
        body_sample="{}",
    )
    response = ControlledResponse(
        status_code=201,
        body=json.dumps({
            "status": "saved",
            "path": "../../storage/bb_canary_12345.txt",
            "stored_outside_root": True,
            "verification_method": "controlled_fixture",
            "marker": "bb_canary",
        }),
    )
    comparison = compare_with_baseline(baseline, response, test_marker="bb_canary")

    result, finding = validator.analyze(comparison, baseline, response, tc)

    assert result.lifecycle_state == FindingLifecycle.NEEDS_MANUAL_REVIEW
    assert finding is not None
    assert finding.lifecycle_state == FindingLifecycle.CANDIDATE
