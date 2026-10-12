"""
Deterministic Tests for Finding Lifecycle and Report Readiness Enforcement.

Covers Workstream B:
- Candidate-to-validated attempts without adequate evidence
- Evidence with missing or invalid integrity metadata
- Missing reproduction steps
- Missing validation rationale
- Successful transition after applicable proof requirements pass
- Report generation rejection for candidate, rejected, duplicate, and zero-evidence findings
- Report generation success for legitimately validated findings
- Secret redaction in rendered evidence
- Backward compatibility of legitimate existing finding serialization
"""

from __future__ import annotations

import json
import pytest

from framework.findings.lifecycle import (
    FindingLifecycle,
    InvalidLifecycleTransition,
    validate_transition,
)
from framework.findings.schema import (
    Finding,
    FindingValidationError,
)


def _build_test_candidate() -> Finding:
    return Finding(
        title="SQL Injection on /api/v1/search",
        summary="User input in parameter 'query' is concatenated into SQL statement.",
        affected_asset="api.example.com",
        affected_endpoint="/api/v1/search",
        vulnerability_type="SQL Injection",
        severity="HIGH",
        description="The query parameter reflects SQL error syntax and time delays.",
        root_cause="Unescaped dynamic string concatenation in PostgreSQL query.",
        prerequisites="Public unauthenticated network access.",
        reproduction_steps=[
            "1. Send GET request to /api/v1/search?query=test' with legitimate token.",
            "2. Observe PostgreSQL syntax error in response body.",
            "3. Send time-delay payload and observe response latency differential.",
        ],
        expected_result="HTTP 200 with sanitized results or HTTP 400 Bad Request.",
        observed_result="HTTP 500 with unhandled PostgreSQL syntax error disclosure.",
        security_impact="Potential unauthorized database record disclosure.",
        remediation="Use parameterized queries and prepared statements.",
        scope_reference="api.example.com in targets.domains",
        confidence="HIGH",
        lifecycle_state=FindingLifecycle.CANDIDATE,
    )


def test_transition_to_validated_fails_without_evidence():
    """Verifies that transitioning to VALIDATED without evidence raises InvalidLifecycleTransition."""
    finding = _build_test_candidate()
    assert len(finding.evidence) == 0

    with pytest.raises(InvalidLifecycleTransition, match="evidence"):
        finding.transition_to(FindingLifecycle.VALIDATED, notes="Verified SQLi differential.")


def test_transition_to_validated_fails_with_invalid_integrity_metadata():
    """Verifies that evidence with malformed SHA-256 metadata raises InvalidLifecycleTransition."""
    finding = _build_test_candidate()
    finding.add_evidence(
        evidence_type="HTTP_CAPTURE",
        content="GET /api/v1/search?query=test' HTTP/1.1\n\nHTTP/1.1 500 Internal Error",
        metadata={"sha256": "not_a_valid_sha256_hash"},
    )

    with pytest.raises(InvalidLifecycleTransition, match="SHA-256"):
        finding.transition_to(FindingLifecycle.VALIDATED, notes="Verified SQLi differential.")


def test_transition_to_validated_fails_without_validation_notes():
    """Verifies that transitioning to VALIDATED without notes or rationale raises InvalidLifecycleTransition."""
    finding = _build_test_candidate()
    finding.add_evidence(
        evidence_type="HTTP_CAPTURE",
        content="GET /api/v1/search?query=test' HTTP/1.1\n\nHTTP/1.1 500 Internal Error",
        metadata={"sha256": "f" * 64},
    )

    with pytest.raises(InvalidLifecycleTransition, match="validation notes"):
        finding.transition_to(FindingLifecycle.VALIDATED, notes="")


def test_transition_to_validated_fails_with_missing_repro_steps():
    """Verifies that empty or too-short reproduction steps block transition to VALIDATED."""
    finding = _build_test_candidate()
    finding.reproduction_steps = ["hi"]  # Too short
    finding.add_evidence(
        evidence_type="HTTP_CAPTURE",
        content="GET /api/v1/search HTTP/1.1",
        metadata={"sha256": "e" * 64},
    )

    with pytest.raises(InvalidLifecycleTransition, match="reproduction step"):
        finding.transition_to(FindingLifecycle.VALIDATED, notes="Rationale provided.")


def test_successful_transition_to_validated_with_proof():
    """Verifies that transition succeeds when all proof requirements are satisfied."""
    finding = _build_test_candidate()
    finding.add_evidence(
        evidence_type="HTTP_CAPTURE",
        content="GET /api/v1/search?query=test' HTTP/1.1\nHost: api.example.com\n\nHTTP/1.1 500 Internal Error\nSyntax error at line 1",
        metadata={"sha256": "c" * 64},
    )
    finding.transition_to(
        FindingLifecycle.VALIDATED,
        notes="Empirical differential confirmed: baseline returned 200, single quote returned syntax error.",
    )

    assert finding.lifecycle_state == FindingLifecycle.VALIDATED
    ready, reason = finding.is_report_ready()
    assert ready is True
    assert "report-ready" in reason


def test_report_generation_rejection_for_non_validated_states():
    """Verifies that candidate, rejected, duplicate, and zero-evidence findings cannot be rendered as disclosure reports."""
    finding = _build_test_candidate()

    # 1. Candidate state
    ready, reason = finding.is_report_ready()
    assert ready is False
    with pytest.raises(FindingValidationError, match="not report-ready"):
        finding.to_markdown_report()

    # 2. Rejected state
    finding.transition_to(FindingLifecycle.REJECTED, notes="False positive marker eliminated.")
    ready, _ = finding.is_report_ready()
    assert ready is False
    with pytest.raises(FindingValidationError, match="not report-ready"):
        finding.to_markdown_report()

    # 3. Duplicate state
    finding.lifecycle_state = FindingLifecycle.DUPLICATE
    finding.duplicate_of = "BB-2026-PREV-01"
    ready, _ = finding.is_report_ready()
    assert ready is False
    with pytest.raises(FindingValidationError, match="not report-ready"):
        finding.to_markdown_report()


def test_secret_redaction_in_rendered_markdown_report():
    """Verifies that sensitive authorization headers, bearer tokens, and session cookies are redacted in rendered markdown."""
    finding = _build_test_candidate()
    raw_sensitive_evidence = (
        "GET /api/v1/search HTTP/1.1\n"
        "Host: api.example.com\n"
        "Authorization: Bearer secret_live_jwt_token_1234567890\n"
        "Cookie: sessionid=secret_session_cookie_abc123; tracking=xyz\n\n"
        "HTTP/1.1 500 Internal Server Error\n"
        "Set-Cookie: session=secret_admin_token\n"
    )

    finding.add_evidence(
        evidence_type="RAW_HTTP",
        content=raw_sensitive_evidence,
        metadata={"sha256": "b" * 64},
    )
    finding.transition_to(
        FindingLifecycle.VALIDATED,
        notes="Demonstrated differential SQL injection error disclosure.",
    )

    report_md = finding.to_markdown_report()
    assert "secret_live_jwt_token_1234567890" not in report_md
    assert "secret_session_cookie_abc123" not in report_md
    assert "secret_admin_token" not in report_md
    assert "[REDACTED_BY_BB_AGENT]" in report_md


def test_backward_compatibility_and_safe_deserialization():
    """Verifies that legacy findings with missing evidence are safely downgraded to NEEDS_MANUAL_REVIEW on from_dict."""
    legacy_data = {
        "finding_id": "BB-LEGACY-01",
        "title": "Legacy Unverified Finding",
        "summary": "Older finding serialized without evidence",
        "affected_asset": "legacy.example.com",
        "affected_endpoint": "/legacy",
        "vulnerability_type": "Information Disclosure",
        "severity": "LOW",
        "confidence": "LOW",
        "lifecycle_state": "VALIDATED",
        "description": "Legacy finding description",
        "root_cause": "Unknown",
        "prerequisites": "None",
        "reproduction_steps": ["Step 1 detailed here", "Step 2 detailed here"],
        "expected_result": "Secure",
        "observed_result": "Insecure",
        "security_impact": "Low impact",
        "remediation": "Update legacy endpoint",
        "scope_reference": "legacy.example.com",
        "evidence": [],  # Missing evidence
    }

    # Deserializing legacy finding does not crash, but flags for manual review
    migrated = Finding.from_dict(legacy_data)
    assert migrated.finding_id == "BB-LEGACY-01"
    assert migrated.lifecycle_state == FindingLifecycle.NEEDS_MANUAL_REVIEW
    ready, _ = migrated.is_report_ready()
    assert ready is False


def test_comprehensive_credential_and_private_key_redaction(tmp_path):
    """
    Verifies that EvidenceStore and Finding markdown reports thoroughly redact:
    - passwords (password=, passwd=, pwd=)
    - secrets (client_secret=, access_key=)
    - authorization headers (Bearer, Basic, Token)
    - session cookies (session=, jwt=, phpsessid=)
    - JSON credentials
    - private key PEM blocks (RSA, EC, Generic)

    Asserts that ALL actual secret strings are completely absent from output,
    while non-sensitive fields are preserved.
    """
    from framework.common.evidence import EvidenceStore, sanitize_sensitive_data

    # Raw secrets that MUST NOT leak
    secret_pw1 = "SuperSecretPassword123!"
    secret_pw2 = "PasswdSecret456!"
    secret_pw3 = "PwdVal789!"
    secret_client = "ClientSecXyz999!"
    secret_ak = "AccessKeyValABC111!"
    secret_bearer = "BearerSecretToken9999!"
    secret_basic = "BasicSecretCreds8888!"
    secret_sess = "SessionCookieSecret2222!"
    secret_jwt = "JwtCookieSecret5555!"
    secret_php = "PhpSessSecret7777!"
    secret_json_pw = "JsonSecretPass3333!"
    secret_json_cs = "JsonClientSecret4444!"
    secret_rsa_pem = "0123456789RSASECRETKEYCONTENT"
    secret_gen_pem = "GENERICPRIVATEKEYDATA987654321"

    all_raw_secrets = [
        secret_pw1, secret_pw2, secret_pw3, secret_client, secret_ak,
        secret_bearer, secret_basic, secret_sess, secret_jwt, secret_php,
        secret_json_pw, secret_json_cs, secret_rsa_pem, secret_gen_pem,
    ]

    raw_request = (
        f"POST /api/v1/auth/login?password={secret_pw1}&passwd={secret_pw2}&pwd={secret_pw3}&user=alice HTTP/1.1\n"
        f"Host: api.example.com\n"
        f"Authorization: Bearer {secret_bearer}\n"
        f"Proxy-Authorization: Basic {secret_basic}\n"
        f"Cookie: session={secret_sess}; jwt={secret_jwt}; phpsessid={secret_php}; public_theme=dark\n"
        f"X-Api-Key: {secret_ak}\n"
        f"Content-Type: application/json\n\n"
        f'{{"password": "{secret_json_pw}", "client_secret": "{secret_json_cs}", "access_key": "{secret_ak}", "username": "alice"}}\n'
    )

    raw_response = (
        f"HTTP/1.1 200 OK\n"
        f"Content-Type: text/plain\n\n"
        f"client_secret={secret_client}&access_key={secret_ak}&status=success\n"
        f"-----BEGIN RSA PRIVATE KEY-----\n{secret_rsa_pem}\n-----END RSA PRIVATE KEY-----\n"
        f"-----BEGIN PRIVATE KEY-----\n{secret_gen_pem}\n-----END PRIVATE KEY-----\n"
    )

    # 1. Test EvidenceStore.save_http_capture()
    store = EvidenceStore(str(tmp_path / "evidence"))
    record = store.save_http_capture(
        request_text=raw_request,
        response_text=raw_response,
        metadata={"target": "api.example.com"},
    )

    with open(record["path"], "r", encoding="utf-8") as f:
        saved_evidence = f.read()

    for secret in all_raw_secrets:
        assert secret not in saved_evidence, f"Leaked raw secret: {secret} in saved evidence file!"

    # Verify non-sensitive metadata is intact
    assert "user=alice" in saved_evidence
    assert "username" in saved_evidence
    assert "public_theme=dark" in saved_evidence
    assert "Content-Type: text/plain" in saved_evidence
    assert "status=success" in saved_evidence
    assert "[REDACTED_BY_BB_AGENT]" in saved_evidence
    assert "[REDACTED_PRIVATE_KEY_BY_BB_AGENT]" in saved_evidence

    # 2. Test Finding.to_markdown_report()
    finding = _build_test_candidate()
    finding.add_evidence(
        evidence_type="HTTP_CAPTURE",
        content=saved_evidence,
        metadata={"sha256": record["sha256"]},
    )
    finding.transition_to(
        FindingLifecycle.VALIDATED,
        notes="Validated credentials handling and redaction integrity.",
    )

    report_md = finding.to_markdown_report()
    for secret in all_raw_secrets:
        assert secret not in report_md, f"Leaked raw secret: {secret} in generated markdown report!"


def test_sec04_add_evidence_and_to_dict_sanitization():
    """SEC-04: Verifies that Finding.add_evidence and to_dict sanitize sensitive credentials."""
    finding = _build_test_candidate()
    raw_content = "POST /login HTTP/1.1\nHost: api.example.com\n\npassword=SuperSecretPassword123!&access_key=ak_9988776655"
    finding.add_evidence(
        evidence_type="HTTP_PAIR",
        content=raw_content,
        metadata={"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
    )

    # In-memory evidence list is sanitized
    assert "SuperSecretPassword123!" not in finding.evidence[0]["content"]
    assert "[REDACTED_BY_BB_AGENT]" in finding.evidence[0]["content"]

    # Serialized dictionary is sanitized
    d = finding.to_dict()
    assert "SuperSecretPassword123!" not in d["evidence"][0]["content"]
    assert "[REDACTED_BY_BB_AGENT]" in d["evidence"][0]["content"]


def test_sec05_evidence_sanitization_preserves_boolean_flags():
    """SEC-05: Verifies that boolean flags like has_access_key=True and requires_password=false are preserved."""
    from framework.common.evidence import sanitize_sensitive_data
    from framework.authentication.evidence import AuthenticationEvidenceManager

    test_input = "query?has_access_key=True&requires_password=false&is_token=null&password=SecretPassword123!"
    sanitized = sanitize_sensitive_data(test_input)

    assert "has_access_key=True" in sanitized
    assert "requires_password=false" in sanitized
    assert "is_token=null" in sanitized
    assert "SecretPassword123!" not in sanitized
    assert "password=[REDACTED_BY_BB_AGENT]" in sanitized

    # Check AuthenticationEvidenceManager.sanitize_dict
    payload = {
        "has_access_key": True,
        "requires_password": False,
        "password": "SecretPassword123!",
        "access_token": "token_abc123xyz",
    }
    san_dict = AuthenticationEvidenceManager.sanitize_dict(payload)
    assert san_dict["has_access_key"] is True
    assert san_dict["requires_password"] is False
    assert san_dict["password"] == "[REDACTED_PASSWORD]"
    assert san_dict["access_token"] == "[REDACTED_TOKEN]"

