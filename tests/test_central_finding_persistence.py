"""
Unit tests for Workstream C: Central Finding Persistence & Cross-Engine Deduplication.

Verifies:
1. New finding persisted to canonical state/findings.json.
2. Same finding submitted twice (deduplicated, marked duplicate_of).
3. Equivalent findings from two different engines (correlated, evidence merged).
4. Similar endpoint with distinct parameters (not merged).
5. Existing legacy state migration via sync_all_engine_findings().
6. Stable deduplication across repeated runs.
7. Retained evidence provenance after correlation.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import pytest

from framework.findings.schema import Finding
from framework.findings.lifecycle import FindingLifecycle
from framework.state.manager import StateManager
from framework.state.dedup import FindingDeduplicator


@pytest.fixture
def temp_program_dir():
    d = tempfile.mkdtemp(prefix="bb_test_central_finding_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


def test_new_finding_persisted_to_canonical_registry(temp_program_dir):
    sm = StateManager(temp_program_dir)
    finding = Finding(
        title="IDOR on User Profile",
        summary="Horizontal authorization bypass accessing user profiles.",
        affected_asset="api.example.com",
        affected_endpoint="/api/v1/users/123",
        vulnerability_type="Insecure Direct Object Reference",
        severity="HIGH",
        confidence="CONFIRMED",
        lifecycle_state=FindingLifecycle.VALIDATED,
        description="User A can view User B's profile.",
        root_cause="Missing authorization check on user ID parameter.",
        prerequisites="Valid user credentials.",
        reproduction_steps=["Login as User A", "Request /api/v1/users/123"],
        expected_result="HTTP 403 Forbidden",
        observed_result="HTTP 200 OK with User B profile",
        security_impact="Unauthorized PII disclosure.",
        remediation="Enforce tenant-based authorization.",
        scope_reference="api.example.com is in scope",
        evidence=[{
            "description": "Proof request",
            "content": "GET /api/v1/users/123 HTTP/1.1\nHost: api.example.com",
            "metadata": {"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"}
        }],
        validation_notes="Verified IDOR across user boundary.",
    )

    persisted, is_dup, dup_id = sm.record_finding(finding, engine_source="authorization")
    assert not is_dup
    assert dup_id is None
    assert persisted.finding_id == finding.finding_id

    # Verify directly in state/findings.json
    findings_file = os.path.join(temp_program_dir, "state", "findings.json")
    assert os.path.exists(findings_file)
    with open(findings_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert finding.finding_id in data
    assert data[finding.finding_id]["provenance"]["engine_source"] == "authorization"


def test_same_finding_submitted_twice_deduplicated(temp_program_dir):
    sm = StateManager(temp_program_dir)
    f1 = Finding(
        title="SQL Injection on Search",
        summary="Time-based blind SQL injection in search parameter.",
        affected_asset="example.com",
        affected_endpoint="/search",
        parameter="q",
        vulnerability_type="SQL Injection",
        severity="CRITICAL",
        confidence="CONFIRMED",
        lifecycle_state=FindingLifecycle.VALIDATED,
        description="Sleep payload triggers 5s delay.",
        root_cause="Raw parameter interpolation in SQL query.",
        prerequisites="Accessible search endpoint.",
        reproduction_steps=["Query /search?q=test' OR SLEEP(5)--"],
        expected_result="Immediate response or validation error.",
        observed_result="5 second response delay.",
        security_impact="Database takeover.",
        remediation="Use parameterized queries.",
        scope_reference="example.com in scope",
        evidence=[{
            "description": "Probe 1",
            "content": "GET /search?q=1 HTTP/1.1",
            "metadata": {"sha256": "1111111111111111111111111111111111111111111111111111111111111111"}
        }],
        validation_notes="Observed sleep delay differential on parameter q.",
    )
    p1, is_dup1, _ = sm.record_finding(f1, engine_source="injection")
    assert not is_dup1

    # Second submission with new ID but exact duplicate target/endpoint/vuln/root_cause
    f2 = Finding(
        title="SQL Injection on Search Duplicate",
        summary="Duplicate finding.",
        affected_asset="example.com",
        affected_endpoint="/search",
        parameter="q",
        vulnerability_type="SQL Injection",
        severity="CRITICAL",
        confidence="CONFIRMED",
        lifecycle_state=FindingLifecycle.VALIDATED,
        description="Duplicate discovery.",
        root_cause="Raw parameter interpolation in SQL query.",
        prerequisites="Accessible search endpoint.",
        reproduction_steps=["Query /search?q=test' OR SLEEP(5)--"],
        expected_result="Immediate response.",
        observed_result="5 second response delay.",
        security_impact="Database takeover.",
        remediation="Use parameterized queries.",
        scope_reference="example.com in scope",
        evidence=[{
            "description": "Probe 2",
            "content": "GET /search?q=2 HTTP/1.1",
            "metadata": {"sha256": "2222222222222222222222222222222222222222222222222222222222222222"}
        }],
        validation_notes="Observed sleep delay differential on duplicate probe.",
    )
    p2, is_dup2, dup_id2 = sm.record_finding(f2, engine_source="injection")
    assert is_dup2
    assert dup_id2 == f1.finding_id
    assert p2.duplicate_of == f1.finding_id


def test_equivalent_findings_from_different_engines_correlated_and_evidence_merged(temp_program_dir):
    sm = StateManager(temp_program_dir)
    
    # Engine A: validation engine discovers SSRF
    f_engine_a = Finding(
        title="SSRF on Webhook",
        summary="Server-Side Request Forgery via webhook parameter.",
        affected_asset="api.example.com",
        affected_endpoint="/webhook",
        parameter="url",
        vulnerability_type="Server-Side Request Forgery",
        severity="HIGH",
        confidence="CONFIRMED",
        lifecycle_state=FindingLifecycle.VALIDATED,
        description="Validation engine observed DNS query.",
        root_cause="Unvalidated outbound HTTP client.",
        prerequisites="None",
        reproduction_steps=["POST /webhook url=http://attacker.com"],
        expected_result="Blocked",
        observed_result="Callback received",
        security_impact="Internal network access",
        remediation="Validate URL destination",
        scope_reference="api.example.com in scope",
        evidence=[{
            "description": "Validation engine probe",
            "content": "POST /webhook url=http://1.1.1.1",
            "metadata": {"sha256": "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"}
        }],
        validation_notes="Observed outbound callback connection on webhook.",
    )
    _, is_dup_a, _ = sm.record_finding(f_engine_a, engine_source="validation")
    assert not is_dup_a

    # Engine B: specialized SSRF engine discovers the same vulnerability on same endpoint & parameter
    f_engine_b = Finding(
        title="SSRF via Outbound Callback",
        summary="SSRF confirmed by OOB interaction.",
        affected_asset="api.example.com",
        affected_endpoint="/webhook",
        parameter="url",
        vulnerability_type="Server-Side Request Forgery",
        severity="HIGH",
        confidence="CONFIRMED",
        lifecycle_state=FindingLifecycle.VALIDATED,
        description="OOB DNS interaction confirmed.",
        root_cause="Unvalidated outbound HTTP client.",
        prerequisites="None",
        reproduction_steps=["POST /webhook url=http://interactsh.com"],
        expected_result="Blocked",
        observed_result="DNS query received at interactsh",
        security_impact="Internal network access",
        remediation="Validate URL destination",
        scope_reference="api.example.com in scope",
        evidence=[{
            "description": "SSRF engine OOB interaction",
            "content": "POST /webhook url=http://xyz.oast.fun",
            "metadata": {"sha256": "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"}
        }],
        validation_notes="OOB interaction confirmed by interactsh server.",
    )
    _, is_dup_b, dup_id_b = sm.record_finding(f_engine_b, engine_source="ssrf")
    assert is_dup_b
    assert dup_id_b == f_engine_a.finding_id

    # Check canonical findings file to ensure evidence was merged and correlated engines tracked
    findings_file = os.path.join(temp_program_dir, "state", "findings.json")
    with open(findings_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    canonical_record = data[f_engine_a.finding_id]
    assert len(canonical_record["evidence"]) == 2
    hashes = [e["metadata"]["sha256"] for e in canonical_record["evidence"]]
    assert "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111" in hashes
    assert "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222" in hashes

    correlated_engines = canonical_record["provenance"]["correlated_engines"]
    assert "ssrf" in correlated_engines
    assert "validation" in correlated_engines


def test_similar_endpoint_with_distinct_parameters_not_merged(temp_program_dir):
    sm = StateManager(temp_program_dir)

    # Finding 1: XSS on search query parameter
    f1 = Finding(
        title="Reflected XSS on q",
        summary="Reflected XSS in search query.",
        affected_asset="example.com",
        affected_endpoint="/search",
        parameter="q",
        vulnerability_type="Cross-Site Scripting",
        severity="MEDIUM",
        confidence="CONFIRMED",
        lifecycle_state=FindingLifecycle.VALIDATED,
        description="XSS in q",
        root_cause="Unescaped reflection in HTML body.",
        prerequisites="None",
        reproduction_steps=["/search?q=<script>"],
        expected_result="Escaped",
        observed_result="Unescaped",
        security_impact="Script execution",
        remediation="Escape output",
        scope_reference="example.com in scope",
        evidence=[{"content": "proof 1", "metadata": {"sha256": "cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333"}}],
        validation_notes="Unescaped script reflection in parameter q.",
    )
    _, is_dup1, _ = sm.record_finding(f1, engine_source="xss")
    assert not is_dup1

    # Finding 2: XSS on category filter parameter (distinct parameter)
    f2 = Finding(
        title="Reflected XSS on category",
        summary="Reflected XSS in category parameter.",
        affected_asset="example.com",
        affected_endpoint="/search",
        parameter="category",
        vulnerability_type="Cross-Site Scripting",
        severity="MEDIUM",
        confidence="CONFIRMED",
        lifecycle_state=FindingLifecycle.VALIDATED,
        description="XSS in category",
        root_cause="Unescaped reflection in HTML body.",
        prerequisites="None",
        reproduction_steps=["/search?category=<script>"],
        expected_result="Escaped",
        observed_result="Unescaped",
        security_impact="Script execution",
        remediation="Escape output",
        scope_reference="example.com in scope",
        evidence=[{"content": "proof 2", "metadata": {"sha256": "dddd4444dddd4444dddd4444dddd4444dddd4444dddd4444dddd4444dddd4444"}}],
        validation_notes="Unescaped script reflection in parameter category.",
    )
    _, is_dup2, _ = sm.record_finding(f2, engine_source="xss")
    assert not is_dup2
    assert f2.duplicate_of is None

    # Both findings must exist independently in canonical registry
    findings_file = os.path.join(temp_program_dir, "state", "findings.json")
    with open(findings_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert f1.finding_id in data
    assert f2.finding_id in data


def test_legacy_engine_state_migration(temp_program_dir):
    state_dir = os.path.join(temp_program_dir, "state")
    os.makedirs(state_dir, exist_ok=True)

    # Create mock legacy state files
    authz_legacy = {
        "findings": {
            "authz-001": {
                "finding_id": "authz-001",
                "title": "Legacy IDOR",
                "summary": "BFLA on admin endpoint",
                "affected_asset": "app.example.com",
                "affected_endpoint": "/admin/delete",
                "vulnerability_type": "Broken Function Level Authorization",
                "severity": "HIGH",
                "confidence": "VALIDATED",
                "lifecycle_state": "VALIDATED",
                "description": "Standard user can call admin delete",
                "root_cause": "Missing role verification",
                "prerequisites": "Standard user session",
                "reproduction_steps": ["Call /admin/delete"],
                "expected_result": "403 Forbidden",
                "observed_result": "200 OK",
                "security_impact": "Unauthorized deletion",
                "remediation": "Check roles",
                "scope_reference": "In scope",
                "evidence": [{"content": "req", "metadata": {"sha256": "eeee5555eeee5555eeee5555eeee5555eeee5555eeee5555eeee5555eeee5555"}}]
            }
        }
    }
    with open(os.path.join(state_dir, "authorization.json"), "w", encoding="utf-8") as f:
        json.dump(authz_legacy, f)

    cloud_legacy = {
        "findings": [
            {
                "finding_id": "cloud-001",
                "title": "Public S3 Bucket",
                "summary": "Open bucket with list permissions",
                "affected_asset": "example-bucket.s3.amazonaws.com",
                "affected_endpoint": "/",
                "vulnerability_type": "Cloud Storage Misconfiguration",
                "severity": "HIGH",
                "confidence": "VALIDATED",
                "lifecycle_state": "VALIDATED",
                "description": "Public readable bucket",
                "root_cause": "Misconfigured S3 ACL",
                "prerequisites": "None",
                "reproduction_steps": ["aws s3 ls s3://example-bucket"],
                "expected_result": "Access Denied",
                "observed_result": "Bucket listed",
                "security_impact": "Data leak",
                "remediation": "Block public access",
                "scope_reference": "In scope",
                "evidence": [{"content": "s3 ls", "metadata": {"sha256": "ffff6666ffff6666ffff6666ffff6666ffff6666ffff6666ffff6666ffff6666"}}]
            }
        ]
    }
    with open(os.path.join(state_dir, "cloud.json"), "w", encoding="utf-8") as f:
        json.dump(cloud_legacy, f)

    sm = StateManager(temp_program_dir)
    indexed = sm.sync_all_engine_findings()
    assert indexed == 2

    # Verify canonical findings
    all_finds = sm.get_findings()
    find_ids = {f.finding_id for f in all_finds}
    assert "authz-001" in find_ids
    assert "cloud-001" in find_ids

    # Running sync again indexes 0 new findings (idempotent)
    indexed_repeat = sm.sync_all_engine_findings()
    assert indexed_repeat == 0


def test_stable_deduplication_across_repeated_runs(temp_program_dir):
    sm = StateManager(temp_program_dir)
    f = Finding(
        title="Open Redirect",
        summary="Open redirect via next parameter.",
        affected_asset="example.com",
        affected_endpoint="/login",
        parameter="next",
        vulnerability_type="Open Redirect",
        severity="LOW",
        confidence="CONFIRMED",
        lifecycle_state=FindingLifecycle.VALIDATED,
        description="Redirects to arbitrary domain.",
        root_cause="Unvalidated redirect URL.",
        prerequisites="None",
        reproduction_steps=["/login?next=https://evil.com"],
        expected_result="Redirect relative only",
        observed_result="Redirects to evil.com",
        security_impact="Phishing",
        remediation="Validate URL",
        scope_reference="In scope",
        evidence=[{"content": "test", "metadata": {"sha256": "aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000"}}],
        validation_notes="Observed open redirect to external evil.com domain.",
    )

    _, is_dup1, _ = sm.record_finding(f)
    assert not is_dup1

    for _ in range(5):
        # Repeated submission of identical candidate
        f_candidate = Finding(
            title="Open Redirect Duplicate",
            summary="Open redirect via next parameter.",
            affected_asset="example.com",
            affected_endpoint="/login",
            parameter="next",
            vulnerability_type="Open Redirect",
            severity="LOW",
            confidence="CONFIRMED",
            lifecycle_state=FindingLifecycle.VALIDATED,
            description="Redirects to arbitrary domain.",
            root_cause="Unvalidated redirect URL.",
            prerequisites="None",
            reproduction_steps=["/login?next=https://evil.com"],
            expected_result="Redirect relative only",
            observed_result="Redirects to evil.com",
            security_impact="Phishing",
            remediation="Validate URL",
            scope_reference="In scope",
            evidence=[{"content": "test", "metadata": {"sha256": "aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000"}}],
            validation_notes="Observed open redirect to external evil.com domain on duplicate run.",
        )
        _, is_dup, dup_id = sm.record_finding(f_candidate)
        assert is_dup
        assert dup_id == f.finding_id


def test_sec04_state_manager_record_finding_sanitizes_evidence(temp_program_dir):
    """SEC-04: Verifies StateManager.record_finding sanitizes evidence before persisting to state/findings.json."""
    sm = StateManager(temp_program_dir)
    raw_secret = "SecretPassword123!"
    finding = Finding(
        title="Sensitive Evidence Test",
        summary="Testing that StateManager sanitizes evidence on storage.",
        affected_asset="api.example.com",
        affected_endpoint="/api/v1/auth",
        vulnerability_type="Information Disclosure",
        severity="LOW",
        confidence="CONFIRMED",
        lifecycle_state=FindingLifecycle.VALIDATED,
        description="Testing evidence persistence sanitization.",
        root_cause="Information disclosure.",
        prerequisites="None",
        reproduction_steps=["Step 1: Check evidence persistence."],
        expected_result="Evidence sanitized.",
        observed_result="Evidence stored.",
        security_impact="None",
        remediation="Ensure sanitization.",
        scope_reference="api.example.com in scope",
        evidence=[{
            "content": f"POST /api/v1/auth HTTP/1.1\n\npassword={raw_secret}",
            "metadata": {"sha256": "1111222233334444111122223333444411112222333344441111222233334444"}
        }],
        validation_notes="Observed sanitized evidence storage in state manager.",
    )

    sm.record_finding(finding)

    # Read state/findings.json directly from disk
    with open(sm.findings_file, "r", encoding="utf-8") as f:
        disk_findings = json.load(f)

    assert finding.finding_id in disk_findings
    stored_ev = disk_findings[finding.finding_id]["evidence"][0]["content"]
    assert raw_secret not in stored_ev
    assert "[REDACTED_BY_BB_AGENT]" in stored_ev
