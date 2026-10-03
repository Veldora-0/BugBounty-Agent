"""
Tests for Test Fingerprinting and Finding Deduplication.
"""

from framework.state.dedup import (
    FindingDeduplicator,
    canonicalize_parameter,
    canonicalize_url_path,
    generate_test_fingerprint,
)


def test_test_fingerprint_stability():
    fp1 = generate_test_fingerprint(
        target="api.example.com",
        endpoint="/v1/users/",
        method="GET",
        parameter="user_id",
        test_category="idor",
    )

    # Identical with different casing and extra slashes
    fp2 = generate_test_fingerprint(
        target="API.EXAMPLE.COM",
        endpoint="//v1/users",
        method="get",
        parameter="USER_ID",
        test_category="IDOR",
    )

    assert fp1 == fp2
    assert len(fp1) == 64  # SHA-256


def test_test_fingerprint_variance():
    fp_base = generate_test_fingerprint("example.com", "/api", "GET", "id", "sqli")
    fp_diff_param = generate_test_fingerprint("example.com", "/api", "GET", "username", "sqli")
    fp_diff_method = generate_test_fingerprint("example.com", "/api", "POST", "id", "sqli")
    fp_diff_cat = generate_test_fingerprint("example.com", "/api", "GET", "id", "xss")

    assert fp_base != fp_diff_param
    assert fp_base != fp_diff_method
    assert fp_base != fp_diff_cat


def test_finding_deduplication():
    existing_findings = [
        {
            "finding_id": "BB-2026-001",
            "affected_asset": "api.example.com",
            "affected_endpoint": "/api/v1/profile",
            "vulnerability_type": "BOLA / IDOR",
            "root_cause": "Missing tenant ownership check on user_id parameter",
        }
    ]

    # Test candidate with same asset, endpoint, and vuln class
    is_dup, dup_id = FindingDeduplicator.check_duplicate(
        candidate_asset="API.EXAMPLE.COM",
        candidate_endpoint="/api/v1/profile/",
        candidate_vuln="BOLA / IDOR",
        candidate_root_cause="Missing tenant ownership check on user_id parameter",
        existing_findings=existing_findings,
    )
    assert is_dup is True
    assert dup_id == "BB-2026-001"

    # Distinct issue on different endpoint
    is_dup2, dup_id2 = FindingDeduplicator.check_duplicate(
        candidate_asset="api.example.com",
        candidate_endpoint="/api/v1/documents",
        candidate_vuln="BOLA / IDOR",
        candidate_root_cause="Missing ownership check on document_id",
        existing_findings=existing_findings,
    )
    assert is_dup2 is False
    assert dup_id2 is None
