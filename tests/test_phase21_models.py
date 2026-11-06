"""
Tests for Phase 21 Core Models: CorrelatedPrincipalContext, CorrelatedSessionContext,
CorrelationHypothesis, and CorrelationFinding.
"""

import math
import pytest

from framework.auth_correlation.model import (
    CorrelatedPrincipalContext,
    CorrelatedSessionContext,
    CorrelationHypothesis,
    CorrelationFinding,
    CorrelationLifecycle,
    ProbeStatus,
    SerializationSecurityError,
    StateSecurityValidationError,
)


def test_correlated_principal_context_valid():
    """Verifies valid creation, validation, and serialization of CorrelatedPrincipalContext."""
    principal = CorrelatedPrincipalContext(
        principal_id="user_admin_01",
        tenant_id="tenant_alpha",
        role="TENANT_ADMIN",
        privilege_level=80,
        verification_status="VERIFIED",
        evidence_refs=["EVID-0123456789ab"],
        confidence=0.95,
    )
    data = principal.validate()
    assert data["principal_id"] == "user_admin_01"
    assert data["tenant_id"] == "tenant_alpha"
    assert data["role"] == "TENANT_ADMIN"
    assert data["privilege_level"] == 80
    assert data["verification_status"] == "VERIFIED"
    assert data["evidence_refs"] == ["EVID-0123456789ab"]
    assert data["confidence"] == 0.95
    assert principal.to_dict() == data

    # Safe representation check
    rep = repr(principal)
    assert "user_admin_01" in rep
    assert "TENANT_ADMIN" in rep
    assert "VERIFIED" in rep
    assert str(principal) == rep


def test_correlated_principal_type_and_boundary_checks():
    """Verifies strict type enforcement on privilege_level and confidence."""
    # Boolean rejected for privilege_level
    p_bool = CorrelatedPrincipalContext(principal_id="u1", role="USER", privilege_level=True)
    with pytest.raises(SerializationSecurityError, match="must be an integer"):
        p_bool.validate()

    # Out of range privilege_level
    p_neg = CorrelatedPrincipalContext(principal_id="u1", role="USER", privilege_level=-1)
    with pytest.raises(SerializationSecurityError, match="minimum permitted bound"):
        p_neg.validate()

    p_high = CorrelatedPrincipalContext(principal_id="u1", role="USER", privilege_level=101)
    with pytest.raises(SerializationSecurityError, match="maximum permitted bound"):
        p_high.validate()

    # Confidence strictness: boolean, NaN, inf rejected
    for bad_conf in [True, False, float("nan"), float("inf"), -0.1, 1.1]:
        p_bad_conf = CorrelatedPrincipalContext(principal_id="u1", role="USER", confidence=bad_conf)
        with pytest.raises(SerializationSecurityError):
            p_bad_conf.validate()

    # Invalid verification_status
    p_bad_vs = CorrelatedPrincipalContext(principal_id="u1", role="USER", verification_status="INVALID_STATUS")
    with pytest.raises(SerializationSecurityError):
        p_bad_vs.validate()


def test_correlated_session_context_valid():
    """Verifies valid CorrelatedSessionContext creation and serialization."""
    session = CorrelatedSessionContext(
        session_ref="sess_0123456789abcdef0123456789abcdef",
        principal_id="user_admin_01",
        volatile_headers={"Authorization": "Bearer sensitive_token"},
        hmac_fingerprint="0123456789abcdef0123456789abcdef",
        lifecycle=CorrelationLifecycle.VERIFIED,
        expires_at="2026-11-06T20:00:00Z",
        verified_at="2026-11-06T19:00:00Z",
        metadata={
            "token_type": "BEARER",
            "preflight_endpoint": "/api/v1/health",
            "is_test_account": True,
            "tenant_id": "tenant_alpha",
            "observed_role": "ADMIN",
            "claim_keys": ["sub", "role", "exp"],
        },
    )
    data = session.validate()
    assert data["session_ref"] == "sess_0123456789abcdef0123456789abcdef"
    assert data["principal_id"] == "user_admin_01"
    assert data["hmac_fingerprint"] == "0123456789abcdef0123456789abcdef"
    assert data["lifecycle"] == "VERIFIED"
    assert "Authorization" not in data
    assert "volatile_headers" not in data
    assert session.to_dict() == data

    # volatile_headers must be repr=False
    rep = repr(session)
    assert "sensitive_token" not in rep
    assert "Authorization" not in rep
    assert "sess_0123456789abcdef0123456789abcdef" in rep
    assert str(session) == rep


def test_correlated_session_metadata_allowlist():
    """Verifies that unapproved metadata keys fail closed."""
    session = CorrelatedSessionContext(
        session_ref="sess_0123456789abcdef0123456789abcdef",
        principal_id="user_admin_01",
        metadata={"token_type": "BEARER", "unapproved_custom_field": "leak"},
    )
    with pytest.raises(SerializationSecurityError, match="Rejected unapproved metadata keys"):
        session.validate()


def test_correlation_hypothesis_valid():
    """Verifies valid creation and validation of CorrelationHypothesis."""
    hyp = CorrelationHypothesis(
        hypothesis_id="HYP-TENANT-001",
        category="TENANT_ISOLATION",
        target_endpoint="/api/v1/tenant/data",
        principal_a_id="user_tenant_a",
        principal_b_id="user_tenant_b",
        preflight_status=CorrelationLifecycle.VERIFIED,
        expected_result="ISOLATED",
        validation_status="PENDING",
    )
    data = hyp.validate()
    assert data["hypothesis_id"] == "HYP-TENANT-001"
    assert data["category"] == "TENANT_ISOLATION"
    assert data["target_endpoint"] == "/api/v1/tenant/data"
    assert data["principal_a_id"] == "user_tenant_a"
    assert data["principal_b_id"] == "user_tenant_b"
    assert data["preflight_status"] == "VERIFIED"
    assert data["expected_result"] == "ISOLATED"
    assert data["validation_status"] == "PENDING"
    assert hyp.to_dict() == data

    rep = repr(hyp)
    assert "HYP-TENANT-001" in rep
    assert "TENANT_ISOLATION" in rep
    assert "ISOLATED" in rep
    assert str(hyp) == rep


def test_correlation_hypothesis_invalid_fields():
    """Verifies rejection of invalid categories, endpoints, and expectations."""
    # Invalid category
    h1 = CorrelationHypothesis(
        hypothesis_id="HYP-01",
        category="INVALID_CAT",
        target_endpoint="/api/test",
        principal_a_id="pa",
        principal_b_id="pb",
    )
    with pytest.raises(SerializationSecurityError):
        h1.validate()

    # Invalid endpoint (non-URL path)
    h2 = CorrelationHypothesis(
        hypothesis_id="HYP-01",
        category="TENANT_ISOLATION",
        target_endpoint="http://external.com/evil",
        principal_a_id="pa",
        principal_b_id="pb",
    )
    with pytest.raises(SerializationSecurityError):
        h2.validate()

    # Invalid expected_result
    h3 = CorrelationHypothesis(
        hypothesis_id="HYP-01",
        category="TENANT_ISOLATION",
        target_endpoint="/api/test",
        principal_a_id="pa",
        principal_b_id="pb",
        expected_result="UNKNOWN_EXPECTATION",
    )
    with pytest.raises(SerializationSecurityError):
        h3.validate()


def test_correlation_finding_valid_and_native_conversion():
    """Verifies CorrelationFinding validation and conversion to native Finding."""
    finding = CorrelationFinding(
        finding_id="FIND-TENANT-001",
        title="Cross-Tenant Boundary Bypass via IDOR",
        category="TENANT_BOUNDARY_BYPASS",
        severity="HIGH",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        confidence=0.9,
        endpoint="/api/v1/tenant/orders",
        description="Tenant A session successfully accessed Tenant B orders through IDOR substitution.",
        evidence_chain=["EVID-0123456789ab", "EVID-abcdef012345"],
    )
    data = finding.validate()
    assert data["finding_id"] == "FIND-TENANT-001"
    assert data["cvss_score"] == 7.5
    assert data["confidence"] == 0.9
    assert len(data["evidence_chain"]) == 2

    # Safe repr strictly omits title, description, and evidence chain
    rep = repr(finding)
    assert "Cross-Tenant" not in rep
    assert "Tenant A session" not in rep
    assert "EVID-" not in rep
    assert "FIND-TENANT-001" in rep
    assert "TENANT_BOUNDARY_BYPASS" in rep
    assert str(finding) == rep

    # Test conversion to framework.findings.schema.Finding
    native = finding.to_native_finding()
    assert native.finding_id == "FIND-TENANT-001"
    assert native.title == "Cross-Tenant Boundary Bypass via IDOR"
    assert native.severity == "HIGH"
    assert native.confidence == "HIGH"
    assert len(native.evidence) == 2
