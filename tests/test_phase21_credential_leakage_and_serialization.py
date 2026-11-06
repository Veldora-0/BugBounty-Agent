"""
Security tests for Phase 21: Proves rejection of credential leakage, strict allowlisting,
safe object representations, and fail-closed validation on all models.
"""

import math
import pytest

from framework.auth_correlation.model import (
    CorrelatedPrincipalContext,
    CorrelatedSessionContext,
    CorrelationHypothesis,
    CorrelationFinding,
    CorrelationLifecycle,
    SerializationSecurityError,
)


class ExploitObject:
    """Deliberately malicious test object designed to leak secrets via __str__ or __repr__."""
    def __init__(self, payload: str):
        self.payload = payload

    def __str__(self) -> str:
        return f"leak_str_{self.payload}"

    def __repr__(self) -> str:
        return f"leak_repr_{self.payload}"


def test_hypothesis_repr_and_str_with_malicious_objects():
    """Verifies that CorrelationHypothesis never invokes __str__ or __repr__ on malicious objects."""
    h = CorrelationHypothesis(
        hypothesis_id="HYP-001",
        category="TENANT_ISOLATION",
        target_endpoint="/api/v1/test",
        principal_a_id="usr_a",
        principal_b_id="usr_b",
        expected_result=ExploitObject("bearer_token_secret"),
        preflight_status=ExploitObject("evil_lifecycle_obj"),
    )
    # Neither __str__ nor __repr__ of ExploitObject may ever be called
    h_repr = repr(h)
    h_str = str(h)
    assert "leak_str" not in h_repr and "leak_repr" not in h_repr
    assert "leak_str" not in h_str and "leak_repr" not in h_str
    assert "[UNVALIDATED_EXPECTED_RESULT]" in h_repr
    assert "[UNVALIDATED_LIFECYCLE]" in h_repr

    # Validate fail-closed exception without echoing malicious object
    with pytest.raises(SerializationSecurityError) as exc_info:
        h.validate()
    assert "leak" not in str(exc_info.value)


def test_session_repr_and_str_with_unexpected_lifecycle_objects():
    """Verifies that CorrelatedSessionContext never invokes __str__ or __repr__ on unexpected lifecycle objects."""
    s = CorrelatedSessionContext(
        session_ref="sess_0123456789abcdef0123456789abcdef",
        principal_id="usr_a",
        lifecycle=ExploitObject("secret_session_token"),
    )
    s_repr = repr(s)
    s_str = str(s)
    assert "leak_str" not in s_repr and "leak_repr" not in s_repr
    assert "leak_str" not in s_str and "leak_repr" not in s_str
    assert "[UNVALIDATED_LIFECYCLE]" in s_repr

    with pytest.raises(SerializationSecurityError) as exc_info:
        s.validate()
    assert "leak" not in str(exc_info.value)


def test_principal_repr_and_str_with_malicious_objects():
    """Verifies that CorrelatedPrincipalContext never leaks malicious attributes in repr or str."""
    p = CorrelatedPrincipalContext(
        principal_id=ExploitObject("secret_principal_token"),
        role=ExploitObject("secret_role_payload"),
        verification_status=ExploitObject("secret_status_payload"),
    )
    p_repr = repr(p)
    p_str = str(p)
    assert "leak_str" not in p_repr and "leak_repr" not in p_repr
    assert "leak_str" not in p_str and "leak_repr" not in p_str
    assert "[UNVALIDATED_PRINCIPAL_ID]" in p_repr
    assert "[UNVALIDATED_ROLE]" in p_repr
    assert "[UNVALIDATED_STATUS]" in p_repr

    with pytest.raises(SerializationSecurityError) as exc_info:
        p.validate()
    assert "leak" not in str(exc_info.value)


def test_finding_repr_and_str_with_sensitive_strings():
    """Verifies that CorrelationFinding.__repr__ never exposes title, description, or evidence."""
    f = CorrelationFinding(
        finding_id="FIND-001",
        title="Super Secret Internal Key Leaked in Response",
        category="TENANT_BOUNDARY_BYPASS",
        severity="HIGH",
        cvss_score=8.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        confidence=0.9,
        endpoint="/api/v1/resource",
        description="Detailed sensitive payload: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        evidence_chain=["EVID-123456789abc"],
    )
    f_repr = repr(f)
    f_str = str(f)
    assert "Super Secret" not in f_repr
    assert "eyJhbGci" not in f_repr
    assert "EVID-123456789abc" not in f_repr
    assert "Super Secret" not in f_str
    assert "eyJhbGci" not in f_str
    assert "EVID-123456789abc" not in f_str


def test_disguised_credentials_rejected_in_identifiers():
    """Verifies that credential indicator keywords in string fields trigger fail-closed rejection."""
    credential_payloads = [
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "tok_live_secret1234567890abcdef",
        "phpsessid=123456789abcdef",
        "api_key=abcdef1234567890",
        "password=SecretPassword123!",
    ]
    for cred in credential_payloads:
        # In principal_id
        with pytest.raises(SerializationSecurityError, match="Disguised credential detected"):
            CorrelatedPrincipalContext(principal_id=cred, role="USER").validate()

        # In role
        with pytest.raises(SerializationSecurityError, match="Disguised credential detected"):
            CorrelatedPrincipalContext(principal_id="user1", role=cred).validate()

        # In target_endpoint
        with pytest.raises(SerializationSecurityError, match="Disguised credential detected"):
            CorrelationHypothesis(
                hypothesis_id="HYP-01",
                category="TENANT_ISOLATION",
                target_endpoint=f"/api/v1?token={cred}",
                principal_a_id="pa",
                principal_b_id="pb",
            ).validate()


def test_high_entropy_token_rejected_in_free_text():
    """Verifies that finding titles and descriptions reject high-entropy token blocks."""
    high_entropy_hex = "4f8a3c9b2d1e0f7a6b5c4d3e2f1a0b9c"
    
    # In title
    f_bad_title = CorrelationFinding(
        finding_id="FIND-01",
        title=f"Bypass with token {high_entropy_hex}",
        category="TENANT_BOUNDARY_BYPASS",
        severity="HIGH",
        cvss_score=7.0,
        cvss_vector=None,
        confidence=0.8,
        endpoint="/api/test",
        description="Clean description",
    )
    with pytest.raises(SerializationSecurityError, match="high-entropy token"):
        f_bad_title.validate()

    # In description
    f_bad_desc = CorrelationFinding(
        finding_id="FIND-01",
        title="Valid Finding Title",
        category="TENANT_BOUNDARY_BYPASS",
        severity="HIGH",
        cvss_score=7.0,
        cvss_vector=None,
        confidence=0.8,
        endpoint="/api/test",
        description=f"Leaked raw token: {high_entropy_hex}",
    )
    with pytest.raises(SerializationSecurityError, match="high-entropy token"):
        f_bad_desc.validate()


def test_exception_messages_never_echo_rejected_input():
    """Verifies that exception messages never reflect rejected input values or untrusted keys."""
    secret_marker = "SENSITIVE_SECRET_MARKER_98765"
    with pytest.raises(SerializationSecurityError) as exc_info:
        CorrelatedPrincipalContext(principal_id=f"bad_id_{secret_marker}!!!").validate()
    
    err_msg = str(exc_info.value)
    assert secret_marker not in err_msg
    assert "[REDACTED]" in err_msg or "failed schema pattern" in err_msg
