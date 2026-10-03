"""
Tests for Finding Schema, Lifecycle Transitions, and Report Generation.
"""

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


def test_finding_valid_creation():
    finding = Finding(
        title="BOLA on /api/v1/users/{id} Exposing PII",
        summary="User profile endpoint does not check authorization token against requested resource ID.",
        affected_asset="api.example.com",
        affected_endpoint="/api/v1/users/{id}",
        vulnerability_type="Broken Object Level Authorization (IDOR)",
        severity="HIGH",
        description="The endpoint accepts an integer ID and returns user profile details.",
        root_cause="Missing session owner verification before querying user record.",
        prerequisites="Standard low-privilege user account.",
        reproduction_steps=[
            "Authenticate as User A and observe user ID 101.",
            "Send GET /api/v1/users/102 with User A's Authorization token.",
            "Observe full profile and email of User B returned with 200 OK.",
        ],
        expected_result="HTTP 403 Forbidden or 404 Not Found.",
        observed_result="HTTP 200 OK with User B private record.",
        security_impact="Unauthorized access to arbitrary customer personal data.",
        remediation="Enforce authorization check comparing session user ID with requested resource owner.",
        scope_reference="api.example.com in targets.domains",
        confidence="CONFIRMED",
    )

    assert finding.finding_id.startswith("BB-")
    assert finding.lifecycle_state == FindingLifecycle.CANDIDATE

    # Test report generation
    report_md = finding.to_markdown_report()
    assert "## Summary" in report_md
    assert "## Reproduction Steps" in report_md
    assert "## Security Impact" in report_md
    assert "## Remediation" in report_md
    assert "## Scope Reference" in report_md or "Scope Reference" in report_md


def test_finding_validation_failures():
    # Missing required title
    with pytest.raises(FindingValidationError):
        Finding(
            title="",
            summary="Test",
            affected_asset="api.example.com",
            affected_endpoint="/api",
            vulnerability_type="IDOR",
            severity="HIGH",
            description="desc",
            root_cause="rc",
            prerequisites="pre",
            reproduction_steps=["step 1"],
            expected_result="exp",
            observed_result="obs",
            security_impact="imp",
            remediation="rem",
            scope_reference="scope",
        )

    # Invalid severity
    with pytest.raises(FindingValidationError):
        Finding(
            title="Valid Title",
            summary="Test",
            affected_asset="api.example.com",
            affected_endpoint="/api",
            vulnerability_type="IDOR",
            severity="SUPER_CRITICAL_EXTRA",  # Invalid
            description="desc",
            root_cause="rc",
            prerequisites="pre",
            reproduction_steps=["step 1"],
            expected_result="exp",
            observed_result="obs",
            security_impact="imp",
            remediation="rem",
            scope_reference="scope",
        )


def test_lifecycle_state_transitions():
    # Legal transitions:
    # OBSERVATION -> CANDIDATE
    validate_transition(FindingLifecycle.OBSERVATION, FindingLifecycle.CANDIDATE)
    # CANDIDATE -> VALIDATED
    validate_transition(FindingLifecycle.CANDIDATE, FindingLifecycle.VALIDATED)
    # CANDIDATE -> REJECTED
    validate_transition(FindingLifecycle.CANDIDATE, FindingLifecycle.REJECTED)

    # Illegal transition:
    # OBSERVATION cannot jump directly to VALIDATED
    with pytest.raises(InvalidLifecycleTransition):
        validate_transition(FindingLifecycle.OBSERVATION, FindingLifecycle.VALIDATED)


def test_finding_serialization():
    f = Finding(
        title="Test Finding",
        summary="Summary text",
        affected_asset="target.com",
        affected_endpoint="/path",
        vulnerability_type="XSS",
        severity="MEDIUM",
        description="Description",
        root_cause="Improper encoding",
        prerequisites="None",
        reproduction_steps=["Step 1"],
        expected_result="Safe rendering",
        observed_result="Payload executed",
        security_impact="Session hijacking risk",
        remediation="Use context-aware escaping",
        scope_reference="target.com",
    )

    d = f.to_dict()
    f2 = Finding.from_dict(d)
    assert f2.title == f.title
    assert f2.severity == "MEDIUM"
    assert f2.lifecycle_state == FindingLifecycle.CANDIDATE
