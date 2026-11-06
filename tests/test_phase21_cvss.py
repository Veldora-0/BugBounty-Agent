"""
Tests for Phase 21 CVSS 3.1 Base Score Calculator.

Verifies calculation accuracy across all 10 FIRST CVSS v3.1 reference vectors,
validation of base metrics, and zero-impact handling.
"""

import pytest

from framework.auth_correlation.cvss import (
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    CIAImpact,
    CVSS31Metrics,
    CVSS31Calculator,
    CVSSMetricValidationError,
)


def test_cvss_reference_vectors_ref01_to_ref10():
    """Validates CVSS31Calculator across all 10 FIRST reference vectors."""
    vectors = [
        # REF-01: Critical unauthenticated network
        (
            CVSS31Metrics(AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE, Scope.UNCHANGED, CIAImpact.HIGH, CIAImpact.HIGH, CIAImpact.HIGH),
            9.8, "CRITICAL", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        ),
        # REF-02: Tenant boundary bypass profile
        (
            CVSS31Metrics(AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.LOW, UserInteraction.NONE, Scope.UNCHANGED, CIAImpact.HIGH, CIAImpact.HIGH, CIAImpact.NONE),
            8.1, "HIGH", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
        ),
        # REF-03: Pre-MFA privilege leak profile
        (
            CVSS31Metrics(AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE, Scope.UNCHANGED, CIAImpact.HIGH, CIAImpact.NONE, CIAImpact.NONE),
            7.5, "HIGH", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        ),
        # REF-04: Session not invalidated profile
        (
            CVSS31Metrics(AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.LOW, UserInteraction.NONE, Scope.UNCHANGED, CIAImpact.LOW, CIAImpact.LOW, CIAImpact.NONE),
            5.4, "MEDIUM", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
        ),
        # REF-05: Scope changed multiplier
        (
            CVSS31Metrics(AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.LOW, UserInteraction.NONE, Scope.CHANGED, CIAImpact.HIGH, CIAImpact.HIGH, CIAImpact.NONE),
            9.6, "CRITICAL", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N"
        ),
        # REF-06: High AC, High PR, UI Required
        (
            CVSS31Metrics(AttackVector.NETWORK, AttackComplexity.HIGH, PrivilegesRequired.HIGH, UserInteraction.REQUIRED, Scope.UNCHANGED, CIAImpact.LOW, CIAImpact.NONE, CIAImpact.NONE),
            2.0, "LOW", "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
        ),
        # REF-07: Local attack vector
        (
            CVSS31Metrics(AttackVector.LOCAL, AttackComplexity.LOW, PrivilegesRequired.LOW, UserInteraction.NONE, Scope.UNCHANGED, CIAImpact.HIGH, CIAImpact.HIGH, CIAImpact.HIGH),
            7.8, "HIGH", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
        ),
        # REF-08: Physical attack vector
        (
            CVSS31Metrics(AttackVector.PHYSICAL, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE, Scope.UNCHANGED, CIAImpact.HIGH, CIAImpact.HIGH, CIAImpact.HIGH),
            6.8, "MEDIUM", "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        ),
        # REF-09: Adjacent attack vector
        (
            CVSS31Metrics(AttackVector.ADJACENT, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE, Scope.UNCHANGED, CIAImpact.HIGH, CIAImpact.HIGH, CIAImpact.HIGH),
            8.8, "HIGH", "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        ),
        # REF-10: Zero impact
        (
            CVSS31Metrics(AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE, Scope.UNCHANGED, CIAImpact.NONE, CIAImpact.NONE, CIAImpact.NONE),
            0.0, "NONE", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        ),
    ]

    for metrics, expected_score, expected_sev, expected_vec in vectors:
        score, sev, vec = CVSS31Calculator.calculate_base_score(metrics)
        assert score == expected_score, f"Score mismatch for {expected_vec}: got {score}, expected {expected_score}"
        assert sev == expected_sev, f"Severity mismatch for {expected_vec}: got {sev}, expected {expected_sev}"
        assert vec == expected_vec, f"Vector mismatch: got {vec}, expected {expected_vec}"


def test_cvss_metric_validation_failures():
    """Verifies that invalid or non-enum metrics raise CVSSMetricValidationError."""
    with pytest.raises(CVSSMetricValidationError, match="must be an instance of CVSS31Metrics"):
        CVSS31Calculator.validate_metrics("not_a_metric_object")

    # Mismatched metric types
    with pytest.raises(CVSSMetricValidationError, match="Invalid AttackVector"):
        CVSS31Calculator.validate_metrics(
            CVSS31Metrics("INVALID", AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE, Scope.UNCHANGED, CIAImpact.HIGH, CIAImpact.HIGH, CIAImpact.HIGH)
        )
