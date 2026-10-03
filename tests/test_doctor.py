"""
Tests for SystemDoctor diagnostics across all 9 categories.
"""

from framework.tools.doctor import SystemDoctor


def test_doctor_full_diagnosis():
    doctor = SystemDoctor()
    diag = doctor.run_full_diagnosis()

    # Must contain all 9 required categories
    required_categories = [
        "system",
        "dependencies",
        "tools",
        "providers",
        "browser",
        "wordlists",
        "configuration",
        "scope_engine",
        "opencode_integration",
    ]

    for cat in required_categories:
        assert cat in diag, f"Category '{cat}' missing from doctor diagnostics"


def test_doctor_scope_engine_check():
    doctor = SystemDoctor()
    scope_diag = doctor.check_scope_engine()
    assert scope_diag["healthy"] is True
    assert scope_diag["status"] == "HEALTHY"


def test_doctor_opencode_integration_check():
    doctor = SystemDoctor()
    opencode_diag = doctor.check_opencode_integration()
    assert opencode_diag["opencode_jsonc"] is True
    assert opencode_diag["agent_count"] >= 14
    assert opencode_diag["skill_count"] >= 14
    assert opencode_diag["status"] == "READY"
