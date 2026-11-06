"""
Tests for Phase 21 AuthCorrelationEngine, LocalAuthCorrelationLab, and SimulationTransport.

Verifies:
- SimulationTransport boundary enforcement (numeric 127.0.0.1, exact port, http scheme)
- Hop-by-hop redirect verification (max 3 hops, external redirect rejection)
- LocalAuthCorrelationLab 6 deterministic scenarios (SCEN-01 to SCEN-06)
- AuthCorrelationEngine orchestration sequence, preflight gating, and tree rendering
"""

import pytest

from framework.auth_correlation.engine import AuthCorrelationEngine
from framework.auth_correlation.lab import (
    LocalAuthCorrelationLab,
    SimulationTransport,
    SecurityBoundaryViolationError,
)
from framework.auth_correlation.model import (
    CorrelatedPrincipalContext,
    CorrelatedSessionContext,
    CorrelationLifecycle,
)


def test_simulation_transport_boundary_enforcement():
    """Verifies that SimulationTransport rejects non-loopback hosts, IPv6, arbitrary ports, and non-http."""
    port = 8888
    transport = SimulationTransport(lab_port=port)

    # 1. Valid numeric loopback url
    transport.validate_target_url(f"http://127.0.0.1:{port}/api/test")

    # 2. Rejection of 'localhost'
    with pytest.raises(SecurityBoundaryViolationError, match="Only exact numeric '127.0.0.1' is permitted"):
        transport.validate_target_url(f"http://localhost:{port}/api/test")

    # 3. Rejection of IPv6 loopback
    with pytest.raises(SecurityBoundaryViolationError):
        transport.validate_target_url(f"http://[::1]:{port}/api/test")

    # 4. Rejection of external host
    with pytest.raises(SecurityBoundaryViolationError):
        transport.validate_target_url(f"http://example.com:{port}/api/test")

    # 5. Rejection of port mismatch
    with pytest.raises(SecurityBoundaryViolationError, match="Target port must strictly match"):
        transport.validate_target_url(f"http://127.0.0.1:9999/api/test")

    # 6. Rejection of HTTPS
    with pytest.raises(SecurityBoundaryViolationError, match="requires strictly 'http' scheme"):
        transport.validate_target_url(f"https://127.0.0.1:{port}/api/test")


def test_simulation_transport_redirect_isolation():
    """Verifies that SimulationTransport enforces hop limit and rejects external redirects."""
    lab = LocalAuthCorrelationLab()
    port = lab.start()
    try:
        transport = lab.get_transport()

        # External redirect attempt must fail closed
        with pytest.raises(SecurityBoundaryViolationError):
            transport.send_request("GET", f"http://127.0.0.1:{port}/redirect/external")

        # Hop count exceeding limit (> 3 hops) must raise error
        with pytest.raises(SecurityBoundaryViolationError, match="maximum redirect hop limit"):
            transport.send_request("GET", f"http://127.0.0.1:{port}/redirect/hop/1")
    finally:
        lab.stop()


def test_lab_six_scenarios():
    """Verifies all 6 deterministic simulation scenarios in LocalAuthCorrelationLab."""
    lab = LocalAuthCorrelationLab()
    port = lab.start()
    try:
        transport = lab.get_transport()

        # SCEN-01: Expired token returns 401, valid returns 200
        resp1_exp = transport.send_request("GET", f"http://127.0.0.1:{port}/scen01/profile", headers={"Authorization": "Bearer expired_token_b"})
        assert resp1_exp.status_code == 401

        resp1_val = transport.send_request("GET", f"http://127.0.0.1:{port}/scen01/profile", headers={"Authorization": "Bearer valid_token_a"})
        assert resp1_val.status_code == 200
        assert "Alice" in resp1_val.body_text

        # SCEN-02: Post-logout resource persistence
        resp2 = transport.send_request("GET", f"http://127.0.0.1:{port}/scen02/invoices/101")
        assert resp2.status_code == 200
        assert "Alice Corp" in resp2.body_text

        # SCEN-03: Post-password-change invalidation failure
        resp3 = transport.send_request("GET", f"http://127.0.0.1:{port}/scen03/user/settings")
        assert resp3.status_code == 200
        assert "bob@corp.local" in resp3.body_text

        # SCEN-04: Pre-MFA sensitive data exposure
        resp4 = transport.send_request("GET", f"http://127.0.0.1:{port}/scen04/profile", headers={"Authorization": "Bearer pre_mfa_token"})
        assert resp4.status_code == 200
        assert "123-45-6789" in resp4.body_text

        # SCEN-05: Multi-tenant route desynchronization
        resp5 = transport.send_request("GET", f"http://127.0.0.1:{port}/scen05/tenants/tenant_b/invoices/101", headers={"Authorization": "Bearer tok_a"})
        assert resp5.status_code == 200
        assert "tenant_b" in resp5.body_text

        # SCEN-06: Cache hit elimination
        resp6_cached = transport.send_request("GET", f"http://127.0.0.1:{port}/scen06/data")
        assert resp6_cached.status_code == 200
        assert resp6_cached.headers.get("cf-cache-status") == "HIT"

        resp6_busted = transport.send_request("GET", f"http://127.0.0.1:{port}/scen06/data?_bb_cb=123")
        assert resp6_busted.status_code == 403
    finally:
        lab.stop()


def test_auth_correlation_engine_orchestration(tmp_path):
    """Verifies complete orchestration, preflight gating, and tree rendering in AuthCorrelationEngine."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    engine = AuthCorrelationEngine(
        program_id="acme_security",
        workspace_root=str(workspace),
    )

    p_a = CorrelatedPrincipalContext(principal_id="alice", tenant_id="tenant_a", role="ADMIN")
    p_b = CorrelatedPrincipalContext(principal_id="bob", tenant_id="tenant_b", role="USER")
    engine.register_principal(p_a)
    engine.register_principal(p_b)

    s_a = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="alice", volatile_headers={"Authorization": "Bearer tok_a"})
    s_b = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000002", principal_id="bob", volatile_headers={"Authorization": "Bearer tok_b"})
    engine.register_session(s_a)
    engine.register_session(s_b)

    # 1. Candidate discovery
    candidates = engine.discover_candidates()
    assert len(candidates) >= 2

    # 2. Tree rendering
    tree_text = engine.render_tree()
    assert "Correlation Hierarchy: acme_security" in tree_text
    assert "alice" in tree_text
    assert "bob" in tree_text
    assert "sess_00000000000000000000000000000001" in tree_text

    # 3. Dry run execution
    res_dry = engine.run_correlation(dry_run=True)
    assert res_dry["status"] == "DRY_RUN_COMPLETED"
    assert res_dry["hypotheses_planned"] >= 2


def test_engine_preflight_only_execution(tmp_path):
    """Verifies that preflight_only=True evaluates session health and stops before active testing."""
    workspace = tmp_path / "ws_pre"
    workspace.mkdir()

    lab = LocalAuthCorrelationLab()
    port = lab.start()
    try:
        transport = lab.get_transport()
        engine = AuthCorrelationEngine(
            program_id="preflight_test",
            workspace_root=str(workspace),
            validation_engine=transport,
        )

        p_a = CorrelatedPrincipalContext(principal_id="alice", role="USER")
        p_b = CorrelatedPrincipalContext(principal_id="bob", role="USER")
        engine.register_principal(p_a)
        engine.register_principal(p_b)

        s_a = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="alice", volatile_headers={"Authorization": "valid_token_a"})
        s_b = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000002", principal_id="bob", volatile_headers={"Authorization": "valid_token_a"})
        engine.register_session(s_a)
        engine.register_session(s_b)

        res = engine.run_correlation(
            target_asset=f"http://127.0.0.1:{port}",
            preflight_only=True,
        )
        assert res["status"] == "PREFLIGHT_COMPLETED"
        assert res["total_hypotheses"] >= 2
        assert res["verified_hypotheses"] >= 2
        assert res["findings"] == []
    finally:
        lab.stop()


def test_engine_persistence_failure_fail_closed(tmp_path):
    """Verifies that persistence failure returns PERSISTENCE_FAILED and does not silently succeed."""
    workspace = tmp_path / "ws_fail"
    workspace.mkdir()

    engine = AuthCorrelationEngine(
        program_id="persistence_fail_prog",
        workspace_root=str(workspace),
    )

    p_a = CorrelatedPrincipalContext(principal_id="u1", role="USER")
    p_b = CorrelatedPrincipalContext(principal_id="u2", role="USER")
    engine.register_principal(p_a)
    engine.register_principal(p_b)

    s_a = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u1")
    s_b = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000002", principal_id="u2")
    engine.register_session(s_a)
    engine.register_session(s_b)

    def mock_save_fail(*args, **kwargs):
        raise IOError("Simulated disk write failure")

    engine.state_manager.save_state = mock_save_fail

    res = engine.run_correlation(target_asset="http://127.0.0.1:9999")
    assert res["status"] == "PERSISTENCE_FAILED"
    assert "Simulated disk write failure" in res["error"]


def test_engine_principal_session_resolution(tmp_path):
    """Verifies that hypotheses map to sessions by explicit principal_id rather than list index."""
    workspace = tmp_path / "ws_res"
    workspace.mkdir()

    engine = AuthCorrelationEngine(
        program_id="resolution_prog",
        workspace_root=str(workspace),
    )

    p1 = CorrelatedPrincipalContext(principal_id="p_charlie", role="USER")
    p2 = CorrelatedPrincipalContext(principal_id="p_diana", role="ADMIN")
    engine.register_principal(p1)
    engine.register_principal(p2)

    s_diana = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000002", principal_id="p_diana")
    s_charlie = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="p_charlie")
    # Registered in reverse order
    engine.register_session(s_diana)
    engine.register_session(s_charlie)

    assert engine.find_session_for_principal("p_charlie").session_ref == "sess_00000000000000000000000000000001"
    assert engine.find_session_for_principal("p_diana").session_ref == "sess_00000000000000000000000000000002"
    assert engine.find_session_for_principal("nonexistent") is None

