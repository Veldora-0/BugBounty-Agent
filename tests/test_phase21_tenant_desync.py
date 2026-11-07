"""
Tests for Phase 21 MultiTenantDesyncValidator.

Verifies:
- Bidirectional baseline establishment (ground truth)
- Multi-channel parameter substitution with unaltered dual tokens
- Three-state cache assessment engine (CONFIRMED, NOT_INDICATED, UNKNOWN)
- Elimination of reverse-proxy cache false-positive findings
- Authentic CVSS 3.1 scoring on TENANT_BOUNDARY_BYPASS findings
"""

import pytest

from framework.auth_correlation.model import (
    CorrelatedSessionContext,
    CorrelationFinding,
)
from framework.auth_correlation.tenant import MultiTenantDesyncValidator
from framework.authz.model import ResourceAccessTarget
from framework.validation.request import ControlledRequest, ControlledResponse


class MockTenantValidationEngine:
    def __init__(self, routes: Dict[str, ControlledResponse]):
        self.routes = routes
        self.dispatched: list[ControlledRequest] = []

    def send_request(self, req: ControlledRequest) -> ControlledResponse:
        self.dispatched.append(req)
        auth = req.headers.get("Authorization", "ANON")
        key = f"{req.url}|{auth}"
        if key in self.routes:
            return self.routes[key]
        for pattern, resp in self.routes.items():
            if pattern in req.url:
                return resp
        return ControlledResponse(404, {}, b'{"error": "Not Found"}')


def test_three_state_cache_assessment():
    """Verifies that assess_cache_state accurately categorizes cache states."""
    validator = MultiTenantDesyncValidator()

    # 1. CACHE_CONFIRMED
    resp_age = ControlledResponse(200, {"Age": "120"}, b"data")
    assert validator.assess_cache_state(resp_age) == "CACHE_CONFIRMED"

    resp_cf = ControlledResponse(200, {"cf-cache-status": "HIT"}, b"data")
    assert validator.assess_cache_state(resp_cf) == "CACHE_CONFIRMED"

    resp_xcache = ControlledResponse(200, {"X-Cache": "HIT from proxy"}, b"data")
    assert validator.assess_cache_state(resp_xcache) == "CACHE_CONFIRMED"

    # 2. CACHE_NOT_INDICATED
    resp_nostore = ControlledResponse(200, {"cache-control": "no-store, must-revalidate"}, b"data")
    assert validator.assess_cache_state(resp_nostore) == "CACHE_NOT_INDICATED"

    resp_miss = ControlledResponse(200, {"cf-cache-status": "DYNAMIC"}, b"data")
    assert validator.assess_cache_state(resp_miss) == "CACHE_NOT_INDICATED"

    # 3. CACHE_UNKNOWN
    resp_unknown = ControlledResponse(200, {"content-type": "application/json"}, b"data")
    assert validator.assess_cache_state(resp_unknown) == "CACHE_UNKNOWN"


def test_bidirectional_baselines_enforced():
    """Verifies that cross-tenant testing aborts if either tenant baseline access fails."""
    url_a = "https://target.local/api/v1/tenants/t_a/orders"
    url_b = "https://target.local/api/v1/tenants/t_b/orders"

    # Engine where Tenant B baseline fails (403)
    engine = MockTenantValidationEngine({
        f"{url_a}|Bearer tok_a": ControlledResponse(200, {}, b'{"orders": [1, 2, 3]}'),
        f"{url_b}|Bearer tok_b": ControlledResponse(403, {}, b'{"error": "Forbidden"}'),
    })
    validator = MultiTenantDesyncValidator(validation_engine=engine)
    sess_a = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u_a", volatile_headers={"Authorization": "Bearer tok_a"})
    sess_b = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000002", principal_id="u_b", volatile_headers={"Authorization": "Bearer tok_b"})
    res_a = ResourceAccessTarget(resource_id="res_a", resource_type="ORDERS", endpoint=url_a)
    res_b = ResourceAccessTarget(resource_id="res_b", resource_type="ORDERS", endpoint=url_b)

    findings = validator.evaluate_tenant_isolation(sess_a, sess_b, res_a, res_b)
    # Aborts with zero findings; never infers isolation or vulnerability from failed baseline
    assert len(findings) == 0


def test_tenant_boundary_enforced_secure():
    """Verifies that 401/403/404 on cross-tenant probes represents secure isolation."""
    url_a = "https://target.local/api/v1/tenants/t_a/orders"
    url_b = "https://target.local/api/v1/tenants/t_b/orders"

    engine = MockTenantValidationEngine({
        f"{url_a}|Bearer tok_a": ControlledResponse(200, {}, b'{"orders": ["A1", "A2"]}'),
        f"{url_b}|Bearer tok_b": ControlledResponse(200, {}, b'{"orders": ["B1", "B2"]}'),
        f"{url_b}|Bearer tok_a": ControlledResponse(403, {}, b'{"error": "Cross-tenant access forbidden"}'),
        f"{url_a}|Bearer tok_b": ControlledResponse(403, {}, b'{"error": "Cross-tenant access forbidden"}'),
    })
    validator = MultiTenantDesyncValidator(validation_engine=engine)
    sess_a = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u_a", volatile_headers={"Authorization": "Bearer tok_a"})
    sess_b = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000002", principal_id="u_b", volatile_headers={"Authorization": "Bearer tok_b"})
    res_a = ResourceAccessTarget(resource_id="res_a", resource_type="ORDERS", endpoint=url_a)
    res_b = ResourceAccessTarget(resource_id="res_b", resource_type="ORDERS", endpoint=url_b)

    findings = validator.evaluate_tenant_isolation(sess_a, sess_b, res_a, res_b)
    assert len(findings) == 0


def test_tenant_boundary_bypass_detected():
    """Verifies that cross-tenant access to Resource B by Tenant A emits TENANT_BOUNDARY_BYPASS."""
    url_a = "https://target.local/api/v1/tenants/t_a/orders"
    url_b = "https://target.local/api/v1/tenants/t_b/orders"
    orders_b_payload = b'{"tenant": "t_b", "orders": [{"id": 201, "total": 999.50}]}'

    engine = MockTenantValidationEngine({
        f"{url_a}|Bearer tok_a": ControlledResponse(200, {}, b'{"tenant": "t_a", "orders": []}'),
        f"{url_b}|Bearer tok_b": ControlledResponse(200, {}, orders_b_payload),
        # Vulnerability: Tenant A token returns Tenant B data!
        f"{url_b}|Bearer tok_a": ControlledResponse(200, {"cache-control": "no-store"}, orders_b_payload),
        f"{url_a}|Bearer tok_b": ControlledResponse(403, {}, b'{"error": "Forbidden"}'),
    })
    validator = MultiTenantDesyncValidator(validation_engine=engine)
    sess_a = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u_a", volatile_headers={"Authorization": "Bearer tok_a"})
    sess_b = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000002", principal_id="u_b", volatile_headers={"Authorization": "Bearer tok_b"})
    res_a = ResourceAccessTarget(resource_id="res_a", resource_type="ORDERS", endpoint=url_a)
    res_b = ResourceAccessTarget(resource_id="res_b", resource_type="ORDERS", endpoint=url_b)

    findings = validator.evaluate_tenant_isolation(sess_a, sess_b, res_a, res_b)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "TENANT_BOUNDARY_BYPASS"
    assert f.severity == "HIGH"
    assert f.cvss_score == 8.1
    assert f.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    assert f.confidence == 0.95


def test_cache_hit_false_positive_elimination():
    """Verifies that a cached 200 OK response with CACHE_CONFIRMED is busted and eliminated."""
    url_a = "https://target.local/api/v1/tenants/t_a/orders"
    url_b = "https://target.local/api/v1/tenants/t_b/orders"
    orders_b_payload = b'{"tenant": "t_b", "orders": [{"id": 201}]}'

    engine = MockTenantValidationEngine({
        f"{url_a}|Bearer tok_a": ControlledResponse(200, {}, b'{"tenant": "t_a", "orders": []}'),
        f"{url_b}|Bearer tok_b": ControlledResponse(200, {}, orders_b_payload),
        # Initial cross-probe returns cached 200 OK
        f"{url_b}|Bearer tok_a": ControlledResponse(200, {"CF-Cache-Status": "HIT", "Age": "300"}, orders_b_payload),
        # Cache-busted probe returns true backend status: 403 Forbidden!
        "_bb_cb": ControlledResponse(403, {}, b'{"error": "Forbidden"}'),
        f"{url_a}|Bearer tok_b": ControlledResponse(403, {}, b'{"error": "Forbidden"}'),
    })
    validator = MultiTenantDesyncValidator(validation_engine=engine)
    sess_a = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u_a", volatile_headers={"Authorization": "Bearer tok_a"})
    sess_b = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000002", principal_id="u_b", volatile_headers={"Authorization": "Bearer tok_b"})
    res_a = ResourceAccessTarget(resource_id="res_a", resource_type="ORDERS", endpoint=url_a)
    res_b = ResourceAccessTarget(resource_id="res_b", resource_type="ORDERS", endpoint=url_b)

    findings = validator.evaluate_tenant_isolation(sess_a, sess_b, res_a, res_b)
    # Zero findings recorded because cache busting confirmed it was a proxy cache artifact!
    assert len(findings) == 0


def test_query_channel_bidirectional_substitution():
    """Verifies that query-parameter channel is tested in both directions (A->B and B->A)."""
    url_a = "https://target.local/api/v1/orders"
    url_b = "https://target.local/api/v1/orders"
    data_b = b'{"tenant": "tenant_b", "invoices": [101]}'
    data_a = b'{"tenant": "tenant_a", "invoices": [202]}'

    class QueryMockEngine:
        def __init__(self):
            self.dispatched = []

        def send_request(self, req: ControlledRequest) -> ControlledResponse:
            self.dispatched.append(req)
            auth = req.headers.get("Authorization", "")
            if auth == "Bearer tok_a" and "tenant_id=tenant_b" in req.url:
                return ControlledResponse(200, {"cache-control": "no-store"}, data_b)
            if auth == "Bearer tok_b" and "tenant_id=tenant_a" in req.url:
                return ControlledResponse(200, {"cache-control": "no-store"}, data_a)
            if auth == "Bearer tok_a":
                return ControlledResponse(200, {}, data_a)
            if auth == "Bearer tok_b":
                return ControlledResponse(200, {}, data_b)
            return ControlledResponse(404, {}, b"Not Found")

    validator = MultiTenantDesyncValidator(validation_engine=QueryMockEngine())
    sess_a = CorrelatedSessionContext(
        session_ref="sess_00000000000000000000000000000001",
        principal_id="u_a",
        volatile_headers={"Authorization": "Bearer tok_a"},
        metadata={"tenant_id": "tenant_b"},  # Target B id
    )
    sess_b = CorrelatedSessionContext(
        session_ref="sess_00000000000000000000000000000002",
        principal_id="u_b",
        volatile_headers={"Authorization": "Bearer tok_b"},
        metadata={"tenant_id": "tenant_a"},  # Target A id
    )
    res_a = ResourceAccessTarget(resource_id="res_a", resource_type="ORDERS", endpoint=url_a)
    res_b = ResourceAccessTarget(resource_id="res_b", resource_type="ORDERS", endpoint=url_b)

    findings = validator.evaluate_tenant_isolation(sess_a, sess_b, res_a, res_b)
    query_findings = [f for f in findings if "QUERY" in f.title]
    assert len(query_findings) == 2


def test_header_channel_bidirectional_substitution():
    """Verifies that header channel (X-Tenant-ID) is tested in both directions (A->B and B->A)."""
    url_a = "https://target.local/api/v1/resource"
    url_b = "https://target.local/api/v1/resource"
    data_b = b'{"tenant": "tb", "secret": "b_records"}'
    data_a = b'{"tenant": "ta", "secret": "a_records"}'

    class HeaderMockEngine:
        def __init__(self):
            self.dispatched = []

        def send_request(self, req: ControlledRequest) -> ControlledResponse:
            self.dispatched.append(req)
            auth = req.headers.get("Authorization", "")
            x_tid = req.headers.get("X-Tenant-ID", "")
            if auth == "Bearer tok_a" and x_tid == "tb":
                return ControlledResponse(200, {"cache-control": "no-store"}, data_b)
            if auth == "Bearer tok_b" and x_tid == "ta":
                return ControlledResponse(200, {"cache-control": "no-store"}, data_a)
            if auth == "Bearer tok_a":
                return ControlledResponse(200, {}, data_a)
            if auth == "Bearer tok_b":
                return ControlledResponse(200, {}, data_b)
            return ControlledResponse(404, {}, b"Not Found")

    validator = MultiTenantDesyncValidator(validation_engine=HeaderMockEngine())
    sess_a = CorrelatedSessionContext(
        session_ref="sess_00000000000000000000000000000001",
        principal_id="u_a",
        volatile_headers={"Authorization": "Bearer tok_a"},
        metadata={"tenant_id": "ta"},
    )
    sess_b = CorrelatedSessionContext(
        session_ref="sess_00000000000000000000000000000002",
        principal_id="u_b",
        volatile_headers={"Authorization": "Bearer tok_b"},
        metadata={"tenant_id": "tb"},
    )
    res_a = ResourceAccessTarget(resource_id="res_a", resource_type="DATA", endpoint=url_a)
    res_b = ResourceAccessTarget(resource_id="res_b", resource_type="DATA", endpoint=url_b)

    findings = validator.evaluate_tenant_isolation(sess_a, sess_b, res_a, res_b)
    header_findings = [f for f in findings if "HEADER" in f.title]
    assert len(header_findings) == 2


def test_cache_unknown_and_cache_busting_corroboration():
    """Verifies that CACHE_UNKNOWN produces findings ONLY when corroborated by cache-busting."""
    url_a = "https://target.local/api/v1/orders"
    url_b = "https://target.local/api/v1/tenants/b/orders"
    data_b = b'{"tenant": "b", "items": ["item1"]}'

    # Case 1: CACHE_UNKNOWN where cache busting corroborates 200 OK with data_b
    class CorroboratedEngine:
        def send_request(self, req: ControlledRequest) -> ControlledResponse:
            if "_bb_cb" in req.url:
                # Corroborating dynamic probe returns 200 with data_b
                return ControlledResponse(200, {}, data_b)
            auth = req.headers.get("Authorization", "")
            if auth == "Bearer tok_a" and url_b in req.url:
                # Ambiguous headers: CACHE_UNKNOWN
                return ControlledResponse(200, {"content-type": "application/json"}, data_b)
            if auth == "Bearer tok_a":
                return ControlledResponse(200, {}, b'{"tenant": "a"}')
            if auth == "Bearer tok_b":
                return ControlledResponse(200, {}, data_b)
            return ControlledResponse(404, {}, b"Not Found")

    validator = MultiTenantDesyncValidator(validation_engine=CorroboratedEngine())
    sess_a = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000001", principal_id="u_a", volatile_headers={"Authorization": "Bearer tok_a"})
    sess_b = CorrelatedSessionContext(session_ref="sess_00000000000000000000000000000002", principal_id="u_b", volatile_headers={"Authorization": "Bearer tok_b"})
    res_a = ResourceAccessTarget(resource_id="res_a", resource_type="ORDERS", endpoint=url_a)
    res_b = ResourceAccessTarget(resource_id="res_b", resource_type="ORDERS", endpoint=url_b)

    findings = validator.evaluate_tenant_isolation(sess_a, sess_b, res_a, res_b)
    assert len(findings) >= 1
    f = findings[0]
    assert "Corroborated via cache-busting probe" in f.description
    assert "Cache state: CACHE_UNKNOWN" in f.description
    assert len(f.evidence_chain) >= 1
    assert all(ev.startswith("EVID-") for ev in f.evidence_chain)

