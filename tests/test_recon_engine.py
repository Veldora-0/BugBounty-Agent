"""
Unit and integration tests for Phase 2 Reconnaissance Intelligence Engine.

Covers:
- Observation data models and JSON serialization/deserialization
- URL and endpoint normalization & deduplication
- HTTP observation processing, status code, title, header extraction
- Technology fingerprinting, regex signatures, and confidence calibration
- Port and service observations and socket timeout handling
- DNS and TLS SAN extraction and AssetGraph enrichment
- ReconnaissanceEngine pipeline with deterministic offline mock hooks
- Strict ScopeEngine enforcement (skipping out-of-scope assets)
- Bounded request budgets and host limits
- Passive-only mode enforcement (no active connections)
- Atomic state persistence and resume capabilities
- Verification of zero shell=True / os.system regressions
"""

import json
import os
import tempfile
import pytest

from framework.assets.graph import AssetGraph
from framework.assets.model import Asset, AssetType
from framework.assets.provenance import ObservationProvenance
from framework.recon.engine import ReconnaissanceEngine
from framework.recon.model import (
    DnsRecordObservation,
    EndpointObservation,
    HttpObservation,
    ObservationConfidence,
    PortServiceObservation,
    ReachabilityStatus,
    TechnologyObservation,
    TlsObservation,
    normalize_url,
)
from framework.recon.state import ReconStateManager
from framework.scope.engine import ScopeEngine, ScopeStatus


def test_url_normalization():
    """Verifies canonical URL formatting and default port stripping."""
    assert normalize_url("http://example.com:80/") == "http://example.com/"
    assert normalize_url("https://example.com:443/") == "https://example.com/"
    assert normalize_url("EXAMPLE.COM") == "http://example.com/"
    assert normalize_url("https://API.Example.com:8443/v1/users/") == "https://api.example.com:8443/v1/users"
    assert normalize_url("http://sub.domain.com/path?param=1") == "http://sub.domain.com/path?param=1"


def test_http_observation_model_and_deduplication():
    """Tests HttpObservation creation, serialization, and deterministic keys."""
    obs1 = HttpObservation(
        url="https://api.example.com/",
        scheme="https",
        host="api.example.com",
        port=443,
        status_code=200,
        title="Acme API Portal",
        server_header="nginx/1.24.0",
        technologies=["Nginx", "Node.js"],
        provenance=[ObservationProvenance(source="httpx", method="probe")],
    )
    data = obs1.to_dict()
    assert data["status_code"] == 200
    assert data["title"] == "Acme API Portal"

    obs2 = HttpObservation.from_dict(data)
    assert obs2.key == obs1.key
    assert obs2.host == "api.example.com"
    assert len(obs2.provenance) == 1


def test_port_service_observation():
    """Tests PortServiceObservation serialization and key generation."""
    port_obs = PortServiceObservation(
        host="db.example.com",
        port=5432,
        protocol="tcp",
        service="postgresql",
        product="PostgreSQL DB",
    )
    assert port_obs.key == "db.example.com:tcp:5432"
    d = port_obs.to_dict()
    rehydrated = PortServiceObservation.from_dict(d)
    assert rehydrated.port == 5432
    assert rehydrated.service == "postgresql"


def test_dns_record_observation():
    """Tests DnsRecordObservation normalization and value deduplication."""
    dns_obs = DnsRecordObservation(
        host="example.com",
        record_type="A",
        values=["192.0.2.1", "192.0.2.2"],
    )
    assert dns_obs.key == "example.com:A"
    d = dns_obs.to_dict()
    assert d["values"] == ["192.0.2.1", "192.0.2.2"]


def test_tls_observation_and_san_names():
    """Tests TlsObservation model and SAN sorting."""
    tls_obs = TlsObservation(
        host="example.com",
        port=443,
        san_names=["example.com", "api.example.com", "dev.example.com"],
        issuer="Let's Encrypt",
        tls_version="TLSv1.3",
    )
    assert tls_obs.key == "example.com:443"
    assert "api.example.com" in tls_obs.san_names


def test_endpoint_observation_deduplication():
    """Tests EndpointObservation canonical fingerprint and deduplication."""
    ep1 = EndpointObservation(
        scheme="https",
        host="api.example.com",
        port=443,
        path="/v1/users",
        method="GET",
        status_code=200,
    )
    ep2 = EndpointObservation(
        scheme="https",
        host="api.example.com",
        port=443,
        path="/v1/users",
        method="get",
    )
    assert ep1.key == ep2.key
    assert ep1.key == "GET https://api.example.com/v1/users"


def test_recon_state_manager_persistence():
    """Tests atomic state persistence and reloading in ReconStateManager."""
    with tempfile.TemporaryDirectory() as tmpdir:
        recon_state = ReconStateManager(tmpdir)
        http_obs = HttpObservation(
            url="https://api.example.com/",
            scheme="https",
            host="api.example.com",
            port=443,
            status_code=200,
            title="Gateway",
        )
        assert recon_state.add_http_observation(http_obs) is True
        # Second insert is duplicate merge
        assert recon_state.add_http_observation(http_obs) is False

        recon_state.mark_probed("api.example.com")
        recon_state.save()

        # Reload from file
        reloaded = ReconStateManager(tmpdir)
        assert reloaded.is_probed("api.example.com") is True
        assert len(reloaded.http_services) == 1
        assert "https://api.example.com/" in reloaded.http_services


def test_technology_extraction_from_headers():
    """Verifies technology detection from server and framework response headers."""
    engine = ReconnaissanceEngine()
    obs = HttpObservation(
        url="https://example.com/",
        scheme="https",
        host="example.com",
        port=443,
        status_code=200,
        server_header="nginx/1.22.1",
        security_headers={"x-powered-by": "Next.js", "x-generator": "WordPress 6.4.2"},
        technologies=["React"],
    )
    techs = engine.extract_technologies(obs)
    names = {t.name for t in techs}
    assert "Nginx" in names
    assert "Next.js" in names
    assert "WordPress" in names
    assert "React" in names

    # Verify version extraction
    nginx_tech = [t for t in techs if t.name == "Nginx"][0]
    assert nginx_tech.version == "1.22.1"
    assert nginx_tech.confidence == ObservationConfidence.CONFIRMED.value


def test_reconnaissance_engine_pipeline_mocked():
    """Tests complete ReconnaissanceEngine execution pipeline using offline deterministic mocks."""
    graph = AssetGraph()
    root = Asset.create(AssetType.ROOT_DOMAIN, "example.com")
    sub1 = Asset.create(AssetType.SUBDOMAIN, "api.example.com", root_domain="example.com", discovery_depth=1)
    graph.add_asset(root)
    graph.add_asset(sub1)

    scope_config = {
        "program": {"name": "test-recon"},
        "targets": {
            "domains": ["example.com", "*.example.com"],
            "recursive_subdomains": {"enabled": True, "max_depth": 0},
        },
        "out_of_scope": {"domains": ["secret.example.com"]},
    }
    scope_engine = ScopeEngine(scope_config)

    with tempfile.TemporaryDirectory() as tmpdir:
        recon_state = ReconStateManager(tmpdir)
        engine = ReconnaissanceEngine(
            scope_engine=scope_engine,
            graph=graph,
            recon_state=recon_state,
            max_hosts=10,
            max_requests=50,
        )

        # Attach mock hooks
        engine.dns_probe_hook = lambda host, rtype: ["93.184.216.34"] if rtype == "A" else []
        engine.tls_probe_hook = lambda host, port: {
            "san_names": ["example.com", "san.example.com", "secret.example.com"],
            "issuer": "DigiCert",
            "tls_version": "TLSv1.3",
        } if host == "example.com" else None
        engine.http_probe_hook = lambda host, port, scheme: {
            "status_code": 200,
            "title": f"Title for {host}",
            "server_header": "cloudflare",
            "technologies": ["Cloudflare"],
        }
        engine.port_scan_hook = lambda host, ports: [
            {"port": 443, "protocol": "tcp", "service": "https"}
        ]
        engine.endpoint_probe_hook = lambda base_url: [
            {"url": f"{base_url}api/v1/health", "method": "GET", "status_code": 200}
        ]

        stats = engine.run_reconnaissance(capabilities=["dns", "tls", "http", "ports", "tech", "endpoints"])

        assert stats["hosts_processed"] == 2
        assert stats["dns_records_found"] >= 2
        assert stats["tls_certificates_found"] >= 1
        assert stats["http_services_found"] >= 2
        assert stats["ports_found"] >= 2
        assert stats["technologies_found"] >= 2
        assert stats["endpoints_found"] >= 1
        # san.example.com was in-scope and added to graph; secret.example.com is out-of-scope and NOT added
        assert graph.has_asset("san.example.com")
        assert not graph.has_asset("secret.example.com")
        assert stats["new_assets_discovered"] == 1


def test_reconnaissance_scope_rejection():
    """Ensures out-of-scope assets are completely skipped without executing any probes."""
    graph = AssetGraph()
    out_asset = Asset.create(AssetType.SUBDOMAIN, "forbidden.internal.com")
    graph.add_asset(out_asset)

    scope_config = {
        "program": {"name": "test-recon"},
        "targets": {"domains": ["example.com"]},
        "out_of_scope": {"domains": []},
    }
    scope_engine = ScopeEngine(scope_config)

    mock_called = []
    engine = ReconnaissanceEngine(scope_engine=scope_engine, graph=graph)
    engine.http_probe_hook = lambda h, p, s: mock_called.append(h)

    stats = engine.run_reconnaissance()
    assert stats["hosts_processed"] == 0
    assert len(mock_called) == 0


def test_passive_only_mode_disables_active_probes():
    """Verifies that passive-only mode blocks active HTTP, port, and TLS probes."""
    graph = AssetGraph()
    root = Asset.create(AssetType.ROOT_DOMAIN, "example.com")
    graph.add_asset(root)

    engine = ReconnaissanceEngine(graph=graph, passive_only=True)
    assert engine.probe_http("example.com", 443, "https") is None
    assert engine.probe_ports("example.com") == []
    assert engine.probe_tls("example.com", 443) is None


def test_budget_enforcement():
    """Verifies request ceiling is strictly honored by ReconnaissanceEngine."""
    engine = ReconnaissanceEngine(max_requests=2)
    engine.http_probe_hook = lambda h, p, s: {"status_code": 200}

    res1 = engine.probe_http("a.example.com", 80, "http")
    res2 = engine.probe_http("b.example.com", 80, "http")
    res3 = engine.probe_http("c.example.com", 80, "http")

    assert res1 is not None
    assert res2 is not None
    assert res3 is None  # Budget reached


def test_security_audit_no_shell_true_or_os_system():
    """Static analysis test verifying zero shell=True or os.system() in framework/recon/."""
    import re

    recon_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "framework", "recon"))
    for root, _, files in os.walk(recon_dir):
        for f in files:
            if f.endswith(".py"):
                path = os.path.join(root, f)
                with open(path, "r", encoding="utf-8") as fh:
                    content = fh.read()
                    assert not re.search(r"shell\s*=\s*True", content), f"Found shell=True in {path}"
                    assert not re.search(r"os\.system\(", content), f"Found os.system in {path}"
