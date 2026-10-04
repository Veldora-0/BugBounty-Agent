"""
Reconnaissance Orchestration Engine for BugBounty-Agent.

Consumes assets from AssetGraph, applies strict ScopeEngine verification,
intelligently queries CapabilityGraph for applicable recon tools, executes bounded
probes with fallback handling and mock hooks, normalizes observations, attaches
multi-source provenance, and updates local state atomically.
"""

from __future__ import annotations

from datetime import datetime, timezone
import os
import re
import socket
import ssl
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from framework.assets.graph import AssetGraph
from framework.assets.model import (
    Asset,
    AssetConfidence,
    AssetStatus,
    AssetType,
    generate_asset_id,
)
from framework.assets.provenance import ObservationProvenance
from framework.assets.relationship import RelationType
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
from framework.tools.capability import CapabilityGraph
from framework.tools.detector import EXTENDED_SEARCH_PATHS
from framework.tools.registry import ToolRegistry


# Common technology header/fingerprint signatures
TECH_HEADER_SIGNATURES: List[Tuple[str, str, str, str]] = [
    # (header, regex_pattern, tech_name, category)
    ("server", r"nginx(?:/([\d\.]+))?", "Nginx", "web-server"),
    ("server", r"apache(?:/([\d\.]+))?", "Apache HTTP Server", "web-server"),
    ("server", r"cloudflare", "Cloudflare", "cdn"),
    ("server", r"microsoft-iis(?:/([\d\.]+))?", "Microsoft IIS", "web-server"),
    ("server", r"caddy", "Caddy", "web-server"),
    ("x-powered-by", r"express", "Express", "framework"),
    ("x-powered-by", r"next\.js(?:/([\d\.]+))?", "Next.js", "framework"),
    ("x-powered-by", r"php(?:/([\d\.]+))?", "PHP", "programming-language"),
    ("x-powered-by", r"asp\.net", "ASP.NET", "framework"),
    ("x-generator", r"wordpress(?: ([\d\.]+))?", "WordPress", "cms"),
    ("x-generator", r"drupal(?: ([\d\.]+))?", "Drupal", "cms"),
]

# Standard default web ports
DEFAULT_HTTP_PORTS = [80, 443, 8080, 8443]


class ReconnaissanceEngine:
    """
    Intelligent Reconnaissance Orchestrator for BugBounty-Agent.
    Enriches attack surface assets with structured HTTP, TLS, DNS, Port, Technology,
    and Endpoint observations.
    """

    def __init__(
        self,
        scope_engine: Optional[ScopeEngine] = None,
        graph: Optional[AssetGraph] = None,
        recon_state: Optional[ReconStateManager] = None,
        tool_registry: Optional[ToolRegistry] = None,
        capability_graph: Optional[CapabilityGraph] = None,
        passive_only: bool = False,
        max_hosts: int = 500,
        max_requests: int = 2000,
        max_endpoints: int = 1000,
        dry_run: bool = False,
    ):
        self.scope_engine = scope_engine
        self.graph = graph or AssetGraph()
        self.recon_state = recon_state
        self.registry = tool_registry or ToolRegistry()
        self.capability_graph = capability_graph or CapabilityGraph(self.registry)
        self.passive_only = passive_only
        self.max_hosts = max_hosts
        self.max_requests = max_requests
        self.max_endpoints = max_endpoints
        self.dry_run = dry_run

        self.request_count = 0
        self.hosts_processed = 0

        # Pluggable execution hooks for deterministic offline testing
        self.http_probe_hook: Optional[Callable[[str, int, str], Optional[Dict[str, Any]]]] = None
        self.port_scan_hook: Optional[Callable[[str, List[int]], List[Dict[str, Any]]]] = None
        self.dns_probe_hook: Optional[Callable[[str, str], List[str]]] = None
        self.tls_probe_hook: Optional[Callable[[str, int], Optional[Dict[str, Any]]]] = None
        self.endpoint_probe_hook: Optional[Callable[[str], List[Dict[str, Any]]]] = None

    def _is_in_scope(self, target: str) -> bool:
        """Enforces ScopeEngine checks before ANY active or passive probing."""
        if not self.scope_engine:
            return True
        decision = self.scope_engine.check(target)
        return decision.status == ScopeStatus.IN_SCOPE

    # ==========================================================================
    # 1. DNS RESOLUTION & ENRICHMENT
    # ==========================================================================

    def probe_dns(self, host: str) -> List[DnsRecordObservation]:
        """Collects DNS record observations for host (A, AAAA, CNAME)."""
        if not self._is_in_scope(host):
            return []

        observations: List[DnsRecordObservation] = []

        if self.dns_probe_hook:
            for rtype in ["A", "AAAA", "CNAME", "MX", "NS"]:
                vals = self.dns_probe_hook(host, rtype)
                if vals:
                    obs = DnsRecordObservation(
                        host=host,
                        record_type=rtype,
                        values=sorted(list(vals)),
                        provenance=[
                            ObservationProvenance(
                                source="dns_resolver_hook",
                                method="dns-query",
                                confidence="CONFIRMED",
                            )
                        ],
                    )
                    observations.append(obs)
            return observations

        # Live fallback using standard socket safely
        if not self.passive_only:
            try:
                _, aliases, ips = socket.gethostbyname_ex(host)
                if ips:
                    obs_a = DnsRecordObservation(
                        host=host,
                        record_type="A",
                        values=[ip for ip in ips if ":" not in ip],
                        provenance=[
                            ObservationProvenance(
                                source="socket",
                                method="gethostbyname_ex",
                                confidence="CONFIRMED",
                            )
                        ],
                    )
                    observations.append(obs_a)
                if aliases:
                    obs_cname = DnsRecordObservation(
                        host=host,
                        record_type="CNAME",
                        values=aliases,
                        provenance=[
                            ObservationProvenance(
                                source="socket",
                                method="gethostbyname_ex",
                                confidence="CONFIRMED",
                            )
                        ],
                    )
                    observations.append(obs_cname)
            except (socket.gaierror, socket.herror, OSError):
                pass

        return observations

    # ==========================================================================
    # 2. TLS CERTIFICATE INSPECTION
    # ==========================================================================

    def probe_tls(self, host: str, port: int = 443) -> Optional[TlsObservation]:
        """Extracts TLS SAN names, issuer, and validity details."""
        if not self._is_in_scope(host) or self.passive_only:
            return None

        if self.tls_probe_hook:
            res = self.tls_probe_hook(host, port)
            if not res:
                return None
            return TlsObservation(
                host=host,
                port=port,
                san_names=res.get("san_names", []),
                issuer=res.get("issuer"),
                subject=res.get("subject"),
                valid_from=res.get("valid_from"),
                valid_to=res.get("valid_to"),
                tls_version=res.get("tls_version"),
                cipher=res.get("cipher"),
                expired=bool(res.get("expired", False)),
                provenance=[
                    ObservationProvenance(
                        source="tls_probe_hook",
                        method="tls-handshake",
                        confidence="CONFIRMED",
                    )
                ],
            )

        # Safe fallback standard ssl context
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=3.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False) or {}
                    cipher_info = ssock.cipher()
                    tls_ver = ssock.version()

                    sans: List[str] = []
                    for k, val in cert.get("subjectAltName", []):
                        if k.lower() == "dns":
                            sans.append(val.strip().lower())

                    obs = TlsObservation(
                        host=host,
                        port=port,
                        san_names=sans,
                        tls_version=tls_ver,
                        cipher=cipher_info[0] if cipher_info else None,
                        provenance=[
                            ObservationProvenance(
                                source="ssl_socket",
                                method="tls-handshake",
                                confidence="CONFIRMED",
                            )
                        ],
                    )
                    return obs
        except Exception:
            return None

    # ==========================================================================
    # 3. HTTP PROBING & SERVICE INTELLIGENCE
    # ==========================================================================

    def probe_http(self, host: str, port: int, scheme: str) -> Optional[HttpObservation]:
        """Probes an HTTP/HTTPS service, extracting status, headers, title, and fingerprints."""
        if not self._is_in_scope(host) or self.passive_only:
            return None

        if self.request_count >= self.max_requests:
            return None

        self.request_count += 1
        raw_url = f"{scheme}://{host}:{port}/" if (scheme == "http" and port != 80) or (scheme == "https" and port != 443) else f"{scheme}://{host}/"

        if self.http_probe_hook:
            res = self.http_probe_hook(host, port, scheme)
            if not res:
                return None
            return HttpObservation(
                url=res.get("url", raw_url),
                scheme=scheme,
                host=host,
                port=port,
                status_code=int(res.get("status_code", 200)),
                title=res.get("title"),
                content_type=res.get("content_type"),
                content_length=res.get("content_length"),
                redirect_chain=res.get("redirect_chain", []) or [],
                final_url=res.get("final_url"),
                server_header=res.get("server_header"),
                security_headers=res.get("security_headers", {}) or {},
                technologies=res.get("technologies", []) or [],
                response_time_ms=res.get("response_time_ms"),
                reachability=ReachabilityStatus.REACHABLE.value,
                provenance=[
                    ObservationProvenance(
                        source="http_probe_hook",
                        method="http-request",
                        confidence="CONFIRMED",
                    )
                ],
            )

        # Fallback using urllib.request with bounded read and timeout
        import urllib.request
        try:
            req = urllib.request.Request(
                raw_url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BugBounty-Agent/2.0"},
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=4.0, context=ctx if scheme == "https" else None) as resp:
                status = resp.status
                headers = dict(resp.headers)
                body = resp.read(8192).decode("utf-8", errors="ignore")

                title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                title = title_match.group(1).strip() if title_match else None

                server = headers.get("Server") or headers.get("server")
                ct = headers.get("Content-Type") or headers.get("content-type")
                cl = None
                cl_header = headers.get("Content-Length") or headers.get("content-length")
                if cl_header and cl_header.isdigit():
                    cl = int(cl_header)

                return HttpObservation(
                    url=raw_url,
                    scheme=scheme,
                    host=host,
                    port=port,
                    status_code=status,
                    title=title,
                    content_type=ct,
                    content_length=cl,
                    server_header=server,
                    provenance=[
                        ObservationProvenance(
                            source="urllib",
                            method="http-get",
                            confidence="CONFIRMED",
                        )
                    ],
                )
        except Exception:
            return None

    # ==========================================================================
    # 4. TECHNOLOGY EXTRACTION
    # ==========================================================================

    def extract_technologies(self, http_obs: HttpObservation) -> List[TechnologyObservation]:
        """Infers technology observations from headers, server banners, and status response."""
        tech_obs: List[TechnologyObservation] = []
        host = http_obs.host

        # Check server header & common headers
        headers_to_check = {
            "server": http_obs.server_header or "",
        }
        for k, v in http_obs.security_headers.items():
            headers_to_check[k.lower()] = v

        for hdr, pattern, tech_name, category in TECH_HEADER_SIGNATURES:
            val = headers_to_check.get(hdr.lower(), "")
            if not val:
                continue
            match = re.search(pattern, val, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex and match.lastindex >= 1 else None
                obs = TechnologyObservation(
                    host=host,
                    name=tech_name,
                    category=category,
                    version=version,
                    confidence=ObservationConfidence.CONFIRMED.value if version else ObservationConfidence.PROBABLE.value,
                    evidence_source=f"header:{hdr}",
                    provenance=[
                        ObservationProvenance(
                            source="header_fingerprint",
                            method="regex-match",
                            confidence="CONFIRMED" if version else "PROBABLE",
                            raw_observation=val,
                        )
                    ],
                )
                tech_obs.append(obs)

        # Add explicit technologies detected from tool output
        for t in http_obs.technologies:
            obs = TechnologyObservation(
                host=host,
                name=t,
                category="general",
                confidence=ObservationConfidence.PROBABLE.value,
                evidence_source="tool-output",
                provenance=[
                    ObservationProvenance(
                        source="tool_detector",
                        method="fingerprint",
                        confidence="PROBABLE",
                    )
                ],
            )
            tech_obs.append(obs)

        return tech_obs

    # ==========================================================================
    # 5. PORT & SERVICE SCANNING
    # ==========================================================================

    def probe_ports(self, host: str, ports: Optional[List[int]] = None) -> List[PortServiceObservation]:
        """Probes specified ports for open TCP services."""
        if not self._is_in_scope(host) or self.passive_only:
            return []

        target_ports = ports or DEFAULT_HTTP_PORTS
        observations: List[PortServiceObservation] = []

        if self.port_scan_hook:
            res_list = self.port_scan_hook(host, target_ports)
            for res in res_list:
                obs = PortServiceObservation(
                    host=host,
                    port=int(res.get("port", 0)),
                    protocol=res.get("protocol", "tcp"),
                    service=res.get("service", "unknown"),
                    product=res.get("product"),
                    version=res.get("version"),
                    banner=res.get("banner"),
                    provenance=[
                        ObservationProvenance(
                            source="port_scan_hook",
                            method="socket-connect",
                            confidence="CONFIRMED",
                        )
                    ],
                )
                observations.append(obs)
            return observations

        # Live bounded socket connect
        for p in target_ports:
            if self.request_count >= self.max_requests:
                break
            self.request_count += 1
            try:
                with socket.create_connection((host, p), timeout=1.5):
                    obs = PortServiceObservation(
                        host=host,
                        port=p,
                        protocol="tcp",
                        service="https" if p in (443, 8443) else "http" if p in (80, 8080) else "unknown",
                        provenance=[
                            ObservationProvenance(
                                source="socket_connect",
                                method="tcp-syn",
                                confidence="CONFIRMED",
                            )
                        ],
                    )
                    observations.append(obs)
            except (socket.timeout, ConnectionRefusedError, OSError):
                continue

        return observations

    # ==========================================================================
    # 6. ENDPOINT DISCOVERY
    # ==========================================================================

    def probe_endpoints(self, base_url: str) -> List[EndpointObservation]:
        """Collects discovered endpoints/paths for a web service."""
        parsed = urlparse(base_url)
        host = parsed.hostname or ""
        if not self._is_in_scope(host):
            return []

        observations: List[EndpointObservation] = []

        if self.endpoint_probe_hook:
            items = self.endpoint_probe_hook(base_url)
            for item in items:
                if len(observations) >= self.max_endpoints:
                    break
                p_url = urlparse(item.get("url", base_url))
                scheme = p_url.scheme or "https"
                h = p_url.hostname or host
                port = p_url.port or (443 if scheme == "https" else 80)
                path = p_url.path or "/"

                obs = EndpointObservation(
                    scheme=scheme,
                    host=h,
                    port=port,
                    path=path,
                    method=item.get("method", "GET").upper(),
                    status_code=item.get("status_code"),
                    content_type=item.get("content_type"),
                    source_tool=item.get("source_tool", "crawler"),
                    provenance=[
                        ObservationProvenance(
                            source="endpoint_probe_hook",
                            method="crawl",
                            confidence="OBSERVED",
                        )
                    ],
                )
                observations.append(obs)

        return observations

    # ==========================================================================
    # 7. MAIN RECONNAISSANCE PIPELINE
    # ==========================================================================

    def run_reconnaissance(
        self,
        assets: Optional[List[Asset]] = None,
        capabilities: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Executes capability-driven reconnaissance across target assets.
        Enriches AssetGraph and persists to ReconStateManager if configured.
        """
        # Determine candidate assets
        if assets is not None:
            candidates = assets
        else:
            candidates = [
                a for a in self.graph.get_all_assets()
                if a.type in (AssetType.ROOT_DOMAIN, AssetType.SUBDOMAIN, AssetType.HOSTNAME)
                and a.scope_status == ScopeStatus.IN_SCOPE.value
            ]

        # Enforce host budget
        if len(candidates) > self.max_hosts:
            candidates = candidates[: self.max_hosts]

        selected_caps = set([c.lower().strip() for c in capabilities]) if capabilities else {
            "dns", "tls", "http", "ports", "tech"
        }

        stats = {
            "hosts_processed": 0,
            "http_services_found": 0,
            "ports_found": 0,
            "dns_records_found": 0,
            "tls_certificates_found": 0,
            "technologies_found": 0,
            "endpoints_found": 0,
            "new_assets_discovered": 0,
        }

        for asset in candidates:
            host = asset.value.strip().lower()
            if not self._is_in_scope(host):
                continue

            self.hosts_processed += 1
            stats["hosts_processed"] += 1

            # 1. DNS Resolution
            if "dns" in selected_caps:
                dns_obs_list = self.probe_dns(host)
                for dns_obs in dns_obs_list:
                    stats["dns_records_found"] += 1
                    if self.recon_state and not self.dry_run:
                        self.recon_state.add_dns_observation(dns_obs)

                    # Enrich asset attributes
                    if dns_obs.record_type == "A":
                        ips = asset.attributes.get("ip_addresses", [])
                        for ip in dns_obs.values:
                            if ip not in ips:
                                ips.append(ip)
                        asset.attributes["ip_addresses"] = ips

            # 2. TLS Certificate Inspection
            if "tls" in selected_caps:
                tls_obs = self.probe_tls(host, port=443)
                if tls_obs:
                    stats["tls_certificates_found"] += 1
                    if self.recon_state and not self.dry_run:
                        self.recon_state.add_tls_observation(tls_obs)

                    # Check for new in-scope SAN names to enrich AssetGraph
                    for san in tls_obs.san_names:
                        clean_san = san.strip().lower()
                        if clean_san.startswith("*."):
                            clean_san = clean_san[2:]
                        if clean_san and not self.graph.has_asset(clean_san):
                            if self._is_in_scope(clean_san):
                                new_asset = Asset.create(
                                    asset_type=AssetType.SUBDOMAIN,
                                    value=clean_san,
                                    root_domain=asset.root_domain or asset.value,
                                    parent_id=asset.id,
                                    parent_hostname=asset.value,
                                    discovery_depth=asset.discovery_depth + 1,
                                    provenance=ObservationProvenance(
                                        source="tls_san",
                                        method="tls-certificate",
                                        confidence="CONFIRMED",
                                    ),
                                )
                                self.graph.add_asset(new_asset)
                                from framework.assets.relationship import AssetRelationship
                                self.graph.add_relationship(
                                    AssetRelationship(
                                        source_id=asset.id,
                                        destination_id=new_asset.id,
                                        relation_type=RelationType.PRESENT_IN_CERT,
                                    )
                                )
                                stats["new_assets_discovered"] += 1

            # 3. Port & Service Discovery
            if "ports" in selected_caps:
                port_obs_list = self.probe_ports(host)
                for port_obs in port_obs_list:
                    stats["ports_found"] += 1
                    if self.recon_state and not self.dry_run:
                        self.recon_state.add_port_observation(port_obs)

            # 4. HTTP Probing (Ports 80 & 443)
            if "http" in selected_caps:
                http_candidates = [
                    (80, "http"),
                    (443, "https"),
                ]
                for p, s in http_candidates:
                    http_obs = self.probe_http(host, port=p, scheme=s)
                    if http_obs:
                        stats["http_services_found"] += 1
                        if self.recon_state and not self.dry_run:
                            self.recon_state.add_http_observation(http_obs)

                        # Attach HTTP attributes to Asset
                        services = asset.attributes.get("http_services", [])
                        if http_obs.url not in services:
                            services.append(http_obs.url)
                        asset.attributes["http_services"] = services
                        if http_obs.title and not asset.attributes.get("http_title"):
                            asset.attributes["http_title"] = http_obs.title

                        # 5. Technology Fingerprinting from HTTP observations
                        if "tech" in selected_caps:
                            tech_list = self.extract_technologies(http_obs)
                            for tech_obs in tech_list:
                                stats["technologies_found"] += 1
                                if self.recon_state and not self.dry_run:
                                    self.recon_state.add_technology_observation(tech_obs)

                                asset_techs = asset.attributes.get("technologies", [])
                                if tech_obs.name not in asset_techs:
                                    asset_techs.append(tech_obs.name)
                                asset.attributes["technologies"] = asset_techs

                        # 6. Endpoints
                        if "endpoints" in selected_caps:
                            ep_list = self.probe_endpoints(http_obs.url)
                            for ep_obs in ep_list:
                                stats["endpoints_found"] += 1
                                if self.recon_state and not self.dry_run:
                                    self.recon_state.add_endpoint_observation(ep_obs)

            # Mark host as probed
            if self.recon_state and not self.dry_run:
                self.recon_state.mark_probed(host)

        # Save state if attached
        if self.recon_state and not self.dry_run:
            self.recon_state.save()

        return stats
