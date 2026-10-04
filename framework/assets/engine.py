"""
Asset Intelligence Engine for BugBounty-Agent.

Executes arbitrary-depth recursive subdomain discovery, DNS resolution, IP/ASN
attribution, wildcard DNS mitigation, TLS SAN extraction, CDN edge identification,
and strict scope authorization boundary enforcement.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import ipaddress
import re
import socket
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
import uuid

from framework.assets.graph import AssetGraph
from framework.assets.model import (
    Asset,
    AssetConfidence,
    AssetStatus,
    AssetType,
    CDNAttribution,
    generate_asset_id,
)
from framework.assets.provenance import ObservationProvenance
from framework.assets.relationship import AssetRelationship, RelationType
from framework.scope.engine import ScopeDecision, ScopeEngine, ScopeStatus
from framework.scope.normalizer import (
    calculate_subdomain_depth,
    is_dns_label_descendant,
    normalize_hostname,
    NormalizationError,
)
from framework.tools.capability import CapabilityGraph


# Known CDN CNAME suffixes and their providers
KNOWN_CDN_CNAME_PATTERNS = [
    (r"\.cloudflare\.(net|com)$", "Cloudflare"),
    (r"\.cloudfront\.net$", "Amazon CloudFront"),
    (r"\.(akamai|akamaiedge|edgekey|akadns)\.net$", "Akamai"),
    (r"\.fastly(lb)?\.net$", "Fastly"),
    (r"\.(azureedge\.net|trafficmanager\.net)$", "Microsoft Azure CDN"),
    (r"\.(googlehosted\.com|ghs\.google\.com)$", "Google Cloud"),
    (r"\.(incapdns\.net|imperva\.com)$", "Imperva Incapsula"),
    (r"\.sucuri\.net$", "Sucuri"),
]

# Known ASN mappings for major CDN / cloud edges
KNOWN_ASN_CDN_MAP = {
    "AS13335": ("Cloudflare", CDNAttribution.CONFIRMED),
    "AS209242": ("Cloudflare", CDNAttribution.CONFIRMED),
    "AS16509": ("Amazon AWS", CDNAttribution.PROBABLE),
    "AS14618": ("Amazon AWS", CDNAttribution.PROBABLE),
    "AS15169": ("Google Cloud", CDNAttribution.PROBABLE),
    "AS396982": ("Google Cloud", CDNAttribution.PROBABLE),
    "AS8075": ("Microsoft Azure", CDNAttribution.PROBABLE),
    "AS54113": ("Fastly", CDNAttribution.CONFIRMED),
    "AS16625": ("Akamai", CDNAttribution.CONFIRMED),
    "AS20940": ("Akamai", CDNAttribution.CONFIRMED),
}


class AssetIntelligenceEngine:
    """
    Orchestrates recursive asset intelligence with multi-source provenance,
    DNS/ASN/TLS/CDN enrichment, and offline scope authorization checks.
    """

    def __init__(
        self,
        scope_engine: Optional[ScopeEngine] = None,
        graph: Optional[AssetGraph] = None,
        capability_graph: Optional[CapabilityGraph] = None,
        max_depth: int = 0,  # 0 indicates unlimited / arbitrary depth
        max_assets: int = 2000,
        passive_only: bool = False,
        detect_wildcards: bool = True,
        rate_limit_per_second: float = 10.0,
    ):
        self.scope_engine = scope_engine
        self.graph = graph or AssetGraph()
        self.capability_graph = capability_graph or CapabilityGraph()
        self.max_depth = max_depth
        self.max_assets = max_assets
        self.passive_only = passive_only
        self.detect_wildcards = detect_wildcards
        self.rate_limit_per_second = rate_limit_per_second

        # Traversal tracking
        self.visited_hostnames: Set[str] = set()
        self.wildcard_domains: Dict[str, Set[str]] = {}  # domain -> set of wildcard IPs

        # Pluggable hooks for offline testing & mockability
        self.dns_resolver_hook: Optional[Callable[[str, str], List[str]]] = None
        self.asn_resolver_hook: Optional[Callable[[str], Dict[str, Any]]] = None
        self.tls_san_hook: Optional[Callable[[str, int], List[str]]] = None
        self.subdomain_discovery_hook: Optional[Callable[[str], List[str]]] = None
        self.cdn_detector_hook: Optional[
            Callable[[str, List[str], List[str]], Tuple[Optional[str], CDNAttribution]]
        ] = None

    # ---------------- Scope Verification ----------------

    def evaluate_scope(self, target: str) -> ScopeDecision:
        """Evaluates target scope using the configured ScopeEngine."""
        if not self.scope_engine:
            return ScopeDecision(
                status=ScopeStatus.IN_SCOPE,
                reason="No ScopeEngine attached; defaulting to permissive in-scope.",
                target=target,
                normalized_target=target.strip().lower(),
            )
        return self.scope_engine.check(target)

    # ---------------- DNS & Infrastructure Resolvers ----------------

    def resolve_dns(self, hostname: str) -> Dict[str, List[str]]:
        """
        Resolves DNS records (A, AAAA, CNAME) for a hostname.
        Delegates to dns_resolver_hook if provided, otherwise uses standard socket.
        """
        if self.dns_resolver_hook:
            a_records = self.dns_resolver_hook(hostname, "A") or []
            aaaa_records = self.dns_resolver_hook(hostname, "AAAA") or []
            cname_records = self.dns_resolver_hook(hostname, "CNAME") or []
            return {
                "A": a_records,
                "AAAA": aaaa_records,
                "CNAME": cname_records,
            }

        # Safe fallback without external third-party library dependency
        results: Dict[str, List[str]] = {"A": [], "AAAA": [], "CNAME": []}
        try:
            _, aliases, ips = socket.gethostbyname_ex(hostname)
            results["A"] = [ip for ip in ips if ":" not in ip]
            results["AAAA"] = [ip for ip in ips if ":" in ip]
            results["CNAME"] = aliases
        except (socket.gaierror, socket.herror, OSError):
            pass
        return results

    def check_wildcard(self, domain: str) -> Tuple[bool, Set[str]]:
        """
        Probes randomized subdomains to detect wildcard DNS resolution.
        Returns (is_wildcard, set_of_wildcard_ips).
        """
        if domain in self.wildcard_domains:
            return True, self.wildcard_domains[domain]

        probe1 = f"_bb_probe_{uuid.uuid4().hex[:8]}.{domain}"
        probe2 = f"_bb_probe_{uuid.uuid4().hex[:8]}.{domain}"

        res1 = self.resolve_dns(probe1)
        res2 = self.resolve_dns(probe2)

        ips1 = set(res1.get("A", []) + res1.get("AAAA", []))
        ips2 = set(res2.get("A", []) + res2.get("AAAA", []))

        # If both randomized non-existent subdomains resolve to IPs
        if ips1 and ips2 and (ips1 == ips2 or (ips1 & ips2)):
            wildcard_ips = ips1 | ips2
            self.wildcard_domains[domain] = wildcard_ips
            return True, wildcard_ips

        return False, set()

    def resolve_asn(self, ip: str) -> Dict[str, Any]:
        """
        Resolves ASN, BGP prefix, and organization for an IP address.
        Uses asn_resolver_hook if provided.
        """
        if self.asn_resolver_hook:
            return self.asn_resolver_hook(ip) or {}

        # Default local heuristic / stub
        return {
            "asn": "UNKNOWN",
            "org": "UNKNOWN",
            "cidr": f"{ip}/32",
        }

    def detect_cdn(
        self, hostname: str, ips: List[str], cnames: List[str]
    ) -> Tuple[Optional[str], CDNAttribution]:
        """
        Identifies CDN edge infrastructure from CNAME chains and IP/ASN attribution.
        """
        if self.cdn_detector_hook:
            return self.cdn_detector_hook(hostname, ips, cnames)

        # Check CNAME patterns
        for cname in cnames:
            for pattern, cdn_name in KNOWN_CDN_CNAME_PATTERNS:
                if re.search(pattern, cname, re.IGNORECASE):
                    return cdn_name, CDNAttribution.CONFIRMED

        # Check ASN attribution
        for ip in ips:
            asn_info = self.resolve_asn(ip)
            asn = asn_info.get("asn", "")
            if asn in KNOWN_ASN_CDN_MAP:
                cdn_name, attribution = KNOWN_ASN_CDN_MAP[asn]
                return cdn_name, attribution

        return None, CDNAttribution.UNKNOWN

    def extract_tls_sans(self, hostname: str, port: int = 443) -> List[str]:
        """
        Extracts Subject Alternative Names (SANs) from TLS certificate.
        Uses tls_san_hook if provided.
        """
        if self.tls_san_hook:
            return self.tls_san_hook(hostname, port) or []
        return []

    # ---------------- Recursive Discovery Pipeline ----------------

    def run_discovery(
        self,
        root_domains: List[str],
        seed_subdomains: Optional[List[str]] = None,
    ) -> AssetGraph:
        """
        Executes arbitrary-depth recursive asset graph construction.
        Traverses seed subdomains and child discoveries, correlates DNS/IP/ASN/CDN,
        and enforces scope authorization at every step.
        """
        # Queue items: (hostname, root_domain, parent_hostname, depth, source_tool)
        queue: deque[Tuple[str, str, Optional[str], int, str]] = deque()

        # Initialize roots
        for raw_root in root_domains:
            try:
                root_norm = normalize_hostname(raw_root)
            except NormalizationError:
                continue

            root_scope = self.evaluate_scope(root_norm)
            root_asset = Asset.create(
                asset_type=AssetType.ROOT_DOMAIN,
                value=root_norm,
                root_domain=root_norm,
                discovery_depth=0,
                scope_status=root_scope.status.value,
                provenance=ObservationProvenance(
                    source="user_input",
                    method="root_seed",
                    confidence=AssetConfidence.CONFIRMED.value,
                ),
            )
            self.graph.add_asset(root_asset)
            self.visited_hostnames.add(root_norm)

            if root_scope.status == ScopeStatus.IN_SCOPE:
                # Check wildcard DNS on root
                if self.detect_wildcards and not self.passive_only:
                    is_wc, _ = self.check_wildcard(root_norm)
                    if is_wc:
                        root_asset.attributes["is_wildcard"] = True

                # Correlate root infrastructure
                self._enrich_asset_infrastructure(root_asset)

                # Queue root for child subdomain discovery
                queue.append((root_norm, root_norm, None, 0, "root_seed"))

        # Add seed subdomains if provided
        if seed_subdomains:
            for seed in seed_subdomains:
                try:
                    seed_norm = normalize_hostname(seed)
                except NormalizationError:
                    continue

                # Match seed with corresponding root domain
                matching_root = None
                for raw_root in root_domains:
                    norm_root = raw_root.strip().lower()
                    if is_dns_label_descendant(seed_norm, norm_root):
                        matching_root = norm_root
                        break

                if not matching_root:
                    continue

                depth, parent_h = calculate_subdomain_depth(seed_norm, matching_root)
                queue.append((seed_norm, matching_root, parent_h, depth, "seed"))

        # Process traversal queue (Arbitrary Depth BFS)
        while queue:
            # Check total asset budget limit
            if len(self.graph.get_all_assets()) >= self.max_assets:
                break

            current_host, root_dom, parent_host, depth, source_tool = queue.popleft()

            # Enforce depth limit only if max_depth > 0 (0 means unlimited / arbitrary)
            if self.max_depth > 0 and depth > self.max_depth:
                continue

            # Ensure valid DNS label descendant of the program root
            if current_host != root_dom and not is_dns_label_descendant(current_host, root_dom):
                continue

            # Scope boundary validation
            scope_dec = self.evaluate_scope(current_host)

            # Retrieve or create parent asset ID
            parent_id = None
            if parent_host:
                parent_id = generate_asset_id(
                    AssetType.ROOT_DOMAIN if parent_host == root_dom else AssetType.SUBDOMAIN,
                    parent_host,
                )

            # Create or update current subdomain asset
            asset_type = AssetType.ROOT_DOMAIN if current_host == root_dom else AssetType.SUBDOMAIN
            prov = ObservationProvenance(
                source=source_tool,
                method="subdomain_discovery" if depth > 0 else "root_seed",
                raw_observation=current_host,
                confidence=AssetConfidence.HIGH.value if current_host == root_dom else AssetConfidence.MEDIUM.value,
            )

            asset = Asset.create(
                asset_type=asset_type,
                value=current_host,
                root_domain=root_dom,
                parent_id=parent_id,
                parent_hostname=parent_host,
                discovery_depth=depth,
                scope_status=scope_dec.status.value,
                provenance=prov,
            )
            self.graph.add_asset(asset)

            # Record HAS_SUBDOMAIN edge from parent if applicable
            if parent_id and parent_id in self.graph._assets:
                self.graph.add_relationship(
                    AssetRelationship(
                        source_id=parent_id,
                        destination_id=asset.id,
                        relation_type=RelationType.HAS_SUBDOMAIN,
                        confidence=AssetConfidence.CONFIRMED.value,
                    )
                )

            # If out of scope or ambiguous, do NOT probe actively or recurse deeper
            if scope_dec.status != ScopeStatus.IN_SCOPE:
                asset.status = AssetStatus.SKIPPED.value
                continue

            # If already visited for discovery expansion, continue
            if current_host in self.visited_hostnames and current_host != root_dom:
                continue
            self.visited_hostnames.add(current_host)

            # Infrastructure correlation (DNS, IP, ASN, TLS, CDN)
            self._enrich_asset_infrastructure(asset)
            asset.status = AssetStatus.VERIFIED.value

            # Extract TLS SANs and enqueue newly discovered in-scope subdomains
            if not self.passive_only:
                sans = self.extract_tls_sans(current_host)
                for san in sans:
                    try:
                        norm_san = normalize_hostname(san)
                    except NormalizationError:
                        continue

                    # Check if SAN belongs to root domain
                    if is_dns_label_descendant(norm_san, root_dom):
                        san_depth, san_parent = calculate_subdomain_depth(norm_san, root_dom)
                        # Add PRESENT_IN_CERT relationship
                        san_id = generate_asset_id(AssetType.SUBDOMAIN, norm_san)
                        self.graph.add_relationship(
                            AssetRelationship(
                                source_id=asset.id,
                                destination_id=san_id,
                                relation_type=RelationType.PRESENT_IN_CERT,
                                confidence=AssetConfidence.CONFIRMED.value,
                            )
                        )
                        if norm_san not in self.visited_hostnames:
                            queue.append((norm_san, root_dom, san_parent, san_depth, "tls_san"))

            # Discover child subdomains (via discovery hook or registered tools)
            child_subdomains = self._discover_child_subdomains(current_host)
            for child in child_subdomains:
                try:
                    norm_child = normalize_hostname(child)
                except NormalizationError:
                    continue

                if not is_dns_label_descendant(norm_child, current_host):
                    continue

                if norm_child not in self.visited_hostnames:
                    child_depth, _ = calculate_subdomain_depth(norm_child, root_dom)
                    queue.append((norm_child, root_dom, current_host, child_depth, "child_discovery"))

            asset.status = AssetStatus.RECURSED.value

        return self.graph

    # ---------------- Infrastructure Enrichment Helper ----------------

    def _enrich_asset_infrastructure(self, asset: Asset) -> None:
        """
        Enriches an asset with DNS records, resolved IPs, ASN info,
        CNAME chains, and CDN edge classification.
        """
        dns_records = self.resolve_dns(asset.normalized)
        a_records = dns_records.get("A", [])
        aaaa_records = dns_records.get("AAAA", [])
        cnames = dns_records.get("CNAME", [])
        all_ips = a_records + aaaa_records

        asset.attributes["dns_records"] = dns_records
        if all_ips:
            asset.attributes["ip_addresses"] = all_ips
        if cnames:
            asset.attributes["cname"] = cnames[0]
            asset.attributes["cname_chain"] = cnames

        # Mark active DNS confirmation in provenance
        if all_ips or cnames:
            asset.add_provenance(
                ObservationProvenance(
                    source="dns_resolver",
                    method="active_dns",
                    confidence=AssetConfidence.CONFIRMED.value,
                )
            )

        # Record CNAME relationships
        for cname_target in cnames:
            try:
                norm_cname = normalize_hostname(cname_target)
                cname_asset_id = generate_asset_id(AssetType.HOSTNAME, norm_cname)
                # Create CNAME target asset in graph if absent
                if not self.graph.has_asset(cname_asset_id):
                    self.graph.add_asset(
                        Asset.create(
                            asset_type=AssetType.HOSTNAME,
                            value=norm_cname,
                            scope_status=self.evaluate_scope(norm_cname).status.value,
                            provenance=ObservationProvenance(
                                source="dns_cname",
                                method="cname_chain",
                                confidence=AssetConfidence.CONFIRMED.value,
                            ),
                        )
                    )
                self.graph.add_relationship(
                    AssetRelationship(
                        source_id=asset.id,
                        destination_id=cname_asset_id,
                        relation_type=RelationType.CNAME_TO,
                        confidence=AssetConfidence.CONFIRMED.value,
                    )
                )
            except NormalizationError:
                pass

        # Record IP assets and RESOLVES_TO relationships
        for ip in all_ips:
            ip_norm = ip.strip()
            ip_asset_id = generate_asset_id(AssetType.IP_ADDRESS, ip_norm)
            ip_scope = self.evaluate_scope(ip_norm)

            asn_info = self.resolve_asn(ip_norm)
            ip_attributes = {"asn_info": asn_info}
            if asn_info.get("asn"):
                ip_attributes["asn"] = asn_info["asn"]
            if asn_info.get("org"):
                ip_attributes["org"] = asn_info["org"]

            if not self.graph.has_asset(ip_asset_id):
                self.graph.add_asset(
                    Asset.create(
                        asset_type=AssetType.IP_ADDRESS,
                        value=ip_norm,
                        scope_status=ip_scope.status.value,
                        provenance=ObservationProvenance(
                            source="dns_resolver",
                            method="active_dns",
                            confidence=AssetConfidence.CONFIRMED.value,
                        ),
                        attributes=ip_attributes,
                    )
                )

            # Hostname -> IP resolution edge
            self.graph.add_relationship(
                AssetRelationship(
                    source_id=asset.id,
                    destination_id=ip_asset_id,
                    relation_type=RelationType.RESOLVES_TO,
                    confidence=AssetConfidence.CONFIRMED.value,
                )
            )

            # IP -> ASN relationship if ASN known
            if asn_info.get("asn") and asn_info["asn"] != "UNKNOWN":
                asn_asset_id = generate_asset_id(AssetType.INFRASTRUCTURE_REF, asn_info["asn"])
                if not self.graph.has_asset(asn_asset_id):
                    self.graph.add_asset(
                        Asset.create(
                            asset_type=AssetType.INFRASTRUCTURE_REF,
                            value=asn_info["asn"],
                            attributes={"org": asn_info.get("org", "")},
                            scope_status=ScopeStatus.IN_SCOPE.value,
                        )
                    )
                self.graph.add_relationship(
                    AssetRelationship(
                        source_id=ip_asset_id,
                        destination_id=asn_asset_id,
                        relation_type=RelationType.BELONGS_TO_ASN,
                        confidence=AssetConfidence.CONFIRMED.value,
                    )
                )

        # Detect CDN & Cloud edge
        cdn_name, attribution = self.detect_cdn(asset.normalized, all_ips, cnames)
        if cdn_name:
            asset.attributes["cdn"] = cdn_name
            asset.attributes["cdn_attribution"] = attribution.value
            cdn_asset_id = generate_asset_id(AssetType.CLOUD_RESOURCE, cdn_name)
            if not self.graph.has_asset(cdn_asset_id):
                self.graph.add_asset(
                    Asset.create(
                        asset_type=AssetType.CLOUD_RESOURCE,
                        value=cdn_name,
                        scope_status=ScopeStatus.IN_SCOPE.value,
                    )
                )
            self.graph.add_relationship(
                AssetRelationship(
                    source_id=asset.id,
                    destination_id=cdn_asset_id,
                    relation_type=RelationType.HOSTED_BY,
                    confidence=AssetConfidence.CONFIRMED.value
                    if attribution == CDNAttribution.CONFIRMED
                    else AssetConfidence.MEDIUM.value,
                )
            )

    def _discover_child_subdomains(self, parent_hostname: str) -> List[str]:
        """Queries discovery tools or hook for child subdomains of a hostname."""
        if self.subdomain_discovery_hook:
            return self.subdomain_discovery_hook(parent_hostname) or []
        return []

    def _extract_parent_hostname(self, hostname: str, root_domain: str) -> str:
        """
        Calculates immediate parent hostname:
        e.g., 'a.b.example.com' -> 'b.example.com'.
        If 'b.example.com' with root 'example.com' -> 'example.com'.
        """
        if hostname == root_domain:
            return root_domain
        parts = hostname.split(".")
        root_parts = root_domain.split(".")
        if len(parts) > len(root_parts):
            return ".".join(parts[1:])
        return root_domain
