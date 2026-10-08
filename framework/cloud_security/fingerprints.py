"""
Provider Fingerprinting and Signature Engine (Phase 13).

Scores multiple independent signals (DNS CNAMEs, DNS answers, IP/ASN ownership,
TLS SAN/CN data, HTTP headers, Server fingerprints, and hostnames) to classify
cloud providers with calibrated confidence.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from framework.cloud_security.models import CloudProvider, CloudServiceType


# Multi-signal regex signatures for cloud providers
PROVIDER_SIGNATURES: Dict[CloudProvider, Dict[str, List[Tuple[str, float]]]] = {
    CloudProvider.AWS: {
        "hostname": [
            (r"\.amazonaws\.com$", 0.85),
            (r"\.cloudfront\.net$", 0.85),
            (r"\.elasticbeanstalk\.com$", 0.80),
            (r"\.awsglobalaccelerator\.com$", 0.80),
        ],
        "dns": [
            (r"aws", 0.30),
            (r"amazon", 0.30),
            (r"cloudfront", 0.70),
            (r"elb\.amazonaws\.com", 0.85),
            (r"awsdns", 0.75),
        ],
        "headers": [
            (r"x-amz-", 0.80),
            (r"x-amzn-", 0.80),
            (r"awselb", 0.75),
            (r"cloudfront", 0.70),
        ],
        "server": [
            (r"amazons3", 0.90),
            (r"cloudfront", 0.75),
        ],
        "tls": [
            (r"\.amazonaws\.com", 0.80),
            (r"\.cloudfront\.net", 0.80),
            (r"amazon", 0.40),
        ],
        "asn": [
            (r"amazon", 0.60),
            (r"aws", 0.60),
        ],
    },
    CloudProvider.AZURE: {
        "hostname": [
            (r"\.azurewebsites\.net$", 0.85),
            (r"\.blob\.core\.windows\.net$", 0.90),
            (r"\.cloudapp\.azure\.com$", 0.85),
            (r"\.azure-api\.net$", 0.85),
            (r"\.trafficmanager\.net$", 0.80),
            (r"\.azureedge\.net$", 0.85),
            (r"\.azurefd\.net$", 0.85),
        ],
        "dns": [
            (r"azure", 0.60),
            (r"trafficmanager\.net", 0.75),
            (r"windows\.net", 0.70),
        ],
        "headers": [
            (r"x-ms-", 0.80),
            (r"x-azure-", 0.80),
            (r"azure", 0.40),
        ],
        "server": [
            (r"microsoft-iis", 0.30),
            (r"microsoft-httpapi", 0.30),
            (r"windows-azure", 0.80),
            (r"azure", 0.80),
            (r"appservice", 0.80),
        ],
        "tls": [
            (r"\.azurewebsites\.net", 0.85),
            (r"\.windows\.net", 0.75),
            (r"microsoft", 0.40),
        ],
        "asn": [
            (r"microsoft", 0.60),
        ],
    },
    CloudProvider.GCP: {
        "hostname": [
            (r"\.storage\.googleapis\.com$", 0.90),
            (r"\.appspot\.com$", 0.85),
            (r"\.run\.app$", 0.85),
            (r"\.cloudfunctions\.net$", 0.85),
            (r"\.googleapis\.com$", 0.75),
        ],
        "dns": [
            (r"google", 0.40),
            (r"1e100\.net", 0.60),
            (r"googledomains", 0.40),
        ],
        "headers": [
            (r"x-goog-", 0.80),
            (r"x-cloud-trace-context", 0.75),
        ],
        "server": [
            (r"gse", 0.50),
            (r"gws", 0.50),
            (r"google frontend", 0.75),
            (r"uploadserver", 0.70),
        ],
        "tls": [
            (r"google", 0.40),
            (r"\.appspot\.com", 0.85),
        ],
        "asn": [
            (r"google", 0.60),
        ],
    },
    CloudProvider.CLOUDFLARE: {
        "hostname": [
            (r"\.cloudflare\.com$", 0.80),
            (r"\.workers\.dev$", 0.85),
            (r"\.pages\.dev$", 0.85),
        ],
        "dns": [
            (r"cloudflare", 0.70),
        ],
        "headers": [
            (r"cf-ray", 0.90),
            (r"cf-cache-status", 0.80),
            (r"cf-mitigated", 0.80),
        ],
        "server": [
            (r"cloudflare", 0.85),
        ],
        "tls": [
            (r"cloudflare", 0.60),
        ],
        "asn": [
            (r"cloudflare", 0.70),
        ],
    },
    CloudProvider.FASTLY: {
        "hostname": [
            (r"\.fastly\.net$", 0.85),
            (r"\.fastlylb\.net$", 0.85),
        ],
        "dns": [
            (r"fastly", 0.70),
        ],
        "headers": [
            (r"x-fastly-", 0.85),
            (r"fastly-restarts", 0.80),
        ],
        "server": [
            (r"fastly", 0.80),
        ],
        "tls": [
            (r"fastly", 0.60),
        ],
        "asn": [
            (r"fastly", 0.70),
        ],
    },
    CloudProvider.DIGITALOCEAN: {
        "hostname": [
            (r"\.digitaloceanspaces\.com$", 0.90),
            (r"\.ondigitalocean\.app$", 0.85),
        ],
        "dns": [
            (r"digitalocean", 0.70),
        ],
        "headers": [
            (r"x-do-", 0.70),
        ],
        "server": [],
        "tls": [
            (r"digitalocean", 0.60),
        ],
        "asn": [
            (r"digitalocean", 0.70),
        ],
    },
    CloudProvider.ORACLE: {
        "hostname": [
            (r"\.oraclecloud\.com$", 0.85),
        ],
        "dns": [
            (r"oraclecloud", 0.70),
        ],
        "headers": [
            (r"x-oracle-", 0.70),
        ],
        "server": [],
        "tls": [
            (r"oraclecloud", 0.70),
        ],
        "asn": [
            (r"oracle", 0.60),
        ],
    },
}


class ProviderFingerprinter:
    """Evaluates multi-source signals and attributes assets to cloud providers."""

    @classmethod
    def fingerprint(
        cls,
        hostname: Optional[str] = None,
        cnames: Optional[List[str]] = None,
        dns_records: Optional[List[str]] = None,
        headers: Optional[Dict[str, str]] = None,
        server: Optional[str] = None,
        tls_san: Optional[List[str]] = None,
        asn: Optional[str] = None,
    ) -> Tuple[CloudProvider, float, List[str]]:
        """
        Determines most likely cloud provider, combined confidence score (0.0 to 1.0),
        and list of matched signals.
        """
        scores: Dict[CloudProvider, float] = {p: 0.0 for p in CloudProvider if p != CloudProvider.UNKNOWN}
        matches: Dict[CloudProvider, List[str]] = {p: [] for p in CloudProvider if p != CloudProvider.UNKNOWN}

        headers_str = ""
        server_val = server
        if headers:
            headers_str = " ".join([f"{k}:{v}" for k, v in headers.items()]).lower()
            if not server_val:
                server_val = headers.get("server") or headers.get("Server")

        cnames_str = " ".join(cnames or []).lower()
        dns_str = " ".join(dns_records or []).lower()
        tls_str = " ".join(tls_san or []).lower()
        asn_str = (asn or "").lower()
        server_str = (server_val or "").lower()
        host_str = (hostname or "").lower()

        for provider, categories in PROVIDER_SIGNATURES.items():
            # 1. Hostname signatures
            if host_str:
                for pattern, weight in categories.get("hostname", []):
                    if re.search(pattern, host_str, re.IGNORECASE):
                        scores[provider] += weight
                        matches[provider].append(f"hostname_match:{pattern}")

            # 2. CNAME and DNS
            combined_dns = f"{cnames_str} {dns_str}"
            if combined_dns.strip():
                for pattern, weight in categories.get("dns", []):
                    if re.search(pattern, combined_dns, re.IGNORECASE):
                        scores[provider] += weight * 0.75
                        matches[provider].append(f"dns_match:{pattern}")

            # 3. HTTP Headers
            if headers_str:
                for pattern, weight in categories.get("headers", []):
                    if re.search(pattern, headers_str, re.IGNORECASE):
                        scores[provider] += weight * 0.70
                        matches[provider].append(f"header_match:{pattern}")

            # 4. Server header
            if server_str:
                for pattern, weight in categories.get("server", []):
                    if re.search(pattern, server_str, re.IGNORECASE):
                        scores[provider] += weight * 0.65
                        matches[provider].append(f"server_match:{pattern}")

            # 5. TLS SAN/CN
            if tls_str:
                for pattern, weight in categories.get("tls", []):
                    if re.search(pattern, tls_str, re.IGNORECASE):
                        scores[provider] += weight * 0.60
                        matches[provider].append(f"tls_match:{pattern}")

            # 6. ASN / IP Ownership
            if asn_str:
                for pattern, weight in categories.get("asn", []):
                    if re.search(pattern, asn_str, re.IGNORECASE):
                        scores[provider] += weight * 0.50
                        matches[provider].append(f"asn_match:{pattern}")

        # Determine winner
        best_provider = CloudProvider.UNKNOWN
        best_score = 0.0
        best_signals: List[str] = []

        for p, s in scores.items():
            if s > best_score:
                best_score = s
                best_provider = p
                best_signals = matches[p]

        if best_score < 0.40 or not best_signals:
            return CloudProvider.UNKNOWN, 0.0, []

        # Base confidence from highest score
        base_conf = min(0.95, best_score / 1.5)
        distinct_sources = {sig.split(":")[0] for sig in best_signals}
        if len(distinct_sources) >= 3:
            normalized_conf = min(0.98, max(0.85, base_conf + 0.15))
        elif len(distinct_sources) >= 2:
            normalized_conf = min(0.95, max(0.80, base_conf + 0.10))
        else:
            normalized_conf = min(0.90, max(0.50, base_conf))

        return best_provider, round(normalized_conf, 2), best_signals
