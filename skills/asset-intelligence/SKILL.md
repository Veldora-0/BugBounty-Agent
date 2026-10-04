---
name: asset-intelligence
description: Asset normalization, arbitrary-depth recursive hierarchy modeling, DNS/ASN correlation, CDN identification, and provenance tracking.
---

# Asset Intelligence Methodology

## Core Objective
Synthesize raw discovery data into an authoritative, structured attack surface intelligence model. Establish parent-child domain hierarchies across arbitrary recursion depths, correlate network infrastructure (DNS, IP, ASN, TLS), detect CDN edges, and track multi-source discovery provenance with confidence scoring.

## 1. Canonical Normalization
* **Hostname Standardization**: Convert to lowercase, strip trailing DNS root dots (`.`), strip standard web ports (`:80`, `:443`).
* **URL Normalization**: Standardize protocol, remove tracking parameters, decode safe percent-encodings, normalize trailing slashes.
* **Alias Resolution**: Disentangle CNAME chains to associate virtual hosts with underlying infrastructure.
* **Stable Identifiers**: Construct deterministic canonical IDs (e.g. `asset:subdomain:api.example.com`, `asset:ip_address:192.0.2.1`).

## 2. Arbitrary-Depth Recursive Hierarchy
Do NOT limit discovery to fixed 2-tier or 3-tier ceilings. Map recursive subdomains to arbitrary depth levels:
```text
example.com (Depth 0 - Root)
└── api.example.com (Depth 1)
    └── dev.api.example.com (Depth 2)
        └── internal.dev.api.example.com (Depth 3)
            └── test.internal.dev.api.example.com (Depth 4)
                └── microservice.test.internal.dev.api.example.com (Depth 5)
```
Each node in the hierarchy records:
* `id`: Canonical asset identifier (`asset:subdomain:...`).
* `hostname` / `normalized`: Fully qualified domain name.
* `root_domain`: Apex domain matching program scope.
* `parent_hostname`: Direct parent hostname.
* `discovery_depth`: Integer nesting depth relative to the apex root (0 = root, 1 = first level, ...).
* `scope_status`: `IN_SCOPE`, `OUT_OF_SCOPE`, or `AMBIGUOUS`.

## 3. Infrastructure & Network Correlation
* **DNS Intelligence**: Record `A`, `AAAA`, `CNAME`, `MX`, `NS`, and `TXT` records.
* **Wildcard Mitigation**: Probe randomized non-existent subdomains (`_bb_probe_<uuid>.<domain>`) to identify wildcard DNS responses before active resolution to prevent wildcard explosion.
* **IP & ASN Attribution**: Group assets by shared IPv4/IPv6 addresses, BGP Autonomous System Numbers (ASN), and network CIDR blocks via `BELONGS_TO_ASN` relationships.
* **TLS & Certificate Intelligence**: Extract Subject Alternative Names (SANs) from X.509 certificates to discover co-hosted services; enqueue newly discovered in-scope subdomains back into the recursive exploration pipeline.
* **CDN & Cloud Edge Detection**: Identify reverse proxies and cloud edges (Cloudflare, CloudFront, Fastly, Akamai, Azure, GCP) using CNAME fingerprints and BGP ASN mapping to distinguish edge behavior from origin infrastructure (`HOSTED_BY`).

## 4. Multi-Source Provenance & Confidence Calibration
Every asset record preserves historical observation context:
```json
{
  "id": "asset:subdomain:test.internal.dev.api.example.com",
  "type": "SUBDOMAIN",
  "hostname": "test.internal.dev.api.example.com",
  "root_domain": "example.com",
  "parent": "internal.dev.api.example.com",
  "discovery_depth": 4,
  "scope_status": "IN_SCOPE",
  "confidence": "CONFIRMED",
  "status": "VERIFIED",
  "attributes": {
    "dns_records": {"A": ["198.51.100.42"], "CNAME": []},
    "ip_addresses": ["198.51.100.42"],
    "asn": "AS13335",
    "cdn": "Cloudflare",
    "cdn_attribution": "CONFIRMED",
    "is_wildcard": false
  },
  "provenance": [
    {
      "source": "subfinder",
      "method": "passive",
      "confidence": "MEDIUM",
      "timestamp": "2026-10-04T12:00:00Z"
    },
    {
      "source": "dns_resolver",
      "method": "active_dns",
      "confidence": "CONFIRMED",
      "timestamp": "2026-10-04T12:01:00Z"
    }
  ],
  "first_seen": "2026-10-04T12:00:00Z",
  "last_seen": "2026-10-04T12:01:00Z"
}
```

Confidence score progression:
* `LOW`: Unverified passive third-party observation.
* `MEDIUM`: Single reliable observation.
* `HIGH`: Observed by 2 or more independent sources.
* `CONFIRMED`: Verified via active DNS resolution or verified network response.

## 5. CLI Usage & State Management
* **CLI Command**: `bb-assets`
  ```bash
  # Discover recursive assets for a target root with scope validation
  bb-assets --domain example.com --scope scope.yaml --tree

  # Run for an initialized program workspace
  bb-assets --program acme-corp --tree

  # Passive analysis without active DNS or TLS probes
  bb-assets --program acme-corp --passive-only --tree

  # Output full asset graph as JSON
  bb-assets --program acme-corp --json
  ```
* **Persistent Local State**: Asset graphs are stored in `~/BugBounty-Workspace/programs/<name>/state/assets.json` outside of Git.
