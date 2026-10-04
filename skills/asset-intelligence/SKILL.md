---
name: asset-intelligence
description: Asset normalization, arbitrary-depth recursive hierarchy modeling, DNS/ASN correlation, CDN identification, and provenance tracking.
---

# Asset Intelligence Methodology

## Core Objective
Synthesize raw discovery data into an authoritative, structured attack surface intelligence model. Establish parent-child domain hierarchies across arbitrary recursion depths, correlate network infrastructure (DNS, IP, ASN, TLS), detect CDN edges, and track discovery provenance.

## 1. Canonical Normalization
* **Hostname Standardization**: Convert to lowercase, strip trailing DNS root dots (`.`), strip standard web ports (`:80`, `:443`).
* **URL Normalization**: Standardize protocol, remove tracking parameters, decode safe percent-encodings, normalize trailing slashes.
* **Alias Resolution**: Disentangle CNAME chains to associate virtual hosts with underlying infrastructure.

## 2. Arbitrary-Depth Recursive Hierarchy
Do NOT limit discovery to fixed 2-tier or 3-tier ceilings. Map recursive subdomains to arbitrary depth levels:
```text
example.com (Depth 0 - Root)
└── api.example.com (Depth 1)
    └── dev.api.example.com (Depth 2)
        └── internal.dev.api.example.com (Depth 3)
            └── test.internal.dev.api.example.com (Depth 4)
```
Each node in the hierarchy records:
* `hostname`: Fully qualified domain name.
* `root_domain`: Apex domain matching program scope.
* `parent`: Direct parent hostname.
* `depth`: Integer nesting depth relative to the apex root.

## 3. Infrastructure & Network Correlation
* **DNS Intelligence**: Record `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, and `SOA` records.
* **Wildcard Detection**: Probe randomized non-existent subdomains (e.g. `xyz123random.example.com`) to identify wildcard DNS responses before active resolution.
* **IP & ASN Attribution**: Group assets by shared IPv4/IPv6 addresses, BGP Autonomous System Numbers (ASN), and network CIDR blocks.
* **TLS & Certificate Intelligence**: Extract Subject Alternative Names (SANs) from X.509 certificates to discover co-hosted services and organizational assets.
* **CDN & Cloud Edge Detection**: Identify reverse proxies and cloud edges (Cloudflare, CloudFront, Fastly, Akamai) using `cdncheck` to distinguish edge behavior from origin infrastructure.

## 4. Provenance & Lifecycle Tracking
Every asset record must preserve historical observation context:
```json
{
  "hostname": "test.internal.dev.api.example.com",
  "root_domain": "example.com",
  "parent": "internal.dev.api.example.com",
  "depth": 4,
  "scope_status": "IN_SCOPE",
  "ip_addresses": ["198.51.100.42"],
  "asn": "AS13335",
  "cdn": "Cloudflare",
  "wildcard": false,
  "technologies": ["Nginx", "Node.js", "Express"],
  "provenance": {
    "source_tool": "subfinder",
    "provider": "crt.sh",
    "timestamp": "2026-10-04T12:00:00Z"
  },
  "first_seen": "2026-10-04T12:00:00Z",
  "last_seen": "2026-10-04T12:00:00Z"
}
```

## 5. Usage Guidelines
* Use `bb-target-normalize` for canonical target parsing.
* Store correlated records in local state: `~/BugBounty-Workspace/programs/<name>/state/assets.json`.
* Regularly reconcile asset updates to eliminate duplicate hostnames arising from case variances or protocol permutations.
