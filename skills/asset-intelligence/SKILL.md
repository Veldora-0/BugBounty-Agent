---
name: asset-intelligence
description: Scoped asset graph construction from supplied roots, seeds, optional Subfinder results, DNS answers, and bounded TLS SAN observations.
---

# Asset Intelligence Methodology

## Core Objective
Build a scoped local asset graph from researcher-supplied roots and seeds, optional Subfinder results, DNS answers, and bounded TLS certificate SAN observations. The graph can represent arbitrary subdomain depth subject to the configured depth and asset budgets. It is an inventory of collected observations, not a complete or authoritative map of a target.

## 1. Canonical Normalization
* **Hostname Standardization**: Convert to lowercase, strip trailing DNS root dots (`.`), strip standard web ports (`:80`, `:443`).
* **URL Normalization**: Standardize protocol, remove tracking parameters, decode safe percent-encodings, normalize trailing slashes.
* **Alias Resolution**: Record CNAME answers returned by the resolver as relationships; the engine does not guarantee that it has traced every hop in a provider's alias chain. The built-in resolver returns A, AAAA, and CNAME data; it does not query MX, NS, or TXT records.
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
* **DNS Intelligence**: The built-in resolver records `A`, `AAAA`, and `CNAME` answers. It does not query `MX`, `NS`, or `TXT` records.
* **Wildcard Signal**: When active discovery and scope permit it, query two randomized subdomains under the root and record whether they share wildcard answers. The result is currently a graph annotation; it does not suppress candidate names from the graph.
* **IP Attribution**: Link resolved IPv4/IPv6 addresses to hostnames. No built-in ASN or BGP provider is configured; ASN, organization, and CIDR fields default to `UNKNOWN` unless a caller supplies an explicit resolver hook. No `BELONGS_TO_ASN` edge is created for `UNKNOWN`.
* **TLS & Certificate Intelligence**: The active workflow may make at most 100 bounded, scope-checked TLS SAN probes across a discovery run. Only in-scope names beneath the configured root are queued. This is certificate metadata, not proof that a name is a live service or target-owned.
* **CDN & Cloud Edge Detection**: Built-in identification uses known CNAME suffix patterns. ASN-based identification is possible only when a caller supplies a resolver hook that returns a known ASN; the default `UNKNOWN` result cannot support it. CDN attribution is heuristic and does not identify the origin server.

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
    "asn_info": {"asn": "UNKNOWN", "org": "UNKNOWN", "cidr": "198.51.100.42/32"},
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

Confidence labels are heuristic model values, not calibrated probabilities. They are assigned from the observation source/type and may be upgraded when the graph receives additional provenance. Treat them as relative bookkeeping labels, not as proof that an asset is reachable, owned by the program, or authorized for testing.

## 5. CLI Usage & State Management
* **CLI Command**: `bb-assets`
  ```bash
  # Build a graph for a target root with explicit scope validation
  bb-assets --domain example.com --scope scope.yaml --tree

  # Run for an initialized program workspace
  bb-assets --program acme-corp --tree

  # Passive analysis without active DNS or TLS probes
  bb-assets --program acme-corp --passive-only --tree

  # Opt in to one bounded passive Subfinder query per configured root
  bb-assets --program acme-corp --subfinder --passive-only --tree

  # Output full asset graph as JSON
  bb-assets --program acme-corp --json
  ```
* **Persistent Local State**: Asset graphs are stored in `~/BugBounty-Workspace/programs/<name>/state/assets.json` outside of Git.
* **Discovery boundary**: The graph supports arbitrary depth, but the default run does not perform generic recursive name generation. CLI Subfinder integration is queried once per root; deeper children can come from supplied seeds or accepted in-scope TLS SAN observations. Discovery is bounded by `--depth` and `--budget`.
