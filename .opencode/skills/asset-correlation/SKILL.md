---
name: asset-correlation
description: Asset normalization, relationship modeling, duplicate consolidation, and provenance tracking across discovered infrastructure.
---

# Asset Correlation Methodology

## Core Objective
Synthesize raw recon outputs into a cohesive, structured attack surface model. Prevent fragmented analysis by clustering related services, tracking parent-child domain hierarchies, and recording provenance.

## Correlation Operations
1. **Canonical Normalization**:
   * Lowercase all hostnames and URLs.
   * Strip trailing DNS root dots and default web ports (:80, :443).
   * Group aliases (e.g. CNAME pointers pointing to the same virtual host).
2. **Hierarchy Modeling**:
   * Calculate subdomain depth relative to root domain.
   * Establish parent pointers (e.g. `v2.dev.api.corp.com` -> parent `dev.api.corp.com`).
3. **Infrastructure Clustering**:
   * Correlate assets sharing identical IP addresses or CDN providers (Cloudflare, Fastly, Akamai).
   * Correlate assets sharing TLS certificates or Subject Alternative Names (SANs).
4. **Lifecycle & Provenance**:
   * Assign `first_seen` and `last_seen` UTC timestamps.
   * Attribute discovery source (e.g. `source: "subfinder:crt.sh"`).

## Output Expectations
Every correlated asset record must adhere to the schema:
```json
{
  "hostname": "api.example.com",
  "root_domain": "example.com",
  "parent": "example.com",
  "depth": 1,
  "scope_status": "IN_SCOPE",
  "technologies": ["Nginx", "Node.js", "Express"],
  "first_seen": "2026-10-01T12:00:00Z",
  "last_seen": "2026-10-03T18:30:00Z"
}
```
