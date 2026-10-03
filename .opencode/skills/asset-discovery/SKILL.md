---
name: asset-discovery
description: Controlled passive and active asset discovery, certificate transparency analysis, DNS mapping, and HTTP service probing.
---

# Asset Discovery Methodology

## Core Objective
Systematically map the authorized external attack surface without triggering aggressive or disruptive traffic. Discover domains, subdomains, web applications, and network services within program scope.

## Discovery Workflow
1. **Passive Reconnaissance (Zero Target Traffic)**:
   * Query certificate transparency logs (crt.sh, Certspotter).
   * Query passive DNS datasets via `subfinder` and `assetfinder`.
   * Cross-reference WHOIS / ASN data where authorized.
2. **Strict Scope Filtering**:
   * Feed all discovered hostnames through `bb-scope-check`.
   * Discard any third-party SaaS hostnames (e.g. `*.s3.amazonaws.com`, `*.zendesk.com`) unless explicitly owned and authorized.
3. **Controlled Active Resolution**:
   * Resolve DNS records (`A`, `AAAA`, `CNAME`) for in-scope candidates.
   * Identify dangling CNAME records for takeover evaluation.
4. **HTTP Service Discovery**:
   * Probe standard web ports (80, 443, 8080, 8443) using `httpx` with configured rate limits (`--rate-limit 5`).
   * Capture status codes, title, server headers, and TLS certificates.

## Standard Tool Integration
* `bb-recon --program <program_name> --domain <in_scope_domain>`
* Directly wraps `subfinder`, `assetfinder`, and `httpx`.

## Rules & Caveats
* Never execute high-speed port scanners without explicit scope permission.
* Never test out-of-scope siblings or customer tenants discovered in DNS logs.
* Maintain discovery provenance: record where each asset was first identified.
