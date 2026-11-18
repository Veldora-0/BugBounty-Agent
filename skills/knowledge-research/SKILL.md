---
name: knowledge-research
description: Architecture for public security intelligence ingestion, disclosure indexing, CVE/CWE reference retrieval, and research writeups.
---

# Knowledge & Public Research Methodology

## Core Objective
Establish a clean, extensible architectural foundation for referencing and retrieving public security research, vulnerability disclosure writeups, standard vulnerability catalogs (CVE, CWE, CISA KEV), and community templates.

## 1. Authorized Public Intelligence Sources
Knowledge ingestion and reference retrieval is strictly confined to verified, publicly accessible security research:
* **Public Bug Bounty Disclosures**:
  * HackerOne Hacktivity (publicly disclosed reports)
  * Bugcrowd Public Research and disclosure summaries
  * Google Bug Hunters public articles and reward summaries
  * YesWeHack and Intigriti community research blogs
* **Standard Catalogs & Taxonomies**:
  * **CWE (Common Weakness Enumeration)**: Architectural flaw categorization.
  * **CVE & NVD (National Vulnerability Database)**: Known component vulnerability records and CVSS vectors.
  * **CISA KEV (Known Exploited Vulnerabilities)**: Actively exploited in-the-wild defect tracking.
  * **OWASP Top 10 & API Top 10**: Canonical web and API security standards.
* **Security Advisories & Community Templates**:
  * GitHub Security Advisories (GHSA)
  * ProjectDiscovery Nuclei Community Templates
  * Vendor security bulletins (Microsoft MSRC, Debian Security Advisories, Google Security).
  * High-quality public security researcher blogs and conference presentations.
* **Search-query reference**:
  * The [Google Hacking Database (GHDB)](https://www.exploit-db.com/google-hacking-database/) is a public index of search queries that may reveal unintentionally indexed material. Use it only as methodology context for a current, authorized program. A GHDB query is not a vulnerability disclosure, not proof that a target is affected, and not target evidence.

## 2. Ingestion & Retrieval Invariants
* **Strict Confidentiality**: NEVER ingest private, confidential, or non-disclosed bug bounty reports.
* **Read-Only Intelligence**: Public research serves as contextual knowledge to inform hypothesis formulation—not as autonomous exploit payloads.
* **Source Attribution**: When citing public research or disclosure writeups in reports, always provide full public URL citations and author attribution.

## 3. Extensible Modular Design
This skill serves as the foundational interface for future retrieval-augmented generation (RAG) and local vector knowledge indexing in subsequent development phases.

## 4. `/Arise` — Phase 23 public research and coverage planning
When the researcher invokes `/Arise`:

1. Load the selected program workspace and validate its current scope configuration offline. If scope is missing or invalid, do not associate research with target assets and do not recommend testing.
2. Build the local coverage snapshot with `bb-plan --program <name> --coverage-only --json`. Use only in-scope assets/endpoints, local technology observations, test fingerprints, and validated findings.
3. Search only public, disclosed reports and public security research using an available read-only web search/research capability. Recheck every saved source URL for continued public availability, attribution, and metadata before marking its source checked. On HackerOne, select **Disclosed** reports; Hacktivity can also contain activity whose report details are not public. Respect source access terms and rate limits. If no research/search capability is available, say sources were not checked; do not claim a search occurred.
   * When useful, consult GHDB as a reference for broad exposure classes such as indexed configuration files or administrative pages. Convert a relevant category into a researcher-reviewed, domain-specific hypothesis; never run an unbounded search or open/download sensitive results automatically. Keep GHDB methodology citations separate from disclosed-report records submitted to `bb-arise`.
4. Retain only source metadata and concise attributed methodology notes. Never copy full report text, private/non-disclosed content, credentials, or target data. Keep public-source claims separate from target evidence.
5. Produce a JSON array of records with `source_url`, `disclosure_status: "PUBLICLY_DISCLOSED"`, `title`, `author` or `source_attribution`, `published_at`, `technologies`, `vulnerability_families`, and `technique_summary` (at most 600 characters). Save it only in the selected program's local workspace, then run `bb-arise --program <name> --discoveries <local-json> --checked-source <verified-host> --unchecked-source <failed-host> --json`, repeating those flags for each source. The local tool rejects reports without explicit public disclosure status, attribution, non-HTTPS or unapproved domains, redacts common secrets, re-evaluates saved entries, and records pruning reasons without retaining deleted report content. Entries are never described as source-checked unless their host was explicitly listed as checked.
6. Run `bb-plan --program <name> --budget <request-budget> --json` to get ranked hypotheses. Explain relevance, confidence, safety, estimated cost, prior coverage, skipped tests, source references, and uncertainty. An empty result is valid; never lower the relevance bar to force recommendations.
7. Recommendations and public reports are not target evidence or permission. Any active follow-up remains a separate action and must pass the existing scope, operator-approval, dispatch, and request-budget gates. Never submit reports automatically.

The local Phase 23 commands perform no target network requests. They consume researcher-reviewed public metadata and local program state; live public-source discovery is performed only through the available public research capability, and source failures are reported explicitly.
