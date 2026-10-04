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

## 2. Ingestion & Retrieval Invariants
* **Strict Confidentiality**: NEVER ingest private, confidential, or non-disclosed bug bounty reports.
* **Read-Only Intelligence**: Public research serves as contextual knowledge to inform hypothesis formulation—not as autonomous exploit payloads.
* **Source Attribution**: When citing public research or disclosure writeups in reports, always provide full public URL citations and author attribution.

## 3. Extensible Modular Design
This skill serves as the foundational interface for future retrieval-augmented generation (RAG) and local vector knowledge indexing in subsequent development phases.
