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

## 4. `/Arise` — agent-wide public methodology learning
`/Arise` is independent of any target or program. Its purpose is to find useful public bug-finding methodology the `Bug-Bounty` agent does not yet capture well. Compare the 18 skills and the existing methodology library to public, disclosed bounty reports, security research, standards, advisories, and reputable technical writeups. Seek novel or underrepresented methods across vulnerability families; do not search for reports because they mention a currently selected target.

Use an available read-only research/search capability and respect source terms and rate limits. If unavailable, say that source discovery did not happen. Never ingest private or undisclosed reports. GHDB is a methodology reference for search-exposure classes, not a disclosure or proof; do not run broad dorks or retrieve sensitive indexed content.

Store only a compact reference: public source URL, title, author/source attribution, publication date if available, vulnerability family, optional technology tags, and an attributed methodology note of at most 600 characters. Reports must be publicly disclosed; official public standards and methodology references may use `PUBLICLY_AVAILABLE`. Do not save report bodies, screenshots, copied long text, credentials, target details, or raw evidence. Save a researcher-reviewed JSON array in a temporary file outside the repository, import it using `scripts/bb-arise --discoveries <local-json> --checked-source <host> --unchecked-source <host> --json` from the repository root (or `bb-arise` if installed globally), and remove that staging file after a successful import. Its default library is `<OPENCODE_CONFIG_DIR>/bug-bounty-agent/knowledge/methodology.json` (normally `~/.config/opencode/bug-bounty-agent/knowledge/methodology.json`), shared across all program workspaces and outside Git. The CLI is offline, validates source and metadata, and caps the library at 1,000 references. It never removes methodology merely because a target does not use a tagged technology, because a test was run, or because a source check was unavailable; if full, ask for curation instead of deleting automatically.

When the researcher later asks for target research, validate that program's scope first. Read the global methodology library through `scripts/bb-plan --program <name> --budget <request-budget> --json` from the repository root (or use `bb-plan` if installed globally); relevant references are attached to recommendations by vulnerability family, even when source technologies differ. The agent should use the short note to decide whether a source link is useful, inspect the public source on demand through its read-only research capability, and adapt its method to the current authorized surface. Clearly distinguish source-derived methodology from local observations and target evidence. A reference does not prove a vulnerability, confer permission, or trigger testing. Active follow-up still requires current scope checks, operator approval, the dispatcher, and request/time/response budgets.
