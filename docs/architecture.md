# BugBounty-Agent Architecture

## 1. Architectural Philosophy

BugBounty-Agent is built on four core architectural tenets:

1. **Strict Data Isolation**: The Git repository contains **only** the reusable agent framework, methodology, configuration, scripts, tests, templates, and documentation. All target-specific intelligence, scan outputs, HTTP captures, credentials, and findings reside locally on the researcher's system and are strictly ignored by Git.
2. **Deterministic Scope Boundaries**: Every network interaction is pre-validated through the Scope Engine before execution. Silently assuming authorization is architecturally impossible.
3. **Hypothesis-Driven Security Research**: The framework prioritizes structured reasoning:
   $$\text{Observation} \longrightarrow \text{Hypothesis} \longrightarrow \text{Targeted Test} \longrightarrow \text{Evidence} \longrightarrow \text{Validation} \longrightarrow \text{Report}$$
4. **OpenCode Global Integration**: Canonical agent (`agents/Bug-Bounty.md`) and skills (`skills/`) deployed globally to `~/.config/opencode/` via `bb-deploy`, accessible from any working directory with zero duplicate registrations.

---

## 2. System Layers

```text
┌────────────────────────────────────────────────────────┐
│               OpenCode Single-Agent Layer              │
│       (Bug-Bounty unified orchestrator agent)          │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│                 Modular Skills Catalog                 │
│      (18 methodology SKILL.md guides and rules)        │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│              Controlled CLI Wrappers                   │
│   (bb-scope-check, bb-recon, bb-http, bb-nuclei, etc.)  │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│               Framework Core (Python 3)                │
│   ├── framework/scope (Engine, Normalizer, Boundary)   │
│   ├── framework/assets (Graph, DNS, ASN, TLS, CDN)     │
│   ├── framework/recon (Service Probing, Enrichment)    │
│   ├── framework/webapp (Attack Surface, Forms, Crawl)  │
│   ├── framework/api (OpenAPI, GraphQL, Byte Budget)    │
│   ├── framework/state (Manager, Fingerprint, Dedup)    │
│   ├── framework/validation (Policy, TestCases, Compare)│
│   ├── framework/authentication (Models, Sessions, MFA) │
│   ├── framework/ssrf (Canary, Alt-IP, Provider Gates)  │
│   ├── framework/xxe (XML Hardening, Reflection Lab)    │
│   ├── framework/findings (Schema, Lifecycle, Report)   │
│   └── framework/common (Evidence, Tools, XML Security) │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│         Local Runtime Workspace (Outside Git)          │
│   ~/BugBounty-Workspace/programs/<PROGRAM_NAME>/       │
│      (targets, recon, scans, evidence, findings)       │
└────────────────────────────────────────────────────────┘
```

---

## 3. Subsystem Breakdown

### 3.1 Framework Core
* **`framework.scope`**: Implements RFC-compliant DNS normalizations, label boundary checks, CIDR/IP evaluations, and recursive subdomain depth logic.
* **`framework.assets`**: Implements recursive asset graphs, infrastructure attribution, TLS SAN harvesting, and multi-source confidence ratings.
* **`framework.recon` & `framework.webapp`**: Dynamically orchestrates passive/active reconnaissance and structures web application attack surface models (`state/webapps.json`).
* **`framework.api`**: Parses OpenAPI 2.0/3.x specifications up to depth 10, provides opt-in GraphQL introspection, enforces continuous streaming response-byte budgets (`total_bytes_transferred`), and gates loopback fixture ports.
* **`framework.state`**: Manages isolated JSON state storage per program, tracking discovered assets, endpoints, technologies, and coverage metrics.
* **`framework.validation`**: Coordinates bounded security test cases, enforces conservative ceilings via `SecurityTestPolicy`, performs baseline response comparisons (`BaselineComparison`), and hosts pluggable validators (`XxeValidator`, `SsrfValidator`).
* **`framework.ssrf` & `framework.xxe`**: Safely mutates SSRF requests across 5 payload formats, parses alternate numeric IP notations (`parse_alternate_ip`), verifies OOB provider availability and trusted destinations (`validate_oob_destination`), enforces Billion Laughs / quadratic blowup XML parser defenses (`safe_parse_xml`), and classifies synthetic entity reflections conservatively.
* **`framework.findings`**: Enforces strict finding lifecycle transitions (`OBSERVATION` to `VALIDATED`) and formats reports to 17 standard bug bounty disclosure sections.
* **`framework.authentication`**: Models authentication state machines, session lifecycles, and identity boundaries across 14 vulnerability families. Ingests 7 real multi-phase state files (`webapps.json`, `api.json`, `javascript.json`, `assets.json`, `recon.json`, `authorization.json`, and `workflows.json`), executes differential baseline testing via `BoundedAuthenticationExecutor` with anti-SSRF protections, enforces fail-closed scope checking, performs deterministic SHA-256 test deduplication, and persists validated findings to `state/findings.json`.
* **`framework.common`**: Provides cryptographic evidence hashing (SHA-256), credential redaction, safe XML parsing primitives (`xml_safe`), transport utilities, and external tool detection.

### 3.2 Controlled Command Layer
Rather than allowing arbitrary shell execution, agents execute controlled wrapper scripts located in `scripts/`. Every wrapper enforces:
* Input validation and normalization
* Mandatory pre-execution scope verification
* Rate limiting and timeout caps
* Cryptographic evidence capture and token sanitization
