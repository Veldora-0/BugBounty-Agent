---
name: javascript
description: Static analysis of JavaScript bundles, client routing, secrets classification with masking, dependency detection, source maps, and API endpoint extraction.
---

# JavaScript Security Analysis Methodology

## Core Objective
Extract hidden application routes, parameter definitions, client dependencies, and architectural logic embedded in frontend JavaScript bundles. Convert raw JavaScript resources discovered during Phase 3 into structured, queryable security intelligence without executing untrusted target code.

---

## 1. Static Analysis Architecture (Phase 4)

The **JavaScript Intelligence Engine** operates on JavaScript resources cataloged in `state/webapp.json` or provided via CLI. It performs pure static pattern analysis and deterministic extraction.

```
+-----------------------------------------------------------+
|          JavaScript Resources (state/webapp.json)         |
+-----------------------------------------------------------+
                             |
                             v
+-----------------------------------------------------------+
|               JavaScriptIntelligenceEngine                |
|  - Scope Verification (ScopeEngine)                       |
|  - Bounded Ingestion Policy (max files, byte budget)      |
+-----------------------------------------------------------+
                             |
                             v
+-----------------------------------------------------------+
|                    JavaScriptAnalyzer                     |
|  - Endpoints (fetch, axios, ajax, xhr, websocket, rest)   |
|  - Frontend Routes (react, vue, vue-router, client link)  |
|  - Parameters (query params, URLSearchParams, req.query)  |
|  - Dependencies (React, Vue, Angular, Axios, Lodash, etc)|
|  - Source Map References (//# sourceMappingURL=...)       |
|  - Strings & Credentials (classified & masked)            |
+-----------------------------------------------------------+
                             |
                             v
+-----------------------------------------------------------+
|           State & Intelligence (state/javascript.json)    |
+-----------------------------------------------------------+
```

---

## 2. Extraction Capabilities

### A. Endpoint Extraction
* **HTTP Client Patterns**: `fetch(...)`, `axios.<method>(...)`, `$.ajax(...)`, `$.get(...)`, `$.post(...)`, `XMLHttpRequest.open(...)`.
* **Realtime Channels**: `new WebSocket(...)`.
* **Path Templates**: REST endpoints (`/api/v1/...`, `/v2/...`, `/graphql`, `/oauth/...`, `/admin/...`).
* Normalizes URLs relative to script source or domain host.

### B. Frontend SPA Route Discovery
* Analyzes routing declarations for React Router (`<Route path="...">`), Vue Router (`path: '...'`), and client links.
* Uncovers hidden administrative paths, internal portals, and unlinked views.

### C. Parameter Discovery
* Identifies parameter keys from `URLSearchParams`, query string templates (`?param=`, `&param=`), object keys in queries, and request destructurings.
* Seeds parameter lists for downstream authorization and injection testing.

### D. Client Dependency Identification
* Identifies client frameworks and utility libraries: React, Vue.js, Angular, jQuery, Axios, Lodash, Next.js, Webpack, Vite.
* Extracts detected version strings where embedded.

### E. Source Map Detection
* Discovers source map directives (`//# sourceMappingURL=...` or `//@ sourceMappingURL=...`).
* Resolves source map targets deterministically against the script URL.

### F. Sensitive String Classification & Masking
* **Strict Masking Invariant**: Sensitive credentials (AWS access keys, JWTs, private keys, bearer tokens) are **automatically masked** in all memory structures, serialized state, and console output.
* **Sensitivity Classification**:
  * `HIGH_CONFIDENCE_SECRET`: AWS Keys (`AKIA...`), GitHub Personal Access Tokens, Private Key blocks (`BEGIN PRIVATE KEY`).
  * `SENSITIVE_LOOKING`: Slack Webhooks, Bearer tokens, high-entropy API tokens.
  * `INTERESTING`: Internal hostnames (`.internal`, `.corp`), S3 bucket URLs, Google Cloud Storage endpoints, Firebase URLs, `process.env.*` references.
  * `INFORMATIONAL`: Public identifiers, generic configuration keys.
* **Triage Rule**: An exposed string or token in frontend JavaScript is NOT an automatic vulnerability. Expected public keys (e.g. Firebase API keys, Google Maps keys) must not be reported as findings unless they confer unauthorized privileged operations.

---

## 3. CLI Usage (`bb-js`)

```bash
# Analyze all JavaScript resources for a program
bb-js --program myprogram

# Target a specific domain
bb-js --program myprogram --domain example.com

# Target a single JavaScript resource URL
bb-js --program myprogram --resource https://example.com/static/js/main.js

# Target a specific asset ID from AssetGraph
bb-js --program myprogram --asset ast_1234567890ab

# Display hierarchical extracted intelligence tree
bb-js --program myprogram --tree

# Output JSON summary
bb-js --program myprogram --json

# Resume interrupted analysis
bb-js --program myprogram --resume

# Preview operations without network downloads
bb-js --program myprogram --dry-run
```

---

## 4. State Management (`state/javascript.json`)

The state is persisted atomically in `~/BugBounty-Workspace/<program>/state/javascript.json`:
* `resources`: Catalog of analyzed JavaScript resources with hash, byte size, minification status, and timestamps.
* `endpoints`: Discovered API and HTTP endpoints with extraction methods and provenance.
* `routes`: Client-side single-page application routes.
* `parameters`: Discovered query parameter keys with provenance.
* `dependencies`: Detected libraries, frameworks, and versions.
* `source_maps`: Detected source map directives and target URLs.
* `interesting_strings`: Classified strings with masked values and contextual evidence snippets.

---

## 5. Security & Operational Guardrails

1. **Purely Static Analysis**: Untrusted target scripts are NEVER executed (`eval`, `exec`, or browser execution of downloaded code are forbidden during this phase).
2. **Scope Verification**: Every script URL and target domain is validated against `scope.yaml` before download. Out-of-scope targets are skipped.
3. **Budget & Rate Limiting**: Bounded by `JavaScriptPolicy` (`max_files=200`, `max_requests=500`, `max_bytes_per_file=5MB`, `total_byte_budget=50MB`).
4. **Secret Protection**: Real credential secrets are never stored in plaintext or logged. All evidence snippets mask sensitive values.
5. **No Automated Probing**: Extracting an endpoint does NOT trigger automated probes or vulnerability testing. Downstream phases formulate hypotheses before testing.
