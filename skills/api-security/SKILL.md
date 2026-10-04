---
name: api-security
description: API surface discovery, REST/GraphQL intelligence, OpenAPI/Swagger specification parsing, parameter classification, and schema correlation.
---

# API Security & Parameter Intelligence Methodology

## Core Objective
Systematically discover, normalize, catalog, and correlate API attack surfaces and parameter definitions across REST, GraphQL, and RPC architectures. Transform multi-source reconnaissance (HTTP recon, web endpoints, JavaScript bundles, API specifications) into a coherent, queryable API attack surface model without executing intrusive or destructive vulnerability attacks.

---

## 1. Phase 5 Architecture & Multi-Source Correlation

Phase 5 operates as an intelligence and discovery engine. It correlates API endpoints and parameters across prior phases and authoritative specifications:

```
+-------------------------------------------------------------------+
| Phase 2 HTTP Recon | Phase 3 WebApp Endpoints | Phase 4 JS Routes |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                    ApiIntelligenceEngine                          |
|  - Scope Verification (ScopeEngine)                               |
|  - OpenAPI 2.0 (Swagger) & OpenAPI 3.x Parser                     |
|  - GraphQL Surface Detector                                       |
|  - REST Path Parameter Inference & Normalization                  |
|  - Parameter Semantic Role Classification                         |
|  - Bounded Request / Response Schema Builder                      |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|               API Graph (framework/api/graph.py)                  |
|  WebApplication -> ApiApplication -> ApiEndpoint -> ApiParameter |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                 State (state/api.json)                            |
+-------------------------------------------------------------------+
```

---

## 2. Intelligence Capabilities

### A. OpenAPI / Swagger Parsing
* **Supported Formats**: OpenAPI 2.0 (Swagger) and OpenAPI 3.x (JSON and YAML).
* **Extracted Entities**: Base URLs / servers, paths, HTTP methods, operation IDs, query/path/header/cookie/body parameters, request bodies, response schemas, security definitions (`basic`, `bearer`, `api-key`, `oauth2`, `openid-connect`).
* **Safety Bounds**: Enforces maximum path caps, schema recursion limits (depth $\le 5$), and field count ceilings ($\le 100$) to prevent memory exhaustion from cyclic schemas.

### B. REST Intelligence & Path Parameter Inference
* **Deterministic Normalization**: Preserves observed concrete URLs while inferring clean path parameter templates:
  * `/api/v1/users/123` $\longrightarrow$ `/api/v1/users/{user_id}`
  * `/api/orders/550e8400-e29b-41d4-a716-446655440000` $\longrightarrow$ `/api/orders/{order_id}`
* **Inference Guardrails**: Recognizes UUIDs, integer IDs, and hex hashes while strictly preserving static routes (e.g. `/users/me`, `/status`).

### C. GraphQL Intelligence
* **Endpoint Detection**: Flags endpoints matching `/graphql`, `/gql`, content type `application/graphql`, or GraphQL request/response bodies.
* **Controlled Introspection**: Introspection queries (`{ __schema { types { name } } }`) are disabled by default and only executed when explicitly enabled via `--graphql` policy under strict request budgets.

### D. Parameter Intelligence & Semantic Role Classification
* **Multi-Source Parameter Merging**: Unifies parameters discovered across URL query strings, path templates, form inputs, JavaScript code, and API specifications without losing provenance.
* **Semantic Roles**: Classifies parameters into security-relevant categories for downstream validation phases:
  * `user_id`, `account_id`, `resource_id`, `identifier`
  * `redirect`, `callback`, `return_url`
  * `search`, `filter`, `sort`
  * `page`, `limit`, `offset`
  * `token`, `session`
  * `file`, `path`
* **Invariant**: Role classification is security intelligence, NOT a vulnerability finding.

### E. Bounded Schemas & Security Metadata
* Normalizes request and response schemas to structured type definitions (`properties`, `required`, `enums`).
* Captures authentication schemes, headers (`Authorization`, `X-API-Key`), CORS observations, and content types.

---

## 3. CLI Usage (`bb-api`)

```bash
# Render visual ASCII API attack surface tree for a program
bb-api --program myprogram --tree

# Filter API tree by target domain or host
bb-api --program myprogram --domain api.example.com --tree

# Ingest and correlate a specific OpenAPI / Swagger specification
bb-api --program myprogram --spec https://api.example.com/openapi.json

# Highlight GraphQL surfaces
bb-api --program myprogram --graphql --tree

# Export complete API state in JSON
bb-api --program myprogram --json

# Passive correlation only (disables conventional spec probing)
bb-api --program myprogram --passive-only

# Preview operations without persisting to state
bb-api --program myprogram --dry-run

# Resume interrupted analysis
bb-api --program myprogram --resume
```

---

## 4. Operational Boundaries & Safety Guarantees

1. **Discovery Only**: Phase 5 NEVER performs vulnerability exploitation (no SQL injection, command injection, SSRF, BOLA/IDOR exploits, mass assignment attacks, or credential fuzzing).
2. **Safe HTTP Methods**: Active specification discovery requests are strictly restricted to safe read methods (`GET`, `HEAD`, `OPTIONS`). State-changing verbs (`POST`, `PUT`, `DELETE`, `PATCH`) are never automatically executed.
3. **Scope Verification**: Every discovered host and specification URL must pass `ScopeEngine` checks before any network request is issued.
4. **Data Isolation**: All state is persisted in `~/BugBounty-Workspace/programs/<name>/state/api.json` outside the Git repository.
