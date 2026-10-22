---
name: api-security
description: API surface discovery, REST/GraphQL intelligence, OpenAPI/Swagger specification parsing, parameter classification, and schema correlation.
---

# API Security & Parameter Intelligence Methodology

## Core Objective
Systematically discover, normalize, catalog, and correlate API attack surfaces and parameter definitions across REST, GraphQL, and RPC architectures. Transform multi-source reconnaissance (HTTP recon, web endpoints, JavaScript bundles, API specifications) into a coherent, queryable API attack surface model without executing intrusive or destructive vulnerability attacks.

Orchestrated globally by the single primary agent **`Bug-Bounty`** as part of its 18 modular skills catalog.

---

## 1. Architecture & Multi-Source Correlation

Phase 5 operates as an intelligence and discovery engine. It correlates API endpoints and parameters across prior phases and authoritative specifications:

```
+-------------------------------------------------------------------+
| Phase 2 HTTP Recon | Phase 3 WebApp Endpoints | Phase 4 JS Routes |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                    ApiIntelligenceEngine                          |
|  - Fail-Closed Scope Verification (ScopeEngine)                   |
|  - Anti-SSRF Destination IP Pinning & Safe Redirect Handling     |
|  - OpenAPI 2.0 (Swagger) & OpenAPI 3.x Parser ($ref & Precedence) |
|  - GraphQL Surface Detector & Safe Opt-In Introspection           |
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
|  Dual-Export: {"catalog": {...}, "endpoints": [...]}              |
+-------------------------------------------------------------------+
```

---

## 2. Intelligence Capabilities

### A. OpenAPI / Swagger Parsing & Schema Resolution
* **Supported Formats**: OpenAPI 2.0 (Swagger) and OpenAPI 3.x (JSON and YAML).
* **Local Reference Resolution**: Recursively resolves RFC 6901 local `$ref` pointers (e.g. `#/components/schemas/User`) up to depth 5 with circular reference protection. Strictly forbids external network or file references.
* **Parameter Precedence**: Operation-level parameters override path-level parameters sharing the same `(name, location)` tuple while preserving distinct locations (e.g., path `id` vs query `id`).
* **Extracted Entities**: Base URLs / servers, paths, HTTP methods, operation IDs, query/path/header/cookie/body parameters, request bodies, response schemas, security definitions (`basic`, `bearer`, `api-key`, `oauth2`, `openid-connect`).
* **Safety Bounds**: Enforces maximum path caps, schema recursion limits (depth $\le 5$), and field count ceilings ($\le 100$) to prevent memory exhaustion from cyclic schemas.

### B. REST Intelligence & Path Parameter Inference
* **Deterministic Normalization**: Preserves observed concrete URLs while inferring clean path parameter templates:
  * `/api/v1/users/123` $\longrightarrow$ `/api/v1/users/{user_id}`
  * `/api/orders/550e8400-e29b-41d4-a716-446655440000` $\longrightarrow$ `/api/orders/{order_id}`
* **Inference Guardrails**: Recognizes UUIDs, integer IDs, and hex hashes while strictly preserving static routes (e.g. `/users/me`, `/status`).

### C. GraphQL Intelligence
* **Endpoint Detection**: Flags endpoints matching `/graphql`, `/gql`, content type `application/graphql`, or GraphQL request/response bodies.
* **Controlled Introspection**: Introspection queries (`{ __schema { types { name } } }`) are **disabled by default** (`allow_graphql_introspection=False`).
* **Opt-In Introspection**: When explicitly enabled via `--allow-graphql-introspection`:
  * Enforces fail-closed scope checking before issuing queries.
  * Queries are strictly read-only, non-destructive, structurally bounded (selection set nesting depth $\le 6$, schema traversal depth $\le 3$: `__schema` $\to$ `types` $\to$ `fields` with bounded `args`), avoiding recursive or circular fragment expansions, and never issue mutations.
  * Responses are parsed into `ApiEndpoint` operations (`#query:field` and `#mutation:field`) and `ApiParameter` input arguments.

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

### E. Bounded Schemas & Cross-Engine State Compatibility
* Normalizes request and response schemas to structured type definitions (`properties`, `required`, `enums`).
* Captures authentication schemes, headers (`Authorization`, `X-API-Key`), CORS observations, and content types.
* **Dual Export**: `state/api.json` maintains backward-compatible `"catalog"` dictionary mapping along with full `"endpoints"` list, embedded parameters, and compatibility properties (`.url`, `.path`, `.app_id`, `.role`), ensuring zero breakage across downstream consumers (`authorization`, `injection`, `validation`, `authentication`).

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

# Opt-in active GraphQL schema introspection
bb-api --program myprogram --graphql --allow-graphql-introspection --tree

# Resource limit enforcement and custom timeouts
bb-api --program myprogram --max-endpoints 250 --timeout 8.0 --tree

# Export complete API state in JSON
bb-api --program myprogram --json

# Passive correlation only (disables conventional spec probing)
bb-api --program myprogram --passive-only

# Preview operations in-memory without persisting to state
bb-api --program myprogram --dry-run --tree

# Resume interrupted analysis
bb-api --program myprogram --resume
```

---

## 4. Operational Boundaries & Safety Guarantees

1. **Discovery Only**: Phase 5 NEVER performs vulnerability exploitation (no SQL injection, command injection, SSRF, BOLA/IDOR exploits, mass assignment attacks, or credential fuzzing).
2. **Safe HTTP Methods**: Active specification discovery requests are strictly restricted to safe read methods (`GET`, `HEAD`, `OPTIONS`) and safe, read-only GraphQL queries. State-changing verbs (`POST`, `PUT`, `DELETE`, `PATCH`) are never automatically executed on user endpoints.
3. **Fail-Closed Scope Verification**: Every discovered host and specification URL must pass `ScopeEngine` checks before any network request is issued. If `ScopeEngine` is omitted, active network testing fails closed immediately.
4. **Anti-SSRF Transport & Protocol Invariants**: Destination hosts are resolved to IPs and verified against prohibited ranges (loopback, RFC 1918 private, link-local metadata `169.254.169.254`). Pinned connections prevent DNS rebinding. Redirects re-verify scope at every hop and forbid protocol downgrades (HTTPS $\to$ HTTP).
5. **Data Isolation**: All state is persisted in `~/BugBounty-Workspace/programs/<name>/state/api.json` outside the Git repository.
6. **Downstream Pipeline**: API schemas and parameters feed Phase 8 (`authorization` / BOLA), Phase 9 (`oob` / `ssrf`), Phase 10 (`injection`), and Phase 11 (`http_trust` / CORS / HPP).

---

## 5. API Header Trust, CORS, and Parameter Pollution (Phase 11)

API endpoints are prime targets for cross-origin trust failures, unkeyed cache poisoning, and HTTP Parameter Pollution:
* **CORS Trust Analysis**: REST APIs handling authentication headers or cookies are evaluated for credentialed reflection (`Access-Control-Allow-Credentials: true` with reflected `Origin`).
* **HTTP Parameter Pollution (HPP)**: Evaluates whether duplicate query parameters (`?id=1&id=2`) bypass API authorization checks or cause parser confusion between API gateway and microservices.
* **Header-Based Routing & Forwarded Trust**: Probes whether microservice routing trusts `X-Forwarded-Host` or `Forwarded` over API gateway hostname rules.
