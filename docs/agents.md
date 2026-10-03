# BugBounty-Agent — Agents Reference

This reference details the role, inputs, outputs, and behavioral boundaries of each agent in the BugBounty-Agent framework.

---

## 1. Primary Orchestrator

### `bb-hunter`
* **Role**: Primary Security Research Orchestrator.
* **Responsibilities**:
  1. Loads `scope.yaml` and initializes program state.
  2. Directs `bb-recon` to map attack surfaces.
  3. Coordinates with `bb-asset` to maintain a normalized asset inventory.
  4. Formulates testable security hypotheses.
  5. Dispatches specialist subagents (`bb-authz`, `bb-injection`, `bb-business-logic`, `bb-cloud`).
  6. Submits all candidates to `bb-validator` for verification.
  7. Ensures issues are deduplicated by `bb-dedup`.
  8. Triggers `bb-report` to generate disclosure-ready markdown reports.
  9. Tracks coverage across categories: Authentication, Authorization, API, JavaScript, Uploads, Business Logic, and Cloud.

---

## 2. Authorization & Reconnaissance Specialists

### `bb-scope`
* **Role**: Scope and authorization verification.
* **Network Access**: **None**. Offline verification against `scope.yaml`.
* **Outputs**: `IN_SCOPE`, `OUT_OF_SCOPE`, or `AMBIGUOUS` with provenance, depth, and matched rule.

### `bb-recon`
* **Role**: Controlled reconnaissance.
* **Tools**: `subfinder`, `assetfinder`, `amass`, `httpx`.
* **Outputs**: Discovered subdomains, DNS records, responsive HTTP ports, server banners, and tech stacks.

### `bb-asset`
* **Role**: Asset normalization and correlation.
* **Outputs**: Correlated asset records in `state/assets.json` with parent-child hierarchy, depth, and discovery provenance.

---

## 3. Application & Surface Specialists

### `bb-web`
* **Role**: Web application mapping and surface analysis.
* **Investigates**: Login workflows, session cookie security flags, CORS policies, CSRF protections, open redirects, and debug exposures.

### `bb-js`
* **Role**: JavaScript analysis.
* **Investigates**: Client route tables, hidden API endpoints, unminified source maps, and client-side authorization assumptions.
* **Caveat**: Distinguishes between public frontend API keys and privileged credentials.

### `bb-api`
* **Role**: REST, GraphQL, and WebSocket API analysis.
* **Investigates**: HTTP method handling (`OPTIONS`, `PUT`, `DELETE`), API versioning differences (`/v1/` vs `/v2/`), GraphQL introspection, and hidden parameter schemas.

---

## 4. Vulnerability Specialists

### `bb-authz`
* **Role**: Authorization vulnerability specialist.
* **Investigates**: Broken Object Level Authorization (BOLA/IDOR), Broken Function Level Authorization (BFLA), and tenant boundary isolation.
* **Requirement**: Requires controlled dual-account proof of access.

### `bb-injection`
* **Role**: Safe input-handling and injection specialist.
* **Investigates**: XSS, SQLi, SSTI, command injection, and path traversal.
* **Requirement**: Strictly non-destructive probes (time delay, arithmetic evaluations, safe read-only markers).

### `bb-business-logic`
* **Role**: Business logic and workflow specialist.
* **Investigates**: Sequence skipping, race conditions, decimal rounding, and quantity manipulation.
* **Boundary**: Zero real-world financial transactions or destructive side-effects.

### `bb-cloud`
* **Role**: Cloud configuration and storage review.
* **Investigates**: Public bucket permissions, cloud metadata exposure (SSRF), and dangling CNAME records.
* **Boundary**: Never attacks unrelated third-party cloud infrastructure.

---

## 5. Quality Control & Delivery Specialists

### `bb-validator`
* **Role**: Adversarial finding validator.
* **Responsibilities**: Challenges candidate findings, tests reproducibility, checks scope, and eliminates scanner illusions.
* **Outputs**: `VALIDATED`, `REJECTED`, or `NEEDS_MORE_EVIDENCE`.

### `bb-dedup`
* **Role**: Finding and test deduplication.
* **Responsibilities**: Identifies duplicate reports sharing the same root cause, endpoint, or affected component. Prevents redundant testing via fingerprint hashes.

### `bb-report`
* **Role**: Professional vulnerability report generation.
* **Responsibilities**: Converts validated findings into 17-section markdown disclosure reports.
* **Boundary**: Realistic CVSS severity; strictly no automated external submissions.
