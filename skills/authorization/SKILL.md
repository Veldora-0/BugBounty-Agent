---
name: authorization
description: Access control testing covering horizontal (BOLA/IDOR), vertical (BFLA), multi-tenant isolation, and dual-account differential verification.
---

# Authorization & Access-Control Intelligence Methodology

## Core Objective
Evaluate whether target applications rigorously enforce access controls across domain objects, privilege tiers, and multi-tenant organizational boundaries. Eliminate unauthorized data exposure, vertical escalation, and cross-tenant leakage through structured, hypothesis-driven, non-destructive testing with strict human approval gating.

---

## 1. Vulnerability Classes & Taxonomy
* **Broken Object Level Authorization (BOLA / IDOR)** (`horizontal`):
  * User A accesses resources belonging to peer User B at the same permission level.
  * Predictable Object Identifiers: Sequential integers, UUIDs, or hashes.
* **Broken Function Level Authorization / Privilege Escalation** (`vertical`):
  * Standard authenticated users invoking administrative routes (e.g. `/api/admin/*`, `/api/manage/*`).
  * Direct invocation of administrative endpoints without role-based access control.
* **Multi-Tenant Boundary Isolation** (`tenant`):
  * Cross-tenant data leakage: Tenant A accesses Tenant B's data via modified tenant headers (`X-Tenant-ID`, `X-Org-ID`), query parameters, or route paths.
* **Unauthenticated Access to Protected Resources** (`unauthenticated`):
  * Endpoints intended for authenticated users accessible anonymously without credentials.
* **Method & Verb Inconsistencies** (`method_inconsistency`):
  * Discrepancies in access control rules when using different HTTP verbs (e.g. `GET` vs `HEAD` vs `OPTIONS`).

---

## 2. Mandatory 3-Point Comparative Baseline Model
A single HTTP 200 response NEVER proves an authorization bypass. Authorization intelligence requires a rigorous 3-point comparative baseline to eliminate false positives:

```text
1. Baseline A (Owner Access):
   Principal A (Owner)  ──► GET /api/v1/documents/101 ──► HTTP 200 (Valid Data)

2. Baseline B (Invalid Resource):
   Principal B (Tester) ──► GET /api/v1/documents/999999 ──► HTTP 404 / Soft-404 (Reference Baseline)

3. Testing Probe (Cross-Principal Access):
   Principal B (Tester) ──► GET /api/v1/documents/101 ──► Evaluated against Baseline A & B
```

### False-Positive Elimination Checks
1. **Soft-404 Detection**: If the test response matches Baseline B with >90% similarity, it is an empty or nonexistent placeholder, NOT an IDOR.
2. **Generic 200 Denial Detection**: Inspects response bodies for explicit denial keywords ("Access Denied", "Forbidden", "Permission Denied", "Sign In").
3. **Login Form Redirection**: Catches HTTP 302 redirects to `/login` or 200 responses containing password input elements.
4. **Semantic Content Matching**: Confirms ownership identifiers or resource payload keys actually appear in the testing response.

---

## 3. Security Boundaries & Invariants
* **Single-Agent Architecture**: Orchestrated exclusively by the single primary agent `Bug-Bounty`. Subagents remain disabled (`depth: 1`, `permissions: subagent: deny`).
* **Non-Destructive Safe Operations**: Only safe HTTP methods (`GET`, `HEAD`, `OPTIONS`) are permitted by default. Destructive operations (`DELETE`, `PUT`, `POST` mutations) are strictly prohibited in automated testing.
* **Zero Credential Persisting in Git**: Session tokens and cookies are referenced by masked identifiers (e.g. `[MASKED_TOKEN]`, `auth-profile-user-a`). Actual tokens reside in researcher volatile memory or environment files (`~/.config/bugbounty-agent/secrets.env`).
* **Human Approval Gate**: Live tests require explicit human authorization (`--approve` or `--approve-id`). The system renders structured dossiers detailing target endpoints, principals, and planned requests.
* **Anti-SSRF & Scope Enforcement**: All target URLs must pass strict offline validation against `scope.yaml` prior to dispatch.

---

## 4. CLI Tooling: `bb-authz`

The engine is driven via the command-line interface `bb-authz`:

```bash
# Render candidate tree with categories and lifecycles
bb-authz --program <name> --tree

# Passive discovery and candidate modeling only (zero HTTP traffic)
bb-authz --program <name> --passive-only

# Review human approval dossiers for pending candidates
bb-authz --program <name> --dossier

# Plan tests without sending live requests
bb-authz --program <name> --dry-run

# Execute approved tests for horizontal BOLA
bb-authz --program <name> --category horizontal --approve

# Test a specific endpoint with explicit approval
bb-authz --program <name> --endpoint "https://api.example.com/documents/101" --approve

# Output structured JSON results
bb-authz --program <name> --json
```

---

## 5. State Management & Evidence Architecture
State is maintained atomically outside Git in `~/BugBounty-Workspace/programs/<name>/state/authorization.json`:
* `principals`: Authorized test principal profiles and privilege tiers.
* `resources`: Discovered resource access targets and identifier types.
* `policies`: Formal expected access decisions (`ALLOW`, `DENY`).
* `test_cases`: Test specifications and comparative baseline results.
* `approved_tests`: Human approval records with approver identity and timestamp.
* `findings`: Cryptographically signed finding records (`FindingDeduplicator` deduplicated).
