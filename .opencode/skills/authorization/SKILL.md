---
name: authorization
description: Access control testing covering horizontal (BOLA/IDOR), vertical (BFLA), multi-tenant isolation, and dual-account differential verification.
---

# Authorization Security Methodology

## Core Objective
Evaluate whether the application rigorously enforces access controls across objects, roles, and multi-tenant organizational boundaries. Eliminate unauthorized data exposure and unauthorized state modification.

## 1. Vulnerability Classes
* **Broken Object Level Authorization (BOLA / IDOR)**:
  * Horizontal BOLA: User A accesses, modifies, or deletes resources belonging to User B at the same permission level.
  * Predictable Object Identifiers: Sequential integers, timestamps, or predictable GUIDs.
  * Encoded Identifiers: Base64 or hash encodings of sequential IDs.
* **Broken Function Level Authorization (BFLA)**:
  * Vertical Privilege Escalation: Standard authenticated user invokes administrative APIs or functions (e.g. `/api/admin/users`, `/api/manage/roles`).
  * Direct invocation of administrative endpoints without role checks.
* **Multi-Tenant Isolation**:
  * Cross-tenant data leakage: Tenant A accesses Tenant B's data by modifying tenant headers (`X-Tenant-ID`, `X-Org-ID`), URL path parameters, or subdomain identifiers.

## 2. Mandatory Dual-Account Testing Model
To prevent false positives, authorization testing **MUST** be performed using controlled multi-account credentials:

```text
┌─────────────────┐       GET /api/documents/101       ┌──────────────────┐
│  User A (Owner) ├───────────────────────────────────►│  200 OK (Owner)  │
└─────────────────┘                                    └──────────────────┘

┌─────────────────┐       GET /api/documents/101       ┌──────────────────┐
│ User B (Victim) ├───────────────────────────────────►│  403 / 404 (Safe)│
│  or Attacker    │                                    │  200 OK (BOLA!)  │
└─────────────────┘                                    └──────────────────┘
```

## 3. Controlled Verification Procedure
1. **Identify Object IDs**: Locate resource identifiers in URLs, query strings, headers, or request bodies.
2. **Execute Baseline Request**: Send request as Account A (authorized owner) and capture valid baseline response.
3. **Execute Cross-Account Probe**: Re-send identical request using session credentials of Account B (unauthorized user).
4. **Evaluate Differential**:
   * If Account B receives `401 Unauthorized`, `403 Forbidden`, or `404 Not Found`: Authorization is securely enforced.
   * If Account B receives `200 OK` containing Account A's private data: Potential BOLA confirmed.
5. **Unauthenticated Probe**: Re-send request without any authorization headers to check for complete public exposure.

## 4. Evidence Standards
* Every candidate authorization finding must include dual-account HTTP captures showing both the owner response and the unauthorized actor's access.
* Redact all sensitive personal data, authorization tokens, and credentials via `scripts/bb-evidence`.
