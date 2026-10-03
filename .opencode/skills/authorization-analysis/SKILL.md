---
name: authorization-analysis
description: Authorization flaw analysis covering BOLA/IDOR, broken function-level authorization, and multi-tenant isolation.
---

# Authorization Analysis Methodology

## Core Objective
Evaluate whether authorization boundaries are consistently enforced on every object, tenant, and function. Focus on high-impact logic flaws where an attacker can access or mutate another user's private data.

## Primary Vulnerability Classes
1. **Broken Object Level Authorization (BOLA / IDOR)**:
   * **Horizontal**: User A accesses User B's resources at the same privilege tier (e.g. `GET /api/documents/102` with User A's token).
   * **Vertical**: Standard user accesses Administrator resources or functions.
   * **Tenant Isolation**: Cross-organization or cross-workspace access in multi-tenant SaaS environments.
2. **Broken Function Level Authorization (BFLA)**:
   * Low-privileged user invoking endpoints reserved for higher roles (e.g. `POST /api/admin/users/invite`).
   * Bypassing UI restrictions by calling backend APIs directly.

## Evidence Requirements
* Must prepare two distinct testing accounts: User A (Tenant A) and User B (Tenant B).
* Demonstrate access: Send request using User A's authorization headers against User B's object identifier.
* Confirm that response returns sensitive private data of User B, or modifies User B's state.
* Capture both HTTP request and response in evidence storage.
