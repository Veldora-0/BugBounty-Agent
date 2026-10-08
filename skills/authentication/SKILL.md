---
name: authentication
description: Authentication, Session & Identity Security Intelligence skill for BugBounty-Agent. Models identity lifecycles, session states, MFA boundaries, password reset flows, and JWT structures using controlled differential testing without credential guessing or brute forcing.
---

# Authentication, Session & Identity Security Intelligence Skill

## Mission & Architectural Role

The **authentication** skill equips the `Bug-Bounty` agent with a structured, hypothesis-driven methodology for discovering, modeling, and validating authentication and session security boundaries in authorized targets.

> [!IMPORTANT]
> **Safety Boundary & Invariants**:
> - Strictly non-destructive: **Zero** password spraying, credential stuffing, password guessing, OTP brute-forcing, token enumeration, or CAPTCHA bypass.
> - Researcher-controlled identities only. Never interact with or send reset emails to third-party accounts.
> - Credential protection: Passwords, raw session cookies, and live bearer tokens are **never** persisted in agent state.
> - Human approval gate: State-mutating operations (password reset execution, password changes, MFA enrollments) strictly require human operator confirmation (`--approve`).

---

## 1. Authentication Surface Discovery

The skill correlates intelligence from earlier reconnaissance and analysis phases:
- **Web Applications (Phase 3)**: Form actions, input fields (`password`, hidden tokens), login views, CSRF tokens.
- **JavaScript Intelligence (Phase 4)**: Client-side routing table entries, API endpoint paths, authentication libraries, storage keys.
- **API Security (Phase 5)**: OpenAPI security definitions (`securitySchemes`, `bearerAuth`, `oauth2`), token exchange endpoints.
- **Authorization Engine (Phase 8)**: Principals, roles, and protected resources.
- **Business Logic Engine (Phase 12)**: Workflow transitions and multi-step state machines.

Key endpoint heuristics include:
- Login / Session initialization (`/login`, `/signin`, `/auth/token`, `/session`)
- Termination (`/logout`, `/signout`)
- Password Lifecycle (`/password/change`, `/password/reset`, `/forgot-password`)
- Multi-Factor Authentication (`/mfa`, `/2fa`, `/otp/verify`)
- Token Refresh (`/token/refresh`, `/auth/refresh`)

---

## 2. Structured Identity & Session Modeling

### Identity Profiles (`IdentityProfile`)
Tracks researcher-controlled accounts and observed principals across defined lifecycle states:
- `ANONYMOUS`
- `PARTIALLY_AUTHENTICATED` (e.g., pre-MFA state)
- `MFA_REQUIRED` / `MFA_VERIFIED`
- `AUTHENTICATED`
- `LOGGED_OUT` / `EXPIRED` / `LOCKED`

### Session Profiles (`SessionProfile`)
Tracks session identifiers by their cryptographic SHA-256 fingerprints (`sess_sha256_...`), observing:
- Creation, rotation, and termination across privilege changes.
- Transport mechanisms: headers, query parameters, cookies.
- Cookie attributes (`Secure`, `HttpOnly`, `SameSite`). Note: Missing cookie attributes on non-sensitive cookies are filtered as informational or non-vulnerabilities.

---

## 3. Core Testing Hypotheses & Differential Analysis

### A. Authentication Bypass vs Access Control
- **Differential Baseline**: Compares Anonymous vs Authenticated access to sensitive endpoints.
- **False Positive Rejection**: HTTP 200 returning a login page or static documentation is actively rejected. A bypass requires demonstrated unauthenticated retrieval of sensitive user or tenant resources.

### B. Pre-MFA Privilege Exposure
- Validates whether an endpoint requiring two-factor authentication leaks account or administrative functionality while the session is still in `MFA_REQUIRED` status.

### C. Session Invalidation (Logout & Password Change)
- Submits post-logout or post-password-change requests using the previous session identifier.
- Vulnerability confirmed only if the protected backend continues returning HTTP 200 with active user state rather than HTTP 401/403.

### D. Session Fixation
- Analyzes whether a pre-login session identifier is retained unchanged after authentication and successfully provides authenticated access.

### E. Password Reset Token Lifecycle & Account Enumeration
- **Token Reuse**: Verifies whether a password reset token can be submitted multiple times.
- **Expiration**: Verifies whether expired tokens are rejected.
- **Account Enumeration**: Compares differential error messages and status codes between existing and non-existing accounts. Uniform responses are classified as `NO_ENUMERATION_SIGNAL`.

### F. Token & JWT Intelligence
- Decodes JWT structure locally without network tampering.
- Catalogs presence/absence of `alg`, `iss`, `sub`, `exp`, and custom role/privilege claims.
- Missing `exp` claim is classified as an informational configuration observation, not an automatic critical finding.

---

## 4. Interaction with Other Engines

```
[Phase 3 / 4 / 5: Web, JS & API Intelligence]
                     │
                     ▼
       [Phase 14: Authentication Engine]
       "Is the identity properly authenticated?"
                     │
                     ▼
         [Phase 8: Authorization Engine]
       "Does the authenticated identity have permission to this resource?"
                     │
                     ▼
         [Phase 12: Business Logic Engine]
       "Is the state machine sequence valid?"
                     │
                     ▼
       [Validation & Global Reporting]
```

---

## 5. CLI Execution & Tooling

```bash
# Display visual tree of authentication surfaces and findings
bb-auth --program <program> --tree

# Passive discovery and modeling without active requests
bb-auth --program <program> --passive-only --json

# List generated hypotheses
bb-auth --program <program> --hypotheses

# Run dry-run validation plan
bb-auth --program <program> --flow session --dry-run

# Run local deterministic offline lab
bb-auth --lab --tree
```
