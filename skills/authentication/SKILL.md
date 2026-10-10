---
name: authentication
description: Authentication, Session & Identity Security Intelligence skill for BugBounty-Agent. Models identity lifecycles, session states, MFA boundaries, password reset flows, and JWT structures using controlled differential testing without credential guessing or brute forcing.
---

# Authentication, Session & Identity Security Intelligence Skill

## Mission & Architectural Role

The **authentication** skill equips the `Bug-Bounty` agent with a structured, hypothesis-driven methodology for discovering, modeling, and validating authentication and session security boundaries in authorized targets.

> [!IMPORTANT]
> **Safety Invariants & Scope Boundaries**:
> - Strictly non-destructive: **Zero** password spraying, credential stuffing, password guessing, OTP brute-forcing, token enumeration, or CAPTCHA bypass.
> - Researcher-controlled identities only. Never interact with or send reset emails to third-party accounts.
> - Credential protection: Passwords, raw session cookies, and live bearer tokens are **never** persisted in agent state or Git. Recursive structural redaction sanitizes query parameters, cookies, headers, and nested JSON payloads (`[REDACTED_PASSWORD]`, `[REDACTED_COOKIE]`, `[REDACTED_TOKEN]`, `[REDACTED_SECRET]`).
> - Fail-closed scope enforcement: Targets must resolve to `IN_SCOPE` via canonical scope path (`<program_dir>/scope/scope.yaml` or `--scope`). Missing or ambiguous scope immediately aborts active execution. No working directory fallbacks.
> - Invariant: Operator approval (`--approve`) **never** overrides scope restrictions.
> - Bounded execution & Executor Safety: Requests enforce standard TLS certificate and hostname verification (`check_hostname=True`, `verify_mode=CERT_REQUIRED`), destination-IP pinning at socket connection (retaining SNI and `Host` header to prevent DNS rebinding), safe proxy bypassing (`ProxyHandler({})`), per-redirect hop scope and anti-SSRF re-verification (including IPv4-mapped IPv6 `::ffff:0:0/96`), 10s maximum timeout, and 100KB body cap.
> - Zero-traffic offline modes: Dry-run (`--dry-run`), passive-only (`--passive-only`), and hypotheses (`--hypotheses`) modes execute with strictly zero socket connections and zero DNS resolutions.

---

## 1. Controlled Finding Taxonomy (14 Families)

The engine enforces the complete 14-family taxonomy declared in `AuthenticationFindingFamily`:

### Operational Families (Differential Validation Required)
1. `AUTHENTICATION_BYPASS`: Protected resource accessible unauthenticated; response differs from anonymous baseline and matches authenticated profile. Never confirmed with synthetic responses.
2. `PRE_AUTH_PRIVILEGE_EXPOSURE`: Pre-auth route exposes actions/data intended only for authenticated users; verified via intermediate pre-MFA tokens.
3. `SESSION_FIXATION`: Pre-session identifier accepted post-auth and provides authenticated privileges.
4. `SESSION_NOT_INVALIDATED`: Post-logout or post-password-change session reuse successfully accesses protected resources.
5. `PASSWORD_RESET_TOKEN_REUSE`: Consumed reset token successfully resets password a second time on researcher-controlled test account.
6. `PASSWORD_RESET_STATE_CONFUSION`: Parameter tampering or out-of-order execution allows resetting arbitrary account.
7. `ACCOUNT_ENUMERATION`: Multi-trial differential validation (>500ms timing delta or divergent error responses across multiple trials); single-trial variations are rejected as transient network noise.
8. `MFA_BYPASS`: Bypassing secondary factor grants access to an endpoint/action strictly requiring verified MFA.
9. `MFA_STATE_CONFUSION`: Manipulating MFA session state transitions skips secondary verification.
10. `REFRESH_TOKEN_REUSE`: Replaying an already rotated refresh token successfully yields new access tokens.
11. `AUTHENTICATION_STATE_INCONSISTENCY`: Divergent authentication state enforcement across application boundaries/services.

### Observation-Only Families (Informational by Default)
12. `SESSION_NOT_ROTATED`: Missing session ID rotation across privilege change without session fixation remains an observation (`FindingLifecycle.INFORMATIONAL`).
13. `TOKEN_TRANSPORT_EXPOSURE`: Token in URL query params or headers without demonstrated leakage remains an observation (`FindingLifecycle.INFORMATIONAL`).
14. `AUTHENTICATION_CONFIGURATION_WEAKNESS`: Missing cookie security flags (`Secure`, `HttpOnly`, `SameSite`) or JWT structural concerns without exploitable server acceptance remain observations (`FindingLifecycle.INFORMATIONAL`).

---

## 2. Cross-Phase State Ingestion

The engine ingests and normalizes attack surface intelligence from all 7 previous phases (supporting both dict-of-dicts and list-of-dicts schemas):
- `state/webapps.json`: Forms, input fields, cookies, and endpoint routes.
- `state/api.json`: OpenAPI/REST endpoints, parameters, and authentication observations.
- `state/javascript.json`: Client routes, interesting authentication strings, and script endpoints.
- `state/assets.json` & `state/recon.json`: Hostnames, TLS SAN records, and HTTP services.
- `state/authorization.json`: Seeding identity profiles from Phase 8 principals and tenant metadata.
- `state/workflows.json`: Phase 12 business logic workflow steps and multi-stage state transitions.

---

## 3. False-Positive Elimination & Genuine Validation Pipeline

1. **Status-Code-Only False Positives**:
   - HTTP 200 responses are inspected for HTML login forms (`<form>`, `type="password"`), OAuth login prompts, and public documentation. Generic 200 OK login forms are actively rejected.
   - WAF challenge pages (`cf-ray`, Cloudflare blocks, bot challenges) are detected and filtered out.
2. **Baseline Differential Validation**:
   - Compares authentic anonymous request responses against authenticated baselines.
   - Zero hardcoded mock responses on real targets; authentic requests only.
   - When required credentials or sessions are missing, hypotheses deterministically report `SKIPPED` or `CANDIDATE`, never fabricating validation.
3. **Multi-Trial Account Enumeration**:
   - Requires repeatable differential responses (`trial_count >= 2`) under stable conditions before confirming enumeration.

---

## 4. Test Deduplication & State Recovery

- **Deterministic Context-Aware Fingerprinting**: Hypothesis IDs use canonical SHA-256 digests (`HYP-<family>-<hash>`) over family, endpoint, principal, and required state. Test fingerprints indexed into `state/tests.json` incorporate principal roles (`role:ANON` vs `role:ADMIN`) so differential testing across user contexts is never suppressed.
- **Resume Support (`--resume`)**: Loads existing progress from `state/authentication.json` and skips previously evaluated hypotheses with terminal statuses (`VALIDATED`, `CONFIRMED`, `REJECTED`, `SKIPPED`).
- **Resilient State Persistence**: Detects corrupted state files, backs up to `state/authentication.json.corrupt.<timestamp>`, and raises `CorruptedStateError` rather than silently discarding records. Atomic disk writes use tempfile, flush, `os.fsync`, and `os.replace`.
- **Native Findings Integration**: Validated candidate findings transition to `FindingLifecycle.VALIDATED` only on true differential proof and are persisted into `state/findings.json` using `StateManager.save_finding()`.

---

## 5. CLI Execution & Tooling

```bash
# Display ASCII tree view of surfaces, hypotheses, and validated findings
bb-auth --program <program> --tree

# Passive discovery and surface modeling without active probing
bb-auth --program <program> --passive-only --json

# List generated hypotheses only
bb-auth --program <program> --hypotheses

# Dry-run validation planning (audit dossier generation)
bb-auth --program <program> --flow session --dry-run

# Execute active validation with human approval for sensitive mutations
bb-auth --program <program> --validate --approve

# Resume interrupted validation run
bb-auth --program <program> --validate --resume

# Execute and validate deterministic local offline lab end-to-end
bb-auth --validate --lab --tree
```
