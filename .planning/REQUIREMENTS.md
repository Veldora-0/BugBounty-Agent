# Requirements: BugBounty-Agent

**Defined:** 2026-10-09  
**Core Value:** Enable safe, hypothesis-driven, non-destructive bug bounty security research with strict offline scope enforcement, local data isolation outside Git, and adversarial validation without scanner false positives.

## v1 Requirements (Phase 14.1: Authentication Engine Hardening)

Requirements for Phase 14.1 hardening and pipeline integration. Each requirement maps directly to Phase 14.1 execution plans.

### Pipeline Execution & CLI Wiring

- [ ] **PIPE-01**: `bb-auth --validate` executes an end-to-end operational pipeline coordinating surface discovery, hypothesis generation, safe testing, and evidence storage without unhandled exceptions.
- [ ] **PIPE-02**: `bb-auth` supports distinct operational flags (`--passive-only`, `--dry-run`, `--hypotheses`, `--validate`, `--flow`, `--identity`, `--resume`, `--approve`, and `--tree`) with verified parameter handling.
- [ ] **PIPE-03**: Dry-run, passive-only, hypothesis-only, and lab-planning execution paths make strictly zero external network requests.
- [ ] **PIPE-04**: Safe execution terminates cleanly with structured return codes and informative ASCII tree status summaries without throwing uncaught tracebacks.

### Scope & Target Integration

- [ ] **SCOPE-01**: Authentication engine integrates directly with `framework.scope.engine.ScopeEngine`, validating all candidate target endpoints offline prior to any network interaction.
- [ ] **SCOPE-02**: Program-level `scope.yaml` and directory-level scope paths are deterministically resolved; missing or ambiguous scope fails closed and aborts active testing.
- [ ] **SCOPE-03**: Automatic exclusion of out-of-scope third-party identity providers (e.g. Google, GitHub, Okta OAuth endpoints) unless explicitly authorized in `scope.yaml`.

### Actual Cross-Phase State Ingestion

- [ ] **STATE-01**: Ingest discovered web endpoints, login forms, cookies, and parameters from `state/webapps.json` using `WebAppStateManager` schemas.
- [ ] **STATE-02**: Ingest discovered API routes, parameters, request/response schemas, and authentication observations from `state/api.json` using `ApiStateManager` schemas.
- [ ] **STATE-03**: Ingest client-side authentication routes, interesting secrets, and token patterns from `state/javascript.json` using `JavaScriptStateManager` schemas.
- [ ] **STATE-04**: Ingest infrastructure hostnames, IP resolutions, and TLS SANs from `state/assets.json` and `state/recon.json` using `StateManager` schemas.
- [ ] **STATE-05**: Cross-correlate authorization principals, sessions, and policies from `state/authorization.json` using `AuthorizationStateManager` schemas.
- [ ] **STATE-06**: Ingest workflow state machines and transition steps from `state/workflows.json` using `WorkflowStateManager` schemas.
- [ ] **STATE-07**: Gracefully handle missing, partial, or corrupted JSON state files without crashing, falling back safely to discovered targets or local lab fixtures.

### Operational Coverage of the 14 Vulnerability Families

Preserves the exact Phase 14 taxonomy (`AuthenticationFindingFamily`) and distinguishes operational support levels:

- [ ] **COV-01 (Operational)**: `AUTHENTICATION_BYPASS` — Verifies unauthenticated access to protected account data using evidence-backed anonymous vs. authenticated baselines.
- [ ] **COV-02 (Operational)**: `PRE_AUTH_PRIVILEGE_EXPOSURE` — Verifies protected account endpoints are accessible prior to secondary authentication or MFA completion.
- [ ] **COV-03 (Operational)**: `SESSION_FIXATION` — Verifies session identifier reuse across the login boundary combined with proven authenticated access using the fixed identifier.
- [ ] **COV-04 (Operational)**: `SESSION_NOT_INVALIDATED` — Verifies session token reuse against a protected resource after logout or password change, checked against authentic baseline responses.
- [ ] **COV-05 (Observation-Only)**: `SESSION_NOT_ROTATED` — Observes failure to rotate session identifiers across unauthenticated privilege transitions; tracked as a hardening concern, not an automatic high-severity finding.
- [ ] **COV-06 (Operational)**: `PASSWORD_RESET_TOKEN_REUSE` — Verifies that a password reset token remains valid after successful password change; executed strictly on researcher-controlled test accounts.
- [ ] **COV-07 (Operational)**: `PASSWORD_RESET_STATE_CONFUSION` — Verifies state machine bypasses or step-skipping in the password reset workflow.
- [ ] **COV-08 (Operational)**: `ACCOUNT_ENUMERATION` — Detects differential responses (timing deltas >500ms or distinct error strings); requires repeatable differential evidence across multiple trials before confirmation.
- [ ] **COV-09 (Operational)**: `MFA_BYPASS` — Proves that an enforced secondary authentication boundary was circumvented to reach post-MFA functionality.
- [ ] **COV-10 (Operational)**: `MFA_STATE_CONFUSION` — Detects intermediate session desynchronization between primary login and MFA challenge states.
- [ ] **COV-11 (Operational)**: `REFRESH_TOKEN_REUSE` — Verifies that an expired or rotated refresh token successfully issues a new access token.
- [ ] **COV-12 (Observation-Only)**: `TOKEN_TRANSPORT_EXPOSURE` — Identifies sensitive tokens transmitted in URL query strings or Referer headers; classified as an exposure observation unless impact is proven.
- [ ] **COV-13 (Operational)**: `AUTHENTICATION_STATE_INCONSISTENCY` — Proves divergence between client/server or gateway/backend authentication states.
- [ ] **COV-14 (Observation-Only)**: `AUTHENTICATION_CONFIGURATION_WEAKNESS` — Surfaces missing cookie flags (`Secure`, `HttpOnly`, `SameSite`), JWT structural concerns (`alg: "none"`, missing `exp`), or excessive token expiration horizons as informational/hardening observations unless exploitable impact is demonstrated.

### Validation Quality & Safety Invariants

- [ ] **HEUR-01**: Evidence-backed validation eliminating status-code-only heuristics; generic 200 OK login pages and WAF challenges are explicitly rejected.
- [ ] **HEUR-02**: Baseline verification: all bypass and invalidation claims must establish both baseline response (unauthenticated/anonymous) and test response differentials.
- [ ] **HEUR-03**: Password reset testing is restricted strictly to designated, researcher-controlled accounts; zero testing against third-party users.
- [ ] **HEUR-04**: Strict operator approval gating (`AuthenticationApprovalGate`) requiring `--approve` for all state-mutating actions (password resets, credential changes, MFA enrollments).
- [ ] **HEUR-05**: Bounded network requests: rate limits and timeout caps enforced across all active network probes.

### Deterministic Fingerprinting, Deduplication & Resume

- [ ] **DEDUP-01**: Compute deterministic SHA-256 test fingerprints via `framework.state.dedup.generate_test_fingerprint` combining normalized endpoint, HTTP method, parameter, and category.
- [ ] **DEDUP-02**: Index executed tests into `state/tests.json` using `StateManager.record_test` to eliminate duplicate network probes across runs.
- [ ] **DEDUP-03**: Support `--resume` flag to recover previously evaluated hypotheses and findings from `state/authentication.json` without re-executing completed tests.

### Evidence Sanitization & Native Findings Integration

- [ ] **EVID-01**: Strict credential redaction via `AuthenticationEvidenceManager`: passwords, session cookies, bearer tokens, reset tokens, refresh tokens, OTPs, API keys, and authorization headers are sanitized prior to storage.
- [ ] **EVID-02**: Cryptographic SHA-256 digests generated for request/response captures to ensure provenance, but hashes are never treated as proof of vulnerability on their own.
- [ ] **EVID-03**: Direct integration with `framework.findings.schema.Finding`: verified candidates are stored in `state/findings.json` using `StateManager.save_finding`, respecting valid severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`) and confidence (`CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`) enums.

### Test Acceptance Criteria & Quality Gates

- [ ] **TEST-01**: All 21 existing offline authentication lab scenarios in `framework/authentication/lab.py` must pass with 100% deterministic reliability.
- [ ] **TEST-02**: Add 18 new integration and safety test cases:
  1. End-to-end `bb-auth --validate` execution in lab mode.
  2. Cross-phase state ingestion from `state/webapps.json`.
  3. Cross-phase state ingestion from `state/api.json`.
  4. Cross-phase state ingestion from `state/javascript.json`.
  5. Cross-phase state ingestion from `state/assets.json` and `state/recon.json`.
  6. Authorization cross-correlation from `state/authorization.json`.
  7. Workflow cross-correlation from `state/workflows.json`.
  8. Missing state file tolerance and graceful fallback.
  9. Corrupted JSON state file handling without unhandled exceptions.
  10. Missing scope file fails closed (active validation aborted).
  11. Out-of-scope targets blocked offline before network request.
  12. Sensitive credential redaction across all stored evidence.
  13. Test fingerprinting and `state/tests.json` deduplication.
  14. Engine `--resume` state recovery.
  15. Status-code-only false positive rejection.
  16. Evidence-backed baseline validation for session invalidation.
  17. Operator approval gate (`--approve`) enforcement.
  18. Native `Finding` conversion and persistence in `state/findings.json`.
- [ ] **TEST-03**: Active testing during implementation runs against local lab targets only (zero external traffic).
- [ ] **TEST-04**: Full regression suite passes on both Windows development workstation and Kali Linux VM runtime (`python -m pytest -q`).
- [ ] **TEST-05**: All 23 diagnostic categories report `[HEALTHY]` in `bb-doctor`.

### Documentation, OpenCode Integration & Commit

- [ ] **DOCS-01**: Update `skills/authentication/SKILL.md` with operational methodology for all 14 families, state ingestion, and evidence gathering.
- [ ] **DOCS-02**: Update `README.md`, `CHANGELOG.md`, and `docs/architecture.md` reflecting Phase 14.1 hardening.
- [ ] **DOCS-03**: Consolidated into single final implementation commit: `fix: harden authentication validation pipeline`.

## v2 Requirements (Deferred to Future Phases)

- **AUTH-V2-01**: Automated SAML 2.0 assertion validation and signature wrapping analysis.
- **AUTH-V2-02**: WebAuthn / FIDO2 credential attestation flow analysis.
- **AUTH-V2-03**: Dynamic OAuth 2.0 PKCE code injection and redirect URI loose matching verification.

## Out of Scope

| Feature | Reason |
|---------|--------|
| Credential stuffing / password spraying | Violates bug bounty safety invariants and defensive focus |
| Automated OTP brute-forcing | Prohibited by ethical research policy and rate limit caps |
| Modifying completed Phases 1–13 | Established baseline must remain protected from regressions |
| Parallelizing implementation plans | Sequential execution preserves stability and traceability |
| Multi-agent OpenCode configuration | Single-agent `Bug-Bounty` architecture is invariant |
| External pentest engine integration | Engine must remain native without Xalgorix or Strix |
| Inventing parallel finding models | Standard `framework.findings.schema.Finding` must be reused |

## Traceability

Mapping of Phase 14.1 requirements to execution plans:

| Requirement | Plan | Status |
|-------------|------|--------|
| PIPE-01 | Plan 14.1-01: Pipeline and Scope Integration | Pending |
| PIPE-02 | Plan 14.1-01: Pipeline and Scope Integration | Pending |
| PIPE-03 | Plan 14.1-01: Pipeline and Scope Integration | Pending |
| PIPE-04 | Plan 14.1-01: Pipeline and Scope Integration | Pending |
| SCOPE-01 | Plan 14.1-01: Pipeline and Scope Integration | Pending |
| SCOPE-02 | Plan 14.1-01: Pipeline and Scope Integration | Pending |
| SCOPE-03 | Plan 14.1-01: Pipeline and Scope Integration | Pending |
| STATE-01 | Plan 14.1-02: Cross-Phase State Ingestion | Pending |
| STATE-02 | Plan 14.1-02: Cross-Phase State Ingestion | Pending |
| STATE-03 | Plan 14.1-02: Cross-Phase State Ingestion | Pending |
| STATE-04 | Plan 14.1-02: Cross-Phase State Ingestion | Pending |
| STATE-05 | Plan 14.1-02: Cross-Phase State Ingestion | Pending |
| STATE-06 | Plan 14.1-02: Cross-Phase State Ingestion | Pending |
| STATE-07 | Plan 14.1-02: Cross-Phase State Ingestion | Pending |
| COV-01 | Plan 14.1-03: Validation Quality and Coverage | Pending |
| COV-02 | Plan 14.1-03: Validation Quality and Coverage | Pending |
| COV-03 | Plan 14.1-03: Validation Quality and Coverage | Pending |
| COV-04 | Plan 14.1-03: Validation Quality and Coverage | Pending |
| COV-05 | Plan 14.1-03: Validation Quality and Coverage | Pending |
| COV-06 | Plan 14.1-03: Validation Quality and Coverage | Pending |
| COV-07 | Plan 14.1-03: Validation Quality and Coverage | Pending |
| COV-08 | Plan 14.1-03: Validation Quality and Coverage | Pending |
| COV-09 | Plan 14.1-03: Validation Quality and Coverage | Pending |
| COV-10 | Plan 14.1-03: Validation Quality and Coverage | Pending |
| COV-11 | Plan 14.1-03: Validation Quality and Coverage | Pending |
| COV-12 | Plan 14.1-03: Validation Quality and Coverage | Pending |
| COV-13 | Plan 14.1-03: Validation Quality and Coverage | Pending |
| COV-14 | Plan 14.1-03: Validation Quality and Coverage | Pending |
| HEUR-01 | Plan 14.1-03: Validation Quality and Coverage | Pending |
| HEUR-02 | Plan 14.1-03: Validation Quality and Coverage | Pending |
| HEUR-03 | Plan 14.1-03: Validation Quality and Coverage | Pending |
| HEUR-04 | Plan 14.1-03: Validation Quality and Coverage | Pending |
| HEUR-05 | Plan 14.1-03: Validation Quality and Coverage | Pending |
| DEDUP-01 | Plan 14.1-04: Deduplication, Resume, Evidence & Findings | Pending |
| DEDUP-02 | Plan 14.1-04: Deduplication, Resume, Evidence & Findings | Pending |
| DEDUP-03 | Plan 14.1-04: Deduplication, Resume, Evidence & Findings | Pending |
| EVID-01 | Plan 14.1-04: Deduplication, Resume, Evidence & Findings | Pending |
| EVID-02 | Plan 14.1-04: Deduplication, Resume, Evidence & Findings | Pending |
| EVID-03 | Plan 14.1-04: Deduplication, Resume, Evidence & Findings | Pending |
| TEST-01 | Plan 14.1-05: Regression Testing, Diagnostics & Documentation | Pending |
| TEST-02 | Plan 14.1-05: Regression Testing, Diagnostics & Documentation | Pending |
| TEST-03 | Plan 14.1-05: Regression Testing, Diagnostics & Documentation | Pending |
| TEST-04 | Plan 14.1-05: Regression Testing, Diagnostics & Documentation | Pending |
| TEST-05 | Plan 14.1-05: Regression Testing, Diagnostics & Documentation | Pending |
| DOCS-01 | Plan 14.1-05: Regression Testing, Diagnostics & Documentation | Pending |
| DOCS-02 | Plan 14.1-05: Regression Testing, Diagnostics & Documentation | Pending |
| DOCS-03 | Plan 14.1-05: Regression Testing, Diagnostics & Documentation | Pending |

**Coverage:**
- v1 requirements: 48 total
- Mapped to Phase 14.1 plans: 48
- Unmapped: 0 ✓

---
*Requirements defined: 2026-10-09*
*Last updated: 2026-10-09 after Phase 14.1 correction pass*
