# Requirements: BugBounty-Agent

**Defined:** 2026-10-09  
**Core Value:** Enable safe, hypothesis-driven, non-destructive bug bounty security research with strict offline scope enforcement, local data isolation outside Git, and adversarial validation without scanner false positives.

---

## Completed Requirements: Phase 14.1 (Authentication Engine Hardening)

Shipped in commit `89a30ee` (2026-10-10).

- [x] **PIPE-01**: `bb-auth --validate` executes an end-to-end operational pipeline coordinating surface discovery, hypothesis generation, safe testing, and evidence storage without unhandled exceptions.
- [x] **PIPE-02**: `bb-auth` supports distinct operational flags (`--passive-only`, `--dry-run`, `--hypotheses`, `--validate`, `--flow`, `--identity`, `--resume`, `--approve`, and `--tree`) with verified parameter handling.
- [x] **PIPE-03**: Dry-run, passive-only, hypothesis-only, and lab-planning execution paths make strictly zero external network requests.
- [x] **PIPE-04**: Safe execution terminates cleanly with structured return codes and informative ASCII tree status summaries without throwing uncaught tracebacks.
- [x] **SCOPE-01**: Authentication engine integrates directly with `framework.scope.engine.ScopeEngine`, evaluating all candidate target endpoints offline via `ScopeEngine.check(target)` and requiring `ScopeDecision.status == ScopeStatus.IN_SCOPE` prior to any active network interaction.
- [x] **SCOPE-02**: Canonical initialized program scope path `<program_dir>/scope/scope.yaml` (or explicitly passed `--scope`) is resolved deterministically; missing, malformed, or ambiguous scope fails closed and aborts active testing without cross-program fallback.
- [x] **SCOPE-03**: Automatic exclusion of out-of-scope third-party identity providers (e.g. Google, GitHub, Okta OAuth endpoints) unless explicitly authorized in `scope.yaml`.
- [x] **STATE-01**: Ingest discovered web endpoints, login forms, cookies, and parameters from `state/webapps.json` using `WebAppStateManager` schemas.
- [x] **STATE-02**: Ingest discovered API routes, parameters, request/response schemas, and authentication observations from `state/api.json` using `ApiStateManager` schemas.
- [x] **STATE-03**: Ingest client-side authentication routes, interesting secrets, and token patterns from `state/javascript.json` using `JavaScriptStateManager` schemas.
- [x] **STATE-04**: Ingest infrastructure hostnames, IP resolutions, and TLS SANs from `state/assets.json` and `state/recon.json` using `StateManager` schemas.
- [x] **STATE-05**: Cross-correlate authorization principals, sessions, and policies from `state/authorization.json` using `AuthorizationStateManager` schemas.
- [x] **STATE-06**: Ingest workflow state machines and transition steps from `state/workflows.json` using `WorkflowStateManager` schemas.
- [x] **STATE-07**: Gracefully handle missing, partial, or corrupted JSON state files without crashing, falling back safely to discovered targets or local lab fixtures.
- [x] **COV-01 (Operational)**: `AUTHENTICATION_BYPASS` — Initial baseline validation implemented.
- [x] **COV-02 (Operational)**: `PRE_AUTH_PRIVILEGE_EXPOSURE` — Initial pre-MFA privilege checks implemented.
- [x] **COV-03 (Operational)**: `SESSION_FIXATION` — Session identifier tracking implemented.
- [x] **COV-04 (Operational)**: `SESSION_NOT_INVALIDATED` — Logout invalidation checks implemented.
- [x] **COV-05 (Observation-Only)**: `SESSION_NOT_ROTATED` — Surfaced as hardening observation.
- [x] **COV-06 (Operational)**: `PASSWORD_RESET_TOKEN_REUSE` — Reset token reuse checks implemented.
- [x] **COV-07 (Operational)**: `PASSWORD_RESET_STATE_CONFUSION` — Step confusion checks implemented.
- [x] **COV-08 (Operational)**: `ACCOUNT_ENUMERATION` — Multi-trial differential checks implemented.
- [x] **COV-09 (Operational)**: `MFA_BYPASS` — Secondary auth checks implemented.
- [x] **COV-10 (Operational)**: `MFA_STATE_CONFUSION` — MFA session confusion checks implemented.
- [x] **COV-11 (Operational)**: `REFRESH_TOKEN_REUSE` — Token refresh rotation checks implemented.
- [x] **COV-12 (Observation-Only)**: `TOKEN_TRANSPORT_EXPOSURE` — URL query/header token exposure observed.
- [x] **COV-13 (Operational)**: `AUTHENTICATION_STATE_INCONSISTENCY` — State discrepancy checks implemented.
- [x] **COV-14 (Observation-Only)**: `AUTHENTICATION_CONFIGURATION_WEAKNESS` — Missing cookie flags and JWT structure observed.
- [x] **HEUR-01**: WAF challenge and generic login page false positive filtering.
- [x] **HEUR-02**: Baseline response comparisons (anonymous vs authenticated).
- [x] **HEUR-03**: Password reset restrictions to test accounts.
- [x] **HEUR-04**: Approval gating (`--approve`) with invariant that approval never overrides scope.
- [x] **HEUR-05**: Bounded network requests: rate limits and timeout caps.
- [x] **DEDUP-01**: Test fingerprinting via `framework.state.dedup.generate_test_fingerprint`.
- [x] **DEDUP-02**: Test deduplication against `state/tests.json`.
- [x] **DEDUP-03**: State resumption via `--resume`.
- [x] **EVID-01**: Credential redaction via `AuthenticationEvidenceManager`.
- [x] **EVID-02**: SHA-256 provenance hashes generated for captures.
- [x] **EVID-03**: Native `Finding` persistence in `state/findings.json`.
- [x] **TEST-01**: All 21 offline lab scenarios passing.
- [x] **TEST-02**: 18 integration and safety test cases added (42 tests total in suite).
- [x] **TEST-03**: Zero external network traffic during test execution.
- [x] **TEST-04**: Complete regression suite passing (341/341 passed).
- [x] **TEST-05**: All 23 diagnostic categories reporting `[HEALTHY]` in `bb-doctor`.
- [x] **DOCS-01**: `skills/authentication/SKILL.md` updated.
- [x] **DOCS-02**: `README.md`, `CHANGELOG.md`, `docs/architecture.md` updated.
- [x] **DOCS-03**: Single consolidated commit: `fix: harden authentication validation pipeline`.

---

## Active Requirements: Phase 14.2 (Authentication Validation Integrity & Executor Safety)

Requirements for Phase 14.2 correcting validation integrity, removing synthetic response values, and hardening executor network safety.

### 1. Real Validation Pipeline & Differential Testing
- [ ] **VAL-01**: Remove all hardcoded synthetic comparison responses (e.g. `auth_status=200`, synthetic user JSON bodies, hardcoded session IDs like `sess_fixed_id`, hardcoded error bodies like `{"error": "user not found"}`) from the real-target execution path in `engine.py`.
- [ ] **VAL-02**: Define genuine, bounded multi-step test sequences for every operational finding family using permitted requests and actual researcher-controlled identities, sessions, and tokens.
- [ ] **VAL-03**: Explicitly report a non-validated state (`SKIPPED`, `UNVALIDATED`, or `MISSING_PREREQUISITES`) whenever required test credentials or endpoints are unavailable, rather than inventing evidence or fabricating responses.
- [ ] **VAL-04**: Enforce strict taxonomy boundaries distinguishing discovered hypotheses, observations, candidates, and validated findings. Only assign `FindingLifecycle.VALIDATED` when family-specific differential proof is achieved.
- [ ] **VAL-05**: Honestly report operational coverage: operational families without full runtime implementation must be clearly marked `UNSUPPORTED` / `PENDING`, and observation-only families (`SESSION_NOT_ROTATED`, `TOKEN_TRANSPORT_EXPOSURE`, `AUTHENTICATION_CONFIGURATION_WEAKNESS`) must remain informational.

### 2. Request-Executor Safety, TLS & Anti-SSRF
- [ ] **EXEC-01**: Restore normal TLS certificate and hostname verification (`ssl.create_default_context()`, `check_hostname=True`, `verify_mode=ssl.CERT_REQUIRED`). Treat TLS validation errors as hard failures and log evidence without bypassing verification.
- [ ] **EXEC-02**: Guarantee strict zero external network traffic, zero socket creation, and zero DNS resolution in `--dry-run`, `--passive-only`, `--hypotheses`, and `--lab` modes.
- [ ] **EXEC-03**: Harden anti-SSRF defenses against prohibited IPv4, IPv6 (`::1`, `fc00::/7`, `fe80::/10`), IPv4-mapped IPv6 (`::ffff:127.0.0.1`, `::ffff:169.254.169.254`, `::ffff:0:0/96`), link-local, loopback, carrier-grade NAT, and cloud metadata (`169.254.169.254`, `metadata.google.internal`).
- [ ] **EXEC-04**: Mitigate DNS rebinding and TOCTOU races by pre-resolving and validating destination IPs, and pinning the socket connection to the validated destination IP address.
- [ ] **EXEC-05**: Validate every redirect hop independently against scope and anti-SSRF boundaries, terminating immediately on unsafe, private, loopback, or out-of-scope targets (capped at 5 hops).
- [ ] **EXEC-06**: Maintain bounded request execution: timeout capped at 10.0s, response size capped at 100KB, max 5 requests per endpoint, and configurable delay.

### 3. Scope Resolution & Approval Gate Integrity
- [ ] **SCOPE-01**: Enforce strict scope evaluation via `ScopeEngine.check(target)` requiring `ScopeDecision.status == ScopeStatus.IN_SCOPE`. Missing, ambiguous, malformed, or out-of-scope targets deterministically fail closed.
- [ ] **SCOPE-02**: Resolve scope file deterministically only from explicit `--scope` or canonical program path `<program_dir>/scope/scope.yaml` (or `<program_dir>/scope.yaml`). Forbid unsafe current working directory fallbacks that could inherit unrelated scopes.
- [ ] **SCOPE-03**: Enforce the non-negotiable security invariant that operator approval (`--approve`) never overrides scope boundaries.
- [ ] **SCOPE-04**: Bind approval gating to the concrete operation being planned (`PASSWORD_RESET_SUBMIT`, `PASSWORD_CHANGE`, `MFA_ENROLLMENT`) and the specific researcher-controlled account, rather than generic placeholder operations.

### 4. Finding Quality, Evidence Redaction & State Persistence
- [ ] **EVID-01**: Make hypothesis IDs and fingerprints deterministic and context-aware (endpoint, family, principal, required state) so resume and deduplication operate reliably without random UUID divergence.
- [ ] **EVID-02**: Ensure test deduplication against `state/tests.json` and state recovery via `--resume` reuses identical hypotheses without suppressing legitimate re-tests under different principals or security contexts.
- [ ] **EVID-03**: Comprehensive credential sanitization across query parameters, form fields, headers (Bearer, Basic, custom API keys), cookies, OTPs, reset tokens, and nested JSON structures.
- [ ] **EVID-04**: Clarify and document that cryptographic SHA-256 digests represent provenance and auditability metadata, never standalone proofs of vulnerability.
- [ ] **EVID-05**: Robust state loading and persistence error handling: do not silently swallow exceptions in `storage.py`. Corrupted JSON state files must be flagged with explicit error reporting.

### 5. Cross-Phase Integration Resiliency
- [ ] **STATE-01**: Resilient schema parsing for `webapps.json`, `api.json`, `javascript.json`, `assets.json`, `recon.json`, `authorization.json`, and `workflows.json`.
- [ ] **STATE-02**: Support both list-of-dicts and dict-of-dicts serialized formats without data loss or exceptions.
- [ ] **STATE-03**: Handle missing, empty, or partial state files with graceful degradation and safe fallbacks.

### 6. Testing, Diagnostics & Documentation
- [ ] **TEST-01**: Preserve all 21 offline lab scenarios in `LocalAuthenticationSecurityLab` with 100% deterministic accuracy.
- [ ] **TEST-02**: Add local fixture HTTP server integration tests covering real multi-step sequences with negative controls for each operational family.
- [ ] **TEST-03**: Assert zero socket creation and zero DNS resolution in all advertised offline modes (`--dry-run`, `--passive-only`, `--lab`).
- [ ] **TEST-04**: Security boundary tests verifying TLS failure handling, SSRF blocks (including IPv4-mapped IPv6), DNS rebinding safeguards, redirect limits, and fail-closed scope resolution.
- [ ] **TEST-05**: Full test suite passes 100% across the repository, `bb-doctor` Category 23 reports healthy, and OpenCode deployment is verified.
- [ ] **DOCS-01**: Update `skills/authentication/SKILL.md`, `README.md`, `CHANGELOG.md`, and `docs/architecture.md`.
- [ ] **DOCS-02**: Plan and conclude work in a single consolidated commit: `fix: correct authentication validation integrity and executor safety`.

---

## Traceability: Phase 14.2

| Requirement | Plan | Status |
|-------------|------|--------|
| EXEC-01 | Plan 14.2-01: Request-Executor Safety, TLS & Scope/Approval Integrity | Planned |
| EXEC-02 | Plan 14.2-01: Request-Executor Safety, TLS & Scope/Approval Integrity | Planned |
| EXEC-03 | Plan 14.2-01: Request-Executor Safety, TLS & Scope/Approval Integrity | Planned |
| EXEC-04 | Plan 14.2-01: Request-Executor Safety, TLS & Scope/Approval Integrity | Planned |
| EXEC-05 | Plan 14.2-01: Request-Executor Safety, TLS & Scope/Approval Integrity | Planned |
| EXEC-06 | Plan 14.2-01: Request-Executor Safety, TLS & Scope/Approval Integrity | Planned |
| SCOPE-01 | Plan 14.2-01: Request-Executor Safety, TLS & Scope/Approval Integrity | Planned |
| SCOPE-02 | Plan 14.2-01: Request-Executor Safety, TLS & Scope/Approval Integrity | Planned |
| SCOPE-03 | Plan 14.2-01: Request-Executor Safety, TLS & Scope/Approval Integrity | Planned |
| SCOPE-04 | Plan 14.2-01: Request-Executor Safety, TLS & Scope/Approval Integrity | Planned |
| EVID-01 | Plan 14.2-02: State Ingestion Resiliency & Deterministic Fingerprinting | Planned |
| EVID-02 | Plan 14.2-02: State Ingestion Resiliency & Deterministic Fingerprinting | Planned |
| EVID-03 | Plan 14.2-02: State Ingestion Resiliency & Deterministic Fingerprinting | Planned |
| EVID-04 | Plan 14.2-02: State Ingestion Resiliency & Deterministic Fingerprinting | Planned |
| EVID-05 | Plan 14.2-02: State Ingestion Resiliency & Deterministic Fingerprinting | Planned |
| STATE-01 | Plan 14.2-02: State Ingestion Resiliency & Deterministic Fingerprinting | Planned |
| STATE-02 | Plan 14.2-02: State Ingestion Resiliency & Deterministic Fingerprinting | Planned |
| STATE-03 | Plan 14.2-02: State Ingestion Resiliency & Deterministic Fingerprinting | Planned |
| VAL-01 | Plan 14.2-03: Genuine Validation Pipeline & Honest Family Status | Planned |
| VAL-02 | Plan 14.2-03: Genuine Validation Pipeline & Honest Family Status | Planned |
| VAL-03 | Plan 14.2-03: Genuine Validation Pipeline & Honest Family Status | Planned |
| VAL-04 | Plan 14.2-03: Genuine Validation Pipeline & Honest Family Status | Planned |
| VAL-05 | Plan 14.2-03: Genuine Validation Pipeline & Honest Family Status | Planned |
| TEST-01 | Plan 14.2-04: Comprehensive Safety, Integration & Lab Verification Suite | Planned |
| TEST-02 | Plan 14.2-04: Comprehensive Safety, Integration & Lab Verification Suite | Planned |
| TEST-03 | Plan 14.2-04: Comprehensive Safety, Integration & Lab Verification Suite | Planned |
| TEST-04 | Plan 14.2-04: Comprehensive Safety, Integration & Lab Verification Suite | Planned |
| TEST-05 | Plan 14.2-04: Comprehensive Safety, Integration & Lab Verification Suite | Planned |
| DOCS-01 | Plan 14.2-04: Comprehensive Safety, Integration & Lab Verification Suite | Planned |
| DOCS-02 | Plan 14.2-04: Comprehensive Safety, Integration & Lab Verification Suite | Planned |

**Phase 14.2 Requirements Count:** 30 total mapped to 4 plans (0 unmapped).
