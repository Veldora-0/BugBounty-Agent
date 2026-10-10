# Roadmap: BugBounty-Agent

## Milestones

- ✅ **v1.0 Foundational Capabilities** — Phases 1–14 (shipped 2026-10-08)
- 🚧 **v1.14.1 Hardening & Pipeline Integration** — Phase 14.1 (in progress)

## Completed Milestones

<details>
<summary>✅ v1.0 Foundational Capabilities (Phases 1–14) — SHIPPED 2026-10-08</summary>

- **Phase 1: Asset Intelligence & Graph Discovery** — Recursive subdomain discovery, asset graph modeling, TLS SAN extraction, CDN attribution.
- **Phase 2: Reconnaissance Intelligence** — Passive CT logs and DNS intelligence, controlled active HTTP probing, rate-limiting.
- **Phase 3: Web Application Intelligence** — Web attack surface mapping, CORS origin analysis, cookie security, endpoint inventory.
- **Phase 4: JavaScript Intelligence** — Client-side static JS analysis, route extraction, AST parsing, DOM sink mapping.
- **Phase 5: API Security & Parameter Intelligence** — REST verb tampering, GraphQL introspection/depth limits, schema parameter discovery.
- **Phase 6: Security Validation Foundation** — 6-gate adversarial verification checklist, false positive classification.
- **Phase 7: XSS Intelligence & Validation** — Context-aware XSS validation, DOM sinks, headless browser execution proof.
- **Phase 8: Authorization & Access Control** — BOLA/IDOR, horizontal/vertical privilege escalation, tenant isolation.
- **Phase 9: SSRF & Out-of-Band Intelligence** — ProjectDiscovery Interactsh integration, blind SSRF/XXE callback verification.
- **Phase 10: Injection Intelligence** — Non-destructive proof markers (arithmetic `{{7*7}}`, safe time delay `sleep(3)`) for SQLi, NoSQLi, SSTI, CMDi.
- **Phase 11: HTTP / Header Trust Security** — Host header injection, cache poisoning, HTTP request smuggling analysis.
- **Phase 12: Business Logic Intelligence** — Workflow state machine bypasses, race conditions, decimal rounding, negative quantity tampering.
- **Phase 13: Cloud Security Intelligence** — S3/GCS bucket permissions, cloud metadata SSRF, dangling CNAME takeovers.
- **Phase 14: Authentication & Identity Intelligence Baseline** — Data models, session analyzers, JWT parsers, MFA checks, 21 offline lab scenarios.

</details>

---

## Active Phase Details

### Phase 14.1: Authentication Engine Hardening & Pipeline Integration

**Goal**: Transform the Phase 14 authentication baseline into a fully hardened, pipeline-integrated operational subsystem capable of consuming real multi-phase state, enforcing strict scope boundaries, executing deterministic test workflows, and producing high-confidence validated findings.

**Depends on**: Phase 14 baseline  
**Requirements**: PIPE-01, PIPE-02, PIPE-03, PIPE-04, SCOPE-01, SCOPE-02, SCOPE-03, STATE-01, STATE-02, STATE-03, STATE-04, STATE-05, STATE-06, STATE-07, COV-01, COV-02, COV-03, COV-04, COV-05, COV-06, COV-07, COV-08, COV-09, COV-10, COV-11, COV-12, COV-13, COV-14, HEUR-01, HEUR-02, HEUR-03, HEUR-04, HEUR-05, DEDUP-01, DEDUP-02, DEDUP-03, EVID-01, EVID-02, EVID-03, TEST-01, TEST-02, TEST-03, TEST-04, TEST-05, DOCS-01, DOCS-02, DOCS-03

**Success Criteria** (what must be TRUE):
1. `bb-auth --validate` executes end-to-end without unhandled exceptions across surface discovery, hypothesis generation, safe testing, and evidence generation. Dry-run, passive-only, and lab paths make zero external network requests.
2. Scope engine validates all target URLs and hostnames offline prior to network interaction; missing or ambiguous scope deterministically fails closed.
3. Ingests actual state files (`state/webapps.json`, `state/api.json`, `state/javascript.json`, `state/assets.json`, `state/recon.json`, `state/authorization.json`, `state/workflows.json`) using real models, with graceful degradation when individual files are missing or empty.
4. Preserves all 14 declared vulnerability families in `AuthenticationFindingFamily`, clearly distinguishing operational validation (with baseline differential evidence) from observation-only hardening concerns.
5. Evidence-backed validation rejects status-code-only false positives (generic 200 OK login pages and WAF challenges). Password-reset testing is restricted to researcher-controlled accounts, and operator approval (`--approve`) is strictly enforced for mutations.
6. Deterministic SHA-256 test fingerprints prevent duplicate probing in `state/tests.json`, and `--resume` accurately restores engine state.
7. Verified findings integrate natively into `framework.findings.schema.Finding` within `state/findings.json` without parallel models. Sensitive credentials are fully redacted, and request/response hashes are treated as provenance records rather than vulnerability proof.
8. All 21 existing offline lab scenarios pass, plus 18 new integration/safety test cases pass. Pytest suite passes 100% on Windows and Kali Linux, all 23 `bb-doctor` categories report `[HEALTHY]`, OpenCode configuration is verified, and work concludes in one final implementation commit: `fix: harden authentication validation pipeline`.

**Plans** (Sequential Execution — No Parallelization):

- [ ] **14.1-01: Pipeline & Scope Engine Integration**
  - Connect `bb-auth --validate` execution stages end-to-end through a bounded internal request executor.
  - Require integration test proving `bb-auth --validate --lab` executes real hypothesis processing and validation.
  - Integrate `ScopeEngine` using its actual `check(target)` API returning `ScopeDecision` and checking `status == ScopeStatus.IN_SCOPE`.
  - Resolve canonical initialized program scope path `<program_dir>/scope/scope.yaml` (or explicit `--scope`), failing closed if missing or ambiguous.
  - Enforce zero external network traffic on dry-run, passive-only, hypothesis-only, and lab paths.
  - Ensure clean termination with exit codes (0=clean, 1=error/scope, 2=pending approval) without uncaught exceptions.

- [ ] **14.1-02: Cross-Phase State Ingestion & Surface Discovery**
  - Implement real schema loaders for `state/webapps.json` (`WebAppStateManager`), `state/api.json` (`ApiStateManager`), `state/javascript.json` (`JavaScriptStateManager`), `state/assets.json`, and `state/recon.json` (lists of dicts vs dicts).
  - Ingest authorization context from `state/authorization.json` (`AuthorizationStateManager`, dict of principals) and workflow context from `state/workflows.json` (`WorkflowStateManager`, dict of workflows).
  - Implement defensive error handling for missing, empty, partial, or corrupted JSON state files without crashing.
  - Map discovered routes, parameters, cookies, tokens, and forms into unified `AuthenticationSurfaceDiscoverer`.

- [ ] **14.1-03: Operational Coverage & Hardened Validation Heuristics**
  - Implement operational validation across all 11 operational families (`AUTHENTICATION_BYPASS`, `PRE_AUTH_PRIVILEGE_EXPOSURE`, `SESSION_FIXATION`, `SESSION_NOT_INVALIDATED`, `PASSWORD_RESET_TOKEN_REUSE`, `PASSWORD_RESET_STATE_CONFUSION`, `ACCOUNT_ENUMERATION`, `MFA_BYPASS`, `MFA_STATE_CONFUSION`, `REFRESH_TOKEN_REUSE`, `AUTHENTICATION_STATE_INCONSISTENCY`).
  - Classify 3 observation-only families (`SESSION_NOT_ROTATED`, `TOKEN_TRANSPORT_EXPOSURE`, `AUTHENTICATION_CONFIGURATION_WEAKNESS`) as observations without escalating to unproven vulnerabilities.
  - Implement baseline differential validation (anonymous vs authenticated) to reject generic 200 OK login forms and WAF challenges.
  - Treat timing differences and response text variations as signals, requiring repeatable differential evidence across multiple trials for account enumeration.
  - Enforce operator approval gating (`AuthenticationApprovalGate`) via `--approve` for state mutations on test accounts. Invariant: approval never overrides scope restrictions.

- [ ] **14.1-04: Deterministic Fingerprinting, Deduplication, Resume & Evidence Model**
  - Implement deterministic SHA-256 test fingerprints via `generate_test_fingerprint` with context-awareness (principal, role) to prevent suppressing legitimate retests.
  - Integrate with `state/tests.json` using exact `StateManager.has_test_run` and `StateManager.record_test` methods.
  - Support `--resume` flag to recover previously evaluated hypotheses and findings from `state/authentication.json`.
  - Enforce strict credential sanitization in `AuthenticationEvidenceManager` (passwords, cookies, tokens, OTPs, API keys) with SHA-256 provenance hashes.
  - Map verified candidates to native `framework.findings.schema.Finding` objects respecting `FindingLifecycle.VALIDATED` only on true verification, and persist via `StateManager.save_finding`.

- [ ] **14.1-05: Regression Testing, Doctor Diagnostics, Cross-Platform Validation & Documentation**
  - Preserve all 21 existing offline authentication lab scenarios in `framework/authentication/lab.py`.
  - Add 18 new integration and safety test cases covering real state ingestion, fail-closed scope, redaction, deduplication, resume, and baseline validation.
  - Run active tests against local lab targets only with zero external network traffic.
  - Verify complete regression suite passes on Windows workstation and Kali Linux VM (`python -m pytest -q`).
  - Verify all 23 diagnostic categories report `[HEALTHY]` in `bb-doctor`.
  - Validate global deployment (`bb-deploy`) and OpenCode configuration (`Bug-Bounty`, 18 skills).
  - Update `skills/authentication/SKILL.md`, `README.md`, `CHANGELOG.md`, and `docs/architecture.md`.
  - Conclude implementation in a single consolidated commit: `fix: harden authentication validation pipeline`.

---

## Progress

**Execution Order:**
Plans execute strictly in sequence: 14.1-01 → 14.1-02 → 14.1-03 → 14.1-04 → 14.1-05. No parallelization.

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| Phases 1–14 | v1.0 | 14/14 | Complete | 2026-10-08 |
| Phase 14.1: Authentication Hardening | v1.14.1 | 0/5 | Not started | - |

---
*Roadmap defined: 2026-10-09*
*Immediate focus: Phase 14.1 only*
