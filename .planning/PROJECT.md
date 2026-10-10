# BugBounty-Agent

## What This Is

A professional, modular Bug Bounty Security Research Agent framework built for OpenCode. The system operates as a single global primary orchestrator agent named `Bug-Bounty` supported by 18 specialized methodology skills, executing deterministic hypothesis-driven reconnaissance, attack surface analysis, vulnerability testing, and adversarial verification on authorized bug bounty targets.

## Core Value

Enable safe, hypothesis-driven, non-destructive bug bounty security research with strict offline scope enforcement, local data isolation outside Git, and adversarial validation without scanner false positives.

## Requirements

### Validated

<!-- Shipped and confirmed valuable across Phases 1–14 and Phase 14.1 -->

- ✓ [Phase 1: Asset Intelligence] Recursive subdomain discovery, asset graph modeling, TLS SAN extraction, CDN attribution — v1.1.0
- ✓ [Phase 2: Reconnaissance Intelligence] Passive intelligence (crt.sh, subfinder) and rate-limited active probing (httpx) — v1.2.0
- ✓ [Phase 3: Web Application Intelligence] Web surface cataloging, CORS policy analysis, cookie audits, endpoint extraction — v1.3.0
- ✓ [Phase 4: JavaScript Intelligence] Static JS analysis, route discovery, source map reconstruction, DOM sink triage — v1.4.0
- ✓ [Phase 5: API Security & Parameter Intelligence] REST verb tampering, GraphQL introspection/depth, parameter discovery — v1.5.0
- ✓ [Phase 6: Security Validation Foundation] 6-gate adversarial verification checklist, false positive classification, confidence scoring — v1.6.0
- ✓ [Phase 7: XSS Intelligence & Validation] Context-aware reflection, DOM sink verification, headless browser proof — v1.7.0
- ✓ [Phase 8: Authorization & Access Control] BOLA/IDOR, horizontal/vertical privilege escalation, tenant isolation — v1.8.0
- ✓ [Phase 9: SSRF & Out-of-Band Intelligence] ProjectDiscovery Interactsh callbacks, blind SSRF/XXE verification — v1.9.0
- ✓ [Phase 10: Injection Intelligence] Non-destructive proof markers (arithmetic `{{7*7}}`, safe time delay `sleep(3)`) for SQLi, NoSQLi, SSTI, CMDi — v1.10.0
- ✓ [Phase 11: HTTP / Header Trust Security] Host header injection, cache poisoning, HTTP request smuggling analysis — v1.11.0
- ✓ [Phase 12: Business Logic Intelligence] Multi-step workflow bypasses, sequence skipping, race conditions, decimal rounding — v1.12.0
- ✓ [Phase 13: Cloud Security Intelligence] S3/GCS bucket permissions, cloud metadata SSRF, dangling CNAME takeovers — v1.13.0
- ✓ [Phase 14: Authentication & Identity Intelligence Baseline] Initial data models, analyzers, 14 vulnerability families, and 21 offline lab scenarios — v1.14.0
- ✓ [Phase 14.1: Authentication Engine Hardening & Pipeline Integration] Pipeline orchestration, ScopeEngine.check integration, cross-phase state ingestion from 7 schemas, test deduplication, credential sanitization, 42 tests passing — v1.14.1

### Active

<!-- Current scope: Phase 14.2 Authentication Validation Integrity & Executor Safety -->

- [ ] **VAL-01**: Purge all hardcoded synthetic comparison responses from live target execution in `engine.py`.
- [ ] **VAL-02**: Implement genuine bounded multi-step test sequences for operational families using actual requests and researcher identities.
- [ ] **VAL-03**: Set explicit non-validated states (`SKIPPED`, `UNVALIDATED`, `MISSING_PREREQUISITES`) when test prerequisites or credentials are not provided.
- [ ] **VAL-04**: Enforce strict taxonomy boundaries distinguishing hypotheses, observations, candidates, and validated findings. Only assign `FindingLifecycle.VALIDATED` upon genuine differential proof.
- [ ] **VAL-05**: Strictly preserve observation-only families (`SESSION_NOT_ROTATED`, `TOKEN_TRANSPORT_EXPOSURE`, `AUTHENTICATION_CONFIGURATION_WEAKNESS`) as informational hardening observations without escalating to vulnerabilities.
- [ ] **EXEC-01**: Restore standard TLS certificate and hostname verification in `BoundedAuthenticationExecutor`, failing closed on certificate errors without bypassing checks.
- [ ] **EXEC-02**: Enforce strict zero external network traffic, zero socket creation, and zero DNS resolution in `--dry-run`, `--passive-only`, and `--lab` modes.
- [ ] **EXEC-03**: Harden anti-SSRF defenses against IPv4, IPv6 (`::1`, `fc00::/7`, `fe80::/10`), IPv4-mapped IPv6 (`::ffff:127.0.0.1`, `::ffff:169.254.169.254`), and cloud metadata destinations.
- [ ] **EXEC-04**: Mitigate DNS rebinding and TOCTOU races by pre-resolving and pinning destination IPs during socket connection.
- [ ] **EXEC-05**: Re-verify scope and destination safety on each redirect hop (max 5 redirects).
- [ ] **EXEC-06**: Maintain bounded request execution: timeout capped at 10.0s, response size capped at 100KB, max 5 requests per endpoint.
- [ ] **SCOPE-01**: Enforce strict scope evaluation via `ScopeEngine.check(target)` requiring `ScopeDecision.status == ScopeStatus.IN_SCOPE`.
- [ ] **SCOPE-02**: Resolve scope file deterministically only from explicit `--scope` or canonical program path `<program_dir>/scope/scope.yaml` (or `<program_dir>/scope.yaml`), eliminating unsafe current working directory fallbacks.
- [ ] **SCOPE-03**: Enforce the non-negotiable security invariant that operator approval (`--approve`) never overrides scope boundaries.
- [ ] **SCOPE-04**: Bind approval gating to the concrete operation being planned and the specific researcher-controlled account.
- [ ] **EVID-01**: Make hypothesis IDs deterministic and context-aware based on canonical SHA-256 hashes instead of random UUIDs.
- [ ] **EVID-02**: Ensure test deduplication against `state/tests.json` and state recovery via `--resume` reuses identical hypotheses without suppressing legitimate re-tests.
- [ ] **EVID-03**: Comprehensive credential sanitization across query parameters, form fields, headers (Bearer, Basic, custom API keys), cookies, OTPs, reset tokens, and nested JSON structures.
- [ ] **EVID-04**: Document that cryptographic SHA-256 digests represent provenance and auditability metadata, never standalone proofs of vulnerability.
- [ ] **EVID-05**: Robust state loading and persistence error handling without silent exception swallowing.
- [ ] **STATE-01**: Resilient schema parsing for `webapps.json`, `api.json`, `javascript.json`, `assets.json`, `recon.json`, `authorization.json`, and `workflows.json`.
- [ ] **STATE-02**: Support both list-of-dicts and dict-of-dicts serialized formats without data loss.
- [ ] **STATE-03**: Handle missing, empty, or partial state files with graceful degradation.
- [ ] **TEST-01**: Preserve all 21 offline lab scenarios in `LocalAuthenticationSecurityLab` with 100% deterministic accuracy.
- [ ] **TEST-02**: Add local fixture HTTP server integration tests with negative controls for each operational family.
- [ ] **TEST-03**: Assert zero socket creation and zero DNS resolution in all offline modes.
- [ ] **TEST-04**: Security boundary tests for TLS errors, SSRF blocks (including IPv4-mapped IPv6), DNS rebinding, and fail-closed scope resolution.
- [ ] **TEST-05**: Full test suite passes 100% across repository, `bb-doctor` Category 23 reports healthy, and OpenCode deployment verified.
- [ ] **DOCS-01**: Update documentation and skill guidance.
- [ ] **DOCS-02**: Plan and conclude work in a single consolidated commit: `fix: correct authentication validation integrity and executor safety`.

### Out of Scope

<!-- Explicit boundaries to prevent scope creep -->

- Redesigning the single-agent architecture or altering accepted Phases 1–13.
- Spawning product runtime subagents or introducing multi-agent configurations (`subagent_depth = 1` invariant).
- External pentesting engines (no Xalgorix, no Strix).
- Destructive testing, credential stuffing, password spraying, dictionary attacks, or OTP brute-forcing.
- Active network testing against real-world external targets during planning or testing.
- Automated vulnerability submission to bug bounty platforms.
- Git history rewriting, force-pushing, or committing runtime secrets/evidence.

## Context

- **Brownfield Baseline**: BugBounty-Agent has 14 completed product phases, Phase 14.1 hardened pipeline, 18 modular skills, and 341 passing automated tests.
- **Operating Environments**: Windows 10/11 acts as the local development workstation; Kali Linux 2024+ acts as the target security runtime hosting OpenCode.
- **Phase 14.2 Focus**: Correcting validation integrity and request-executor safety defects. The goal is producing defensible, reproducible, evidence-backed findings suitable for responsible disclosure.

## Constraints

- **Single-Agent Invariant**: Exactly ONE OpenCode primary agent named `Bug-Bounty` (`agents/Bug-Bounty.md`).
- **Skills Catalog**: Exactly 18 modular skills in `skills/`.
- **Scope Verification**: Every network interaction must be pre-verified by `framework/scope/engine.py` against `scope.yaml`.
- **Operator Gating**: State-mutating operations require explicit `--approve` operator confirmation via `AuthenticationApprovalGate`. Invariant: approval never overrides scope restrictions.
- **Data Protection**: Real secrets, tokens, credentials, and evidence must never be committed to Git.
- **Sequential Execution**: Phase 14.2 plans must be executed sequentially, never parallelized.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Single Global Agent (`Bug-Bounty`) | Eliminates token fragmentation, inter-agent sync lag, and subagent orchestration failures | ✓ Good |
| 18 Modular Skills | Encapsulates specialized domain methodologies as lightweight markdown guides | ✓ Good |
| Real Differential Validation | Purges fabricated comparison strings and hardcoded mocks from live evaluation | ✓ Planned |
| Connection-Time SSRF / Pinning | Mitigates TOCTOU / DNS rebinding attacks against loopback, private, and metadata IP ranges | ✓ Planned |
| Canonical Scope Enforcement | Removes unsafe cwd fallbacks to guarantee strict multi-program isolation | ✓ Planned |
| Deterministic Hypothesis Fingerprints | SHA-256 context-aware hashing enables deterministic deduplication and resume | ✓ Planned |
| Single Consolidated Commit | Clean git history without intermediate broken commits | ✓ Planned |
