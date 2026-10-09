# BugBounty-Agent

## What This Is

A professional, modular Bug Bounty Security Research Agent framework built for OpenCode. The system operates as a single global primary orchestrator agent named `Bug-Bounty` supported by 18 specialized methodology skills, executing deterministic hypothesis-driven reconnaissance, attack surface analysis, vulnerability testing, and adversarial verification on authorized bug bounty targets.

## Core Value

Enable safe, hypothesis-driven, non-destructive bug bounty security research with strict offline scope enforcement, local data isolation outside Git, and adversarial validation without scanner false positives.

## Requirements

### Validated

<!-- Shipped and confirmed valuable across Phases 1–14 -->

- ✓ [Phase 1: Asset Intelligence] Recursive subdomain discovery, asset graph modeling, TLS SAN extraction, CDN attribution — v1.1.0
- ✓ [Phase 2: Reconnaissance Intelligence] Passive intelligence (crt.sh, subfinder) and rate-limited active probing (httpx) — v1.2.0
- ✓ [Phase 3: Web Application Intelligence] Web surface cataloging, CORS policy analysis, cookie audits, endpoint extraction — v1.3.0
- ✓ [Phase 4: JavaScript Intelligence] Static JS analysis, route discovery, source map reconstruction, DOM sink triage — v1.4.0
- ✓ [Phase 5: API Security & Parameter Intelligence] REST verb tampering, GraphQL introspection/depth, parameter discovery — v1.5.0
- ✓ [Phase 6: Security Validation Foundation] 6-gate verification checklist, false positive classification, confidence scoring — v1.6.0
- ✓ [Phase 7: XSS Intelligence & Validation] Context-aware reflection, DOM sink verification, headless browser proof — v1.7.0
- ✓ [Phase 8: Authorization & Access Control] BOLA/IDOR, horizontal/vertical privilege escalation, tenant isolation — v1.8.0
- ✓ [Phase 9: SSRF & Out-of-Band Intelligence] ProjectDiscovery Interactsh callbacks, blind SSRF/XXE verification — v1.9.0
- ✓ [Phase 10: Injection Intelligence] Non-destructive proof markers (arithmetic `{{7*7}}`, safe time delay `sleep(3)`) for SQLi, NoSQLi, SSTI, CMDi — v1.10.0
- ✓ [Phase 11: HTTP / Header Trust Security] Host header injection, cache poisoning, HTTP request smuggling analysis — v1.11.0
- ✓ [Phase 12: Business Logic Intelligence] Multi-step workflow bypasses, sequence skipping, race conditions, decimal rounding — v1.12.0
- ✓ [Phase 13: Cloud Security Intelligence] S3/GCS bucket permissions, cloud metadata SSRF, dangling CNAME takeovers — v1.13.0
- ✓ [Phase 14: Authentication & Identity Intelligence Baseline] Initial data models, analyzers, 14 vulnerability families, and 21 offline lab scenarios — v1.14.0

### Active

<!-- Current scope: Phase 14.1 Authentication Engine Hardening & Pipeline Integration -->

- [ ] **PIPE-01**: Complete the end-to-end operational execution pipeline for `bb-auth --validate` against target workflows without unhandled exceptions.
- [ ] **PIPE-02**: Support verified handling of operational flags (`--passive-only`, `--dry-run`, `--hypotheses`, `--validate`, `--flow`, `--identity`, `--resume`, `--approve`, and `--tree`).
- [ ] **SCOPE-01**: Integrate directly with `framework.scope.engine.ScopeEngine`, validating candidate target endpoints offline prior to network interaction.
- [ ] **SCOPE-02**: Resolve program-level and directory-level `scope.yaml` paths deterministically; fail closed upon missing or ambiguous scope.
- [ ] **STATE-01**: Ingest actual state files from prior phases (`state/webapps.json`, `state/javascript.json`, `state/api.json`, `state/assets.json`, `state/recon.json`, `state/authorization.json`, `state/workflows.json`).
- [ ] **STATE-02**: Ensure robust handling of missing, partial, or corrupted state files with graceful fallbacks.
- [ ] **COV-01**: Operational coverage across all 14 declared vulnerability families:
  - `AUTHENTICATION_BYPASS` (operational, baseline-verified)
  - `PRE_AUTH_PRIVILEGE_EXPOSURE` (operational, boundary-verified)
  - `SESSION_FIXATION` (operational, pre/post-auth ID reuse verified)
  - `SESSION_NOT_INVALIDATED` (operational, post-logout/post-PW reuse verified)
  - `SESSION_NOT_ROTATED` (observation-only / hardening concern)
  - `PASSWORD_RESET_TOKEN_REUSE` (operational on approved accounts)
  - `PASSWORD_RESET_STATE_CONFUSION` (operational / workflow state mismatch)
  - `ACCOUNT_ENUMERATION` (operational, repeatable differential evidence required)
  - `MFA_BYPASS` (operational, verified boundary crossing)
  - `MFA_STATE_CONFUSION` (operational / intermediate session confusion)
  - `REFRESH_TOKEN_REUSE` (operational, post-rotation reuse verified)
  - `TOKEN_TRANSPORT_EXPOSURE` (observation-only / query string & header transport)
  - `AUTHENTICATION_STATE_INCONSISTENCY` (operational, component discrepancy verified)
  - `AUTHENTICATION_CONFIGURATION_WEAKNESS` (observation-only / cookie flags & token lifetime)
- [ ] **HEUR-01**: Evidence-backed validation heuristics eliminating false positives on static 200 OK login pages through baseline response differentials.
- [ ] **HEUR-02**: Differential proof requirements for account enumeration and session invalidation against protected resources.
- [ ] **HEUR-03**: Strict operator approval gating (`AuthenticationApprovalGate`) via `--approve` for all state-mutating actions.
- [ ] **DEDUP-01**: Deterministic SHA-256 hypothesis fingerprinting based on normalized target endpoint, HTTP method, vulnerability family, and principal role.
- [ ] **DEDUP-02**: Test deduplication against `state/tests.json` and reliable `--resume` state recovery from `state/authentication.json`.
- [ ] **EVID-01**: High-integrity evidence management with SHA-256 request/response digests and strict redaction of credentials, cookies, tokens, and OTPs.
- [ ] **EVID-02**: Native findings integration using `framework.findings.schema.Finding` and persistence in `state/findings.json`.
- [ ] **TEST-01**: Preserve all 21 existing offline authentication lab scenarios and add 18 new integration and safety test cases.
- [ ] **TEST-02**: Cross-platform verification on Windows workstation and Kali Linux VM with 100% test pass rate and all 23 `bb-doctor` categories healthy.
- [ ] **DOCS-01**: Update documentation, OpenCode configuration, and skill guidance in `skills/authentication/SKILL.md`.

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

- **Brownfield Baseline**: BugBounty-Agent has 14 completed product phases, 18 modular skills, and 323 passing automated tests.
- **Operating Environments**: Windows 10/11 acts as the local development workstation; Kali Linux 2024+ acts as the target security runtime hosting OpenCode.
- **Phase 14 Baseline**: Phase 14 established foundational models, analyzers, and 21 offline lab scenarios. Phase 14.1 hardens the active CLI pipeline (`bb-auth --validate`), scope integration, cross-phase state ingestion, and end-to-end evidence synthesis.

## Constraints

- **Single-Agent Invariant**: Exactly ONE OpenCode primary agent named `Bug-Bounty` (`agents/Bug-Bounty.md`).
- **Skills Catalog**: Exactly 18 modular skills in `skills/`.
- **Scope Verification**: Every network interaction must be pre-verified by `framework/scope/engine.py` against `scope.yaml`.
- **Operator Gating**: State-mutating operations require explicit `--approve` operator confirmation via `AuthenticationApprovalGate`.
- **Data Protection**: Real secrets, tokens, credentials, and evidence must never be committed to Git.
- **Sequential Execution**: Phase 14.1 plans must be executed sequentially, never parallelized.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Single Global Agent (`Bug-Bounty`) | Eliminates token fragmentation, inter-agent sync lag, and subagent orchestration failures | ✓ Good |
| 18 Modular Skills | Encapsulates specialized domain methodologies as lightweight markdown guides | ✓ Good |
| Native Python Engine Architecture | Eliminates brittle third-party autonomous pentest engine dependencies | ✓ Good |
| Root-Anchored Git Isolation | Ensures all program state (`state/`), evidence (`evidence/`), and scans remain local | ✓ Good |
| Preserved 14 Vulnerability Families | Maintains consistency with existing Phase 14 models; maps signals without inventing new families | ✓ Good |
| Native Finding Model Integration | Uses existing `framework.findings.schema.Finding` without introducing parallel structures | ✓ Good |
| Phase 14.1 Hardening Focus | Hardens the active CLI pipeline and cross-phase state ingestion before progressing | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-10-09 after Phase 14.1 planning correction pass*
