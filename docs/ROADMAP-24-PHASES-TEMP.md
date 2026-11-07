# BugBounty-Agent — Temporary 24-Phase Roadmap

> **TEMPORARY PROJECT MEMORY FILE.** This file was requested to preserve the agreed continuation roadmap during planning. Delete it when the user explicitly asks. It is not a runtime configuration file and must not contain target data, credentials, or findings.
>
> **Current Repository Baseline:** `6d1e3a5304f6eac08f7d272dd39ce8793379af66` (Phase 21 final security closure and regression verification completed; baseline starting HEAD: `6d1e3a5304f6eac08f7d272dd39ce8793379af66`; pre-Phase 21 baseline: `45b4edb1210ac02144b26d1226d104d9f1d15042`; historical Phase 1–20 baseline: `396ed0e5986f9f1e41bb0bec1201ee217011bc56`; Stage C baseline: `1841280b2f71b103b0e9217b961f1d859bd94272`; starting baseline: `c8bfebefe91c24b2fa5fd1ad20240f76cc7390ae`)
> **Current phase:** Phase 21 — Authentication & Authorization Correlation (Complete; Next Phase: Phase 22 — Cross-Engine Attack-Path Correlation — PLANNED)
> **Architecture invariants:** one custom OpenCode agent (`Bug-Bounty`); subagents disabled; no Xalgorix/Strix; runtime program data and secrets stay outside Git; scope enforcement fails closed; no destructive or unauthorized testing; no automatic report submission.

## 1. Roadmap at a glance

| Phase | Name | Priority | Status |
|---|---|---:|---|
| 1–14 | Existing core and intelligence engines | — | Complete; do not reopen without concrete evidence |
| 15 | File Upload, Path Traversal & Local File Exposure | Critical | Complete (acceptance report supplied) |
| 16 | Browser Runtime & Client-Side Security | High | Complete (accepted with documented limitations) |
| 17 | Advanced API Security | High | Complete (accepted at `5502633bf4828e1c3a7493f36cdccbf435a1ebbf` with documented limitations) |
| 18 | SSRF, XXE & Server-Side Parser Expansion | High | Complete (accepted at `1fcd552d53f99cf0a06802ddae45197796ec74c5` with documented limitations) |
| 19 | Infrastructure & Configuration Exposure | Medium–High | Complete (accepted at `78f949a6d3b614ca60a82d7f776641787a6bebaa` with documented limitations) |
| 20 | Race Conditions & Distributed Workflows | Medium–High | Complete (accepted at `3759f1ecb59168a6d4bb5ddaba7674d98afff24f` with documented limitations) |
| 21 | Authentication & Authorization Correlation | Medium | Complete (Accepted; Stages 1–5 verified) |
| 22 | Cross-Engine Attack-Path Correlation | Very High | Planned |
| 23 | Autonomous Research Planning & Coverage Intelligence | High | Planned |
| 24 | Final Integration & Production Readiness | Mandatory | Planned |

Priorities are provisional and must be refined by evidence from the repository and tests. Phase numbering is the roadmap, not a requirement to duplicate capabilities that already exist.

## 2. Repository-informed planning notes

A targeted inspection at the earlier planning baseline found useful foundations, but not a complete Phase 15 engine. Phase 15 was subsequently accepted by the supplied acceptance report at `d1f7df8f1f17811d9e49484c202cb950edfc582f`; its reported test results have not been independently rerun in this synchronization step:

- Web application parsing already records HTML forms and whether a form contains a file input.
- API parameter classification already recognizes file-related parameter names.
- The validation model includes `PATH_TRAVERSAL` and `FILE_UPLOAD` vulnerability families, but the validation skill describes path-traversal capability as unavailable.
- Existing path-traversal protections for report/artifact paths protect the agent's own filesystem paths; they do **not** constitute a target-side path-traversal assessment engine.
- Cloud security explicitly prohibits automated file upload, deletion, and overwrite operations. Preserve that safety boundary.
- A browser skill and Playwright tool registration exist, but that alone does not prove the runtime, browser dependencies, headless operation, or browser-driven security workflow are reliable.
- API security and SSRF already have dedicated engines. Phases 17 and 18 must extend those capabilities where evidence shows gaps, not create competing duplicate engines.
- Authentication, authorization, shared finding lifecycle, evidence handling, scope enforcement, and reporting already exist and should be reused.

### Phase 17 Acceptance & Verification Record
Phase 17 (Advanced API Security) was accepted at baseline commit `5502633bf4828e1c3a7493f36cdccbf435a1ebbf`.
- **Test execution results reported by environments**:
  - Windows 11 (Python 3.14.7): 87 passed in `tests/test_api_engine.py`; 628 passed, 2 skipped (expected Playwright real-browser tests in `tests/test_phase16_browser_runtime.py` when browser binaries are not installed) in full test suite.
  - Kali Linux (Python 3.14.8): 87 passed in `tests/test_api_engine.py`; 630 passed, 0 skipped in full test suite.
- **Review and acceptance status**:
  - Independent code and diff review conducted against baseline `5502633bf4828e1c3a7493f36cdccbf435a1ebbf`.
  - Continuous response-byte budget accounting (Finding A) and fixture-port exact-port gating with exclusion precedence (Finding B) verified.
- **Documented Phase 17 limitations**:
  - Active GraphQL introspection is strictly opt-in (`allow_graphql_introspection=True`, default `False`) and bounded to 5,000 parameters and max schema depth.
  - Continuous response-byte accounting (`total_bytes_transferred`) depletes the global network budget (`max_bytes`) even on malformed, oversized, truncated, or rejected responses.
  - OpenAPI 3.0/3.1 and Swagger 2.0 reference resolution supports local and relative file/URL references up to depth 10; remote references outside authorized scope fail closed.
  - Ephemeral loopback fixture ports strictly require explicit unprivileged integer registration (`1024-65535`) and scope authorization; production targets strictly forbid loopback/RFC 1918/cloud metadata.
  - Explicit scope exclusions take strict precedence over fixture port allowances and target inclusions.
  - Automated exploitation and automatic report submission are strictly prohibited.

### Phase 18 Acceptance & Verification Record
Phase 18 (SSRF, XXE & Server-Side Parser Expansion) was accepted at baseline commit `1fcd552d53f99cf0a06802ddae45197796ec74c5`.
- **Test execution results reported by environments** *(from prior verification passes; not independently rerun during documentation-only tasks)*:
  - Windows 11 (Python 3.14.7): 26 passed in `tests/test_ssrf_engine.py`; 92 passed in `tests/test_phase18_*.py`; 729 passed, 2 skipped (expected Playwright real-browser interactive PTY tests in `tests/test_browser_skill.py`) in full test suite.
  - Kali Linux (Python 3.14.8): 118 passed across targeted SSRF and Phase 18 test suites; 731 passed, 0 skipped in full regression suite.
- **Review and acceptance status**:
  - Independent source review conducted across `framework/common/xml_safe.py`, `framework/common/transport.py`, `framework/ssrf/`, `framework/xxe/`, `framework/validation/`, and related test suites.
  - Verified agent-side XML parser hardening with cumulative expanded-character ceilings (`max_expanded_chars`), Expat amplification factor defenses, and safe sitemap parsing.
  - Verified alternate numeric IP parsing (`parse_alternate_ip`), continuous response-byte accounting across partial reads, redirects, and HTTP errors, and multi-record DNS resolution anti-SSRF protections.
  - Verified safe SSRF mutation across Query, Path, JSON, Form, and XML payloads.
  - Verified conservative XXE signal classification: internal entity reflection emits `OBSERVATION` (`INFORMATIONAL`, `MEDIUM` confidence); parser errors emit zero findings.
  - Verified truthful OOB provider availability reporting: unconfigured providers report `CONFIG_REQUIRED`; configured adapters without operational live wire polling report `UNAVAILABLE`.
  - Verified fail-closed provider availability gate before canary generation or probe dispatch.
  - Verified mandatory `validate_oob_destination` method presence and callable verification before network dispatch in both SSRF and XXE engines.
  - Verified mock provider interactions strictly produce `SIMULATED` (`INFORMATIONAL`, `LOW` confidence) findings and can never produce live validated findings.
- **Documented Phase 18 limitations**:
  - Zero sensitive local file extraction (`file://`, `/etc/passwd`, `/etc/shadow`, `win.ini`) or cloud metadata probing (`169.254.169.254`, `metadata.google.internal`) is permitted; any matching target fails closed immediately.
  - Configured Interactsh and Collaborator adapters do not have operational live wire polling implemented in this repository; local in-memory storage only. Truthful status reports `UNAVAILABLE` when configured.
  - Internal entity reflection proves internal DTD processing only and does not establish external entity resolution.
  - External entity resolution is unconfirmed unless an attributable, permitted out-of-band callback is received by an active provider.
  - All active SSRF and XXE validation requires prior explicit human approval (`approval_status == 'APPROVED'`). Automated exploitation and automatic report submission are strictly prohibited.

### Phase 19 Acceptance & Verification Record
Phase 19 (Infrastructure & Configuration Exposure) was completed and accepted.
- **Test execution results reported by environments**:
  - Windows 11 (Python 3.14.7): 39 passed in `tests/test_infrastructure_engine.py`; 4 passed in `tests/test_doctor.py`; 769 passed, 2 skipped (expected Playwright real-browser interactive PTY tests in `tests/test_browser_skill.py`) in full test suite (125.49s).
  - Kali Linux (Python 3.14.8): SSH connectivity check to `127.0.0.1:2222` returned connection refused; VBoxManage reports VM "Kali" is registered but offline (0 running VMs). Full suite synchronization and run pending host VM boot.
- **Review and acceptance status**:
  - Core module `framework/infrastructure/` implemented with 8 exposure classes: Version Control (`.git`, `.svn`), Configuration Files (`.env`, `web.config`), Backup Archives (`.zip`, `.tar.gz`), Administrative Interfaces (`/actuator/health`, `/admin`), Deployment Manifests (`package.json`, `composer.json`), Source Maps (`.js.map`), Directory Listings (`Index of /`), and Debug / Diagnostic Endpoints.
  - Differential soft-404 comparison engine (`DifferentialSoft404Engine`) with dynamic token stripping (timestamps, nonces, CSRFs) and token Jaccard similarity; strictly enforces non-rejection invariant (never rejects candidate solely because baseline returned 200).
  - Evidence-sufficiency stopping rules strictly enforced (32 KB response ceiling, 8 KB config ceiling, 1 KB binary magic bytes ceiling) with continuous byte budget accounting.
  - Strict read-only safe HTTP methods (`{"GET", "HEAD", "OPTIONS"}`); state-changing query parameters and `POST`/`PUT`/`DELETE`/`TRACE` strictly blocked.
  - Scope fail-closed and anti-SSRF IP literal protections enforced prior to any request dispatch.
  - Sentinel secret scrub and automatic redaction across state, findings, and reports (`sanitize_sensitive_data`).
  - Added CLI tool `scripts/bb-infra` (`scripts/bb-infra.cmd`), `bb-doctor` category 24, and OpenCode V2 permissions.
- **Documented Phase 19 limitations**:
  - Read-only safe probing only; zero automated exploitation, credential brute-forcing, archive downloads, or secret replay.
  - Administrative login interfaces are classified strictly as `OBSERVATION` (`INFORMATIONAL`, `HIGH` confidence), never as high-severity vulnerabilities.
  - Local simulation lab (`LocalInfrastructureLab`) findings are marked `SIMULATED` (`INFORMATIONAL`, `CONFIRMED` confidence) and cannot produce live validated findings.
  - Automatic disclosure report submission is strictly prohibited.

### Phase 21 Acceptance & Verification Record
Phase 21 (Authentication & Authorization Correlation) was completed and accepted across all 5 implementation stages with comprehensive post-implementation security corrections and cross-platform verification.
- **Test execution results reported by environments**:
  - Windows 11 (Python 3.14.7): 72 passed, 1 skipped in targeted Phase 21 suite (`tests/test_phase21_*.py`) in 8.61s; 1012 passed, 3 skipped in full regression suite (154.68s).
  - Kali Linux (Python 3.14.8): 72 passed, 1 skipped in targeted Phase 21 suite in 6.93s; 1014 passed, 1 skipped in full regression suite (127.99s); real browser Firefox integration test passed in 16.48s (`test_real_browser_firefox_local_spa_integration`); concurrency regression test passed in 0.72s.
  - System Diagnostics (`bb-doctor` Category 26): `[HEALTHY]` (status HEALTHY, 6 scenarios verified across all 26 diagnostic categories; 44 security tools registered).
- **Review and acceptance status**:
  - Delivered `framework/auth_correlation/` with 9 core modules: `model.py` (strict allowlists, safe string/repr representations masking credentials/secrets), `cvss.py` (FIRST CVSS 3.1 metric equations), `preflight.py` (`DualControlPreflightValidator`), `revocation.py` (`PostRevocationResourceValidator`), `pre_mfa.py` (`PreMfaPrivilegeValidator`), `tenant.py` (`MultiTenantDesyncValidator`), `engine.py` (`AuthCorrelationEngine`), `state.py` (`AuthCorrelationStateManager`), and `lab.py` (`SimulationTransport`, `LocalAuthCorrelationLab`).
  - Added CLI tool `scripts/bb-auth-correlate` (`scripts/bb-auth-correlate.cmd`), Category 26 in `framework/tools/doctor.py`, and OpenCode V2 permissions in `opencode.jsonc`.
  - Anonymous Differential Preflight Protocol: executes full 3-probe sequence (Probe 1 authenticated $\rightarrow$ Probe 2 authenticated $\rightarrow$ Probe 3 anonymous control $\rightarrow$ differential classification); sequential short-circuiting preserved; fails closed on anonymous 5xx/transport faults; rejects responses equivalent to anonymous control ($> 0.70$ similarity) and generic SPA/WAF/login shells.
  - Verified Invalidation Provenance & File Integrity: Mode A and engine preflight enforce `verify_invalidation_provenance()`, verifying descriptor schema (`evidence_id`, `filename`, `sha256`, `metadata`), verifying presence of regular `.txt` capture file on disk, recomputing SHA-256 capture digest matching descriptor, rejecting Mode A observation captures reused as invalidation proofs, requiring explicit `event_type` from `GENUINE_INVALIDATION_EVENTS`, and requiring exact attribution across `session_ref`, `principal_id`, and `program_id`.
  - Pre-MFA State Enforcement: `PreMfaPrivilegeValidator` independently requires `session_ctx.metadata["mfa_level"] == "PRE_MFA"`, requires comparison session `full_session_ctx.metadata["mfa_level"] == "FULL_MFA"`, verifies 200 OK baseline without login/SPA shells, and rejects missing/ambiguous/`NONE`/malformed metadata prior to probe dispatch, guaranteeing zero network traffic.
  - Mode A Scope Authorization at Dispatch: enforces read-only `GET`/`HEAD` methods strictly; evaluates `ScopeEngine.is_in_scope()` immediately prior to dispatch; fails closed if `scope_engine` is absent or throws on live requests; binds scope engine to prevent redirect escapes.
  - Mode A revocation orchestration directly wired into `engine.py` execution; strictly observation-only (read-only GET/HEAD) with mandatory baseline and attributable invalidation evidence checks.
  - Conservative revocation response classification (`classify_revocation_response`): explicit 401 $\to$ `REVOKED`/`EXPIRED`, generic 401 $\to$ `AUTHENTICATION_FAILED`, 403 $\to$ `AUTHORIZATION_DENIED` (no finding emitted), login redirect $\to$ `REDIRECT_LOGIN`, WAF/shells $\to$ `INCONCLUSIVE`, baseline match $\ge 0.50 \to$ `SESSION_NOT_INVALIDATED`.
  - Candidate discovery contract: candidates derived strictly from registered `resource_targets`, `resource_endpoints`, or explicit `target_asset` path; empty discovery returns `[]` without inventing fabricated application routes; candidate URLs validated against origin substitution and `ScopeEngine`.
  - Truthful evidence persistence: strictly saves captures via `EvidenceStore.save_http_capture()`; if `evidence_store is None`, `evidence_chain = []` and notes `[EVIDENCE_NOT_PERSISTED]` in finding descriptions; never swallows persistence exceptions (raises `EvidencePersistenceError`).
  - Enforced atomic descriptor-based state writes (`os.fdopen`), symlink/reparse point rejection, POSIX private permission enforcement (`0o700` dirs / `0o600` files), hard-link checks (`st_nlink == 1`), Windows Win32 `advapi32` DACL validation (`SE_DACL_PROTECTED` 0x1000), and strict JSON schema checking.
  - Enforced loopback transport confinement: `SimulationTransport` communicates strictly with numeric `127.0.0.1:<active_lab_port>`.
  - Mode B approval with HMAC-SHA256 operator authorization signature (`SIG-<64-hex>`) separated from action integrity (`ACT-<64-hex>`); durable cross-process single-use enforcement (`CrossProcessFileLock`).
  - Mandatory ScopeEngine integration: fail-closed scope check immediately before dispatching any mutation probe.
  - Multi-tenant cross-channel testing across PATH, QUERY, and HEADER channels in both directions (`A_TO_B`, `B_TO_A`) with 3-state cache classification and cache-busting corroboration.
  - CLI Production Hardening: active production mode strictly requires `--target`, $\ge 2$ principals, $\ge 2$ sessions, authorized scope, and uncorrupted state (fails closed with exit code 1); missing/invalid dossiers fail closed with exit code 2.
  - Final acceptance status: **ACCEPTED AND CLOSED**.
- **Documented Phase 21 limitations**:
  - Testing is bounded to operator-provided test identities and credentials; automated password spraying, dictionary attacks, or brute-forcing are strictly prohibited.
  - Active probes require explicit human approval (`--approve`) and enforce strict request ceilings ($\le 15$ per hypothesis) and response-byte budgets.
  - High-entropy secrets and credentials are never persisted in state files or logged.
  - Local simulation lab findings are classified as `SIMULATED` (`INFORMATIONAL`, `CONFIRMED`) and cannot produce live external findings.
  - Automatic disclosure report submission is strictly prohibited.

These notes are a preliminary inspection, not a complete coverage audit. Before implementing each phase, inspect the relevant current code and tests at the then-current HEAD.

## 3. Phase goals and boundaries

### Phase 15 — File Upload, Path Traversal & Local File Exposure
**Goal:** Add a dedicated, evidence-led file-handling security capability that consumes existing form/API observations and integrates with shared scope, validation, evidence, finding lifecycle, deduplication, and reporting.

Coverage should include:
- Upload surface discovery and safe assessment of extension, content-type, filename, storage, and processing controls.
- Path normalization and traversal variants, including encoding and platform-specific separators where relevant.
- Local file inclusion and unintended file disclosure hypotheses.
- Clear separation of observations, unvalidated candidates, rejected hypotheses, and validated findings.
- Deterministic local fixtures and regression tests.

Safety boundaries:
- Only test targets with explicit authorization and scope approval.
- Never read arbitrary local files from the agent host to prove a target-side issue.
- Never upload executable or destructive content, overwrite/delete files, or access real sensitive files.
- Prefer synthetic canary files and local lab fixtures; redact any sensitive response material.
- Reuse existing validators and shared models where appropriate; do not duplicate the validation framework.

### Phase 16 — Browser Runtime & Client-Side Security
**Goal:** Make browser-dependent analysis reproducible in headless Kali/CLI environments, including capability detection, lifecycle/cleanup, bounded navigation, client-side route and DOM behavior analysis, and correlation with existing JavaScript/XSS findings. Gracefully report unavailable browser capability rather than silently skipping it.

### Phase 17 — Advanced API Security
**Status:** Complete (accepted at `5502633bf4828e1c3a7493f36cdccbf435a1ebbf`).
**Delivered:** Bounded OpenAPI 2.0/3.0/3.1 and GraphQL schema parsing, continuous byte accounting (`total_bytes_transferred`), fail-closed transport and scope controls, strict loopback fixture port gating with exclusion precedence, state management (`api.json`), and downstream injection engine integration.

### Phase 18 — SSRF, XXE & Server-Side Parser Expansion
**Status:** Complete (accepted at `1fcd552d53f99cf0a06802ddae45197796ec74c5`).
**Delivered:**
- **Agent-Side XML Hardening**: Implemented portable stdlib XML security in `framework/common/xml_safe.py` (`safe_parse_xml`, `safe_extract_sitemap_urls`, `XmlBombSecurityError`, `ProhibitedDtdSecurityError`, `ExternalEntitySecurityError`) with strict cumulative expanded-character budgets (`max_expanded_chars`), Expat amplification factor defense, input byte limits, and Billion Laughs protection. Hardened sitemap parser in `framework/webapp/engine.py` to fail closed immediately on XML security errors with zero regex fallback.
- **SSRF Transport Hardening**: Added `parse_alternate_ip` in `framework/common/transport.py` supporting dotted decimal, decimal scalars, hex scalars, octal scalars, dotted octal/hex, and inet_aton multi-part formats; hardened destination IP resolution in `framework/validation/engine.py` to fail closed if any DNS answer resolves to loopback, private, or metadata IP addresses; implemented continuous streaming byte accounting (`total_bytes_transferred`) across partial reads, redirects, and HTTP errors; added `max_total_bytes` policy control to `SecurityTestPolicy`.
- **SSRF Request Mutation**: Expanded `_build_mutated_request()` in `framework/ssrf/engine.py` to support Query parameters, Path template parameters (`{param}`, `:param`, `<param>`), JSON bodies (flat and nested dotted keys), Form-encoded bodies, and XML bodies (DOM text replacement with XML entity escaping and safe parse error handling). Added `headers` and `body` fields to `SsrfCandidate`.
- **Conservative XXE Intelligence Subsystem**: Created `framework/xxe/` orchestrating non-destructive synthetic entity reflection, signal classification, deterministic local simulation harness (`LocalXxeLab`), state management (`xxe.json`), and deduplication. Added `XXE = "XXE"` to `VulnerabilityFamily`, safe payloads `PL-XXE-REFL-01` and `PL-SSRF-CANARY-01`, and `XxeValidator` / `SsrfValidator` plugins in `SecurityValidationEngine`.
- **Evidence Semantics & Truthful OOB Availability**:
  - Distinguishes XML candidacy, parser errors, observed internal DTD/entity processing, and external entity resolution.
  - Internal entity reflection alone emits an `OBSERVATION` (`INFORMATIONAL`, `MEDIUM` confidence), never a false `HIGH`-severity `VALIDATED` XXE finding.
  - Parser errors and secure rejections emit zero findings (no false positives).
  - Out-of-band correlation (`validate_oob_candidate`) differentiates mock test harness interactions (`SIMULATED`, `INFORMATIONAL`, `LOW` confidence) from live external target callbacks (`VALIDATED`, `HIGH`). Mock interactions can never produce live validated findings.
  - Truthful OOB Provider Availability: `InteractshOobProvider` and `CollaboratorOobProvider` report `CONFIG_REQUIRED` when unconfigured and `UNAVAILABLE` when configured (because live wire polling over network protocols is not implemented; storage is local in-memory only). A configured token or hostname alone does not establish operational live polling.
- **Enforced OOB Destination Trust Boundary & SSRF Provider Gating**:
  - Added `DEFAULT_TRUSTED_OOB_DOMAINS` and `validate_oob_destination()` in `SecurityTestPolicy` (`framework/validation/policy.py`).
  - Prior to canary issuance, baseline requests, or probe dispatch in `SsrfIntelligenceEngine.validate_candidate()` and `XxeIntelligenceEngine.validate_oob_candidate()`:
    1. Requires candidate approval gate (`approval_status == 'APPROVED'`).
    2. Validates target endpoint against authorized program scope.
    3. Verifies OOB provider availability, failing closed if provider reports `UNAVAILABLE`, `CONFIG_REQUIRED`, or `ERROR` with zero network requests dispatched.
    4. Explicitly validates generated canary destination against `SecurityTestPolicy.validate_oob_destination()` before any request is dispatched; verifies that the validation method exists and is callable, failing closed with `PolicyViolationError`, recording `POLICY_VIOLATION` candidate state with clear diagnostic notes, and dispatching zero network requests if missing or non-callable.
    5. Rejects unsupported schemes (only `http`/`https` allowed), embedded credentials, IP literals (loopback, private, carrier-grade NAT, or metadata IP addresses, including alternate hex/octal/dword encodings and trailing IP suffixes like `169.254.169.254`), prohibited hostnames (`metadata.google.internal`, `localhost`), and untrusted domains before any request is dispatched, preventing arbitrary environment variables from silently redirecting callbacks. Candidate is marked `POLICY_VIOLATION` with zero network egress.
    6. Mock provider interactions in both XXE and SSRF engines strictly emit `SIMULATED` findings (`INFORMATIONAL`, `LOW` confidence), guaranteeing mock callbacks can never become live validated findings.
- **Cross-Platform Verification Results** *(Historical verification records from baseline commit `1fcd552d53f99cf0a06802ddae45197796ec74c5`)*:
  - Windows 11 (Python 3.14.7): 729 passed, 2 skipped (expected Playwright real-browser interactive PTY tests in `tests/test_browser_skill.py`) in 107.93s; targeted Phase 18 suite passed 118/118 items (26 in `tests/test_ssrf_engine.py` + 92 in `tests/test_phase18_*.py`).
  - Kali Linux (Python 3.14.8): Synchronized and verified at baseline `1fcd552` (731 passed, 0 skipped in 84.60s; 118 targeted tests passed). Note: During subsequent documentation audits, Kali SSH (`127.0.0.1:2222`) was offline (connection refused); documentation commits remain to be fast-forward pulled once the Kali environment is booted.
- **Documented Phase 18 Limitations**:
  - Zero sensitive local file extraction (`file://`, `/etc/passwd`, `/etc/shadow`, `win.ini`) or cloud metadata probing (`169.254.169.254`, `metadata.google.internal`) is permitted; any matching target fails closed immediately.
  - Configured Interactsh and Collaborator adapters do not have operational live wire polling implemented in this repository; local in-memory storage only. Truthful status reports `UNAVAILABLE` when configured.
  - Internal entity reflection is reported as an observation without implying external entity resolution.
  - External entity resolution is unconfirmed unless an attributable, permitted out-of-band callback is received by an active provider.
  - All active XXE validation requires explicit human approval gate (`approval_status == 'APPROVED'`) before dispatch.

### Phase 19 — Infrastructure & Configuration Exposure
**Status:** Complete (accepted with documented limitations).
**Delivered:**
- **Core Intelligence Engine**: Implemented `framework/infrastructure/` with 8 exposure classes: `VERSION_CONTROL`, `CONFIG_FILE`, `BACKUP_ARCHIVE`, `ADMIN_INTERFACE`, `DEPLOYMENT_MANIFEST`, `SOURCE_MAP`, `DIRECTORY_LISTING`, and `DEBUG_INTERFACE`.
- **Differential Soft-404 Engine**: Implemented `DifferentialSoft404Engine` supporting SPA catch-all, distinct static file, dynamic error page, and redirect catch-all handling. Tokenizes response body after stripping volatile tokens (nonces, timestamps, hashes), computes Jaccard similarity, and enforces the non-rejection invariant (never rejects candidate solely because baseline returned 200).
- **Evidence-Sufficiency Stopping Rules**: Implemented strict response byte ceilings (32 KB response cap, 8 KB config cap, 1 KB binary magic bytes cap) with continuous streaming byte consumption accounting.
- **Fail-Closed Safety Policy**: Implemented `InfrastructureExposurePolicy` allowing safe methods only (`{"GET", "HEAD", "OPTIONS"}`), blocking state-changing GET parameters, and enforcing anti-SSRF protections and offline ScopeEngine authorization.
- **Deterministic Simulation Lab**: Implemented `LocalInfrastructureLab` serving 16 deterministic scenarios on ephemeral loopback ports.
- **CLI & Diagnostics**: Created `scripts/bb-infra` (`scripts/bb-infra.cmd`), added Category 24 (`check_infrastructure_engine`) to `framework/tools/doctor.py` and `scripts/bb-doctor`, and configured OpenCode V2 permissions.

### Phase 20 — Race Conditions & Distributed Workflows
**Goal:** Model concurrency-sensitive invariants and bounded, explicitly approved tests using isolated fixtures. Avoid high-volume request floods, destructive state changes, or uncontrolled concurrent operations against production systems.
- **Implemented Subsystem**: `framework/concurrency/` providing `BarrierSynchronizer` (microsecond precision barrier release via `threading.Barrier`), `ConcurrencyInvariantEngine` (discriminating CONFIRMED invariant breaches from valid CONCURRENCY_CONTROLLED 409/429 contention and INCONCLUSIVE jitter), `ConcurrencySafetyPolicy` (strictly clamped burst 2-5, max cap 10, TRACE blocking, anti-SSRF IP verification), `ConcurrencyStateManager` (`state/concurrency.json`), and `LocalConcurrencyLab` (8 deterministic in-memory scenarios on ephemeral loopback).
- **CLI & Diagnostics**: Created `scripts/bb-race` (`scripts/bb-race.cmd`), registered Category 25 (`check_concurrency_engine`) in `framework/tools/doctor.py` and `scripts/bb-doctor`, updated global OpenCode deployment for 28 utilities.
- **Accepted with Documented Limitations**: Concurrency probing is bounded to 2-10 requests; high-volume volumetric floods or DoS attacks are strictly prohibited; out-of-scope targets fail closed offline.

### Phase 21 — Authentication & Authorization Correlation
**Status:** Complete (Accepted; Stages 1–5 verified).
**Delivered:**
- **Core Models & Safe Representations**: Implemented `framework/auth_correlation/model.py` with `CorrelatedPrincipalContext`, `CorrelatedSessionContext`, `CorrelationHypothesis`, `CorrelationFinding`, and `CorrelationLifecycle`. Masked credentials in `__repr__` and `__str__`.
- **CVSS 3.1 Base Metric Calculator**: Implemented `framework/auth_correlation/cvss.py` strictly evaluating FIRST CVSS 3.1 equations across all 8 base metrics with 10 reference vector regression verifications.
- **Dual-Control Preflight Validation**: Implemented `framework/auth_correlation/preflight.py` (`DualControlPreflightValidator`) verifying session validity differentials against baseline targets to prevent false-positive access control reports.
- **Post-Revocation Resource Probing**: Implemented `framework/auth_correlation/revocation.py` (`PostRevocationResourceValidator`) supporting Mode A (observation-only) and Mode B (dual-account differential probe with human approval gate).
- **Pre-MFA & Step-Up Boundary Auditing**: Implemented `framework/auth_correlation/pre_mfa.py` (`PreMfaPrivilegeValidator`) auditing sensitive resource access prior to MFA completion.
- **Multi-Tenant Cross-Channel Desynchronization**: Implemented `framework/auth_correlation/tenant.py` (`MultiTenantDesyncValidator`) testing route path, query parameter, and custom header tenant substitution using two valid, cryptographically signed tenant identities while preserving JWT signatures.
- **Orchestration, State, Lab & CLI**: Implemented `AuthCorrelationEngine`, hardened `AuthCorrelationStateManager` with atomic file-descriptor replacement and strict POSIX/Windows DACL permissions, `SimulationTransport` (confined to numeric `127.0.0.1:<lab_port>`), `LocalAuthCorrelationLab` (6 deterministic scenarios), CLI script `scripts/bb-auth-correlate` (`bb-auth-correlate.cmd`), and Category 26 in `framework/tools/doctor.py`.

### Phase 22 — Cross-Engine Attack-Path Correlation
**Goal:** Build a shared correlation layer that relates assets, endpoints, identities, vulnerabilities, evidence, and prerequisites into explainable attack paths. Preserve individual finding identity, provenance, confidence, and lifecycle; do not inflate severity solely because findings are connected.

**Cross-cutting constraint:** Establish compatible correlation identifiers and provenance requirements while implementing Phases 15–21 so that Phase 22 does not require a costly redesign. This is a design constraint, not permission to implement all of Phase 22 early.

### Phase 23 — Autonomous Research Planning & Coverage Intelligence
**Goal:** Use evidence, confidence, coverage gaps, dependencies, budgets, and available capabilities to propose and prioritize the next safe research steps. Track tests as passed, failed, inconclusive, unavailable, skipped, or not attempted. Planning must not override scope, approval, or safety policies.

### Phase 24 — Final Integration & Production Readiness
**Goal:** Perform final acceptance of the connected system: scope enforcement, engine contracts, evidence integrity, finding lifecycle, deduplication, persistence/recovery, resource limits, runtime isolation, secret hygiene, CLI/skill/deployment consistency, documentation, and reproducible Windows/Kali verification. No automatic external submission.

## 4. Recommended execution strategy

1. **Execution Order**: Phases 1–21 are complete and verified. The current active roadmap execution point is Phase 22 (Cross-Engine Attack-Path Correlation). Do not replace individual security phases with premature general orchestration.
2. For each phase, do a focused gap review of relevant code/tests before implementation. Avoid a repeated repository-wide audit unless new evidence warrants it.
3. Write acceptance criteria and negative/security tests before coding.
4. Reuse shared scope, transport, policy, state, evidence, finding lifecycle, deduplication, and reporting components.
5. Implement one bounded phase at a time. Do not silently widen scope.
6. Verify targeted tests, then the full Windows suite. Verify on Kali separately and report exactly what ran; never infer a Kali full-suite pass from targeted tests.
7. Keep test fixtures local and deterministic. Never use live third-party targets as regression fixtures.
8. Commit forward-only changes. Never reset, rebase, or force-push accepted history.
9. Accept a phase only with its commit, changed-file summary, test evidence, limitations, and synchronization status.
10. If a concrete security defect appears, fix it with a narrowly scoped corrective commit and regression test; do not reopen closed phases without evidence.

## 5. Priority interpretation

With Phases 1–21 verified and complete, the sequential roadmap priority is:
1. Phase 22 — Cross-Engine Attack-Path Correlation (Active Planning Gate).
2. Phase 23 — Autonomous Research Planning & Coverage Intelligence.
3. Phase 24 — Final Integration & Production Readiness.

The numeric sequence remains the authoritative execution order. Each phase must be completed and accepted before the subsequent phase begins.

## 6. Project objective

Build an agent that can reliably answer:
1. Which assets and application surfaces are authorized and in scope?
2. Which security boundaries could be violated?
3. What is the safest meaningful test for each hypothesis?
4. What evidence proves, disproves, or leaves the hypothesis unresolved?
5. Which validated findings matter most, and how should they be reported?

The objective is trustworthy, explainable, reproducible security research—not the largest possible collection of scanners.
