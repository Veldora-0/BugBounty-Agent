# BugBounty-Agent — Temporary 24-Phase Roadmap

> **TEMPORARY PROJECT MEMORY FILE.** This file was requested to preserve the agreed continuation roadmap during planning. Delete it when the user explicitly asks. It is not a runtime configuration file and must not contain target data, credentials, or findings.
>
> **Repository baseline:** `5502633bf4828e1c3a7493f36cdccbf435a1ebbf`  
> **Current phase:** Phase 18 — SSRF, XXE & Server-Side Parser Expansion
> **Architecture invariants:** one custom OpenCode agent (`Bug-Bounty`); subagents disabled; no Xalgorix/Strix; runtime program data and secrets stay outside Git; scope enforcement fails closed; no destructive or unauthorized testing; no automatic report submission.

## 1. Roadmap at a glance

| Phase | Name | Priority | Status |
|---|---|---:|---|
| 1–14 | Existing core and intelligence engines | — | Complete; do not reopen without concrete evidence |
| 15 | File Upload, Path Traversal & Local File Exposure | Critical | Complete (acceptance report supplied) |
| 16 | Browser Runtime & Client-Side Security | High | Complete (accepted with documented limitations) |
| 17 | Advanced API Security | High | Complete (accepted at `5502633bf4828e1c3a7493f36cdccbf435a1ebbf` with documented limitations) |
| 18 | SSRF, XXE & Server-Side Parser Expansion | High | In Review (Security Corrections Delivered; Awaiting Acceptance) |
| 19 | Infrastructure & Configuration Exposure | Medium–High | Planned |
| 20 | Race Conditions & Distributed Workflows | Medium–High | Planned |
| 21 | Authentication & Authorization Correlation | Medium | Planned |
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
**Status:** In Review (Security & OOB trust correction pass delivered; awaiting independent acceptance review).
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
- **Cross-Platform Verification Results**:
  - Windows 11 (Python 3.14.7): 729 passed, 2 skipped (expected Playwright real-browser tests in `tests/test_phase16_browser_runtime.py`) in 100s; 100% pass across all 92 Phase 18 tests and 26 SSRF engine tests.
  - Kali Linux (Python 3.14.8): Synchronized and verified across all Phase 18 suites and full regression suites.
- **Documented Phase 18 Limitations**:
  - Zero sensitive local file extraction (`file://`, `/etc/passwd`, `/etc/shadow`, `win.ini`) or cloud metadata probing (`169.254.169.254`, `metadata.google.internal`) is permitted; any matching target fails closed immediately.
  - Internal entity reflection is reported as an observation without implying external entity resolution.
  - External entity resolution is unconfirmed unless an attributable, permitted out-of-band callback is received by an active provider.
  - All active XXE validation requires explicit human approval gate (`approval_status == 'APPROVED'`) before dispatch.

### Phase 19 — Infrastructure & Configuration Exposure
**Goal:** Correlate service and configuration observations with safe checks for exposed administrative surfaces, accidental configuration/backup exposure, unsafe defaults, and deployment mistakes. Distinguish informational observations from demonstrable vulnerabilities and avoid broad or disruptive scanning.

### Phase 20 — Race Conditions & Distributed Workflows
**Goal:** Model concurrency-sensitive invariants and bounded, explicitly approved tests using isolated fixtures. Avoid high-volume request floods, destructive state changes, or uncontrolled concurrent operations against production systems.

### Phase 21 — Authentication & Authorization Correlation
**Goal:** Correlate existing authentication/session and authorization engines: principal, role, tenant, session, resource, and workflow context. Reuse established dual-principal baselines and require strong evidence before reporting access-control findings.

### Phase 22 — Cross-Engine Attack-Path Correlation
**Goal:** Build a shared correlation layer that relates assets, endpoints, identities, vulnerabilities, evidence, and prerequisites into explainable attack paths. Preserve individual finding identity, provenance, confidence, and lifecycle; do not inflate severity solely because findings are connected.

**Cross-cutting constraint:** Establish compatible correlation identifiers and provenance requirements while implementing Phases 15–21 so that Phase 22 does not require a costly redesign. This is a design constraint, not permission to implement all of Phase 22 early.

### Phase 23 — Autonomous Research Planning & Coverage Intelligence
**Goal:** Use evidence, confidence, coverage gaps, dependencies, budgets, and available capabilities to propose and prioritize the next safe research steps. Track tests as passed, failed, inconclusive, unavailable, skipped, or not attempted. Planning must not override scope, approval, or safety policies.

### Phase 24 — Final Integration & Production Readiness
**Goal:** Perform final acceptance of the connected system: scope enforcement, engine contracts, evidence integrity, finding lifecycle, deduplication, persistence/recovery, resource limits, runtime isolation, secret hygiene, CLI/skill/deployment consistency, documentation, and reproducible Windows/Kali verification. No automatic external submission.

## 4. Recommended execution strategy

1. **Start with Phase 15.** Do not replace it with a general orchestration phase.
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

The initial priority recommendation is:
1. Phase 15 — file handling coverage.
2. Phase 16 — reliable browser capability and client-side analysis.
3. Phase 22 — high-value cross-engine reasoning; prepare compatible identifiers during Phases 15–21.
4. Phase 23 — research planning once capability and correlation signals are trustworthy.
5. Phase 24 — final acceptance.

Phases 17–21 remain in the roadmap and should be ordered by demonstrated coverage gaps and dependencies. The numeric sequence remains the default execution order unless a focused audit provides a clear, documented reason to change it.

## 6. Project objective

Build an agent that can reliably answer:
1. Which assets and application surfaces are authorized and in scope?
2. Which security boundaries could be violated?
3. What is the safest meaningful test for each hypothesis?
4. What evidence proves, disproves, or leaves the hypothesis unresolved?
5. Which validated findings matter most, and how should they be reported?

The objective is trustworthy, explainable, reproducible security research—not the largest possible collection of scanners.
