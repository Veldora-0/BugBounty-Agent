# BugBounty-Agent — Temporary 24-Phase Roadmap

> **TEMPORARY PROJECT MEMORY FILE.** This file was requested to preserve the agreed continuation roadmap during planning. Delete it when the user explicitly asks. It is not a runtime configuration file and must not contain target data, credentials, or findings.
>
> **Repository baseline:** `73056c329d440dc51f1485fccfbfad25bf1c4927`  
> **Current next phase:** Phase 15 — File Upload, Path Traversal & Local File Exposure  
> **Architecture invariants:** one custom OpenCode agent (`Bug-Bounty`); subagents disabled; no Xalgorix/Strix; runtime program data and secrets stay outside Git; scope enforcement fails closed; no destructive or unauthorized testing; no automatic report submission.

## 1. Roadmap at a glance

| Phase | Name | Priority | Status |
|---|---|---:|---|
| 1–14 | Existing core and intelligence engines | — | Complete; do not reopen without concrete evidence |
| 15 | File Upload, Path Traversal & Local File Exposure | Critical | **Next** |
| 16 | Browser Runtime & Client-Side Security | High | Planned |
| 17 | Advanced API Security | High | Planned |
| 18 | SSRF, XXE & Server-Side Parser Expansion | High | Planned |
| 19 | Infrastructure & Configuration Exposure | Medium–High | Planned |
| 20 | Race Conditions & Distributed Workflows | Medium–High | Planned |
| 21 | Authentication & Authorization Correlation | Medium | Planned |
| 22 | Cross-Engine Attack-Path Correlation | Very High | Planned |
| 23 | Autonomous Research Planning & Coverage Intelligence | High | Planned |
| 24 | Final Integration & Production Readiness | Mandatory | Planned |

Priorities are provisional and must be refined by evidence from the repository and tests. Phase numbering is the roadmap, not a requirement to duplicate capabilities that already exist.

## 2. Repository-informed planning notes

A targeted inspection at the accepted baseline found useful foundations, but not a complete Phase 15 engine:

- Web application parsing already records HTML forms and whether a form contains a file input.
- API parameter classification already recognizes file-related parameter names.
- The validation model includes `PATH_TRAVERSAL` and `FILE_UPLOAD` vulnerability families, but the validation skill describes path-traversal capability as unavailable.
- Existing path-traversal protections for report/artifact paths protect the agent's own filesystem paths; they do **not** constitute a target-side path-traversal assessment engine.
- Cloud security explicitly prohibits automated file upload, deletion, and overwrite operations. Preserve that safety boundary.
- A browser skill and Playwright tool registration exist, but that alone does not prove the runtime, browser dependencies, headless operation, or browser-driven security workflow are reliable.
- API security and SSRF already have dedicated engines. Phases 17 and 18 must extend those capabilities where evidence shows gaps, not create competing duplicate engines.
- Authentication, authorization, shared finding lifecycle, evidence handling, scope enforcement, and reporting already exist and should be reused.

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
**Goal:** Extend the existing API engine only where coverage gaps justify it. Candidate areas include deeper schema/operation relationships, authorization-aware API flows, GraphQL-specific analysis, content-type/parser edge cases, and safe method/parameter behavior. Preserve strict request budgets, scope checks, and non-destructive defaults.

### Phase 18 — SSRF, XXE & Server-Side Parser Expansion
**Goal:** Extend the existing SSRF engine and add evidence-based, safe server-side parser analysis—especially XXE and relevant structured document formats—without duplicating Phase 9 SSRF functionality. Prefer non-egress canaries and isolated local fixtures; no cloud metadata access or uncontrolled out-of-band callbacks.

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
