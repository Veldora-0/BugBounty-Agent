# Phase 16 — Browser Runtime & Client-Side Security Plan

**Planning baseline:** `d1f7df8f1f17811d9e49484c202cb950edfc582f`  
**Planning commit:** created after Phase 15 roadmap synchronization  
**Status:** Gap review complete; implementation not started.

## 1. Goal

Make browser-dependent analysis reliable in headless Kali/CLI environments while preserving the single `Bug-Bounty` agent, 18-skill architecture, scope enforcement, non-destructive defaults, and shared XSS/finding lifecycle. Reuse existing browser/XSS components; do not create a competing browser engine.

## 2. Repository evidence and gaps

Reviewed current repository files: `framework/xss/browser.py`, `framework/xss/engine.py`, `framework/xss/dom.py`, `framework/tools/doctor.py`, `framework/tools/dependencies.py`, `framework/tools/installer.py`, `skills/browser/SKILL.md`, `tests/test_xss_engine.py`, `tests/test_doctor.py`, and `tests/test_dependencies.py`.

### Existing foundations
- `BrowserXssAssistant` is opt-in and uses Playwright Chromium headless.
- The initial URL is checked for HTTP(S), prohibited literal IPs, and the configured scope validator.
- Browser timeouts are bounded; dialogs are dismissed; console and page errors are sampled.
- `XssIntelligenceEngine` already integrates the assistant and disables it by default.
- The doctor checks Playwright CLI and Python-package presence.
- The browser skill describes SPA routes, DOM mutations, network calls, WebSockets, browser storage, and DOM-XSS investigation.

### Concrete gaps to address
1. **Capability reporting is too weak:** an importable Python package or CLI is reported as ready without verifying that Chromium can actually launch. Browser binaries can be missing or incompatible.
2. **Browser lifecycle is not exception-safe:** explicit browser closure occurs only on the successful navigation path; failures after launch may leave resources open.
3. **Navigation safety is incomplete:** only the initial URL is checked. Automatic redirects and browser subrequests are not individually scope/SSRF checked, creating a potential route to out-of-scope or private destinations.
4. **Hostname resolution is not validated here:** literal-IP checks alone do not establish that a hostname resolves only to allowed public addresses. DNS rebinding and redirects need explicit treatment.
5. **XSS confirmation is not tied to the canary:** `canary_token` is currently unused; any dialog can be counted as observed. The result must distinguish browser execution evidence from unrelated site dialogs and must not overstate confirmation.
6. **Client-side analysis is mostly methodology, not implementation:** route/history changes, DOM mutations, script insertion, bounded request metadata, and safe storage metadata are not provided by this assistant.
7. **Sensitive telemetry risk:** the skill currently calls for capturing authorization headers, POST bodies, storage values, and WebSocket frames. Phase 16 must default to metadata/redaction and never persist credentials or raw sensitive values.
8. **Test coverage is insufficient:** the XSS test file imports the assistant, but contains no focused `BrowserXssAssistant` test cases despite its section description. Doctor tests do not assert browser readiness semantics or missing-browser-binary behavior.

## 3. Scope and non-goals

### In scope
- A truthful browser capability status: package, browser executable, launchability, version/error detail, and unavailable reason.
- Deterministic headless runtime checks suitable for CLI/Kali; no display/X11 requirement.
- Exception-safe cleanup of page/context/browser/Playwright resources.
- Per-navigation and per-request policy enforcement for redirects and subresources; block prohibited protocols, out-of-scope hosts, private/reserved IP destinations, and unsafe redirect chains.
- Bounded SPA observation: same-origin route changes, DOM/script mutation summaries, console/page errors, and network request metadata.
- Correlation with existing JavaScript/DOM-XSS candidates and safe canary-specific browser evidence.
- Redaction and explicit caps for URLs, headers, bodies, storage metadata, messages, time, navigation count, and request count.
- Explicit `UNAVAILABLE`, `BLOCKED`, `INCONCLUSIVE`, and `OBSERVED` outcomes; unavailable browser support must not silently skip work.

### Out of scope
- New autonomous crawling across arbitrary origins.
- Form submission, account changes, uploads, deletion, purchases, or other state-changing actions.
- Recording authentication tokens, cookies, raw storage contents, or full request/response bodies by default.
- Treating a dialog, console error, route, DOM sink, or static source-to-sink match alone as a confirmed vulnerability.
- Replacing the existing XSS engine, scope engine, validation policy, or finding lifecycle.
- Live third-party targets as regression fixtures.

## 4. Test-first acceptance plan

Implement these tests before changing production code.

### A. Capability and doctor tests
- Python package present but Chromium missing => browser status is unavailable, not ready.
- CLI present but Python API missing (and vice versa) => status accurately describes usable capabilities.
- Chromium launch succeeds => ready; launch failure returns actionable, sanitized diagnostics.
- Doctor never installs packages or downloads browser binaries during diagnosis.
- Results remain deterministic under monkeypatched dependency checks.

### B. Safety tests
- Reject non-HTTP(S), malformed URLs, literal loopback/private/link-local/reserved IPv4 and IPv6.
- Reject a public-looking hostname that resolves to a prohibited address.
- Block redirects to private/out-of-scope destinations before following them.
- Block out-of-scope and prohibited destinations for subresources, frames, popups, WebSockets, and worker requests where Playwright exposes interception.
- Bound redirect count, request count, navigation count, and wall-clock duration.
- Scope validator exceptions fail closed.
- Ensure no request is sent when preflight or request policy denies it.

### C. Lifecycle tests
- Close context/browser/Playwright resources after success, navigation timeout, callback exception, blocked redirect, and browser crash.
- Do not leak one browser session into another test or target.
- Cleanup errors do not overwrite the primary failure reason.

### D. Evidence and false-positive tests
- Unrelated JavaScript alert/dialog does not confirm a supplied canary.
- Canary-linked execution evidence is recorded as observed evidence without claiming more than was measured.
- Static DOM source/sink co-occurrence remains a candidate, not a browser-confirmed finding.
- Empty/no-JavaScript pages, blocked navigation, browser unavailable, and timeout are not reported as secure or vulnerable; they are inconclusive/unavailable as appropriate.
- Console errors alone never create a vulnerability finding.
- Evidence caps and redaction remove credentials, cookies, authorization headers, and sensitive body/storage values.

### E. SPA behavior tests
- Deterministic local fixture discovers History API/hash route changes.
- DOM mutation and dynamically inserted script metadata are captured within limits.
- Network metadata captures method, origin, resource type, and status where available without storing secrets or bodies.
- Same-origin navigation is observed; cross-origin navigation is blocked unless independently in scope and explicitly permitted.
- WebSocket metadata is bounded and redacted; frame contents are not persisted by default.

### F. Regression and cross-platform tests
- Existing XSS engine, state persistence, validation, scope, and doctor tests remain green.
- Add local-only fixtures; no public network dependency.
- Run targeted browser/XSS/doctor tests, then the full Windows suite.
- Verify Kali separately and record exact commands/results; do not infer Kali success from Windows results.

## 5. Implementation sequence

1. Add deterministic failing tests for capability, safety, cleanup, and false positives.
2. Implement browser capability probing and accurate doctor status.
3. Add a centralized browser request/navigation policy and fail-closed redirect/subresource interception.
4. Make resource cleanup exception-safe and apply strict time/request/navigation budgets.
5. Add bounded SPA observations and redacted evidence models, reusing existing XSS candidate/state structures.
6. Correlate browser observations with existing XSS candidates without inflating lifecycle/severity.
7. Update browser skill and documentation to remove unsafe raw-secret collection instructions.
8. Run targeted tests, full Windows suite, then separate Kali verification.
9. Produce an acceptance report with changed files, commit, tests, limitations, and synchronization status.

## 6. Acceptance gate

Phase 16 is not complete until:
- browser capability status reflects actual launchability;
- redirects and browser-generated requests cannot bypass scope/SSRF policy;
- all browser resources close on every exit path;
- browser evidence is bounded, redacted, and canary-aware;
- missing capability is explicitly surfaced;
- negative/false-positive tests and existing regressions pass;
- Windows and Kali results are reported independently.

**Current state:** this document is planning only. No Phase 16 production code or tests have been changed by this planning step.
