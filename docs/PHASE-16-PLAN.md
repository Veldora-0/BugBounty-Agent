# BugBounty-Agent — Phase 16 Implementation Plan
## Browser Runtime & Client-Side Security

**Accepted Baseline**: `d1f7df8f1f17811d9e49484c202cb950edfc582f`  
**Reference Document**: `docs/ROADMAP-24-PHASES-TEMP.md` (Phase 16)  
**Status**: Accepted (with documented limitations). Next planned phase: Phase 17 (Advanced API Security).

---

## 1. Goal & Architectural Invariants

### Primary Goal
Make browser-dependent analysis reliable in headless Kali/CLI environments while preserving the single `Bug-Bounty` agent, 18-skill architecture, scope enforcement, non-destructive defaults, and shared XSS/finding lifecycle. Reuse existing browser/XSS components; do not create a competing browser engine.

### Architectural Invariants
1. **Single Orchestrator**: One custom OpenCode agent (`Bug-Bounty`). Subagents disabled.
2. **18 Modular Skills**: Maintain existing skill boundaries without creating competing orchestrators.
3. **No External Attack Engines**: No Xalgorix, Strix, or autonomous unvetted crawlers.
4. **Fail-Closed Scope & Anti-SSRF**: No navigation or subresource fetch without explicit scope approval and strict anti-SSRF IP verification.
5. **Shared Finding Lifecycle**: Findings use established `FindingLifecycle` states (`OBSERVED`, `VALIDATED`, `REJECTED`, `INFORMATIONAL`, `NEEDS_MANUAL_REVIEW`, `SIMULATED`).
6. **Data Privacy & Redaction**: Zero persistence of plaintext credentials, tokens, session cookies, or raw web storage.
7. **Non-Destructive Defaults**: Testing is strictly non-destructive and canary-driven. No automatic report submission.

---

## 2. Repository Evidence, Existing Foundations & Concrete Gaps

Reviewed repository files:
- `framework/xss/browser.py`
- `framework/xss/engine.py`
- `framework/xss/dom.py`
- `framework/tools/doctor.py`
- `framework/tools/dependencies.py`
- `framework/tools/installer.py`
- `skills/browser/SKILL.md`
- `tests/test_xss_engine.py`
- `tests/test_doctor.py`
- `tests/test_dependencies.py`

### Existing Foundations
- `BrowserXssAssistant` is opt-in and uses Playwright Chromium headless.
- The initial URL is checked for HTTP(S), prohibited literal IPs, and the configured scope validator.
- Browser timeouts are bounded; dialogs are dismissed; console and page errors are sampled.
- `XssIntelligenceEngine` already integrates the assistant and disables it by default.
- The doctor checks Playwright CLI and Python-package presence.
- The browser skill describes SPA routes, DOM mutations, network calls, WebSockets, browser storage, and DOM-XSS investigation.

### Concrete Deficiencies & Root Causes to Address
1. **Capability Reporting is Weak / Misleading**:
   - `BrowserXssAssistant.is_playwright_available()` only checked `import playwright`.
   - `SystemDoctor.check_browser()` marked status as `READY` if the Python library was importable, even when node or Chromium binaries were completely missing (e.g. on clean CLI/Kali installations). Status must reflect actual launchability.
2. **Browser Lifecycle is Not Exception-Safe**:
   - Browser context and process resources were not guaranteed to close in exception-safe `finally` blocks during navigation timeouts, request aborts, or crashes. Explicit browser closure only occurred on the successful navigation path.
3. **Incomplete Navigation, Redirect & Subresource Safety**:
   - Only the initial URL was checked. Automatic redirects, subresources (images, scripts, iframes), and WebSockets were not individually checked against scope and anti-SSRF policy, creating potential bypasses to out-of-scope or private destinations.
4. **Hostname Resolution & DNS Limitations**:
   - Literal-IP checks alone do not establish that a hostname resolves only to allowed public addresses. Pre-navigation checks and request interception resolve hostnames and verify addresses against private, loopback, link-local, and cloud metadata ranges (`169.254.169.254`).
   - *Limitation Note*: Pre-flight DNS checks and route interception reduce SSRF exposure, but standard Playwright/Chromium socket-level DNS pinning without low-level proxy pinning cannot guarantee 100% TOCTOU protection against dynamic DNS rebinding occurring mid-connection at the OS socket layer. Scope enforcement avoids claiming socket-level guarantees where absent.
5. **XSS Confirmation Uncorrelated with Canary / False Positive Dialogs**:
   - `BrowserXssAssistant` treated any dialog (e.g. `alert(1)` from unrelated site scripts) as proof of successful XSS validation without correlating dialog content with the injected canary token. Unrelated dialogs must result in `INCONCLUSIVE` or `REJECTED`, never `VALIDATED`.
6. **Client-Side Analysis & SPA Observation Missing**:
   - Modern client-side routing (History API `pushState`/`replaceState`, hashchange), dynamically inserted scripts, and DOM mutation summaries were not collected or bounded by the assistant.
7. **Sensitive Telemetry Risk / Unsafe Data Directives in Skill**:
   - `skills/browser/SKILL.md` described capturing raw `Authorization: Bearer ...` tokens, POST bodies, and localStorage JWTs/secrets. Phase 16 must default to metadata/redaction and never persist credentials or raw sensitive values.
8. **Test Coverage Deficiencies**:
   - Previously no focused unit test coverage for `BrowserXssAssistant` or browser doctor checks under simulated missing dependencies.

---

## 3. Scope and Non-Goals

### In Scope
- Truthful browser capability status: package, browser executable, launchability, version/error detail, and unavailable reason.
- Deterministic headless runtime checks suitable for CLI/Kali; no display/X11 requirement.
- Exception-safe cleanup of page/context/browser/Playwright resources across all exit paths.
- Per-navigation and per-request policy enforcement for redirects and subresources; block prohibited protocols, out-of-scope hosts, private/reserved IP destinations, and unsafe redirect chains.
- Bounded SPA observation: same-origin route changes, DOM/script mutation summaries, console/page errors, and network request metadata.
- Correlation with existing JavaScript/DOM-XSS candidates and safe canary-specific browser evidence.
- Redaction and explicit caps for URLs, headers, bodies, storage metadata, messages, time, navigation count, and request count.
- Explicit `UNAVAILABLE`, `BLOCKED`, `INCONCLUSIVE`, and `OBSERVED` outcomes; unavailable browser support must not silently skip work.

### Out of Scope
- New autonomous crawling across arbitrary origins.
- Form submission, account changes, uploads, deletion, purchases, or other state-changing actions.
- Recording authentication tokens, cookies, raw storage contents, or full request/response bodies by default.
- Treating a dialog, console error, route, DOM sink, or static source-to-sink match alone as a confirmed vulnerability.
- Replacing the existing XSS engine, scope engine, validation policy, or finding lifecycle.
- Live third-party targets as regression fixtures.

---

## 4. Implementation Increments

### Increment 1: Capability Detection & Truthful Doctor Reporting
- Implement `BrowserCapabilityDetector` assessing:
  - Python `playwright` package availability.
  - Browser driver/node availability.
  - Chromium executable existence without downloading binaries.
  - Headless dry-launch verification.
- Update `SystemDoctor.check_browser()` to report truthful statuses: `READY`, `MISSING_PACKAGE`, `MISSING_BROWSER`, `LAUNCH_FAILED`, or `NOT_INSTALLED`.
- Ensure doctor executes zero package or binary installations.

### Increment 2: Exception-Safe Browser Lifecycle
- Implement `BrowserSessionManager` context manager with strict timeout limits (default 5.0s, hard ceiling 15.0s).
- Guarantee `try...finally` closure of `Page`, `BrowserContext`, `Browser`, and Playwright driver.
- Preserve original failure exceptions without masking them with cleanup errors.

### Increment 3: Centralized Request & Navigation Safety Enforcement
- Implement pre-navigation URL parsing, scheme restriction (`http`, `https` only), and DNS resolution check.
- Fail closed if host resolves to loopback, private RFC1918, IPv4-mapped IPv6, or cloud metadata (`169.254.169.254`).
- Integrate with `ScopeEngine.check()` to ensure target URLs are authorized in scope.

### Increment 4: Subresource, Redirect & WebSocket Safeguards
- Configure Playwright route handler (`page.route("**/*")`) to intercept and inspect every browser request.
- Apply scope and anti-SSRF checks on every request, iframe, subresource, and redirect hop before network transmission.
- Abort disallowed requests immediately (`route.abort("accessdenied")`).
- Enforce strict request count budgets (e.g., max 50 subresources per session) and navigation depth.

### Increment 5: Bounded SPA Observation
- Capture client-side route transitions (History API `pushState`/`replaceState`, hashchange).
- Record bounded DOM mutation summaries (count of mutations, added elements).
- Extract dynamically inserted `<script>` tags (sources, hashes, bounded lengths).
- Record console errors, page exceptions, and network request metadata.
- Impose strict caps: max 10 routes, max 20 console messages, max 50 network calls, max 5s observation.

### Increment 6: Canary-Aware Browser Evidence & XSS Correlation
- Require that observed dialogs/alerts explicitly match the injected canary token or derive directly from the candidate payload.
- Unrelated dialogs produce `INCONCLUSIVE` or `REJECTED`, never `VALIDATED`.
- Unresolved / timeout / blocked outcomes remain distinct (`BLOCKED`, `TIMEOUT`, `UNAVAILABLE`).

### Increment 7: Sensitive-Data Protection & Redaction
- Redact Authorization headers, session cookies, API tokens, and credentials in network metadata.
- Never extract or persist raw localStorage/sessionStorage values.
- Strip sensitive query parameters and mask exception diagnostics.

### Increment 8: Browser Skill & Documentation Corrections
- Update `skills/browser/SKILL.md` to remove instructions for capturing raw tokens/secrets.
- Document safe headless investigation, redaction invariants, and bounded SPA analysis.

### Increment 9: Cross-Platform Regression Testing & Verification
- Verify deterministic mock tests on Windows.
- Verify on Kali VM via SSH.
- Run full regression suite to guarantee zero regressions.

---

## 5. Test-First Acceptance Plan

Implement these tests before changing production code.

### A. Capability and Doctor Tests
- Python package present but Chromium missing => browser status is unavailable, not ready.
- CLI present but Python API missing (and vice versa) => status accurately describes usable capabilities.
- Chromium launch succeeds => ready; launch failure returns actionable, sanitized diagnostics.
- Doctor never installs packages or downloads browser binaries during diagnosis.
- Results remain deterministic under monkeypatched dependency checks.

### B. Safety Tests
- Reject non-HTTP(S), malformed URLs, literal loopback/private/link-local/reserved IPv4 and IPv6.
- Reject a public-looking hostname that resolves to a prohibited address.
- Block redirects to private/out-of-scope destinations before following them.
- Block out-of-scope and prohibited destinations for subresources, frames, popups, WebSockets, and worker requests where Playwright exposes interception.
- Bound redirect count, request count, navigation count, and wall-clock duration.
- Scope validator exceptions fail closed.
- Ensure no request is sent when preflight or request policy denies it.

### C. Lifecycle Tests
- Close context/browser/Playwright resources after success, navigation timeout, callback exception, blocked redirect, and browser crash.
- Do not leak one browser session into another test or target.
- Cleanup errors do not overwrite the primary failure reason.

### D. Evidence and False-Positive Tests
- Unrelated JavaScript alert/dialog does not confirm a supplied canary.
- Canary-linked execution evidence is recorded as observed evidence without claiming more than was measured.
- Static DOM source/sink co-occurrence remains a candidate, not a browser-confirmed finding.
- Empty/no-JavaScript pages, blocked navigation, browser unavailable, and timeout are not reported as secure or vulnerable; they are inconclusive/unavailable as appropriate.
- Console errors alone never create a vulnerability finding.
- Evidence caps and redaction remove credentials, cookies, authorization headers, and sensitive body/storage values.

### E. SPA Behavior Tests
- Deterministic local fixture discovers History API/hash route changes.
- DOM mutation and dynamically inserted script metadata are captured within limits.
- Network metadata captures method, origin, resource type, and status where available without storing secrets or bodies.
- Same-origin navigation is observed; cross-origin navigation is blocked unless independently in scope and explicitly permitted.
- WebSocket metadata is bounded and redacted; frame contents are not persisted by default.

### F. Regression and Cross-Platform Tests
- Existing XSS engine, state persistence, validation, scope, and doctor tests remain green.
- Add local-only fixtures; no public network dependency.
- Run targeted browser/XSS/doctor tests, then the full Windows suite.
- Verify Kali separately and record exact commands/results; do not infer Kali success from Windows results.

---

## 6. Implementation Sequence

1. Add deterministic failing tests for capability, safety, cleanup, and false positives.
2. Implement browser capability probing and accurate doctor status.
3. Add a centralized browser request/navigation policy and fail-closed redirect/subresource interception.
4. Make resource cleanup exception-safe and apply strict time/request/navigation budgets.
5. Add bounded SPA observations and redacted evidence models, reusing existing XSS candidate/state structures.
6. Correlate browser observations with existing XSS candidates without inflating lifecycle/severity.
7. Update browser skill and documentation to remove unsafe raw-secret collection instructions.
8. Run targeted tests, full Windows suite, then separate Kali verification.
9. Produce an acceptance report with changed files, commit, tests, limitations, and synchronization status.

---

## 7. Acceptance Gate & Checklist

Phase 16 acceptance criteria satisfied:
- [x] Browser capability status reflects actual launchability across environments.
- [x] Doctor check Category 5 performs zero downloads and reports truthfully.
- [x] Redirects and browser-generated requests cannot bypass scope or anti-SSRF policy.
- [x] All browser resources close on every exit path (success, timeout, exception).
- [x] Browser evidence is bounded, redacted, and canary-aware; unrelated dialogs are rejected as false positives.
- [x] Missing capability is explicitly surfaced without silent failure.
- [x] All existing regression tests continue to pass with zero regressions.
