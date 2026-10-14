# BugBounty-Agent — Phase 16 Implementation Plan
## Browser Runtime & Client-Side Security

**Accepted Baseline**: `d1f7df8f1f17811d9e49484c202cb950edfc582f`  
**Reference Document**: `docs/ROADMAP-24-PHASES-TEMP.md` (Phase 16)  
**Status**: In Progress (Pre-flight & Test-First Implementation)

---

## 1. Architectural Invariants

1. **Single Orchestrator**: One custom OpenCode agent (`Bug-Bounty`). Subagents disabled.
2. **18 Modular Skills**: Maintain existing skill boundaries without creating competing orchestrators.
3. **No External Attack Engines**: No Xalgorix, Strix, or autonomous unvetted crawlers.
4. **Fail-Closed Scope & Anti-SSRF**: No navigation or subresource fetch without explicit scope approval and strict anti-SSRF IP verification.
5. **Shared Finding Lifecycle**: Findings use established `FindingLifecycle` states (`OBSERVED`, `VALIDATED`, `REJECTED`, `INFORMATIONAL`, `NEEDS_MANUAL_REVIEW`, `SIMULATED`).
6. **Data Privacy & Redaction**: Zero persistence of plaintext credentials, tokens, session cookies, or raw web storage.
7. **Non-Destructive Defaults**: Testing is strictly non-destructive and canary-driven. No automatic report submission.

---

## 2. Core Deficiencies in Existing Baseline

1. **False Capability Reporting in Doctor & Assistant**:
   - `BrowserXssAssistant.is_playwright_available()` only tests `import playwright`.
   - `SystemDoctor.check_browser()` marks status as `READY` if the Python library is importable, even when `/usr/bin/node` or Chromium binaries are completely missing (as observed on Kali).
2. **Missing Network & Subresource Safety**:
   - `verify_url_safety()` checks the initial URL's string hostname, but fails to resolve DNS hostnames to verify resolved IPs against prohibited ranges (DNS rebinding / private resolution bypass).
   - No request interception (`page.route()`) is configured to block out-of-scope or private-network redirects, subresources (images, scripts, iframes), or WebSockets.
3. **Lack of Lifecycle Cleanup & Bounded Execution**:
   - Browser context and process resources are not guaranteed to close in exception-safe `finally` blocks during navigation timeouts, request aborts, or crashes.
4. **False Positive XSS Dialog Attribution**:
   - `BrowserXssAssistant` treats *any* dialog (e.g. `alert(1)` from unrelated site scripts) as proof of successful XSS validation without correlating the dialog content with the injected canary token.
5. **No SPA Exploration / Dynamic DOM Observation**:
   - Modern client-side routing (History API `pushState`, hashchange), dynamically inserted scripts, and DOM mutation summaries are not collected or bounded.
6. **Unsafe Data Collection Directives in Skill**:
   - `skills/browser/SKILL.md` describes capturing raw `Authorization: Bearer ...` tokens, POST bodies, and localStorage JWTs/secrets.

---

## 3. Implementation Order & Increments

### Increment 1: Capability Detection & Truthful Doctor Reporting
- Implement `BrowserCapabilityDetector` assessing:
  - Python `playwright` package availability.
  - Browser driver/node availability.
  - Chromium executable existence without downloading binaries.
  - Headless dry-launch verification.
- Update `SystemDoctor.check_browser()` to report truthful statuses: `READY`, `MISSING_PACKAGE`, `MISSING_BROWSER`, `LAUNCH_FAILED`, or `NOT_INSTALLED`.
- Ensure doctor executes zero package or binary installations.

### Increment 2: Exception-Safe Browser Lifecycle
- Implement `BrowserSessionManager` / context manager with strict timeout limits (default 5.0s, hard ceiling 15.0s).
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
- Run full 455-test regression suite to guarantee zero regressions.

---

## 4. Acceptance Criteria

- [ ] All browser capability states (`MISSING_PACKAGE`, `MISSING_BROWSER`, `LAUNCH_FAILED`, `READY`) tested and accurately reported.
- [ ] Doctor check Category 5 performs zero downloads and reports truthfully.
- [ ] Hostname resolution and route interception prevent SSRF, DNS rebinding, and out-of-scope subresources.
- [ ] Unrelated dialogs rejected as false positives.
- [ ] Sensitive headers and tokens redacted by default in all browser evidence.
- [ ] 100% exception-safe cleanup on timeouts and errors.
- [ ] All existing 455 tests continue to pass with zero regressions.
