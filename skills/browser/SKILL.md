---
name: browser
description: Browser-based security investigation using headless automation, DOM execution observation, dynamic SPA analysis, and centralized network interception.
---

# Browser Security Investigation Methodology

## Core Objective
Analyze modern single-page applications (SPAs) and dynamic web interfaces that require JavaScript execution, DOM evaluation, and browser event simulation to expose attack surfaces and verify execution proofs while strictly enforcing privacy, data redaction, execution budgets, and scope constraints.

---

## 1. Prerequisites & Runtime Architecture
* **Strictly Opt-In**: Headless browser automation is disabled by default across all workflows (`browser_enabled=False`). It must be explicitly enabled by researchers for targeted verification.
* **Component Prerequisites**:
  * Python `playwright` package installed.
  * System browser driver (e.g. `/usr/bin/node` on Linux/Kali).
  * Sandboxed Chromium executable installed (`playwright install chromium`).
* **Truthful Capability Detection**: The system evaluates actual launchability before dispatching tasks. Missing packages or browser binaries return `UNAVAILABLE` without attempting automatic package downloads or background installations.
* **Headless & Sandboxed**: All execution occurs in headless mode with sandboxing enabled. Never requires an X11 or Wayland display server.

---

## 2. Scope & Destination Restrictions (Fail-Closed)
* **Centralized Network Policy (`BrowserNetworkPolicy`)**:
  * Applies to the initial main-frame navigation, all subsequent redirects, iframe loads, background subresources (scripts, images, stylesheets, fetch/XHR), and WebSocket connections.
  * **Protocol Restrictions**: Only `http`, `https`, `ws`, and `wss` schemes are permitted. Schemes such as `file:`, `data:`, `javascript:`, `ftp:`, and `gopher:` are immediately rejected.
  * **Literal IP Prohibitions**: Literal loopback (`127.0.0.0/8`, `::1`), private (RFC 1918), link-local (`169.254.0.0/16`, `fe80::/10`), multicast, and cloud metadata (`169.254.169.254`) destinations are blocked.
  * **IPv4-Mapped IPv6**: Mapped representations (e.g. `::ffff:127.0.0.1`, `::ffff:169.254.169.254`) are unmapped and evaluated against prohibitions.
  * **DNS Resolution Enforcement**: Hostnames are resolved via DNS prior to connection. If resolution fails, returns empty results, or resolves to *any* prohibited IP (including mixed public/private DNS records), navigation is aborted fail-closed.
  * **Scope Authorization**: Targets must match authorized rules in `scope.yaml`. Scope authorization cannot override destination or DNS safety failures.
  * **Service Worker Blocking**: Browser contexts configure `service_workers="block"` to prevent background workers from making unintercepted network requests.
* **DNS Rebinding Boundary & Residual Limitations**:
  * Pre-flight DNS validation and route interception prevent browser navigation to private/metadata destinations under normal conditions.
  * *Residual Limitation*: Application-level pre-flight DNS checks and route interception reduce SSRF exposure, but standard Playwright/Chromium socket-level DNS pinning without low-level proxy pinning cannot guarantee 100% TOCTOU protection against dynamic DNS rebinding occurring mid-connection at the OS socket layer. Scope enforcement avoids claiming socket-level guarantees where absent.

---

## 3. Operational Execution Budgets
To prevent runaway browser instances, denial of service, or infinite loops, every session enforces explicit execution budgets:
* **Session Timeout**: Default 5.0s, hard ceiling 15.0s.
* **Redirect Limit**: Maximum 5 redirects per navigation chain.
* **Request Budget**: Maximum 50 network requests per session.
* **Route Observation**: Maximum 10 SPA route transitions.
* **Telemetry Caps**: Maximum 20 console messages, maximum 20 page errors.
* **Evidence Size**: Maximum 64 KB total evidence text payload.
* When a budget is exhausted, subsequent requests are aborted immediately and the session yields `BUDGET_EXCEEDED` without classifying the target as secure or vulnerable.

---

## 4. Privacy, Credential Redaction & Data Minimization
* **Zero Plaintext Credential Storage**:
  * Sensitive request headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `Proxy-Authorization`) are automatically redacted to `[REDACTED]`.
  * Sensitive query parameters (`token`, `access_token`, `api_key`, `key`, `secret`, `password`, `session`, `jwt`, `auth`, `code`) are redacted from URLs before logging or persistence.
  * Embedded URL credentials (`http://user:pass@host/`) have passwords stripped immediately.
  * Console messages, page errors, and exception traces are sanitized through global sensitive-pattern scrubbers before storage.
* **Storage & Body Restrictions**:
  * Never dump or persist raw POST request/response bodies.
  * Never extract, log, or persist raw localStorage/sessionStorage values containing JWTs or tokens. Inspect key names only.
  * Never record raw WebSocket message payload frames.
  * Never commit browser session cache, cookies, or profile folders to Git.

---

## 5. Dynamic Application & SPA Analysis
* **Bounded Route Observation**:
  * Monitors client-side navigation (History API `pushState`, `replaceState`, `hashchange`) within strict bounds.
  * Captures DOM mutation summaries (mutation count, dynamic `<script>` addition count) without unbounded DOM snapshots.
  * Records dynamically inserted script tag source URLs with query parameters sanitized.

---

## 6. Canary-Aware DOM & XSS Verification
* **Canary Correlation**:
  * Inject traceable unique canary tokens (`bbxss_<hex>`).
  * Only script dialogs (`alert`, `confirm`, `prompt`) whose message explicitly contains the injected canary token confirm execution.
* **Evidence Classification**:
  * `CONFIRMED`: Injected canary token verified inside an executed browser dialog.
  * `OBSERVED`: Clean browser execution completed; no script dialog triggered.
  * `INCONCLUSIVE`: Dialog triggered but did not match canary token (unrelated site notification/alert), or canary token was empty.
  * `BLOCKED`: Pre-flight destination safety, DNS check, or scope policy denied navigation.
  * `TIMEOUT`: Navigation or event processing exceeded the allotted timeout budget.
  * `BUDGET_EXCEEDED`: Request, redirect, or observation limits were reached.
  * `UNAVAILABLE`: Headless browser runtime is disabled or missing from the host.
* **Static Matches Remain Unconfirmed**: Co-occurrence of sources and sinks in client JavaScript remains candidate intelligence (`OBSERVED`), never confirmed findings without execution proof.

---

## 7. Exception-Safe Resource Lifecycle
* All browser automation utilizes `BrowserSessionManager` context management.
* Partial initialization failure (e.g. context fails after browser launches, or page fails after context opens) guarantees closure of all opened resources in reverse order without masking primary exceptions.
* All page, context, and browser instances close deterministically across success, timeout, and exception exits.
