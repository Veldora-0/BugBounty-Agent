---
name: browser
description: Browser-based security investigation using headless automation, DOM execution observation, dynamic SPA analysis, and network interception.
---

# Browser Security Investigation Methodology

## Core Objective
Analyze modern single-page applications (SPAs) and dynamic web interfaces that require full JavaScript execution, DOM evaluation, and browser event simulation to expose attack surfaces and vulnerabilities while strictly enforcing privacy, data redaction, and scope constraints.

## 1. Dynamic Application & SPA Analysis
* **Client-Side Rendering**: Headless browser automation (Playwright/Chromium) loads and executes client-side JavaScript, rendering virtual DOM structures that static crawlers miss.
* **Bounded Route & Event Discovery**:
  * Emulate bounded user interactions: button clicks, dropdown expansions, form submissions.
  * Monitor client-side navigation (HTML5 History API: `pushState`, `replaceState`, hashchange) within strict caps (max 10 routes).
  * Capture DOM mutation summaries (mutation count, script count) and dynamically inserted script tag metadata without unbounded content dumps.

## 2. Network & Traffic Observation (Safe & Redacted)
* **XHR / Fetch Interception**: Log background AJAX and Fetch API call metadata (methods, endpoints) with mandatory redaction.
* **Strict Privacy Redaction**:
  * Never persist plaintext credentials, API secrets, session tokens, or `Authorization: Bearer ...` headers.
  * All sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`) are automatically replaced with `[REDACTED]`.
  * Sensitive query parameters (`token`, `access_token`, `api_key`, `secret`, `password`) are redacted before storage.
  * Never persist raw request/response bodies or WebSocket message frames.
* **Subresource Policy & Scope Enforcement**: Apply scope checks and anti-SSRF protections to every background request and frame before transmission; abort out-of-scope or prohibited IP traffic immediately.

## 3. Browser Storage & State Inspection (Metadata Only)
* **Local & Session Storage**: Inspect storage key names only to evaluate state management patterns; never extract, log, or persist raw storage values containing tokens, JWTs, or PII.
* **IndexedDB & Cache**: Inspect database names and store schemas; avoid persisting customer records or operational data.
* **Cookie Flags**: Review observable cookie attribute flags (`Secure`, `HttpOnly`, `SameSite`) without persisting cookie value payloads.

## 4. DOM-Based Vulnerability Detection
* **Canary-Correlated Proof**: Inject traceable canary strings into candidate parameters and require verified presence of the canary token in dialogs (`alert`, `confirm`, `prompt`) before confirming execution.
* **False-Positive Elimination**: Unrelated application alerts, console errors, or static source-to-sink flows alone remain `OBSERVED` or `INCONCLUSIVE`, never confirmed vulnerabilities.
* **Window PostMessage Auditing**: Observe cross-origin `window.postMessage` listener registrations with bounded event capture.

## 5. Tool Integration & Safety Boundaries
* Operate Playwright strictly in headless, sandboxed mode with bounded timeouts (default 5.0s, hard ceiling 15.0s).
* Guarantee exception-safe resource cleanup: pages, browser contexts, and browser instances are closed in `finally` blocks during errors, timeouts, or crashes.
* Never commit browser profiles, cache directories, or runtime session state to Git.
