---
name: browser
description: Browser-based security investigation using headless automation, DOM execution observation, dynamic SPA analysis, and network interception.
---

# Browser Security Investigation Methodology

## Core Objective
Analyze modern single-page applications (SPAs) and dynamic web interfaces that require full JavaScript execution, DOM evaluation, and browser event simulation to expose attack surfaces and vulnerabilities.

## 1. Dynamic Application & SPA Analysis
* **Client-Side Rendering**: Headless browser automation (Playwright/Chromium) loads and executes client-side JavaScript, rendering virtual DOM structures that static crawlers miss.
* **Route & Event Discovery**:
  * Emulate user interactions: button clicks, dropdown expansions, form submissions.
  * Monitor client-side navigation (HTML5 History API: `pushState`, `replaceState`, hashchange).
  * Capture DOM mutations and dynamically inserted script tags.

## 2. Network & Traffic Observation
* **XHR / Fetch Interception**: Log all background AJAX and Fetch API calls, capturing request headers, POST bodies, and authentication tokens (`Authorization: Bearer ...`).
* **WebSocket Monitoring**: Intercept WebSocket handshakes and log bi-directional message frames (`wss://`).
* **Third-Party Request Auditing**: Track third-party analytics and tracking scripts that might receive sensitive customer data or session tokens.

## 3. Browser Storage & State Inspection
* **Local & Session Storage**: Inspect `localStorage` and `sessionStorage` keys for insecure persistence of JWTs, API secrets, or personally identifiable information (PII).
* **IndexedDB**: Review client databases for unencrypted sensitive business records.
* **Cookie States**: Monitor cookie creation and modification during authentication flows, noting `SameSite` flags and lack of `HttpOnly`.

## 4. DOM-Based Vulnerability Detection
* **DOM XSS Observation**: Inject traceable canary strings into URL fragments and monitor whether execution occurs in sensitive DOM sinks (`eval`, `innerHTML`, `document.write`).
* **Window PostMessage Auditing**: Inject controlled cross-origin messages into `window.postMessage` listeners to identify insecure message handling.

## 5. Tool Integration & Safeguards
* Employ Playwright scripts in headless, sandboxed environments.
* Keep browser profiles, cookies, and cache files strictly in local workspace directories (`~/BugBounty-Workspace/programs/<name>/browser/`).
* Never commit browser profiles or session states to Git.
