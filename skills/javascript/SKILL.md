---
name: javascript
description: Static and runtime analysis of JavaScript bundles, source maps, client routing, secrets assessment, DOM sinks, and API endpoint extraction.
---

# JavaScript Security Analysis Methodology

## Core Objective
Extract hidden application routes, parameter definitions, and architectural logic embedded in frontend JavaScript bundles. Identify client-side security assumptions and assess exposed credentials.

## 1. Bundle & Asset Discovery
* Extract all `<script src="...">` references from HTML source and dynamic DOM rendering.
* Collect third-party and first-party scripts, vendor bundles (`chunk-*.js`), and manifest files (`runtime.js`, `manifest.json`).
* Detect and download JavaScript Source Maps (`.js.map`) to reconstruct original TypeScript or ES6 source trees.

## 2. Route & Parameter Extraction
* **API Endpoints**: Extract relative and absolute API routes (e.g. `/api/v1/...`, `/internal/...`, `/graphql`).
* **Hidden Parameters**: Parse query string templates, request builders, and URLSearchParams.
* **Client Routing Tables**: Extract Angular, React Router, Vue Router, and Next.js page routes to uncover unlinked administrative and debug interfaces.
* **WebSocket & GraphQL Declarations**: Identify WebSocket endpoints (`wss://...`) and GraphQL queries/mutations compiled into frontend code.

## 3. Sensitive Configuration & Token Analysis
* **Critical Rule**: An exposed string or token in frontend JavaScript is NOT an automatic vulnerability.
* **Public vs Privileged Classification**:
  * *Expected Public Tokens*: Firebase API keys, Google Maps keys, Stripe publishable keys (`pk_*`), Algolia search keys, Sentry DSNs.
  * *Privileged Secrets*: AWS Access Keys (`AKIA...`), GitHub Personal Access Tokens, Stripe secret keys (`sk_*`), private database credentials, internal service JWTs.
* **Verification Invariant**: Do NOT report public frontend tokens as security vulnerabilities. Only formulate findings if an exposed key grants unauthorized read/write access to sensitive data or backend services.

## 4. Client-Side Sinks & DOM XSS
* **DOM Sources**: `location.search`, `location.hash`, `document.referrer`, `window.name`, `postMessage`.
* **Execution Sinks**: `eval()`, `setTimeout()`, `setInterval()`, `Function()`, `innerHTML`, `outerHTML`, `document.write()`, `document.location.href`.
* **PostMessage Handlers**: Analyze `window.addEventListener('message', ...)` listeners for missing origin checks (`event.origin`).

## 5. Standard Tool Integration
* Run `bb-js --program <program> <url_or_bundle>` to extract endpoints and parameters.
* Use `katana -jc` in JavaScript crawling mode for automated script discovery.
