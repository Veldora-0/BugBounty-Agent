---
name: javascript-analysis
description: Deep static and runtime analysis of JavaScript bundles, source maps, client-side routing, and API declarations.
---

# JavaScript Analysis Methodology

## Core Objective
Extract hidden application topology, unlinked API endpoints, client-side authorization assumptions, and parameter schemas embedded within client-side JavaScript assets.

## Key Investigation Focus
1. **Endpoint & Route Extraction**:
   * Inspect webpack, vite, or rollup bundles for declared route tables.
   * Extract hidden administrative endpoints, internal microservice paths, and deprecation flags.
2. **Source Map Recovery**:
   * Check for `.map` files (e.g. `main.js.map`). If publicly available, examine unminified TypeScript/JavaScript source code.
3. **GraphQL & WebSocket References**:
   * Search for GraphQL query definitions, mutations, subscriptions, and WebSocket endpoint URIs (`wss://`).
4. **OAuth / OIDC Implementations**:
   * Inspect client IDs, redirect URI configurations, response types, and scope requests.
5. **Sensitive Material Handling (Strict Caveat)**:
   * **DO NOT** automatically classify strings resembling secrets as vulnerabilities.
   * Many frontend keys (e.g. Firebase API key, Google Maps key, Stripe publishable key, Algolia search-only key) are **intended to be public**.
   * Investigate whether the key grants unauthorized privileged write/delete access before formulating a hypothesis.

## Standard Tool Integration
* `bb-js <url_or_file> --program <program_name>`
