---
name: web-mapping
description: Web application mapping, routing analysis, parameter identification, and client/server interaction discovery.
---

# Web Mapping Methodology

## Core Objective
Construct a functional model of the web application: enumerate input vectors, authentication boundaries, session handling mechanisms, and state-changing actions.

## Investigation Pillars
1. **Authentication & Session Lifecycle**:
   * Identify login, signup, password reset, and MFA endpoints.
   * Examine session tokens: cookie flags (`Secure`, `HttpOnly`, `SameSite`), token lifetimes, storage mechanisms.
2. **Access Control Surfaces**:
   * Distinguish between public routes, authenticated user routes, and administrative surfaces (`/admin`, `/internal`, `/management`).
3. **Parameter & Input Vector Discovery**:
   * Inspect URL query parameters, form bodies, JSON payloads, and custom HTTP headers.
   * Identify object identifiers (`user_id`, `org_id`, `account_uuid`) for authorization review.
4. **CORS & Origin Policies**:
   * Inspect `Access-Control-Allow-Origin` handling: test reflection of arbitrary or null origins, credential transmission (`Access-Control-Allow-Credentials: true`).
5. **Redirect & Navigation Handling**:
   * Trace destination parameters (`redirect`, `return_to`, `next`, `callback`) for open redirect patterns.
6. **Error Analysis & Information Leakage**:
   * Inspect custom vs framework error pages (stack traces, debug mode, internal IP disclosures).

## Safety & Rate Limits
* Keep request rates bounded (`bb-http --rate 5`).
* Never submit destructive forms (e.g. account deletion, balance transfers) during mapping.
