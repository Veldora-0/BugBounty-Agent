---
name: web-security
description: Web application attack surface analysis, authentication flows, session handling, upload vectors, CORS/CSRF, and web vulnerability assessment.
---

# Web Security Methodology

## Core Objective
Systematically analyze web applications for security weaknesses across authentication mechanisms, session management, input handling, parameter tampering, and browser-facing configurations.

## 1. Attack Surface & Endpoint Mapping
* **Route Discovery**: Map public, authenticated, and administrative routes using crawling (`katana`) and parameter enumeration (`arjun`).
* **Input Vectors**: Identify all URL query parameters, POST body fields, multipart form inputs, and custom HTTP request headers.
* **Form & Action Review**: Extract HTML forms, method types, enctype attributes, and hidden state variables.

## 2. Authentication & Session Security
* **Authentication Flows**:
  * Multi-step login, password reset, registration, and MFA implementations.
  * Credential stuffing resilience, account lockout policies, and username enumeration indicators.
* **Session Lifecycle**:
  * Verify cookie security attributes: `Secure`, `HttpOnly`, `SameSite=Strict|Lax`.
  * Session fixation: verify whether session identifiers rotate across privilege elevation and authentication.
  * Token expiration and invalidation upon logout.

## 3. Web Architecture & Policy Analysis
* **CORS (Cross-Origin Resource Sharing)**:
  * Check for permissive origin reflection: `Access-Control-Allow-Origin: <arbitrary_origin>` with `Access-Control-Allow-Credentials: true`.
  * Check for null origin trust: `Access-Control-Allow-Origin: null`.
* **CSRF (Cross-Site Request Forgery)**:
  * Check state-changing requests (email update, password change, financial transfer) for missing or predictable anti-CSRF tokens.
  * Validate SameSite cookie behavior in modern browsers.
* **Open Redirects**:
  * Test redirection parameters (`next=`, `redirect_uri=`, `return_to=`, `url=`) for bypasses allowing off-domain redirects.
* **File Upload Mechanisms**:
  * Analyze upload handlers for extension validation, MIME type verification, file renaming, and direct execution permissions in upload directories.
* **Security Headers**:
  * Inspect `Content-Security-Policy` (CSP), `X-Frame-Options`, `X-Content-Type-Options`, and `Strict-Transport-Security` (HSTS).

## 4. Controlled Execution Workflow
1. Enforce scope check via `bb-scope-check` prior to contacting endpoints.
2. Dispatch requests via `bb-http` to capture sanitized request and response evidence.
3. Record discovered endpoints into `~/BugBounty-Workspace/programs/<name>/state/endpoints.json`.
4. Avoid destructive actions: never modify administrative configuration or submit malicious payloads that disrupt system integrity.
