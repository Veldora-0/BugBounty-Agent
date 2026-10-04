---
name: api-security
description: API security analysis for REST, GraphQL, and WebSocket architectures, parameter schema discovery, BOLA/BFLA, and mass assignment testing.
---

# API Security Methodology

## Core Objective
Systematically analyze programmatic interfaces (REST, GraphQL, WebSockets, gRPC-Web) for architectural, authorization, and parameter validation flaws.

## 1. Specification & Schema Discovery
* **OpenAPI / Swagger Ingestion**: Check standard paths for API documentation: `/swagger.json`, `/api-docs`, `/openapi.yaml`, `/v1/swagger`, `/v2/api-docs`.
* **GraphQL Introspection**:
  * Execute standard introspection queries to extract complete type definitions, queries, mutations, and subscription fields.
  * Check for query batching vulnerabilities (denial-of-service or brute-force amplification).
  * Check field suggestions ("Did you mean...?") when introspection is disabled.
* **WebSocket Handshake & Frames**:
  * Inspect `Upgrade: websocket` requests for missing authentication and Cross-Site WebSocket Hijacking (CSWSH) due to missing `Origin` verification.

## 2. HTTP Method & Routing Discrepancies
* **Verb Tampering**: Probe alternative HTTP methods (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `HEAD`).
* **Method Override Headers**: Test `X-HTTP-Method-Override`, `X-HTTP-Method`, and `X-Method-Override`.
* **API Version Discrepancies**:
  * Test legacy versions (`/v1/`, `/v2/`, `/beta/`, `/internal/`) for missing authorization controls present in newer versions.
  * Test path extensions (`/api/v1/users.json`, `/api/v1/users.xml`).

## 3. Parameter Manipulation & Mass Assignment
* **Parameter Discovery**: Use `arjun` to discover hidden URL query parameters, POST body parameters, and JSON fields.
* **Mass Assignment (Auto-Binding)**:
  * Attempt to set administrative or privileged fields in object updates: `is_admin: true`, `role: "admin"`, `verified: true`, `tenant_id: "..."`.
  * Compare object creation vs update response payloads.
* **Content-Type Confusion**: Send requests with alternative Content-Types (`application/x-www-form-urlencoded`, `multipart/form-data`, `application/xml`) to bypass JSON schema validators.

## 4. Rate-Limiting & Endpoint Resilience
* Verify rate limits on security-critical endpoints: OTP submission, password reset requests, authentication tokens, API key creation.
* Note header indicators: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After`.

## 5. Tool Integration
* Run `scripts/bb-api <endpoint> --program <program> [--graphql]` to map parameters and verbs safely.
* Capture evidence of disparate status codes and unexpected data exposure via `scripts/bb-evidence`.
