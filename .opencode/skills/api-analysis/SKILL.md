---
name: api-analysis
description: REST, GraphQL, and WebSocket API testing methodology, schema discovery, and parameter exploration.
---

# API Analysis Methodology

## Core Objective
Analyze modern programmatic interfaces (REST, GraphQL, gRPC-web, WebSockets) to identify undocumented endpoints, schema discrepancies, parameter tampering vulnerabilities, and rate-limiting deficiencies.

## Methodology Steps
1. **Endpoint & Method Probing**:
   * Inspect supported HTTP verbs via OPTIONS and targeted test requests (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`).
   * Test API versioning patterns (`/v1/`, `/v2/`, `/v3/`, `/beta/`, `/internal/`). Often older versions omit security controls present in newer versions.
2. **GraphQL Specific Analysis**:
   * Test if GraphQL Introspection is enabled (`{ __schema { types { name } } }`).
   * Check for query batching, deeply nested queries (denial of service testing only within passive limits), and missing field authorization.
3. **Mass Assignment & Hidden Parameters**:
   * Test inclusion of administrative fields in object creation/update payloads (`isAdmin: true`, `role: "superuser"`, `verified: true`).
4. **Rate Limiting & Abuse Controls**:
   * Observe whether rate limits are enforced per-IP, per-user, or completely absent on critical functions (login, OTP, invite).

## Tooling
* `bb-api <endpoint_url> --program <program_name> [--graphql]`
