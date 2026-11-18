# Phase 5 — API Intelligence

**Status:** Implemented for offline correlation and bounded, scope-checked API mapping; schema coverage and authenticated inventory are limited.
**Implementation:** **framework/api/**, **scripts/bb-api**, and the **api-security skill**
**State file:** **state/api.json** in the local program workspace.

## Why this phase exists

An API is an application interface that accepts structured requests and returns structured responses, often as JSON. It may be used by a web page, a mobile application, or another service. APIs commonly have many routes and parameters that are difficult to see by browsing ordinary pages. Phase 5 combines information already collected from reconnaissance, web pages, and JavaScript with API description files such as OpenAPI or Swagger.

The phase creates an inventory that helps you ask a narrow security question. For example, a route with an account identifier may deserve an authorization review using two program-approved test accounts. The existence of the route or parameter is not itself proof that access control is missing.

## Inputs and processing

The engine can correlate Phase 2 HTTP observations, Phase 3 endpoints and forms, and Phase 4 JavaScript routes. It can parse a local API specification without contacting a target. With scope configured, it can also make bounded requests to retrieve common specification paths or inspect an API endpoint. The defaults cap the endpoint count, request count, total bytes, and bytes per specification. Redirects are checked again for scope and destination safety.

The parser understands common OpenAPI 2.0 and 3.x structures and GraphQL surface metadata. GraphQL schema introspection is disabled unless the operator explicitly enables it. The active HTTP method policy is intentionally conservative and defaults to GET, HEAD, and OPTIONS; it is not a general request fuzzer. State is written to **api.json** and includes applications, routes, parameters, schemas, authentication observations, and relationships.

## How to run it

~~~bash
# Correlate current local web, JavaScript, and reconnaissance state.
bb-api --program <program-name> --passive-only --tree

# Review a local OpenAPI or Swagger file without making a target request.
bb-api --program <program-name> --spec ./openapi.json --dry-run --json

# Retrieve an in-scope specification URL under the configured request limits.
bb-api --program <program-name> --spec https://api.example.org/openapi.json --tree

# Limit API surface acquisition for a small review.
bb-api --program <program-name> --max-endpoints 50 --max-requests 30 --json

# Enable GraphQL introspection only when the program rules allow it.
bb-api --program <program-name> --allow-graphql-introspection --graphql --json
~~~

All target URLs in these examples are placeholders. Confirm program permission before requesting a specification or enabling introspection.

## What the inventory tells you

A route says the software or a source file described that path. A method says what the specification or observation reported; it does not guarantee the server implements it. A parameter classification is a prioritization hint based on its name and position, not a vulnerability detector. An authentication observation describes the scheme seen in the data and may be incomplete.

Review candidate endpoints against the live application manually and create a specific hypothesis before any security test. Good next steps include checking whether an endpoint appears in the browser map, whether the route is current, what principal should access it, and what the program permits you to request.

## Safety and limitations

Do not send write or delete methods merely because a specification lists them. Avoid introspection when the program forbids it. Do not treat public specifications as permission to test their host if scope does not include it. Large or unusual schema formats can be skipped or partially parsed, and authenticated API discovery is not yet a complete workflow.

Tests in **tests/test_api_engine.py** cover parsers, correlation, budgets, redirects, and local fixtures. They do not prove complete coverage of a production API. See the **api-security skill**, [scope guide](../scope.md), and [roadmap](../ROADMAP-24-PHASES.md).