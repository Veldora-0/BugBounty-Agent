# Phase 17 — Advanced API Security

**Status:** Implemented as safety and depth controls extending the Phase 5 API inventory; it does not perform general API fuzzing.
**Implementation:** **framework/api/**, **scripts/bb-api**, and the **api-security skill**
**State file:** **state/api.json**, shared with Phase 5.

## Why this phase exists

Phase 5 builds a map of an API’s routes, parameters, and schema. Phase 17 hardens how the engine explores that map. API specifications and GraphQL schemas can be large or recursive; an endpoint can redirect to another host; a familiar hostname can resolve to a private network address; and methods such as PUT or DELETE can change data. These are safety and scope concerns as much as they are API-security questions.

The goal is to learn enough about an authorized API to plan a test without making the inventory tool behave like an uncontrolled fuzzer.

## What the phase adds

The API policy sets ceilings for endpoints, parameters, schema depth, requests, bytes, response size, and redirects. Redirects are checked again for scope, protocol downgrade, and resolved destination safety. Active requests use a vetted destination address so a proxy or a DNS change cannot silently redirect a request into prohibited address space. Local test fixtures require explicit fixture-port registration.

The default active methods are GET, HEAD, and OPTIONS. GraphQL introspection is disabled by default and needs an explicit option. Even when enabled, introspection is bounded by schema and traversal limits. Parsing a schema is not the same as proving that its operations are exploitable.

## How to use it

~~~bash
# Correlate local state without making HTTP requests.
bb-api --program <program-name> --passive-only --tree

# Preview a bounded schema plan.
bb-api --program <program-name> --domain api.example.org --dry-run --json

# Enable GraphQL introspection only when program rules allow it.
bb-api --program <program-name> --endpoint https://api.example.org/graphql --allow-graphql-introspection --max-requests 10 --json

# Inspect the supported CLI options before an active run.
bb-api --help
~~~

The target name is an example. Configure current scope and review the exact operation before enabling live introspection.

## Using the results

A schema can show which operations and fields exist, expected parameter shapes, and possibly authentication metadata. It cannot confirm that the implementation matches the schema, that a field is accessible to a given user, or that sensitive information is exposed. Compare the API map with observed requests from the application and with test identities before proposing authorization checks.

## Safety and limits

Do not invoke state-changing methods merely because a schema lists them. Keep introspection low-volume and only use it when allowed. API discovery does not perform business-logic or authorization validation; those phases need separate hypotheses, test identities, and approval. Unusual schema extensions and authenticated API surfaces may not be fully represented.

Tests: **tests/test_api_engine.py** and the Phase 17 boundary tests within the API suite. They verify local behavior and destination controls, not every production API. See [Phase 5](PHASE-05-api-intelligence.md), [Phase 8](PHASE-08-authorization-bola-idor.md), and [roadmap](../ROADMAP-24-PHASES.md).