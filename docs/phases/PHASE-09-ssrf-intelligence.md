# Phase 9 — Server-Side Request Forgery Intelligence

**Status:** Candidate analysis and safety controls are implemented. A live Interactsh adapter is now available when the official client is installed; end-to-end callback acceptance is still pending. Burp Collaborator polling is not integrated.
**Implementation:** **framework/ssrf/**, **scripts/bb-ssrf**, and the **oob** skill
**State file:** **state/ssrf.json** in the local program workspace.

## What SSRF means

Server-Side Request Forgery (SSRF) is a weakness where an application can be induced to make a network request chosen by a user. The impact depends on what the server can reach and what the response reveals. A parameter named **url** or **callback** is only a clue; it does not prove that the server fetches that value.

Some SSRF behavior is blind: the application does not show the response, so a researcher looks for a safe callback to a controlled out-of-band service. The callback must be uniquely attributable to the test. When `interactsh-client` is installed, Phase 9 starts one bounded client session per canary and polls its JSONL events. It requires an exact correlation identifier, checks the configured callback domain against policy, and stores only a normalized interaction record. Private-server tokens go in a private temporary config file, never in process arguments. A missing binary, failed registration, invalid scope, or provider error stops before sending any request to the target. The public Interactsh server does not require an account or token; use `INTERACTSH_TOKEN` only for a protected private service. Mock callbacks remain simulations and cannot support a live-confirmed finding.

## How the phase works

The engine gathers URL-like parameters from existing application and API state, ranks candidate inputs, checks scope and destination safety, and creates bounded test cases. Active tests require explicit approval and have ceilings for the number of cases, requests, response bytes, and callback wait time. The engine blocks local and cloud metadata destinations and prevents a candidate redirect or resolved address from silently crossing a safety boundary.

Use the deterministic local lab to understand expected behavior without contacting a bounty target. For a live test, the program must permit the exact behavior and the operator must have a functioning, controlled callback provider. The automated tests use a fake client and do not prove a real callback was received; until an owned end-to-end callback test passes, treat live service availability and delivery as an external acceptance requirement. Burp Collaborator continues to report unavailable rather than silently falling back to simulation.

## How to run it

~~~bash
# Build a candidate list from existing local state.
bb-ssrf --program <program-name> --passive-only --tree

# Review a proposed canary test without dispatching it.
bb-ssrf --program <program-name> --endpoint https://app.example.org/fetch --param url --dry-run --json

# Exercise deterministic behavior against the local fixture lab.
bb-ssrf --program <program-name> --lab --json

# A live canary needs explicit case approval and an operational provider.
bb-ssrf --program <program-name> --endpoint https://app.example.org/fetch --param url --approve-id <case-id> --max-tests 1 --max-requests 1 --json
~~~

Do not point a test at internal infrastructure, metadata endpoints, unrelated domains, or a provider you do not control. Read the current CLI help before use.

## How to evaluate a result

A response that changes after a marker is submitted can be an interesting observation, but it does not by itself prove a server-side fetch. A callback observation needs a unique correlation token, a verified provider source, a timestamp, and evidence that ties the callback to the tested request. A local mock can prove the test code’s logic only.

If callback confirmation is unavailable, document the hypothesis and missing evidence. Do not state that a blind SSRF has been confirmed or infer access to internal services. A safe proof should demonstrate the smallest permitted impact without retrieving internal data.

## Safety and limitations

Keep callback identifiers unique to one approved test. Stop on any unexpected interaction or impact. This phase is not an internal-network scanner and does not authorize testing cloud metadata or third-party systems.

Tests in **tests/test_interactsh_live_adapter.py**, **tests/test_ssrf_engine.py**, and **tests/test_providers.py** exercise mocked CLI registration, private token handling, exact ID matching, and fail-closed behavior. They do not establish public-server availability or target-side delivery. See [Phase 18](PHASE-18-ssrf-xxe-server-side-parsers.md), the **OOB skill**, [Interactsh setup](../tools/interactsh.md), and the [project audit issues](../PROJECT-AUDIT-ISSUES.md).
