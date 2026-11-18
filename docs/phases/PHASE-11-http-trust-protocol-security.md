# Phase 11 — HTTP Trust and Protocol Security

**Status:** Implemented for candidate discovery and bounded header-behavior comparisons; results need contextual validation.
**Implementation:** **framework/http_trust/**, **scripts/bb-http**, and the **web-security skill**
**State file:** **state/http-trust.json**.

## Why this phase exists

Web servers often receive more than a URL. They also receive headers that identify the requested host, original scheme, proxy destination, or page origin. Applications sometimes trust those values when creating redirects, deciding which site is allowed to read a response, building password-reset links, or selecting cache entries. If the application trusts a value from the wrong source, an attacker may influence a security-sensitive decision.

Phase 11 asks whether a specific header or parameter affects observable behavior. It covers Host and forwarded headers, scheme and redirect handling, CORS, HTTP parameter pollution, and cache-related behavior. A reflected header is only an observation. To establish a security problem, show which decision it changes and who can benefit.

## How the phase works

The engine reads endpoints from local web, API, and reconnaissance state and generates candidate header variations. The prioritizer explains why a case might matter. Passive-only mode ranks candidates without requests. Dry-run displays a plan; the local lab provides deterministic expected behavior. Live checks require an in-scope URL and explicit invocation of the approved testing mode. Test, request, timeout, and response-byte ceilings bound work.

It records the original and changed request/response characteristics in **http-trust.json**. Compare a normal request with one controlled change at a time. Do not send cache-poisoning content to a shared cache or cause another person’s browser to consume a manipulated response.

## How to run it

~~~bash
# Review candidates without sending requests.
bb-http --program <program-name> --passive-only --tree

# Preview tests for one authorized endpoint.
bb-http --program <program-name> --endpoint https://app.example.org/ --dry-run --json

# Exercise the local protocol lab.
bb-http --program <program-name> --lab --json

# An active test requires current scope and explicit approval.
bb-http --program <program-name> --endpoint https://app.example.org/ --category cors --approve --max-tests 1 --max-requests 2 --json
~~~

A placeholder domain is shown. Check the current program rules and CLI help before active use.

## Interpreting evidence

For a CORS hypothesis, record the request origin, response headers, whether credentials are involved, and what a browser from that origin could actually read. For a redirect or Host hypothesis, record where the application used the supplied value and whether an external user could influence it. For cache behavior, show a controlled cache key difference and a harmless response; do not try to poison a shared user-facing cache.

A header being accepted or echoed does not by itself demonstrate exploitability. Report the specific trust decision and the demonstrated consequence, or leave the issue as an observation.

## Safety and limitations

Do not send secrets or state-changing content in header probes. Keep checks low-volume, do not test shared caches without explicit permission, and stop if a test could affect other users. The engine’s pattern set cannot model every reverse-proxy deployment or browser policy.

Tests in **tests/test_http_trust_engine.py** exercise local cases and comparison logic. They do not establish a live application’s full proxy or cache architecture. See the [security policy](../security.md), **web-security skill**, and [roadmap](../ROADMAP-24-PHASES.md).