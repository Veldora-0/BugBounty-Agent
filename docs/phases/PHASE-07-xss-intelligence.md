# Phase 7 — Cross-Site Scripting Intelligence

**Status:** Implemented for bounded XSS candidate analysis; browser confirmation is optional and belongs to Phase 16.
**Implementation:** **framework/xss/**, **scripts/bb-xss**, and the **injection** and **browser** skills
**State file:** **state/xss.json** in the local program workspace.

## What XSS means

Cross-site scripting, usually shortened to XSS, happens when an application lets attacker-controlled text reach a browser in a way that the browser interprets as executable script in the site’s security context. This can matter because a victim’s browser may perform actions or expose information as that victim. Seeing a value reflected in a response is not enough to prove XSS: the exact HTML or JavaScript context and what the browser does matter.

Phase 7 helps a researcher find and validate candidate reflection points using controlled, harmless markers and bounded requests. It separates a response that merely contains the marker from evidence that the browser interpreted it as code. The optional browser layer is not always installed and should be treated as unavailable when its runtime checks fail.

## Inputs and processing

The engine uses endpoint and parameter observations from earlier phases, or accepts a specific authorized endpoint and parameter. It prepares test cases for reflected, stored, and DOM-related candidates according to available state. Active checks require configured scope and are capped by test count, request count, and timeout. Passive-only mode ranks and reviews local information without network requests. Dry-run plans cases without dispatching them. A browser confirmation option is an additional observation layer, not a way to bypass scope checks.

Results are saved in **xss.json** and can include a candidate, response evidence, a validation outcome, or a reason the test could not be completed. Stored XSS needs special caution: do not submit content that could affect another person or persist on a real service unless the program explicitly permits that exact test and a safe canary account is available.

## How to use it

~~~bash
# Review candidate locations without sending requests.
bb-xss --program <program-name> --passive-only --tree

# Plan a reflected-XSS review for a specific in-scope route.
bb-xss --program <program-name> --endpoint https://app.example.org/search --category reflected --dry-run --json

# Keep the first active run deliberately small.
bb-xss --program <program-name> --asset app.example.org --max-tests 3 --max-requests 10 --json

# Request optional browser confirmation only where runtime support is installed.
bb-xss --program <program-name> --endpoint https://app.example.org/search --browser --max-tests 1 --json
~~~

These examples do not grant permission. Follow the program’s rules for test accounts, persistent input, and browser automation.

## Interpreting candidates

A reflected string is an observation, not an executable outcome. A browser result can still be incomplete if the environment blocks scripts, if the tested path is not representative, or if the browser runtime is unavailable. A finding should explain the input source, where it reached the page, which security context was involved, and the demonstrated effect. Do not claim a confirmed XSS finding based only on static JavaScript patterns or string matching.

Use discovered locations to formulate a narrow hypothesis and manually inspect the relevant browser behavior. If an effect would require exposing user data or acting as another person, do not perform that action; choose a harmless proof or leave the impact unverified.

## Safety and limitations

Request ceilings, scope checks, and harmless probes reduce risk but do not replace human review. The engine does not establish that every framework context is covered. Stored-XSS validation can be inappropriate on a live target without explicit permission and an isolated account. Browser versions and binaries vary by host, and the Phase 16 guide describes those runtime constraints.

Tests in **tests/test_xss_engine.py** cover the candidate engine using controlled fixtures. They do not show that it detects all XSS variants or prove target-side impact. See the [validation guide](PHASE-06-security-validation-foundation.md), [Phase 16 browser guide](PHASE-16-browser-runtime-client-side-security.md), and [roadmap](../ROADMAP-24-PHASES.md).