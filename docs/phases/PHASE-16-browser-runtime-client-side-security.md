# Phase 16 — Browser Runtime and Client-Side Security

**Status:** Implemented as an optional browser-observation and XSS-confirmation layer; real browser binaries and their versions vary by host.
**Implementation:** **framework/xss/browser.py**, **scripts/bb-xss**, and the **browser skill**
**State:** Browser observations are associated with Phase 7’s local **state/xss.json** results.

## Why this phase exists

A static page download cannot show everything a browser does. A single-page application may build its routes after JavaScript runs, change the page without a full reload, store values in browser storage, open WebSockets, or interpret reflected content in a browser-specific context. Phase 16 adds a controlled browser so the researcher can observe that runtime behavior.

The browser is an observer for the authorized application, not an unrestricted browsing agent. It should collect the minimum signals needed for a hypothesis and block requests that leave the approved scope or exceed its execution budget.

## How the browser layer works

The browser capability detector checks whether the required automation library and browser binary are available. A policy checks the starting URL, resolves and validates destinations, limits navigation and capture budgets, and records blocked requests. The browser session can record route changes, DOM mutations, scripts, requests, console messages, page errors, storage-related observations, and WebSocket metadata. Sensitive request headers and URL values are redacted before they are written to logs.

The browser layer can support Phase 7 by checking whether a candidate value actually reaches an executable browser context. If the runtime is unavailable, the outcome should be UNAVAILABLE or INCONCLUSIVE; a static signal must not be upgraded to a browser-confirmed finding.

## How to use it

~~~bash
# First confirm browser runtime availability on the Kali host.
bb-doctor

# Review XSS candidates without opening a browser or sending requests.
bb-xss --program <program-name> --passive-only --tree

# Request bounded browser confirmation for one authorized endpoint.
bb-xss --program <program-name> --endpoint https://app.example.org/search --browser --max-tests 1 --json
~~~

The browser option is implemented through the XSS command; there is no separate browser-scan command. Use a disposable program-approved test account if authentication is necessary. Do not let the browser visit links or navigate to another host simply because the page contains them.

## Reading browser evidence

A browser observation says what the tested browser saw under the tested session and configuration. A route change is not automatically an access-control issue. A console error may be harmless. A request to an API is an endpoint clue. A dangerous client-side sink needs a controlled input-to-sink proof before it supports an XSS report.

Record the browser version, runtime availability, starting page, session context, budget outcome, and any blocked requests. Redact cookies and tokens. Compare the result with the static map and server response rather than relying on a screenshot alone.

## Safety and limitations

Use a separate browser context with no personal browsing profile or unrelated accounts. Never disable network policy or scope checks to make the page load. Dynamic front-end behavior and browser versions change, and this layer cannot guarantee full application coverage. It does not replace server-side validation or prove an impact that was not safely observed.

Tests: **tests/test_phase16_browser_runtime.py** and browser-policy coverage in **tests/test_xss_engine.py**. See [Phase 7](PHASE-07-xss-intelligence.md), the **browser skill**, and [roadmap](../ROADMAP-24-PHASES.md).