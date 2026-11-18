# Phase 3 — Web Application Intelligence

**Status:** Implemented for bounded, read-oriented application mapping; authenticated-session support is limited.
**Implementation:** **framework/webapp/**, **framework/common/transport.py**, **scripts/bb-webapp**, and the **web-security skill**
**State file:** **state/webapps.json** in the local program workspace.

## Why this phase exists

A host is only the beginning of a web application map. The application may have many pages, forms, API-like routes, query parameters, cookies, and JavaScript or other resources. Phase 3 follows a controlled set of links and records that visible surface in a form that a researcher can inspect and use to plan a specific security hypothesis.

For example, a settings page may contain an account identifier, a profile update form, and a JavaScript bundle. Those observations can suggest later authorization, input-handling, or client-side questions. They do not show that the settings page is vulnerable. A crawler maps what it can see; a human must decide what the behavior means and whether further testing is allowed.

## What it consumes and records

The phase starts from a web service already found in Phase 2 or from a host/URL supplied by the operator. Before a live crawl, the target and each followed URL must pass the program scope rules. The crawler applies same-origin and crawl-policy limits so a link to another company or an excluded host does not silently expand the target set.

The parser records applications, pages, endpoints, forms, parameters, cookies, resources, and links. It also inspects common discovery files such as robots.txt and sitemaps when enabled. State is stored in **webapps.json** using atomic writes. The crawler tracks visited and rejected URLs so duplicate links do not produce endless loops.

## How the phase works

The command first resolves the selected application from explicit input or prior reconnaissance. Its crawl policy limits depth, page count, response size, request count, and allowed origins. It fetches pages using the repository’s controlled transport, parses HTML without executing page scripts, normalizes URLs, and adds discovered links to a queue only when the policy permits. Form and input fields are recorded as observations; the engine does not submit them as part of ordinary mapping.

**--passive-only** means analyze existing local state without issuing active HTTP requests. **--dry-run** means do not persist the result. **--resume** uses the stored visited set to avoid repeating the same crawl. Authenticated coverage is not equivalent to supplying arbitrary browser cookies: a supported, well-documented operator session workflow is still limited, so do not assume this phase has mapped content behind login.

## How to run it

~~~bash
# Review the applications and pages already saved in local state.
bb-webapp --program <program-name> --passive-only --tree

# Crawl a known in-scope application using the built-in limits.
bb-webapp --program <program-name> --asset app.example.org --tree

# Use smaller bounds when the program asks for a low request rate.
bb-webapp --program <program-name> --asset app.example.org --max-pages 20 --max-depth 1

# Continue without revisiting pages already recorded.
bb-webapp --program <program-name> --resume --json

# Evaluate without writing new state.
bb-webapp --program <program-name> --dry-run --json
~~~

The domain and program name above are examples. Confirm the application is in scope before using a live crawl.

## How to interpret the map

A page record means the crawler received and parsed that URL. An endpoint record means a URL or form action was observed; it does not mean the endpoint accepts every method or is accessible to every user. A parameter is a place where input may be supplied, not proof that the application trusts it. A cookie attribute is an observation from a response, not a complete session-security assessment.

Use the map to select a narrow next question: for example, whether two authorized test accounts see different records at the same endpoint, or whether a form applies server-side validation. Feed discovered JavaScript and API routes into Phases 4 and 5. Do not crawl an entire linked domain just because the page links to it.

## Safety and current limitations

This phase is intended to map, not mutate. Do not manually change the workflow into form submission, destructive actions, or high-volume crawling. SPA pages whose content is only built after JavaScript runs may be incomplete in this phase; Phase 16 adds optional browser observation. Authenticated session coverage and framework-aware crawl strategies need further work.

Tests in **tests/test_webapp_engine.py** use controlled responses and verify parsing, queueing, boundaries, and state behavior. They do not show that every live application can be crawled or that the resulting map is complete. See the **web-security skill**, **security policy**, and **roadmap**.