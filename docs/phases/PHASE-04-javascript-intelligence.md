# Phase 4 — JavaScript Intelligence

**Status:** Implemented for bounded static analysis; framework-aware extraction and broader source-map recovery remain limited.
**Implementation:** **framework/javascript/**, **scripts/bb-js**, and the **javascript skill**
**State file:** **state/javascript.json** in the local program workspace.

## Why this phase exists

Modern web applications often place route names, API paths, feature flags, and client-side logic in JavaScript files. A researcher can use those files to learn where an application sends requests and which values it expects. Phase 4 collects a bounded set of JavaScript resources and searches their text for these useful clues without running the target’s code.

The phase is an analysis assistant. A string that looks like an endpoint or key is only a clue. Some strings are examples, stale code, public configuration, or unused text. Do not call every discovered string a secret or every route a security issue. Confirm that a route belongs to a current in-scope application before testing it.

## Inputs and processing

The engine reads JavaScript resource observations from Phase 3, or accepts a single resource URL or host filter. Active acquisition requires an in-scope URL and a configured scope engine. The default policy caps the number of files, requests, total bytes, and per-file size. The downloaded script text is hashed for deduplication and analyzed by static patterns for endpoints, routes, parameter references, interesting strings, dependencies, and source-map references.

The analyzer stores structured results rather than executing script code. Source-map reference extraction should be read as discovery of a reference unless the specific implementation and result say the source map itself was acquired and parsed. **--passive-only** reviews scripts already present in local state and avoids active HTTP acquisition. **--resume** skips previously processed resources or hashes where state supports it.

## How to run it

~~~bash
# Review the JavaScript findings already present in state.
bb-js --program <program-name> --passive-only --tree

# Analyze JavaScript resources previously found for one authorized host.
bb-js --program <program-name> --asset app.example.org --tree

# Analyze one known in-scope script URL.
bb-js --program <program-name> --resource https://app.example.org/static/app.js --json

# Reduce transfer sizes and request volume for a cautious run.
bb-js --program <program-name> --max-files 10 --max-requests 20 --max-bytes-per-file 262144

# Preview results without persisting them.
bb-js --program <program-name> --dry-run --json
~~~

Use the program’s real scope and follow its rules for downloads. The URL shown above is illustrative.

## What the output means

The state file contains resources and extracted observations. A route is a candidate path, not proof that it is live. A parameter reference shows that text in a script uses a value, not that the server accepts it or enforces a security boundary. Interesting strings are masked to reduce accidental exposure; inspect them carefully and never copy credentials or tokens into reports or Git.

A productive next step is to compare discovered routes with Phase 5 API observations and Phase 3 pages, then write a hypothesis tied to a specific, authorized endpoint. If you find a candidate credential, first determine safely whether it is a public identifier or a privileged secret without using it to access data or services.

## Safety and limitations

The phase does not execute downloaded code and has acquisition budgets. Those controls do not make an out-of-scope file permissible to download. Large bundles may be truncated or skipped; minified or dynamically generated code can defeat simple patterns. Framework-specific routing, semantic reachability, source-map content recovery, and confidence calibration are not complete. Results need human triage and should never be presented as verified impact by themselves.

Tests in **tests/test_javascript_engine.py** exercise local script fixtures and analysis limits, not comprehensive coverage of modern front-end frameworks. See the **JavaScript skill**, **workflow guide**, and **roadmap**.