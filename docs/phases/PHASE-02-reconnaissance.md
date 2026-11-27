# Phase 2 — Reconnaissance

**Status:** Implemented as a bounded built-in probing engine; external tool execution and broad discovery remain incomplete.
**Implementation:** **framework/recon/**, **framework/assets/**, **framework/common/transport.py**, **scripts/bb-recon**, and the **reconnaissance skill**
**State file:** **state/recon.json** in the local program workspace.

## Why this phase exists

Once you have a list of authorized hosts, reconnaissance records what those hosts expose at a basic level. It can tell you whether a web service responds, what its TLS certificate says, what a response’s headers reveal, and which technologies might be present. This gives later testing phases a map of the application instead of asking them to guess.

Reconnaissance results are observations, not proof of a vulnerability. A server header that appears to identify a framework may be missing or misleading. A port that accepts a connection does not show that the service is in scope for a particular test. Each observation needs a source, timestamp, and confidence that a researcher can review.

## Inputs and prerequisites

Phase 2 normally reads the in-scope domain and host records produced by Phase 1. It also accepts a specific asset or domain. Provide a valid program scope file before any live probing. If the program’s rules change, update the file before running again. The engine skips candidates that fail the scope check and bounds the number of hosts and requests.

The current engine uses its own bounded Python-based probes for DNS, TLS, HTTP, and a small default port list. It does not launch **httpx**, **nmap**, or other catalog scanners as part of **bb-recon**. Subfinder has a separate opt-in integration under Phase 1 (`bb-assets --subfinder`); it is not run by **bb-recon**. This phase is a limited local enrichment engine, not a replacement for a curated reconnaissance workflow. New hostname discovery depends on the Phase 1 inventory or names found in TLS SAN data; **bb-recon** does not perform wordlist enumeration.

## How the phase works

The engine loads the existing asset graph, filters to in-scope hosts, and applies selected capabilities. The default set includes DNS, TLS, HTTP, ports, and technology fingerprints; endpoint discovery is separately selected. The default ceilings are 500 hosts and 2,000 active HTTP/TCP requests, with a separate endpoint ceiling in the engine. The shared HTTP transport requires a configured scope and rejects an out-of-scope URL before resolving its hostname. It records observations in structured state and writes the file atomically so an interrupted write is less likely to leave corrupt JSON.

DNS probing collects a limited set of record information through the available resolver path. TLS probing observes certificate data and can add in-scope certificate names to the asset graph. HTTP probing makes a small GET request to common web ports and records status, title, selected headers, and response metadata. Port probing checks only a short default list rather than sweeping every TCP port. Technology identification uses simple response-header signatures and any explicitly supplied tool output; a signature match can be wrong or incomplete.

Use **--resume** to skip hosts marked as already probed. This saves repeated requests, but it also means old observations may need an intentional refresh when the target changes. Use **--dry-run** to evaluate without persisting updated state, and **--passive-only** to disable live probes.

## How to run it

~~~bash
# Review existing state without making active network connections.
bb-recon --program <program-name> --passive-only --tree

# Probe the program's known in-scope hosts using conservative defaults.
bb-recon --program <program-name> --tree

# Run only selected capabilities on one known host.
bb-recon --program <program-name> --asset api.example.org --capabilities "dns,tls,http"

# Resume an earlier run while respecting request and host ceilings.
bb-recon --program <program-name> --resume --max-hosts 100 --max-requests 300

# Preview the structured state without saving new observations.
bb-recon --program <program-name> --dry-run --json
~~~

These commands are examples, not authorization. Use only hosts included in the program’s current scope and keep request limits appropriate to its rules.

## Reading and using results

Open the local **state/recon.json** or use the tree/JSON output. Check the host, observation type, timestamp, provenance, and confidence. A missing result can mean that the service did not respond, the capability was not selected, the host was out of scope, the budget was exhausted, the runtime could not complete the request, or the observation is not implemented. It does not automatically mean the target has no such service.

Feed reviewed services into Phase 3 web mapping, Phase 4 JavaScript analysis, and Phase 5 API mapping. Keep inferred technologies labeled as hypotheses until independently confirmed.

## Safety and limitations

The request and host budgets do not replace program rate limits. Use passive-only mode if scope is not yet verified. The engine is intentionally read-only and uses bounded requests; do not turn an endpoint inventory into broad fuzzing. The tool registry’s presence should not be confused with a tool being installed or invoked by this phase.

The remaining mismatch between the tool catalog and runtime integration is recorded in the **project audit issues**. Tests use local fixtures and controlled hooks, so they check engine behavior but do not prove broad coverage or live-target effectiveness.

## Source references

Tests: **tests/test_recon_engine.py**, **tests/test_recursive_subdomains.py**, and shared transport regressions in **tests/test_scope_fail_closed_validation.py**. See the **reconnaissance skill**, **runtime guide**, and **roadmap**.
