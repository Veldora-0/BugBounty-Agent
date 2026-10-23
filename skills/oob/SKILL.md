---
name: oob
description: Controlled out-of-band (OOB) interaction testing, blind SSRF confirmation, and asynchronous callback verification via Interactsh.
---

# Out-of-Band (OOB) Testing & SSRF Intelligence Methodology

## Core Objective
Safely detect and validate Server-Side Request Forgery (SSRF) and blind server-side network interactions where the target application causes an outbound request to a researcher-controlled destination. Rely strictly on asynchronous callback verification rather than internal network exploitation.

---

## 1. Vulnerability Classes & Taxonomy
* **Direct SSRF**: Target endpoint fetches an external URL supplied in a parameter and reflects or processes the response.
* **Blind SSRF**: Backend worker or async job initiates an HTTP/HTTPS connection to a remote destination without reflecting the content.
* **Redirect-Mediated SSRF**: Target follows an HTTP 301/302 redirect from an initial target host to the controlled canary.
* **DNS-Only Server-Side Interaction**: Target resolves the canary hostname via DNS (e.g., pre-fetch resolution or URL validation) without establishing an HTTP connection.
* **Webhook / Callback Misconfiguration**: Application delivers webhooks or event notifications to user-supplied URLs without domain restrictions.
* **Remote Importer / Fetcher**: Features such as image proxies, PDF generators, website preview unfurlers, RSS feed parsers, or document synchronizers fetching external assets.

---

## 2. Infrastructure: Pluggable OOB Provider Architecture
The engine abstracts interaction servers through a modular interface:
1. **Mock Provider (`MockOobProvider`)**: Deterministic local in-memory simulation for offline test suites and local security lab verification. Interactions produce `SIMULATED` (`INFORMATIONAL`, `LOW` confidence) observations; they never become live validated findings.
2. **Interactsh Provider (`InteractshOobProvider`)**: ProjectDiscovery Interactsh adapter for production OOB callbacks (`oast.pro` or self-hosted).
3. **Collaborator Provider (`CollaboratorOobProvider`)**: Burp Collaborator polling client adapter.

> [!NOTE]
> **Truthful Provider Availability (Phase 18)**: Unconfigured providers report `CONFIG_REQUIRED`. Configured external adapters report `UNAVAILABLE` because live wire polling over network protocols is not implemented (storage is local in-memory only). A configured token or hostname alone does not establish operational live polling. Before issuing canaries or dispatching probes, the engine checks provider availability; if `UNAVAILABLE`, `CONFIG_REQUIRED`, or `ERROR`, it fails closed immediately with zero network requests dispatched.

---

## 3. Canary Token & Strict Correlation Architecture
Every SSRF probe receives a unique, non-sensitive correlation token:
`bb9-<program_id>-<test_id>-<random_hex>.<oob_domain>`

### Destination Trust & Method Verification (Phase 18):
Before any request is sent, the generated canary destination is validated against `validate_oob_destination()` in `SecurityTestPolicy`. The engine verifies that this method exists and is callable. If missing or non-callable, it fails closed with `PolicyViolationError`, sets `POLICY_VIOLATION` candidate state, and dispatches zero network requests. The destination must belong to authorized trusted domains and strictly forbids IP literals (loopback, private, carrier-grade NAT, or metadata IP addresses, including alternate numeric representations) and prohibited hostnames.

### Correlation Lifecycle:
```text
Candidate Endpoint (e.g. GET /fetch?url=...)
        │
        ▼
Verify Provider Availability (AVAILABLE) ──► Fails closed if UNAVAILABLE / CONFIG_REQUIRED (0 requests)
        │
        ▼
Issue Unique Canary Token (e.g. bb9-acme-01-f4a2.oob.local)
        │
        ▼
Validate OOB Destination Trust Policy ──► Fails closed with PolicyViolationError if untrusted/non-callable
        │
        ▼
Dispatch Controlled Probe with Safe HTTP Method (GET/HEAD)
        │
        ▼
Poll OOB Provider within Bounded Polling Window (max_wait: 3-5s)
        │
        ▼
Match Canary Token + Timestamp Window + Origin IP
        │
        ├── No Interaction Observed     ──► CANDIDATE / TESTED
        ├── DNS-Only Resolution Observed ──► OBSERVED (DNS Primitive)
        ├── Mock Callback Observed       ──► SIMULATED (Informational Mock Proof)
        └── Live Wire Callback Observed  ──► VALIDATED (Confirmed SSRF)
```

---

## 4. False-Positive Elimination & Safety Rules
* **Client-Side vs Server-Side Separation**: Discard interactions originating from the researcher's own client IP or automated browser prefetching.
* **Correlation Window Expiration**: Reject stale callbacks arriving after the bounded test window (default 60s) or associated with previous runs.
* **Agent-Side Anti-SSRF vs Target-Side SSRF Testing**:
  * **Agent Network Safety**: The framework strictly blocks requests to loopback (`127.0.0.1`), private RFC1918 networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local metadata addresses (`169.254.169.254`), and prohibited protocols (`file://`, `gopher://`).
  * **Target SSRF Testing**: Probes exclusively supply researcher-controlled external canary hostnames. The agent NEVER probes private internal addresses, scans internal ports, or attempts cloud metadata exploitation.

---

## 5. Human Approval Gate
All active SSRF canary testing requires explicit human authorization (`--approve` or `--approve-id`). The system renders an approval dossier:
* Target Host & Endpoint
* Parameter & Location (Query, Path, Body)
* SSRF Category & Inferred Sink
* Assigned Canary Token & Destination
* Planned Request Budget
* Non-Destructive Safety Classification

---

## 6. CLI Tooling: `bb-ssrf`

```bash
# Render visual candidate tree across all categories
bb-ssrf --program <name> --tree

# Passive discovery only from Phase 3, 4, and 5 states (zero HTTP probes)
bb-ssrf --program <name> --passive-only

# Review human approval dossiers for pending candidates
bb-ssrf --program <name> --dossier

# Plan test cases with canary tokens without sending requests
bb-ssrf --program <name> --dry-run

# Run active validation with explicit researcher approval
bb-ssrf --program <name> --endpoint "https://app.example.com/fetch?url=" --param url --approve

# Test against built-in deterministic local security lab
bb-ssrf --lab --tree

# Output structured JSON results
bb-ssrf --program <name> --json
```

---

## 7. State Management & Findings
State is maintained atomically outside Git in `~/BugBounty-Workspace/programs/<name>/state/ssrf.json`:
* `candidates`: Discovered SSRF parameter candidates and sink classifications.
* `canaries`: Registered canary tokens and issuance timestamps.
* `approved_tests`: Human approval audit records.
* `interactions`: Sanitized out-of-band interaction events.
* `findings`: Verified findings deduplicated by signature (`FindingDeduplicator`).
