# BugBounty-Agent — Phase 20 Implementation Plan
## Race Conditions & Distributed Workflows Intelligence

**Accepted Baseline**: `30f1b1dfb417989bd6889057a8c8f8a4abfaec8b`  
**Reference Document**: `docs/ROADMAP-24-PHASES-TEMP.md` (Phase 20)  
**Status**: Complete — Hardened, Corrected & Verified  
**Architecture Model**: Single primary OpenCode agent (`Bug-Bounty`) with 18 modular skills (`subagent_depth: 1`)

---

## 1. Executive Summary & Objectives

### Primary Objective
Deliver **Phase 20: Race Conditions & Distributed Workflows Intelligence** as a precision, hypothesis-driven security intelligence subsystem. Phase 20 models, detects, and validates concurrency-sensitive business logic vulnerabilities, check-then-act (TOCTOU) race windows, multi-step distributed workflow desynchronization, duplicate submission flaws, and limit-overrun vulnerabilities across stateful web applications.

Rather than relying on high-volume request flooding, denial-of-service tactics, or uncoordinated threads, Phase 20 employs **bounded, barrier-synchronized microsecond bursts** (2–5 parallel requests, hard limit of 10) coordinated by a deterministic synchronization barrier (`threading.Barrier`). This guarantees that concurrent requests arrive within the server's race window without creating excessive load or service disruption.

### Key Goals & Core Principles
1. **Concurrency Taxonomy**: Formulate explicit hypotheses across **6 distinct race and workflow categories**:
   - `LIMIT_OVERRUN`: Bypassing rate, voting, or action quotas via parallel check-then-act execution.
   - `TOCTOU`: Time-of-check to time-of-use race windows between state validation and action execution.
   - `DOUBLE_SPEND`: Simultaneous multi-redemption of single-use coupons, vouchers, gift cards, or tokens.
   - `IDEMPOTENCY_BYPASS`: Bypassing duplicate submission protections when parallel identical requests are issued without distributed lock or atomic idempotency key persistence.
   - `PARTIAL_EXECUTION_DESYNC`: Multi-step distributed workflow failures where partial commits leave persistent state inconsistent or un-rolled-back.
   - `CONCURRENT_STATE_MUTATION`: Simultaneous conflicting updates to the same resource resulting in data corruption or race window bypass.
2. **Barrier Synchronization (`threading.Barrier`)**:
   - Workers are pre-armed with validated `ControlledRequest` instances and held at an execution barrier.
   - Released simultaneously to transmit within the same microsecond burst window, maximizing race collision probability while strictly minimizing total request count.
3. **Rigorous Invariant Evaluation & Evidence Hardening**:
   - Strictly disallows classifying findings as `CONFIRMED` based solely on HTTP status code counts (`success_count > allowed_limit`).
   - Requires reliable proof of business-state mutation:
     - Distinct committed resource IDs returned across responses (e.g. distinct `order_id`, `redemption_id`, `vote_id`, `tx_id`).
     - Server post-state verification confirming multiple mutations (e.g. `redemptions > allowed_limit` or `balance < 0`).
   - Distinguishes idempotent duplicate responses from duplicate processing:
     - Multiple 200 OK responses with identical bodies, same resource ID, or idempotency markers (`idempotent: true`) are classified as `CONCURRENCY_CONTROLLED`.
     - Multiple identical responses with no verified mutation proof are classified as `INCONCLUSIVE`, never `CONFIRMED`.
   - Requires verified inconsistent state or failed rollback evidence for distributed partial execution (`PARTIAL_EXECUTION_DESYNC`). If consistency cannot be established, classifies as `INCONCLUSIVE`.
   - Missing or malformed post-state evidence without distinct committed resource IDs is classified as `INCONCLUSIVE`, never `CONFIRMED`.
   - Normal contention responses (e.g. HTTP 409 Conflict, HTTP 429 Too Many Requests, optimistic locking rollbacks) are recognized as evidence of proper concurrency control (`CONCURRENCY_CONTROLLED`), NOT vulnerabilities.
   - Transient network errors or timeouts under burst are classified as `INCONCLUSIVE` and never promoted to confirmed findings.
4. **Strict Safety Boundaries & Fail-Closed Transport**:
   - Bounded concurrent bursts: 2–10 parallel worker threads (`MAX_BURST_SIZE = 10`).
   - Hard request budget ceiling: strictly enforced maximum of 15 requests per test (`MAX_REQUESTS_PER_TEST = 15`).
   - Fail-closed scope checks immediately before dispatch in `_send_request_safe()`; in production mode, missing `ScopeEngine`, out-of-scope targets, or scope exceptions refuse dispatch immediately.
   - Mandatory human approval gate (`require_approval`, `--approve`) for all active state mutations.
   - Anti-SSRF enforcement preventing requests to private or loopback IP spaces in production; lab mode explicitly whitelists only ephemeral test ports.
   - Worker timeout and lifecycle handling: explicit tracking of worker thread completion; late-finishing workers are locked out via completion events and cannot mutate finalized test state.
5. **Zero Secret Persistence & Complete Exception Sanitization**:
   - All credentials, tokens, session IDs, and exception messages are scrubbed (`sanitize_sensitive_data()`, secret regex) before persisting to `state/concurrency.json`, logs, finding objects, or markdown reports.
6. **Single-Agent Architecture Invariant**:
   - Implemented within `framework/concurrency/` and CLI `scripts/bb-race` (`bb-race.cmd`).
   - Delivered via existing skills `business-logic` and `validation`. Zero 19th skill added.
   - Registered in `bb-doctor` as Category 25 (`check_concurrency_engine`).

---

## 2. Mandatory Architectural & Safety Invariants

1. **Single Orchestrator Agent**: Exactly one global OpenCode primary agent: `Bug-Bounty`. Subagents remain denied (`subagent_depth: 1`).
2. **18 Modular Skills Catalog**: No new skills added; concurrency capabilities are documented within `skills/business-logic/` and `skills/validation/`.
3. **No Request Flooding or DoS**: Concurrency testing strictly uses synchronized micro-bursts (2 to 5 requests). Mass stress testing or load flooding is prohibited.
4. **Scope Fail-Closed**: Every request URL must pass offline validation via `ScopeEngine.check()` prior to dispatch.
5. **Anti-SSRF Protection**: RFC 1918, loopback, link-local, and cloud metadata targets are blocked in production. Lab simulation explicitly whitelists only the ephemeral lab port.
6. **Deterministic Offline Lab**: `LocalConcurrencyLab` provides 8 deterministic scenarios covering vulnerable and safe controls.
7. **No Plaintext Secret Persistence**: All state persistence in `state/concurrency.json` is scrubbed and written atomically.
8. **Conservative Evidence Standards**: Findings require verified invariant breach (e.g. limit exceeded, negative balance). Varied response times or status codes alone never constitute a confirmed vulnerability.

---

## 3. Subsystem Architecture

```
framework/concurrency/
├── __init__.py           # Subsystem exports
├── model.py              # RaceCategory, RaceConfidence, Hypothesis, TestResult, ConcurrencyProbePlan
├── policy.py             # ConcurrencySafetyPolicy (bounded concurrency, budgets, timeouts, DNS preflight)
├── synchronization.py    # BarrierSynchronizer (threading.Barrier coordinated burst dispatcher, sealing)
├── invariants.py         # ConcurrencyInvariantEngine (ResourceIdentityTracker, provenance evaluation)
├── state.py              # ConcurrencyStateManager (manages state/concurrency.json atomically)
├── lab.py                # LocalConcurrencyLab (8 deterministic offline scenarios)
└── engine.py             # RaceIntelligenceEngine (orchestration, scope, approval, deduplication, budget contexts)

scripts/
├── bb-race               # Shell CLI wrapper for Linux/macOS
└── bb-race.cmd           # Windows batch CLI wrapper
```

---

## 4. Local Lab Scenarios (8 Scenarios)

1. `COUPON_DOUBLE_SPEND`: Check-then-act coupon redemption without locking. Vulnerable to concurrent double redemption (`RACE_LIMIT_OVERRUN`).
2. `BALANCE_TRANSFER_OVERDRAW`: Asynchronous transfer without balance reservation. Vulnerable to negative balance (`TOCTOU`).
3. `VOTING_LIMIT_OVERRUN`: Simultaneous voting requests bypass daily limit (`LIMIT_OVERRUN`).
4. `IDEMPOTENCY_KEY_CACHE_RACE`: Simultaneous duplicate order submission before idempotency key cache write (`IDEMPOTENCY_BYPASS`).
5. `MUTEX_PROTECTED_SAFE`: Properly locked endpoint returning HTTP 409 Conflict for concurrent requests (`CONCURRENCY_CONTROLLED`, safe).
6. `WAF_RATE_LIMIT_SAFE`: Properly rate-limited endpoint returning HTTP 429 (`CONCURRENCY_CONTROLLED`, safe).
7. `INCONCLUSIVE_TIMEOUT`: Server times out under load without state modification (`INCONCLUSIVE`, not a vulnerability).
8. `DISTRIBUTED_PARTIAL_ROLLBACK`: Two-step transaction where step 2 fails and leaves step 1 uncompensated (`PARTIAL_EXECUTION_DESYNC`).

---

## 5. Blocker A: Resource Identity & Invariant Evaluation

### Defect Addressed
Earlier implementations risked treating multiple JSON field aliases representing the same underlying entity (e.g., `{"order_id": "ORD-1", "id": "ORD-1"}`) as two distinct resources, or mixing scalar counters (e.g., `{"count": 2}`) and response status counts into entity ID sets.

### Implemented Hardening
1. **Category-Specific Primary Key Resolution**:
   - `ResourceIdentityTracker` resolves canonical identifiers using category-prioritized keys:
     - `DOUBLE_SPEND` / `LIMIT_OVERRUN`: `redemption_id`, `claim_id`, `coupon_id`, `reward_id`, `vote_id`.
     - `IDEMPOTENCY_BYPASS`: `order_id`, `payment_id`, `transaction_id`, `invoice_id`.
     - General: `id`, `resource_id`, `uuid`.
2. **Field-Alias Deduplication**:
   - When a single HTTP response contains multiple fields with identical values (e.g. `order_id: ORD-1` and `id: ORD-1`), the tracker maps them to a single canonical entity.
   - Cross-response deduplication ensures two responses citing the same identifier are identified as a single created resource, correctly flagging idempotent deduplication (`CONCURRENCY_CONTROLLED`).
3. **Rejection of Nonces, Counters and Trivial Values**:
   - Trivial status markers (`"ok"`, `"true"`, `"success"`, `"created"`, `"failed"`) and generic boolean/status strings are explicitly filtered out.
   - Scalar numeric counters (e.g. `"items_count": 2`) are isolated from resource identity sets.
4. **HTTP Status Independence**:
   - HTTP status code counts alone (`success_count > allowed_limit`) **never** prove an invariant violation. Proof requires either distinct entity identities or authoritative post-state evidence.

---

## 6. Blocker B: Post-State Evidence Provenance & Consistency Contracts

### Defect Addressed
Untrusted caller dictionaries (e.g. passing `post_state_evidence={"overrun_verified": True}`) could previously be accepted as authoritative proof of server-side mutation. Furthermore, inconsistent pre-state vs. post-state observations were not rigorously validated.

### Implemented Hardening
1. **Explicit Provenance Model (`EvidenceSource`)**:
   - Four distinct provenance levels:
     - `UNTRUSTED_CALLER_CLAIM`: Unverified caller assertions. Strictly rejected as authoritative proof.
     - `DIRECT_TRANSPORT_OBSERVATION`: Transport-level responses directly parsed by the engine.
     - `INDEPENDENT_STATE_QUERY`: Direct secondary query verifying server-side state.
     - `LAB_FIXTURE_AUTHORITATIVE`: Authoritative in-memory state returned directly by deterministic lab fixtures (`LocalConcurrencyLab.get_authoritative_state()`).
2. **`PostStateEvidence` Contract**:
   - Encapsulates entity ID, pre-test and post-test values, expected delta, source provenance, and raw state verification data.
   - `is_authoritative()` method enforces that only `INDEPENDENT_STATE_QUERY` and `LAB_FIXTURE_AUTHORITATIVE` qualify for `CONFIRMED` invariant verification.
3. **Consistency Validation**:
   - `validate_consistency()` validates that observed changes match the physics of the operation (e.g., a counter increment cannot result in `post_state < pre_state`).
   - Contradictory, missing, or unverified post-state fails closed to `INCONCLUSIVE`.

---

## 7. Blocker C: Worker Lifecycle, Bounded Deadlines & State Isolation

### Defect Addressed
Thread synchronization using uncoordinated joins could result in cumulative linear timeouts ($N \times \text{timeout}$). Furthermore, background worker threads completing after test conclusion could mutate finalized test results, and thread naming collisions could corrupt cross-burst accounting.

### Implemented Hardening
1. **Single Monotonic Deadline**:
   - `BarrierSynchronizer.execute_burst()` computes a single overall deadline: `deadline = time.monotonic() + self.timeout + 1.0`.
   - All worker joins share this deadline via `remaining = max(0.001, deadline - time.monotonic())`.
   - Bounded join wait prevents runaway linear wait when multiple threads hang.
2. **Worker Lifecycle States (`WorkerLifecycleState`)**:
   - Workers transition through explicit states: `COMPLETED`, `FAILED`, `TIMED_OUT_UNRESOLVED`, and `CANCELLED`.
   - In-flight requests exceeding the timeout are classified as `TIMED_OUT_UNRESOLVED`.
   - Unresolved timeouts fail closed to `INCONCLUSIVE`.
3. **Container Sealing (`BurstExecutionContainer`)**:
   - Execution results are collected in a `BurstExecutionContainer`.
   - Upon join completion, `container.seal()` permanently locks the container against late modifications. Any late-arriving callback from a lagging worker is rejected.
4. **Isolated Worker Thread Naming**:
   - Workers are named `bb-race-worker-{i}-{burst_id}`, where `burst_id` is a unique per-burst UUID.
   - Prevents cross-burst thread tracking collisions and enables deterministic selective joining in unit tests.

---

## 8. Blocker D: Per-Hypothesis Request Budget Isolation

### Defect Addressed
Global or engine-level request counters allowed concurrent or sequential test executions to bleed into, starve, or prematurely exhaust one another's request allocations.

### Implemented Hardening
1. **`HypothesisBudgetContext`**:
   - Thread-safe, isolated request counter bound to each specific hypothesis execution.
   - Clamped strictly to `min(max_requests, MAX_REQUESTS_PER_TEST = 15)`.
2. **Isolation Guarantee**:
   - Parallel or subsequent hypothesis evaluations instantiate their own independent `HypothesisBudgetContext`.
   - No shared global state or instance-level accumulator is used for budget enforcement.
   - Standalone requests fall back to an isolated `engine-default` context.

---

## 9. SSRF & Hostname Preflight Validation & Documented Limitations

### Implemented Controls
1. **Preflight DNS Resolution Hook (`resolve_hostname`)**:
   - In production mode, hostnames in probe URLs are resolved to IP addresses prior to dispatch.
   - Resolved IPs are validated against RFC 1918 private subnets, loopbacks (`127.0.0.0/8`), link-local (`169.254.0.0/16`), carrier-grade NAT (`100.64.0.0/10`), and IPv6 equivalents (`::1`, `fc00::/7`, `fe80::/10`).
   - Supports a pluggable `resolver` hook in `ConcurrencySafetyPolicy` for deterministic testing.
2. **Documented DNS Rebinding Limitation**:
   - **Limitation**: While preflight DNS resolution validates that target hostnames do not initially resolve to internal or metadata IP addresses, standard Python `http.client` and `urllib.request` re-resolve hostnames upon socket connection without transport-level IP pinning.
   - **Risk**: A sophisticated DNS rebinding server returning a public IP on preflight resolution and subsequently returning `127.0.0.1` on socket connection could evade preflight checks.
   - **Production Recommendation**: In high-risk environments, concurrency probes should route through an egress-validating proxy (similar to Phase 16's `ValidatingEgressProxy`) or an OS-level network namespace (`ip netns`) that strictly pins destination IP tuples at the transport socket level.

---

## 10. Verification & Test Plan

1. **Focused Test Suite (`tests/test_concurrency_engine.py`)**:
   - **60 comprehensive tests** (up from initial 43).
   - Covers:
     - All 8 local simulation lab scenarios.
     - Blocker A: Resource identity resolution, alias deduplication, and invariant evaluation.
     - Blocker B: Post-state evidence provenance, authoritative source verification, and consistency checks.
     - Blocker C: Worker lifecycle states, single bounded deadline join, burst container sealing, and timeout fail-closed semantics.
     - Blocker D: Per-hypothesis request budget isolation and thread-safe counter ceiling enforcement.
     - Anti-SSRF: Loopback, private IP, and cloud metadata preflight DNS checks.
     - Secret scrubbing: Zero plaintext token or exception leaks to disk.
     - Phase 19 Sentinel Report Inspection: Verifies absence of exception secrets in generated reports.
2. **Diagnostic Health**:
   - `bb-doctor` Category 25 (`check_concurrency_engine`) reports `[HEALTHY]`.
3. **Cross-Platform Parity**:
   - Verified on Windows 11 (60/60 concurrency tests, 107/107 total test suites).
   - Verified on Kali Linux VM (`ssh veldora@127.0.0.1 -p 2222`).

---

## 11. Operational Boundaries & Non-Goals

1. **No Volumetric Flooding**: Mass denial-of-service, traffic amplification, and uncoordinated stress testing remain strictly prohibited.
2. **Single Orchestrator Invariant**: Phase 20 introduces zero additional agents or skills (`subagent_depth: 1`, 18 modular skills).
3. **No Phase 21 Work**: Phase 21 (Authentication & Authorization Correlation) remains strictly out of scope for Phase 20.
