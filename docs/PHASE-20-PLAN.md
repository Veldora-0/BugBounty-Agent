# BugBounty-Agent — Phase 20 Implementation Plan
## Race Conditions & Distributed Workflows Intelligence

**Accepted Baseline**: `3ab5f7b657e8bcb9c66ffef5db665c7b1f90b121`
**Reference Document**: `docs/ROADMAP-24-PHASES-TEMP.md` (Phase 20)
**Status**: Complete — Hardened, Corrected & Verified (Evidence Trust, Invariant Accuracy, Counter Baselines)
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
   - Distinct response identifiers alone without authoritative post-state evidence are classified as `SUSPECTED` (`OBSERVED`, `INFORMATIONAL`), never `CONFIRMED`.
   - Requires authoritative proof of business-state mutation produced through a verified internal boundary (e.g. `LocalConcurrencyLab.get_authoritative_state()`) to confirm breaches.
   - Distinguishes idempotent duplicate responses from duplicate processing:
     - Multiple 200 OK responses with identical bodies, same resource ID, or idempotency markers (`idempotent: true`) are classified as `CONCURRENCY_CONTROLLED`.
     - Multiple identical responses with no verified mutation proof are classified as `INCONCLUSIVE`, never `CONFIRMED`.
   - Requires verified inconsistent state or failed rollback evidence for distributed partial execution (`PARTIAL_EXECUTION_DESYNC`).
   - Normal contention responses (e.g. HTTP 409 Conflict, HTTP 429 Too Many Requests, optimistic locking rollbacks) are recognized as evidence of proper concurrency control (`CONCURRENCY_CONTROLLED`), NOT vulnerabilities.
   - Transient network errors or timeouts under burst are classified as `INCONCLUSIVE` and never promoted to confirmed findings.
4. **Strict Safety Boundaries & Fail-Closed Transport**:
   - Bounded concurrent bursts: 2–10 parallel worker threads (`MAX_BURST_SIZE = 10`).
   - Hard request budget ceiling: strictly enforced maximum of 15 requests per test (`MAX_REQUESTS_PER_TEST = 15`).
   - Fail-closed scope checks immediately before dispatch in `_send_request_safe()`; in production mode, missing `ScopeEngine`, out-of-scope targets, or scope exceptions refuse dispatch immediately.
   - Mandatory human approval gate (`require_approval`, `--approve`) for all active state mutations.
   - Anti-SSRF enforcement preventing requests to private or loopback IP spaces in production; lab mode explicitly whitelists only ephemeral test ports.
   - Worker timeout and lifecycle handling: explicit tracking of worker thread completion; late-finishing workers are locked out via sealed containers and cannot mutate finalized test state.
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
5. **Anti-SSRF Protection**: RFC 1918, loopback, link-local, carrier-grade NAT, and cloud metadata targets are blocked in production. Lab simulation explicitly whitelists only the ephemeral lab port.
6. **Deterministic Offline Lab**: `LocalConcurrencyLab` provides 8 deterministic scenarios covering vulnerable and safe controls.
7. **No Plaintext Secret Persistence**: All state persistence in `state/concurrency.json` is scrubbed and written atomically.
8. **Conservative Evidence Standards**: Findings require verified invariant breach (e.g. limit exceeded, negative balance). Varied response times or status codes alone never constitute a confirmed vulnerability.

---

## 3. Subsystem Architecture

```
framework/concurrency/
├── __init__.py           # Subsystem exports
├── model.py              # RaceCategory, RaceConfidence, Hypothesis, TestResult, ConcurrencyProbePlan, PostStateEvidence
├── policy.py             # ConcurrencySafetyPolicy (bounded concurrency, budgets, timeouts, fail-closed DNS preflight)
├── synchronization.py    # BarrierSynchronizer (threading.Barrier coordinated burst dispatcher, container sealing)
├── invariants.py         # ConcurrencyInvariantEngine (ResourceIdentityTracker, category-specific evaluation)
├── state.py              # ConcurrencyStateManager (manages state/concurrency.json atomically)
├── lab.py                # LocalConcurrencyLab (8 deterministic offline scenarios, HMAC attestation)
└── engine.py             # RaceIntelligenceEngine (orchestration, scope, approval, deduplication, budget contexts)

scripts/
├── bb-race               # Shell CLI wrapper for Linux/macOS
└── bb-race.cmd           # Windows batch CLI wrapper
```

---

## 4. Local Lab Scenarios (8 Scenarios)

1. `COUPON_DOUBLE_SPEND`: Check-then-act coupon redemption without locking. Vulnerable to concurrent double redemption (`DOUBLE_SPEND`).
2. `BALANCE_TRANSFER_OVERDRAW`: Asynchronous transfer without balance reservation. Vulnerable to negative balance (`TOCTOU`).
3. `VOTING_LIMIT_OVERRUN`: Simultaneous voting requests bypass daily limit (`LIMIT_OVERRUN`).
4. `IDEMPOTENCY_KEY_CACHE_RACE`: Simultaneous duplicate order submission before idempotency key cache write (`IDEMPOTENCY_BYPASS`).
5. `MUTEX_PROTECTED_SAFE`: Properly locked endpoint returning HTTP 409 Conflict for concurrent requests (`CONCURRENCY_CONTROLLED`, safe).
6. `WAF_RATE_LIMIT_SAFE`: Properly rate-limited endpoint returning HTTP 429 (`CONCURRENCY_CONTROLLED`, safe).
7. `INCONCLUSIVE_TIMEOUT`: Server times out under load without state modification (`INCONCLUSIVE`, not a vulnerability).
8. `DISTRIBUTED_PARTIAL_ROLLBACK`: Two-step transaction where step 2 fails and leaves step 1 uncompensated (`PARTIAL_EXECUTION_DESYNC`).

---

## 5. Blocker A: Genuine Evidence-Provenance Trust Boundary & Full Envelope Authentication

### Defect Addressed
`PostStateEvidence.from_dict()` previously accepted a caller-provided `source` label, allowing untrusted callers or deserialized dictionaries to self-attest as authoritative evidence (`LAB_FIXTURE_AUTHORITATIVE`). Furthermore, arbitrary caller state could previously be signed via public helper methods, and signatures previously covered only a subset of fields, risking post-attestation tampering.

### Implemented Hardening
1. **Elimination of Caller Evidence Forgery & Observation Lifecycle (Finding A)**:
   - Completely deleted any public trusted evidence factory (such as `create_authoritative_evidence()`) that accepted arbitrary caller-supplied dictionaries.
   - Authoritative evidence can **only** be issued through genuine observations from an active `LocalConcurrencyLab` instance bound to its live server state and validated port.
   - Implemented strict observation lifecycle:
     - Each execution generates an execution-bound unique observation ID (`obs-{hypothesis_id}-{uuid}`), guaranteeing cross-run isolation and preventing baseline collisions across concurrent or sequential runs.
     - `start_observation(obs_id)` captures a fresh pre-state baseline directly from the server. Duplicate active IDs are rejected safely with `ValueError`.
     - `complete_observation(obs_id)` extracts live post-state, calculates deltas against the baseline, packages the envelope, signs the HMAC token, and pops the observation atomically.
     - `discard_observation(obs_id)` idempotently removes active observations without producing authoritative evidence.
     - Execution engine uses a `try...finally` block guaranteeing that every started observation reaches exactly one safe terminal outcome (Completed, Discarded, or Failed-Closed) with zero state leakage on exceptions, worker timeouts, or externally supplied caller evidence.
2. **Full-Envelope Cryptographic Attestation (Finding B)**:
   - Defined `EvidenceEnvelope` (version `concurrency-evidence-v1`) binding every decision-relevant field:
     - `schema_version`
     - `observation_id`
     - `source`
     - `endpoint`
     - `verified_at`
     - `pre_state`
     - `post_state`
     - `delta_metrics`
     - `provenance_details`
   - Deterministic canonical serialization via `canonical_serialize_envelope()` enforces recursive lexicographical key sorting, strict primitive type verification, and deterministic JSON separators.
   - Signed with HMAC-SHA256 using the process-private 256-bit key `_LAB_TRUST_KEY`.
   - Post-attestation modification of any field or nested structure (such as altering counter values or inserting keys) causes immediate HMAC verification failure (`is_authoritative() == False`).
   - Attestation verifies that the endpoint points to an active lab server on `127.0.0.1` or `localhost`.
3. **Untrusted Deserialization Boundary**:
   - `PostStateEvidence.from_dict(data)` enforces a strict trust boundary: all deserialized external or state dictionaries are assigned `EvidenceSource.UNTRUSTED_CALLER_CLAIM` and stripped of attestation.
   - Deserialization cannot silently elevate untrusted data into authoritative evidence.
4. **Honest Representation of State Query Boundaries**:
   - `EvidenceSource.INDEPENDENT_STATE_QUERY` is recognized as unauthenticated in the current architecture (as no real secondary database integration exists), and `is_authoritative()` returns `False`.
5. **Field Validation & Consistency Constraints**:
   - Required fields, dictionary types, non-negative numbers, and monotonic increment directions are strictly validated. Contradictory evidence fails closed to `INCONCLUSIVE`.
6. **Concurrent Observation Attribution, Overlap Guard & Measurement Lock Exception Safety**:
   - Serialized measurement windows via `_measurement_lock` (`threading.RLock`) in `LocalConcurrencyLab` and `RaceIntelligenceEngine.execute_hypothesis()` serialize observation measurement critical sections across executions, while strictly preserving full barrier-synchronized parallel worker execution (`threading.Barrier`) within each burst.
   - Exception-Safe Lifecycle: Restructured execution lifecycle with nested `try...finally` guards enclosing observation start, synchronized burst dispatch, authoritative post-state collection, and formal invariant evaluation. If any step raises an exception, uncompleted observations are discarded and the measurement lock is guaranteed to be released without leaking active state.
   - Failed Lock Acquisition: If `acquire_measurement_lock(timeout=15.0)` returns `False`, execution aborts immediately; zero burst requests are dispatched, no observation is started, and a safe, clearly diagnosed `INCONCLUSIVE` result (`FindingLifecycle.OBSERVED`, severity `"INFORMATIONAL"`) is returned without bypassing measurement isolation.
   - Ownership-Safe Release: `LocalConcurrencyLab.release_measurement_lock()` releases the underlying `RLock` directly without swallowing lock-ownership defects (`RuntimeError` is preserved if release is attempted on an unowned lock). `RaceIntelligenceEngine` cleanup preserves any in-flight original exception while releasing the lock, allowing subsequent executions to acquire the lock immediately.
   - Overlap Detection: `LocalConcurrencyLab.start_observation()` detects any concurrently active observations (`len(_active_observations) > 0`) and marks all overlapping observations with `has_overlap = True`.
   - Full Envelope Binding: `has_overlap` is bound directly into `EvidenceEnvelope`, `PostStateEvidence`, and canonical serialization (`canonical_serialize_envelope()`). Post-attestation modification of `has_overlap` immediately invalidates the HMAC signature.
   - Invariant Engine Fail-Closed: If `post_state_evidence.has_overlap == True`, `ConcurrencyInvariantEngine.evaluate_burst_results()` logs that measurement windows overlapped on shared mutable state and immediately fails closed to `RaceConfidence.INCONCLUSIVE` (`is_vulnerable = False`, `FindingLifecycle.OBSERVED`), preventing false positive overrun findings when observations overlap on shared mutable state.

---

## 6. Blocker B: Invariant Accuracy, Counter Baselines & Category-Specific Requirements

### Defect Addressed
Distinct resource IDs returned in HTTP responses (e.g. `order_id: ORD-1` and `order_id: ORD-2`) do not prove that corresponding business operations committed on the server. Furthermore, evaluating absolute cumulative counters without establishing a pre-test baseline risks misclassifying pre-existing state as a race condition overrun.

### Implemented Hardening
1. **Response Observations vs. Committed Business State**:
   - Distinct response identifiers without authoritative server-side state verification are classified strictly as `SUSPECTED` (`FindingLifecycle.OBSERVED`, severity `"INFORMATIONAL"`), **never** `CONFIRMED`.
   - Downstream finding creation strictly requires `CONFIRMED` confidence to publish validated vulnerability findings.
2. **Mandatory Pre-State Baselines & Delta Evaluation (Finding C)**:
   - For state-based counter invariants (`LIMIT_OVERRUN`, `DOUBLE_SPEND`, `IDEMPOTENCY_BYPASS`), the invariant engine requires a trusted pre-state baseline (`pre_state`) and computes the exact per-test delta: $\Delta = \text{post} - \text{pre}$.
   - If an absolute counter is observed without a trusted pre-state baseline, the engine records an `unbaselined_counter_observation` and notes that delta cannot be inferred. The test fails safely to `SUSPECTED` or `INCONCLUSIVE`, **never** `CONFIRMED`.
   - Inconsistent counter progression ($\Delta < 0$ for strictly increasing counters) fails closed immediately to `INCONCLUSIVE`.
3. **Category-Specific Invariant Mappings**:
   - `DOUBLE_SPEND`: Requires authoritative evidence of prohibited duplicate redemption delta ($\Delta_{\text{redemptions}} > \text{allowed\_limit}$).
   - `LIMIT_OVERRUN`: Requires authoritative counter overrun delta ($\Delta_{\text{votes}} > \text{allowed\_limit}$).
   - `TOCTOU`: Requires negative balance overdraw (`account_balance < 0`) or transfer overrun.
   - `IDEMPOTENCY_BYPASS`: Requires duplicate committed order records delta ($\Delta_{\text{orders}} > \text{allowed\_limit}$).
   - `PARTIAL_EXECUTION_DESYNC`: Requires verified inconsistent state (`inconsistent_state == True` or uncompensated rollback).

---

## 7. Blocker C: Worker Lifecycle, Monotonic Deadlines & Sealed Containers

### Defect Addressed
Uncoordinated worker joins risked linear timeout accumulation ($N \times \text{timeout}$), and background threads completing after test completion could corrupt state.

### Implemented Hardening
1. **Single Monotonic Deadline**:
   - `BarrierSynchronizer.execute_burst()` computes a single overall deadline: `deadline = time.monotonic() + self.timeout + 1.0`. All worker thread joins share this deadline.
2. **Worker Lifecycle States**:
   - Explicit lifecycle tracking: `COMPLETED`, `FAILED`, `TIMED_OUT_UNRESOLVED`, and `CANCELLED`.
   - In-flight requests exceeding the timeout are classified as `TIMED_OUT_UNRESOLVED`.
   - Unresolved timeouts fail closed to `INCONCLUSIVE`.
3. **Container Sealing**:
   - `BurstExecutionContainer.seal()` permanently locks test containers upon join completion, locking out late-finishing background threads from mutating finalized results.
4. **Documented Transport Limitation**:
   - Standard Python threads and socket transports cannot be forcibly cancelled; remote servers may continue processing late requests, and this uncertainty is preserved.

---

## 8. Blocker D: Request Budget Ownership & Dispatch Accounting

### Defect Addressed
Global or engine-level request counters allowed concurrent or sequential test executions to bleed into or starve one another's request allocations.

### Implemented Hardening
1. **`HypothesisBudgetContext`**:
   - Thread-safe, isolated request counter bound to each specific hypothesis execution.
   - Clamped strictly to `min(max_requests, MAX_REQUESTS_PER_TEST = 15)`.
2. **Isolation Guarantee**:
   - Parallel or subsequent hypothesis evaluations instantiate independent contexts.
   - Scope checks and safety validations occur before budget acquisition, ensuring invalid targets do not consume budget slots.
   - Standalone requests use an isolated `engine-default` context.

---

## 9. Blocker E: Fail-Closed DNS Resolution & Destination Validation

### Defect Addressed
`resolve_hostname()` previously returned empty list on DNS errors, allowing requests to proceed without validation in production mode.

### Implemented Hardening
1. **Fail-Closed Resolution**:
   - In production mode, DNS resolution errors (e.g. `socket.gaierror`) or empty resolution results immediately fail closed with `PolicyViolationError`.
   - Malformed or invalid resolved IP strings fail closed with `PolicyViolationError`.
2. **Comprehensive Address Validation**:
   - EVERY address in the resolution result is validated (not just the first). Mixed public and private results fail closed.
   - Evaluates private RFC 1918, loopbacks (`127.0.0.0/8`, `::1`), link-local/cloud metadata (`169.254.0.0/16`), carrier-grade NAT (`100.64.0.0/10`), test networks, and IPv6 equivalents (`fc00::/7`, `fe80::/10`).
   - IPv4-mapped IPv6 representations (`::ffff:127.0.0.1`, `::ffff:169.254.169.254`, `::ffff:10.0.0.1`, `::ffff:100.64.1.1`) are detected and blocked.
3. **Pluggable Resolver Hook**:
   - Unit tests use a mock resolver hook, avoiding external network traffic.
4. **Documented DNS Rebinding Limitation**:
   - Standard Python `http.client` / `urllib.request` sockets re-resolve hostnames upon transport connection without destination IP pinning. In high-risk target environments, concurrency probes should route through an egress-validating proxy (e.g. Phase 16's `ValidatingEgressProxy`) or an isolated network namespace (`ip netns`).

---

## 10. Verification & Test Plan

1. **Focused Test Suite (`tests/test_concurrency_engine.py`)**:
   - **128 comprehensive tests** covering:
     - Blocker A & Critical Finding A: Elimination of caller-forged trusted evidence factories; genuine observation lifecycle bound to live server state; unique execution identity and cross-run isolation.
     - Blocker A & Critical Finding B: Full-envelope HMAC-SHA256 attestation (`EvidenceEnvelope`, `concurrency-evidence-v1`), canonical deterministic serialization, and tamper resistance across all 9 fields, `has_overlap` flag, and nested dictionaries.
     - Blocker B & Critical Finding C: Invariant evaluation requiring trusted pre-state baselines and per-test counter deltas; safe fallback on unbaselined counters; monotonic progression checks.
     - Observation Lifecycle & Isolation: Zero active observation leakage on externally supplied evidence, dispatch exceptions, or timeouts; duplicate active ID rejection; execution isolation; serialized observation measurement windows; fail-closed `has_overlap` attribution guards on overlapping observations; exception-safe measurement lock cleanup on observation creation failures, failed acquisitions, dispatch exceptions, missing post-state, and invariant evaluation crashes.
     - Primary Exception Preservation & Deterministic Cleanup Exception Precedence: Explicit `primary_exc` capture during hypothesis dispatch and invariant evaluation ensures in-flight primary exceptions are never masked by cleanup failures. Two-stage cleanup handles observation inspection and discard (Stage 1) and measurement lock release (Stage 2) sequentially; lock release is always attempted even if inspection or discard fails. Observation-state inspection (`is_observation_active()`) is safely enclosed within Stage 1 exception handlers, treating inspection errors as cleanup failures and attempting safe discard rather than assuming inactivity or bypassing lock release. When a primary exception is propagating, secondary cleanup failures from inspection, discard, and lock release are attached as diagnostic exception notes (`add_note` / `__notes__`) and structured objects without altering the primary exception type or message. When no primary exception occurs, cleanup failures are never swallowed and propagate directly; when inspection, discard, and lock-release stages fail, all diagnostic information is preserved through explicit chaining (`__context__` and `__cause__`).
     - Structured Cleanup Diagnostic Safety & Failure Isolation: Removal of raw exception objects, tracebacks, and chained exceptions from `primary.__cleanup_failures__`. Replaced them with minimal structured records containing strictly primitive string fields (`stage`, `exception_type`, and length-bounded `diagnostic` sanitized via `sanitize_sensitive_data()`), preventing sensitive-data exposure while keeping cleanup failures individually diagnosable. Wrapped diagnostic generation and formatting in fail-safe fallback guards; string conversion (`__str__`) or sanitizer crashes fall back to the exception type name without leaking unsanitized error messages or masking primary execution exceptions.
     - Blocker B: Category-specific counter mappings, distinct provisional ID handling, and authoritative post-state requirements.
     - Blocker C: Monotonic deadline bounding, worker lifecycle states, and container sealing.
     - Blocker D: Thread-safe per-hypothesis budget contexts and hard ceiling clamping.
     - Blocker E: Fail-closed DNS errors, empty results, malformed IPs, mixed resolution, IPv6 and IPv4-mapped IPv6 address blocks.
     - All 8 local simulation lab scenarios with multithreaded concurrent requests.
     - Secret scrubbing and Phase 19 sentinel report inspection.
2. **Diagnostic Health**:
   - `bb-doctor` Category 25 (`check_concurrency_engine`) reports `[HEALTHY]` (all 17 framework engines healthy).
3. **Cross-Platform Parity**:
   - Verified on Windows 11 (128/128 concurrency tests, 175/175 total test discovery suite).
   - Verified on Kali Linux VM (`ssh veldora@127.0.0.1 -p 2222`).

---

## 11. Operational Boundaries & Non-Goals

1. **No Volumetric Flooding**: Mass denial-of-service, traffic amplification, and uncoordinated stress testing remain strictly prohibited.
2. **Single Orchestrator Invariant**: Phase 20 introduces zero additional agents or skills (`subagent_depth: 1`, 18 modular skills).
3. **No Phase 21 Work**: Phase 21 (Authentication & Authorization Correlation) remains strictly out of scope for Phase 20.
