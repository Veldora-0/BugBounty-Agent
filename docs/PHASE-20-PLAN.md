# BugBounty-Agent — Phase 20 Implementation Plan
## Race Conditions & Distributed Workflows Intelligence

**Accepted Baseline**: `9bc923677f5d662f42b1c3a45105989179ec3617`  
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

## 5. Blocker A: Genuine Evidence-Provenance Trust Boundary

### Defect Addressed
`PostStateEvidence.from_dict()` previously accepted a caller-provided `source` label, allowing untrusted callers or deserialized dictionaries to self-attest as authoritative evidence (`LAB_FIXTURE_AUTHORITATIVE`).

### Implemented Hardening
1. **Cryptographic Attestation Token**:
   - `LocalConcurrencyLab` holds a process-private 256-bit secret key (`_LAB_TRUST_KEY = secrets.token_bytes(32)`) generated in memory on process start.
   - Evidence produced through `LocalConcurrencyLab.get_authoritative_state()` or `create_authoritative_evidence()` carries an HMAC-SHA256 signature (`_attestation_token`) verifying its origin.
   - `PostStateEvidence.is_authoritative()` validates this attestation via `LocalConcurrencyLab.verify_attestation(self)`.
2. **Untrusted Deserialization**:
   - `PostStateEvidence.from_dict(data)` enforces a strict trust boundary: all deserialized external or state dictionaries are assigned `EvidenceSource.UNTRUSTED_CALLER_CLAIM` and stripped of attestation.
   - Deserialization cannot silently elevate untrusted data into authoritative evidence.
3. **Honest Representation of State Query Boundaries**:
   - `EvidenceSource.INDEPENDENT_STATE_QUERY` is recognized as unauthenticated in the current architecture (as no real secondary database integration exists), and `is_authoritative()` returns `False`.
4. **Field Validation & Consistency Constraints**:
   - Required fields, dictionary types, non-negative numbers, and monotonic increment directions are strictly validated. Contradictory evidence fails closed to `INCONCLUSIVE`.

---

## 6. Blocker B: Invariant Accuracy & Category-Specific Evidence Requirements

### Defect Addressed
Distinct resource IDs returned in HTTP responses (e.g. `order_id: ORD-1` and `order_id: ORD-2`) do not prove that corresponding business operations committed on the server.

### Implemented Hardening
1. **Response Observations vs. Committed Business State**:
   - Distinct response identifiers without authoritative server-side state verification are classified strictly as `SUSPECTED` (`FindingLifecycle.OBSERVED`, severity `"INFORMATIONAL"`), **never** `CONFIRMED`.
   - Downstream finding creation strictly requires `CONFIRMED` confidence to publish validated vulnerability findings.
2. **Category-Specific Invariant Mappings**:
   - `DOUBLE_SPEND`: Requires authoritative evidence of prohibited duplicate redemption (`coupon_redemptions > allowed_limit`).
   - `LIMIT_OVERRUN`: Requires authoritative counter overrun (`voting_count > allowed_limit`).
   - `TOCTOU`: Requires negative balance overdraw (`account_balance < 0`) or transfer overrun.
   - `IDEMPOTENCY_BYPASS`: Requires duplicate committed order records (`order_count > allowed_limit`).
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
   - **73 comprehensive tests** covering:
     - Blocker A: HMAC attestation, deserialized untrusted forcing, independent state query unauthenticated handling, and consistency checks.
     - Blocker B: Category-specific counter mappings, distinct provisional ID handling, and authoritative post-state requirements.
     - Blocker C: Monotonic deadline bounding, worker lifecycle states, and container sealing.
     - Blocker D: Thread-safe per-hypothesis budget contexts and hard ceiling clamping.
     - Blocker E: Fail-closed DNS errors, empty results, malformed IPs, mixed resolution, IPv6 and IPv4-mapped IPv6 address blocks.
     - All 8 local simulation lab scenarios.
     - Secret scrubbing and Phase 19 sentinel report inspection.
2. **Diagnostic Health**:
   - `bb-doctor` Category 25 (`check_concurrency_engine`) reports `[HEALTHY]`.
3. **Cross-Platform Parity**:
   - Verified on Windows 11 (73/73 concurrency tests, 120/120 total test discovery suite).
   - Verified on Kali Linux VM (`ssh veldora@127.0.0.1 -p 2222`).

---

## 11. Operational Boundaries & Non-Goals

1. **No Volumetric Flooding**: Mass denial-of-service, traffic amplification, and uncoordinated stress testing remain strictly prohibited.
2. **Single Orchestrator Invariant**: Phase 20 introduces zero additional agents or skills (`subagent_depth: 1`, 18 modular skills).
3. **No Phase 21 Work**: Phase 21 (Authentication & Authorization Correlation) remains strictly out of scope for Phase 20.
