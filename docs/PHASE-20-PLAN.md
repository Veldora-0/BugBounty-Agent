# BugBounty-Agent — Phase 20 Implementation Plan
## Race Conditions & Distributed Workflows Intelligence

**Accepted Baseline**: `7155bac6c109df73950fb28691f1a5f972b216c5`  
**Reference Document**: `docs/ROADMAP-24-PHASES-TEMP.md` (Phase 20)  
**Status**: In Progress — Implementation  
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
3. **Rigorous Invariant Evaluation**:
   - Distinguishes **Confirmed Invariant Violations** (`INVARIANT_VIOLATED`) from **Valid Contention** (`CONCURRENCY_CONTROLLED`) and **Inconclusive Outcomes** (`INCONCLUSIVE`).
   - Normal contention responses (e.g. HTTP 409 Conflict, HTTP 429 Too Many Requests, optimistic locking rollbacks, 1 success + 4 failures) are recognized as evidence of proper concurrency control, NOT vulnerabilities.
   - Transient network errors or timeouts under burst are classified as `INCONCLUSIVE` and never promoted to confirmed findings.
4. **Strict Safety Boundaries**:
   - Strictly bounded requests: default 3–5 concurrent threads; maximum 10 requests per test case.
   - Offline `ScopeEngine` validation before any network probe.
   - Mandatory human approval gate (`require_approval`, `--approve`) for all active state mutations.
   - Anti-SSRF enforcement preventing requests to private or loopback IP spaces in production.
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
├── policy.py             # ConcurrencySafetyPolicy (bounded concurrency, budgets, timeouts)
├── synchronization.py    # BarrierSynchronizer (threading.Barrier coordinated burst dispatcher)
├── invariants.py         # ConcurrencyInvariantEngine (evaluates expected vs observed invariants)
├── state.py              # ConcurrencyStateManager (manages state/concurrency.json atomically)
├── lab.py                # LocalConcurrencyLab (8 deterministic offline scenarios)
└── engine.py             # RaceIntelligenceEngine (orchestration, scope, approval, deduplication)

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

## 5. Verification Plan

1. **Focused Test Suite**: `tests/test_concurrency_engine.py` covering all 8 lab scenarios, barrier synchronization, timeout handling, secret scrubbing, and report verification.
2. **Phase 19 Sentinel Report Inspection Test**: Explicitly generates a markdown report from a finding with sanitized exception data and verifies the sentinel secret is absent on disk.
3. **Cross-Platform Verification**:
   - Windows 11 full test suite pass.
   - Kali Linux VM (`ssh veldora@127.0.0.1 -p 2222`) focused and full test suite pass.
4. **Diagnostic Integrity**: `bb-doctor` runs Category 25 and reports `[HEALTHY]`.
