---
name: business-logic
description: Business logic analysis, multi-step workflow integrity, state transition abuse, race conditions, and trust boundary evaluation.
---

# Business Logic Security Methodology

## Core Objective
Identify flaws in application workflows, business rules, and state machine assumptions that automated scanners cannot detect. Evaluate how the application enforces sequence integrity, quantitative consistency, and trust boundaries.

## 1. Investigation Vectors

### Workflow Sequence Abuse
* **Step Skipping**: Attempt to skip mandatory steps in multi-step workflows (e.g. going directly from cart to order confirmation without payment).
* **Forced State Transitions**: Transitioning resources into invalid states (e.g. cancelling an order after fulfillment, or approving a request before review).
* **Workflow Resumption**: Resuming an expired transaction or checkout session after price adjustments.

### Quantitative & Numeric Manipulation
* **Negative Quantities**: Input negative numbers in item counts, cart quantities, or financial deductions to generate credits.
* **Integer Overflows & Truncation**: Test large integer values or extreme decimal precisions.
* **Currency / Unit Confusion**: Submit mismatched currency codes or unit descriptors in financial transactions.

### Concurrency & Race Conditions
* **Double-Spend & Multi-Redemption**: Send rapid parallel requests to redeem coupons, promo codes, gift cards, or reward points before the database lock persists.
* **Limit Bypass**: Parallel requests against daily withdrawal, transfer, or voting limits.
* **Race Windows**: Identify asynchronous gaps between balance verification and transaction commitment.

### Trust Boundary Discrepancies
* **Client-Calculated Values**: Submitting modified price, discount, or tax values calculated on the client side.
* **Parameter Tampering**: Modifying hidden form fields (`tier=free`, `discount_rate=1.0`).
* **Header Assumptions**: Relying on unverified client headers (`X-Forwarded-For`, `X-User-Role`) for logic decisions.

## 2. Ethical Safeguards & Approval Gates
* **Zero Real Financial Harm**: Never execute transactions with real victim funds or third-party payment gateways.
* **Mock / Sandbox First**: Conduct logic tests strictly in development, sandbox, or staging environments when available.
* **Mandatory Human Approval Gate**: `bb-workflow` requires explicit human approval (`--approve`) with a pre-test audit dossier before mutating multi-step resources or executing bounded concurrent race simulations.
* **Local In-Memory Lab**: 15 deterministic scenarios in `LocalBusinessLogicLab` allow comprehensive verification without any network traffic.

## 3. Evidence Documentation & Invariants
* Document the complete sequence of requests in order with sanitized payloads and SHA-256 evidence digests.
* Highlight the logical inconsistency between expected business rules and actual observed state via `BusinessLogicInvariantEngine` and `ConcurrencyInvariantEngine`.
* Concurrency invariant verification requires verifiable proof of business-state mutation (distinct committed resource IDs, verified post-state counters, balance overdraw) or verified inconsistent state for distributed workflows before classifying findings as `CONFIRMED`.
* Idempotent duplicate responses returning cached representations are classified as `CONCURRENCY_CONTROLLED`; identical responses without mutation proof are marked `INCONCLUSIVE`.
* All active probe dispatches fail closed if out of scope or if `ScopeEngine` is missing in production. Request budgets are strictly enforced at a maximum of 15 requests per test case.
* Support single replay, sequence replay, and bounded concurrent replay (maximum 10 threads/requests).

## 4. CLI Tools: `bb-workflow` & `bb-race`

### `bb-workflow` — Sequence & State Machine Verification
```bash
# Inspect workflow state tree for a program
bb-workflow --program acme-corp --tree

# Run local in-memory business logic lab scenarios (dry-run)
bb-workflow --lab --tree

# Run and approve test case in the lab
bb-workflow --lab --scenario checkout_step_skipping --approve

# Execute workflow testing for a program with approval
bb-workflow --program acme-corp --workflow checkout --approve
```

### `bb-race` — Precision Barrier-Synchronized Concurrency & Invariant Verification
```bash
# View visual ASCII tree of concurrency hypotheses and findings
bb-race --program acme-corp --tree

# Discover hypotheses from prior recon/webapps/api state (dry-run)
bb-race --program acme-corp --dry-run

# Run active barrier-synchronized micro-burst (2-5 threads, max 10) with operator approval
bb-race --program acme-corp --approve --burst 4

# Run against deterministic 8-scenario local concurrency lab
bb-race --lab --tree
```
