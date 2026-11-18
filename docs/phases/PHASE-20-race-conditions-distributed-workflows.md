# Phase 20 — Race Conditions and Distributed Workflows

**Status:** Implemented for bounded concurrency hypotheses and local simulation; live race tests still need target-specific safety and timing review.
**Implementation:** **framework/concurrency/**, **scripts/bb-race**, workflow models in **framework/business_logic/**, and the **business-logic skill**
**State file:** **state/concurrency.json**.

## What a race condition means

A race condition happens when two or more requests overlap and the application’s final state depends on which request it processes first. A classic example is two simultaneous requests trying to use a one-time benefit. If the application checks the rule before updating state, both requests might succeed. Distributed workflows can have the same problem across multiple services or workers.

A race test is more sensitive than an ordinary read. The requests are synchronized or sent close together, and the resulting application state may change. Phase 20 is designed for small, controlled bursts and invariant checks, not load testing.

## How the phase works

The engine uses modeled workflow hypotheses and a low-volume synchronization policy. The default burst size is four concurrent probes and the accepted range is two through ten. Each probe has a timeout, and live execution requires explicit approval and current scope. A local concurrency lab provides deterministic tests for race outcomes without contacting a bounty target. Results record whether they were simulated, observed, or validated and preserve the timing context needed for review.

The command uses the program’s existing concurrency hypotheses; it is not an endpoint scanner. Prepare and review a specific invariant in the earlier workflow phase before asking Phase 20 to test it.

## How to use it

~~~bash
# Preview candidates without dispatching concurrent requests.
bb-race --program <program-name> --dry-run --tree

# Exercise the deterministic local concurrency lab.
bb-race --program <program-name> --lab --tree

# Review a very small approved burst for a safe, disposable workflow.
bb-race --program <program-name> --approve --burst 2 --timeout 5 --json
~~~

Do not use a live payment, inventory, account, or subscription flow unless the program explicitly permits it and supplies a disposable, recoverable test workflow.

## Reading the result

A successful pair of requests is not itself a race vulnerability. Evidence should show the invariant, the starting state, the overlap, the final state, and whether both operations were accepted. Repeat only if permitted and necessary; concurrent retries can compound state changes.

A finding should describe the smallest impact demonstrated and preserve the timing evidence. If the test was performed in the local lab, label it simulated and do not present it as a production result.

## Safety and limitations

Never flood a service, use a large burst, or repeat a transaction to improve confidence. Race outcomes are sensitive to host load, scheduling, queues, and network latency; fixture timing can be flaky under heavy test-suite load. Cancellation controls, target-specific caps, and safe rollback support remain future work.

Tests: **tests/test_concurrency_engine.py** and the deterministic race cases in **tests/test_e2e_local_workflow.py**. See [Phase 12](PHASE-12-business-logic-intelligence.md), [workflow guide](../workflow.md), and [roadmap](../ROADMAP-24-PHASES.md).