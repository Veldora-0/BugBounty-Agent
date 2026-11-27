# Phase 12 — Business Logic Intelligence

**Status:** Workflow modeling and invariant checks are implemented; active tests may submit state-changing requests and are not safe to run against a real transaction flow without a program-approved canary and explicit review.
**Implementation:** **framework/business_logic/**, **scripts/bb-workflow**, and the **business-logic skill**
**State file:** **state/workflows.json**.

## What business-logic testing means

Business logic is the set of rules that defines how an application’s workflow is supposed to behave. A purchase may require a valid cart before checkout. A discount might be allowed once. A user may need to complete an earlier step before a later step. A logic flaw exists when the server lets an actor break one of these rules in a way that causes a security or financial impact.

These problems are different from a malformed input bug: each request may be syntactically valid, while the order or combination of requests is wrong. Phase 12 models steps, actors, states, and invariants, then proposes tests such as skipping a required step or submitting an invalid quantity.

## How the phase works

The engine stores workflow steps and expected invariants and proposes candidate weaknesses. The CLI can inspect that state, build a dry-run plan, or run deterministic local lab scenarios. **Production request dispatch is not implemented in the current CLI.** The engine refuses to invent simulated HTTP responses when no dispatcher is supplied, and `--approve` without `--lab` now exits with a clear message before any request. The shared request policy is not yet integrated into a production workflow dispatcher, so the CLI's request/concurrency flags do not provide production dispatch controls.

This phase has an important live-use limitation: approval and a request cap do not guarantee rollback. A request involving a real purchase, balance, subscription, account setting, or persistent record can create real state changes if the target accepts it. Do not run such a case on a live program unless the program specifically permits the test and provides a disposable canary workflow with a safe rollback plan. If a harmless proof is not possible, keep the case as a hypothesis.

## How to run it

~~~bash
# Inspect modeled workflows without network requests.
bb-workflow --program <program-name> --passive-only --tree

# Review proposed invariants for a specific application.
bb-workflow --program <program-name> --application app.example.org --dry-run --json

# Run the deterministic local lab.
bb-workflow --program <program-name> --lab --json

# The current CLI does not send production business-logic requests.
# --approve without --lab is rejected before any request.
bb-workflow --program <program-name> --approve --json
~~~

The endpoint option is a filter for a known workflow step. `--approve` is an operator gate for the local lab only; it is not permission from a bounty program. Keep live business-logic hypotheses as reviewed plans until a dedicated safe dispatcher supports a researcher-owned canary, transaction-specific limits, and rollback evidence.

## Reading the result

An invariant is a rule the workflow should always maintain, such as “checkout cannot complete before payment authorization.” The engine compares the baseline and test result and records the evidence, actor, violated rule, and lifecycle. A simulated result means the local lab behaved as expected; it says nothing about a production target. An observed difference can also be caused by normal application rules or a failed session.

A report should explain the intended rule, the actor’s starting privileges, the exact sequence, the observed state change, and the safely demonstrated impact. Do not infer monetary impact from an accepted unusual quantity if no transaction completed or if the value was not actually charged.

## Safety and limitations

Never create real financial loss, change customer data, cause repeated charges, or race a high-volume workflow. The current tests validate logic in local fixtures; they do not supply general rollback support for arbitrary targets. Safer cancellation, target-specific caps, and operator-defined transaction invariants remain future work.

Tests: **tests/test_business_logic_engine.py**. See the [scope guide](../scope.md), [workflow guide](../workflow.md), and [roadmap](../ROADMAP-24-PHASES.md).
