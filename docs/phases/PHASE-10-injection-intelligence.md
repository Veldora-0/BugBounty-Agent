# Phase 10 — Injection Intelligence

**Status:** Implemented for bounded candidate testing; timing checks are opt-in and results require human confirmation.
**Implementation:** **framework/injection/**, **scripts/bb-inject**, and the **injection skill**
**State file:** **state/injection.json** in the local program workspace.

## What injection means

Injection happens when an application treats user-controlled input as part of a command or query instead of as ordinary data. Examples include database queries (SQL or NoSQL), template rendering (SSTI), and operating-system commands. The same input can be safe in one context and dangerous in another, so the phase starts from a particular endpoint and parameter rather than spraying every field.

Phase 10 uses small, non-destructive comparisons to look for a signal that input is being interpreted. A harmless arithmetic marker might produce a different response if a template evaluates it. A timing differential can be a clue when a response is consistently delayed under a carefully controlled condition. Neither signal alone proves exploitable impact: network jitter, caching, rate limiting, or application logic can produce similar effects.

## How the phase works

The engine reads candidate parameters from local API and web state, assigns a priority, and constructs cases for SQL, NoSQL, template, and command-injection hypotheses. Each case is checked against the configured scope, and active requests are bounded by test count, request count, timeout, and response-byte ceiling. A case fingerprint allows the engine to skip previous attempts. Timing analysis is disabled unless explicitly selected. Active execution requires the operator’s approval flag; passive-only and dry-run modes are available for planning.

The engine stores results in **injection.json**. Review the baseline and test response together, including status, body differences, and timing data. The system should not extract database contents, read files, run shell commands, or perform destructive actions to prove an issue.

## How to use it

~~~bash
# Rank candidate parameters without sending probes.
bb-inject --program <program-name> --passive-only --tree

# Prepare a safe plan for one endpoint and one parameter.
bb-inject --program <program-name> --endpoint https://app.example.org/search --param q --dry-run --json

# Review the human dossier before a narrow active test.
bb-inject --program <program-name> --endpoint https://app.example.org/search --param q --dossier --json

# Execute only when program rules permit it and the exact test has been reviewed.
bb-inject --program <program-name> --endpoint https://app.example.org/search --param q --approve --max-tests 1 --max-requests 2 --json
~~~

Timing tests and lab mode have separate options; use them only in the intended controlled context. Check **bb-inject --help** before choosing a validator or enabling timing comparisons.

## What counts as evidence

A candidate becomes convincing when the control and test requests differ in a way that is repeatable and explained by the suspected interpreter, while ordinary network variation and application behavior have been ruled out. A reflected input is not automatically SQL injection; a delay is not automatically command execution; a template marker being echoed as text is not template evaluation.

State the exact endpoint, parameter, baseline, harmless test, observed difference, and remaining uncertainty. If the only evidence is a static guess or a one-time delay, report it as a hypothesis and do not claim a confirmed vulnerability.

## Safety and limitations

Do not retrieve records, invoke operating-system commands, create persistent server-side data, or probe an endpoint outside current authorization. The limits are ceilings, not a recommendation to use every allowed request. The validator set is finite and cannot cover every database, encoding, framework, or application-specific parser. Static candidate ranking can miss relevant inputs or prioritize harmless ones.

Tests in **tests/test_injection_engine.py** validate bounded logic with fixtures; they do not prove exploitability on a live service. See the [validation guide](PHASE-06-security-validation-foundation.md), [scope guide](../scope.md), and [roadmap](../ROADMAP-24-PHASES.md).