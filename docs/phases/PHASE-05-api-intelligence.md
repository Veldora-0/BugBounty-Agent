# Phase 5 — API Intelligence

**Status:** Implemented with documented limits
**Implementation:** framework/api/, skills/api-security/, scripts/bb-api

## Purpose and bounty value
Parse OpenAPI/Swagger and GraphQL descriptions; map endpoints and parameters. Active probing is opt-in, scope checked, bounded, and uses transport budgets. The goal is to produce actionable, reproducible evidence for a vulnerability on an explicitly authorized program, not to maximize scan volume. A researcher must confirm program authorization and scope before any network activity.

## Workflow and expected outputs
1. Load the program workspace and validate the target against its scope configuration before network access.
2. Reuse existing asset, endpoint, identity and finding records; formulate a specific hypothesis with a reason to test it.
3. Apply the phase capability with its documented request, time, response-size and safety limits. Stop when evidence is sufficient or a boundary is uncertain.
4. Store redacted evidence and provenance locally, validate the result, deduplicate by root cause, and prepare a human-reviewed report. Do not submit automatically.

Expected outputs are phase-specific observations/hypotheses, state updates, and where confirmed, a finding with reproducible steps and minimal supporting evidence. Runtime targets, credentials, captures and reports belong in the local workspace and must not be committed.

## Safety and scope gates
- Explicit program authorization and the current scope rules are prerequisites; exclusions take precedence.
- Prefer passive analysis. Active checks must be bounded, non-destructive, and use the approved transport and human approval gates required by the engine.
- Do not access unrelated user data, cause service disruption, brute-force credentials, or perform financial/state-changing actions outside an explicitly safe approved workflow.
- Preserve redaction, local-only evidence storage, and honest separation of simulated, observed, and confirmed results.

## Acceptance criteria
- Unit and integration coverage exercises normal, boundary, failure, and out-of-scope behavior on supported platforms.
- The engine fails closed on missing scope, invalid configuration, exceeded budgets, unsafe destinations, or unavailable trust dependencies.
- Results link to reproducible evidence and state their confidence, limitations, and whether they came from simulation or a live authorized test.
- Documentation, CLI/skill integration, and current verification evidence agree. A passing mock suite alone does not establish live-target effectiveness.

## Remaining work and limitations
Broaden schema compatibility and improve authenticated API inventory using operator-supplied test credentials. See [the consolidated project issue register](../PROJECT-AUDIT-ISSUES.md) for known blockers and [future improvements](../FUTURE-IMPROVEMENTS.md) for later work. Phase acceptance reflects repository evidence and does not imply authorization to test any target.

## Source references
Relevant tests: test_api_engine.py. See [the project handbook](../PROJECT-HANDBOOK.md), and [the 24-phase roadmap](../ROADMAP-24-PHASES.md).
