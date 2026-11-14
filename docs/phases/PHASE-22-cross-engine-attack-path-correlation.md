# Phase 22 — Cross-Engine Attack-Path Correlation and Vulnerability Chaining

**Status:** Planned; not implemented as an integrated engine

**Priority outcome:** Starting from a validated bug, identify whether it can be safely combined with other in-scope weaknesses to demonstrate greater real-world impact.
**Implementation foundation:** `framework/findings/`, `framework/assets/`, `framework/auth_correlation/`, and outputs from Phases 1–21.

## Purpose and bounty value

Real bounty impact can depend on a sequence of weaknesses. For example, an exposed low-privilege resource may reveal an identifier that makes a separate authorization flaw exploitable, or a weak access boundary may expose a sensitive workflow. Phase 22 will connect evidence across engines and tell the researcher when a confirmed issue creates a credible path to a more serious outcome.

This capability is **not implemented today**. Existing `framework/findings/` and `tests/test_capability_graph.py` provide foundations, but the repository does not yet contain an integrated, evidence-backed attack-path engine. Phase 22 makes vulnerability chaining a required feature of that planned engine.

## Required researcher workflow

1. Begin with a validated finding or high-confidence observation from an explicitly authorized program. Preserve its evidence, root cause, affected principal, asset, endpoint, and scope provenance.
2. Search existing in-scope assets, endpoints, identities, findings and observations for relationships that could make one weakness enable or amplify another.
3. Build an explainable candidate chain: ordered steps, preconditions, trust-boundary transitions, supporting evidence, missing evidence, likely impact, confidence and safe validation plan.
4. Separate established facts from inferred links. A chain remains a **hypothesis** until every impact-relevant edge is supported by evidence.
5. Recommend the smallest non-destructive follow-up that can prove or reject the chain. Require explicit operator approval before any active request; re-check scope and budgets for every step.
6. If confirmed, produce a report-ready narrative showing the individual vulnerabilities, how they combine, the demonstrated end impact and exact reproduction steps. Keep component finding severities distinct from the chain-level impact assessment.

## Graph and chain model requirements

- Typed nodes for authorized assets, endpoints, principals/sessions, observations, hypotheses, findings, evidence and actions.
- Typed, directional edges such as `reveals`, `enables`, `authenticates_as`, `crosses_tenant_boundary`, `reaches`, and `depends_on`; each edge records source, evidence reference, confidence, timestamp/freshness and whether it is observed, inferred or validated.
- A chain records ordered steps, required privileges, attacker starting position, target impact, assumptions, blocking controls, confidence, scope provenance and validation state.
- Evidence references must resolve to sanitized local evidence; secrets and raw credentials never enter the graph or reports.
- Graph traversal must handle cycles, duplicate root causes, stale observations and uncertain identity/asset joins without manufacturing a path.

## Safety and severity rules

- Every asset and action in a candidate path must remain inside the program's current authorized scope. Exclusions take precedence. A chain cannot use a third-party service, account, tenant or asset that is not explicitly authorized.
- Analysis of existing evidence may be passive. A proposed follow-up is not permission to run it; active validation requires human approval, a narrow hypothesis, safe test identities/canaries, and the existing request/time/byte limits.
- Do not access unrelated user data, extract secrets, bypass payment through real transactions, change or delete customer data, cause denial of service, or execute a destructive payload to prove chain impact.
- Never add severities arithmetically or raise an individual finding solely because a theoretical path exists. Report component severities independently. A higher chain impact may be stated only when the additional privilege or impact is directly demonstrated with authorized, minimal evidence.
- Clearly label simulations, inferred links, unverified steps, and live-confirmed steps. If a safe proof is impossible, retain the path as a hypothesis and state the limitation.

## Acceptance criteria

- Tests demonstrate valid two-or-more-issue chains, rejected false joins, cycles, duplicate roots, stale evidence, missing edges, cross-tenant identity mismatches, and scope/exclusion inheritance.
- The engine can explain why each step is connected, show the evidence behind it, expose unverified assumptions, and suggest one bounded validation action.
- An out-of-scope node, missing scope provenance, invalid approval, or exhausted budget prevents active follow-up before network dispatch.
- Reports distinguish individual finding severity from demonstrated aggregate impact; hypothetical chaining never silently upgrades a confirmed finding.
- Local fixture scenarios cover a harmless chain from initial access to a constrained impact, plus negative controls proving that correlation does not invent exploitability.
- The feature is integrated into the single `Bug-Bounty` orchestrator and existing skills without adding subagents or automatic disclosure submission.

## Remaining work

Design and implement the graph schema, provenance-bearing edge model, bounded path search, human-readable chain explanation, approval-gated validation planner, and report integration. See [Future Improvements](../FUTURE-IMPROVEMENTS.md), the [issue register](../PROJECT-AUDIT-ISSUES.md), and [the 24-phase roadmap](../ROADMAP-24-PHASES.md).

## Source references

Foundation tests: `tests/test_capability_graph.py`. They do not yet verify the integrated chain workflow. See [the project handbook](../PROJECT-HANDBOOK.md) for the full research process.
