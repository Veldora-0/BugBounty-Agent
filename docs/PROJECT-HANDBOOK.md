# BugBounty-Agent Project Handbook

BugBounty-Agent is a security research framework for finding and documenting vulnerabilities on **explicitly authorized bug bounty targets**. It is designed to help a researcher move from scope validation to a defensible, reproducible disclosure report. It is not a general-purpose scanner or an autonomous exploitation service.

## Start here

1. Read the repository [architecture and agent specification](../AGENTS.md), [security policy](security.md), [scope guide](scope.md), and [workflow guide](workflow.md).
2. Install and deploy using [installation](installation.md) and [runtime](runtime.md).
3. Initialize a local program workspace and put the program's current in-scope and excluded assets in its scope configuration. Verify scope offline before any network operation.
4. Work from passive inventory toward a specific hypothesis. Use the engine/skill appropriate to that hypothesis and its built-in safety budgets.
5. Keep credentials, targets, raw captures, state and reports outside the Git repository. Save only sanitized, minimal evidence.
6. Validate and deduplicate candidate findings. A human reviews and submits any disclosure.

## What the repository contains

- `agents/Bug-Bounty.md`: the single primary OpenCode orchestrator.
- `skills/`: 18 modular methods, including scope management, discovery, vulnerability testing, validation, evidence and reporting.
- `framework/`: Python engines, policy checks, parsers, state and finding models.
- `scripts/`: command-line entry points, deployment and diagnostics.
- `config/`, `templates/`, `examples/`: tool declarations, report/config templates and safe examples.
- `tests/`: unit, integration and local simulation coverage. Tests do not grant target authorization or prove every live environment works.
- `docs/phases/`: one guide per roadmap phase, with implementation, safety boundaries and completion gates.

The architecture intentionally uses one `Bug-Bounty` agent and skills rather than separate research agents. Scope checks, human approval gates, bounded requests, destination protections, redaction, local-only runtime data and no automatic report submission are core design requirements.

## Research lifecycle

| Stage | Researcher and system work | Useful output |
|---|---|---|
| Intake | Identify the program and confirm current authorization and scope. Configure exclusions and test accounts. | Validated local scope and program workspace |
| Inventory | Prefer passive asset sources; enrich approved assets with bounded recon. | Deduplicated asset and endpoint inventory |
| Surface mapping | Parse web, JavaScript and API surfaces; record authentication and technology observations. | Endpoints, parameters and observations |
| Research intelligence | Use `/Arise` to review relevant public disclosure methodology against the program's current in-scope assets and coverage; prune irrelevant local links on each invocation. | Attributed public references and researcher-reviewed hypotheses (Phase 23, implemented; public search capability required for new source discovery) |
| Hypothesis | State the suspected control failure, affected asset, preconditions and a safe proof. | Testable, prioritized hypothesis |
| Validation | Run only the minimum approved, non-destructive checks; stop on uncertainty or impact. | Evidence-backed finding or ruled-out hypothesis |
| Chain analysis | Starting from a validated bug, look for other in-scope weaknesses that could combine into a higher-impact path; keep inferred links separate from proven steps. | Explainable attack-path hypothesis and reviewable follow-up plan (Phase 22 candidate correlation is implemented; CLI validation is simulation-only and cannot empirically promote links) |
| Quality and reporting | Challenge confidence, deduplicate root causes, redact and prepare a human-reviewed disclosure report. | Local report and evidence bundle |

## Current implementation status

Phases 1–20 have varying levels of implementation and test coverage; they are not all complete replacements for specialist tools. Phase 1's normal CLI does not yet have a subdomain-discovery provider wired in, and Phase 2's normal CLI does not execute the external tools listed in the catalog. Other limits are recorded in each phase guide; historical tests do not guarantee live-target coverage. Phase 21 is implemented with documented limitations: execution-capability issuance has been restored with independent Ed25519 receipt verification, while Windows service isolation is unsupported and successful authorized mutation through the installed Linux systemd service remains unverified because its test-key setup requires privileged provisioning. Phase 22 builds candidate attack paths and reviewable approval plans, but the current `bb-chain validate` command only runs a deterministic simulation: it creates no target evidence and cannot validate a relationship or chain. Its dispatch boundary requires a live `ScopeEngine` and rechecks every path-bound asset at authorization and execution. Phase 23 implements offline coverage-driven recommendations and `/Arise` metadata reconciliation; discovery of new public-source reports depends on an available read-only research capability. Phase 24's documented beta gates are implemented and verified; unresolved capability and live-service limits remain in the issue register. The current full-suite and hosted CI evidence is recorded in the [Phase 24 verification record](phases/PHASE-24-final-integration-production-readiness.md#post-audit-regression-verification). Consult the roadmap and issue register before relying on any phase as proof of production readiness or live-target effectiveness.

## Documentation map

- [24-phase roadmap](ROADMAP-24-PHASES.md): canonical order, current status and completion gates.
- [Phase guides](phases/): implementation and planned detail for each phase.
- [Project audit issues](PROJECT-AUDIT-ISSUES.md): the consolidated unresolved errors, contradictions, risks and blockers.
- [Future improvements](FUTURE-IMPROVEMENTS.md): proposed work after and alongside the current roadmap.
- [Tooling recommendations](TOOLING-RECOMMENDATIONS.md): optional Kali-oriented tools and safe integration gates.
- [Supported environments](supported-environments.md), [threat model](THREAT-MODEL.md), and [release checklist](release-checklist.md): Phase 24 operating and release gates.
- [Security](security.md), [scope](scope.md), [workflow](workflow.md), [architecture](architecture.md), [skills](skills.md), [runtime](runtime.md), and [installation](installation.md): operational references.
- Historical phase design and audit documents may contain superseded test verdicts. Use the latest commit-linked evidence in the [Phase 24 verification record](phases/PHASE-24-final-integration-production-readiness.md#post-audit-regression-verification), the [issue register](PROJECT-AUDIT-ISSUES.md), and the [roadmap](ROADMAP-24-PHASES.md). Hosted Windows full-suite acceptance passes; Windows production dispatcher isolation remains unsupported.

## Contribution and release expectations

Changes that affect target traffic must preserve offline scope validation, exclusions precedence, conservative request budgets, safe destination checks, credential hygiene, evidence provenance, human review and no auto-submit. Describe meaningful behavior in tests and docs; distinguish simulation from live validation. Do not publish target data, credentials, private evidence or bounty reports in this repository.
