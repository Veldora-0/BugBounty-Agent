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
| Hypothesis | State the suspected control failure, affected asset, preconditions and a safe proof. | Testable, prioritized hypothesis |
| Validation | Run only the minimum approved, non-destructive checks; stop on uncertainty or impact. | Evidence-backed finding or ruled-out hypothesis |
| Quality and reporting | Challenge confidence, deduplicate root causes, redact and prepare a human-reviewed disclosure report. | Local report and evidence bundle |

## Current implementation status

Phases 1–20 have corresponding engines, skills or integrations, and tests. Their precise limitations are recorded in the phase guides; historic acceptance and test runs do not guarantee live-target coverage. Phase 21 has substantial correlation logic and a Linux isolated dispatcher, but remains **partially implemented and not accepted**: capability issuance and controlled-workflow attestation issuance remain disabled. Phase 22–24 are planned. The roadmap records this status as of the current source tree; consult the issue register before treating any phase as production-ready.

## Documentation map

- [24-phase roadmap](ROADMAP-24-PHASES.md): canonical order, current status and completion gates.
- [Phase guides](phases/): implementation and planned detail for each phase.
- [Project audit issues](PROJECT-AUDIT-ISSUES.md): the consolidated unresolved errors, contradictions, risks and blockers.
- [Future improvements](FUTURE-IMPROVEMENTS.md): proposed work after and alongside the current roadmap.
- [Tooling recommendations](TOOLING-RECOMMENDATIONS.md): optional Kali-oriented tools and safe integration gates.
- [Security](security.md), [scope](scope.md), [workflow](workflow.md), [architecture](architecture.md), [skills](skills.md), [runtime](runtime.md), and [installation](installation.md): operational references.
- Historical Phase 21 design/acceptance documents may contain superseded verdicts. The current verdict is the explicit status in the [definitive report](PHASE-21-DEFINITIVE-SECURITY-ACCEPTANCE-REPORT.md) and the issue register.

## Contribution and release expectations

Changes that affect target traffic must preserve offline scope validation, exclusions precedence, conservative request budgets, safe destination checks, credential hygiene, evidence provenance, human review and no auto-submit. Describe meaningful behavior in tests and docs; distinguish simulation from live validation. Do not publish target data, credentials, private evidence or bounty reports in this repository.
