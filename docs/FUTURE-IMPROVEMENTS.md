# Future Improvements and Feature Ideas

This document captures candidate improvements for completing the roadmap and making BugBounty-Agent more useful to real, authorized bounty research. These are proposals, not claims that the functionality exists. Work must preserve explicit authorization, least-impact testing, human oversight and truthful evidence.

## Required roadmap work

### Phase 21 — Trusted authentication/authorization correlation

- Define the supported Windows service-isolation design, or explicitly scope production dispatcher support to Linux until an equivalent boundary is implemented.
- Verify a successful, operator-approved mutation through the installed Linux systemd service using controlled test keys provisioned through a documented privileged setup; retain the existing fail-closed negative tests.
- Document safe key provisioning, rotation, backup, revocation and service recovery.
- Keep independent signed-receipt verification, replay protection, and the rule against caller-writable evidence as release gates.

### Phase 22 — Cross-engine attack-path correlation

- Create a typed graph of assets, endpoints, identities, observations, hypotheses, findings and evidence.
- Define provenance-bearing edges, confidence and freshness; distinguish observed relationships from validated exploit paths.
- Starting from a validated bug, search for other in-scope weaknesses that could combine with it to produce a demonstrated higher-impact outcome. This bug-chaining workflow is a required Phase 22 deliverable.
- Rank chains by demonstrated impact and prerequisites without summing severity mechanically. Keep component severities separate from the chain's evidenced impact.
- Explain every proposed path, show missing evidence, inherit scope restrictions, and require human approval before any active follow-up.
- Provide graph export and reproducible path reports without exposing secrets.
- Complete a supported Windows run for ACL-protected state and add a regression proving the CLI loads the canonical program scope path and refuses validation when scope is absent or invalid.

### Phase 23 — Research planning and coverage intelligence

Core offline coverage planning and `/Arise` metadata reconciliation are implemented. These are follow-on improvements:

- Add optional, narrowly scoped source adapters for feeds/APIs that permit public disclosure indexing; retain the explicit read-only search workflow when no adapter is available.
- Improve exact-hypothesis matching by storing research fingerprints with test records; current deduplication is based on current target and vulnerability category.
- Add an asset-by-vulnerability-family coverage view with dates, confidence and explicit exclusions, while keeping ranking factors explainable and researcher-editable.
- Calibrate ranking weights against researcher feedback and local fixture outcomes without presenting the score as exploitability probability.
- Add local fixture cases for recommendation quality, category boundaries, stale inventory and source removal/version changes.
- Preserve the Phase 23 rule that public research remains separate from target evidence and recommendations never authorize active testing.

### Phase 24 — Integration and production readiness

- Define supported Python and operating system versions; verify clean install, deploy, update, rollback and uninstall workflows.
- Add repeatable CI for Windows and Linux, dependency/runtime diagnostics, and explicit optional browser/OOB service checks.
- Document configuration lifecycle, backup/recovery, workspace permissions, key rotation, upgrade compatibility and incident response.
- Produce versioned threat model, security review, release checklist and phase acceptance evidence tied to exact commits.

### Phases 1–2 — Wire asset discovery and recon capabilities into the CLI

- Connect the asset engine to a deliberately selected, optional passive subdomain provider so normal CLI behavior matches its documented discovery workflow; preserve an offline mode and clear provenance for each source.
- Implement or remove the currently hook-only ASN and TLS SAN extraction claims, with local fixtures and strict scope checks.
- Decide which external reconnaissance tools the project intends to execute. If enabled, add explicit per-tool configuration, binary verification, argument construction, timeout/output limits, and tests. Until then, describe them only as separately installable/manual tools and do not imply `bb-recon` invokes them.

## Cross-cutting improvements

1. **Authorization-aware workspace UX:** Guided program setup that records source and date of scope rules, highlights exclusions, and requires an explicit operator confirmation before active work.
2. **Evidence quality scoring:** Checklist for reproducibility, impact, affected principal, request/response context, redaction and confidence. Keep scores explainable and human-editable.
3. **Coverage dashboard:** Show which asset classes, endpoints, vulnerability families and test accounts have been assessed, with last-tested time and exclusions.
4. **Program policy profiles:** Import policy text for rate limits and prohibited actions into a human-reviewed local profile; never infer authorization from a domain name alone.
5. **Safe test fixtures:** Expand local vulnerable applications for regression testing of each engine, including negative, boundary, redirect, DNS rebinding, malformed response and budget exhaustion cases.
6. **Dependency and supply-chain maintenance:** Pin or constrain dependencies deliberately, generate a software bill of materials, track supported versions, and review external tool updates before enabling them.
7. **Finding interoperability:** Add reviewed exports to common disclosure formats while preserving redaction, provenance and local-only storage.
8. **Usability improvements:** Consistent command help, machine-readable output, clear error remediation, progress cancellation and actionable `bb-doctor` diagnostics.
9. **Observability without sensitive logging:** Structured local audit events that record decisions and budgets while excluding tokens, personal data and raw secrets.
10. **Accessibility and localization:** Improve CLI readability, keyboard workflows and translation support for researcher-facing documentation.

## Guardrails for evaluating proposals

- Does it help verify a specific authorized vulnerability or improve the quality of its evidence?
- Can it fail closed on missing or ambiguous scope and avoid unnecessary target traffic?
- Can it be tested safely against local fixtures, including abuse and failure cases?
- Does it protect credentials, target data and other researchers' accounts?
- Does it keep the researcher in control of active testing and final disclosure?

Ideas that cannot meet these conditions should not be added to the product roadmap.
