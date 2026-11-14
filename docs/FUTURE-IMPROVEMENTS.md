# Future Improvements and Feature Ideas

This document captures candidate improvements for completing the roadmap and making BugBounty-Agent more useful to real, authorized bounty research. These are proposals, not claims that the functionality exists. Work must preserve explicit authorization, least-impact testing, human oversight and truthful evidence.

## Required roadmap work

### Phase 21 — Trusted authentication/authorization correlation

- Resolve the disabled execution capability and controlled-attestation gates through a reviewed OS trust boundary.
- Support and verify successful approved dispatch, evidence binding, single-use approval, revocation checks and ledger persistence; test denial and replay paths.
- Define supported OS service isolation and safe key provisioning/rotation, including a clear Windows support decision.
- Never issue a finding based on caller-writable evidence or an untrusted in-process claim.

### Phase 22 — Cross-engine attack-path correlation

- Create a typed graph of assets, endpoints, identities, observations, hypotheses, findings and evidence.
- Define provenance-bearing edges, confidence and freshness; distinguish observed relationships from validated exploit paths.
- Starting from a validated bug, search for other in-scope weaknesses that could combine with it to produce a demonstrated higher-impact outcome. This bug-chaining workflow is a required Phase 22 deliverable.
- Rank chains by demonstrated impact and prerequisites without summing severity mechanically. Keep component severities separate from the chain's evidenced impact.
- Explain every proposed path, show missing evidence, inherit scope restrictions, and require human approval before any active follow-up.
- Provide graph export and reproducible path reports without exposing secrets.

### Phase 23 — Research planning and coverage intelligence

- Generate researcher-reviewed next-step recommendations from scope, asset inventory, technology observations, prior tests and known coverage gaps.
- Prioritize by potential bounty impact, confidence, test cost, safety and duplicate coverage.
- Track test fingerprints and explain why a test is recommended or skipped.
- Add budget-aware plans and a clear pause/stop control; recommendation generation must not imply permission to execute.

### Phase 24 — Integration and production readiness

- Define supported Python and operating system versions; verify clean install, deploy, update, rollback and uninstall workflows.
- Add repeatable CI for Windows and Linux, dependency/runtime diagnostics, and explicit optional browser/OOB service checks.
- Document configuration lifecycle, backup/recovery, workspace permissions, key rotation, upgrade compatibility and incident response.
- Produce versioned threat model, security review, release checklist and phase acceptance evidence tied to exact commits.

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
