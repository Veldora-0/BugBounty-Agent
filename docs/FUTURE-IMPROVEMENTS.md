# Future Improvements and Feature Ideas

This document captures candidate improvements for completing the roadmap and making BugBounty-Agent more useful to real, authorized bounty research. These are proposals, not claims that the functionality exists. Work must preserve explicit authorization, least-impact testing, human oversight and truthful evidence.

## Required roadmap work

### Phase 21 — Trusted authentication/authorization correlation

- Windows production dispatcher isolation is explicitly unsupported; keep this boundary visible in deployment status and documentation. Revisit only if Windows production deployment becomes a product requirement.
- Verify a successful, operator-approved mutation through the installed Linux systemd service using controlled test keys provisioned through a documented privileged setup; retain the existing fail-closed negative tests.
- Document safe key provisioning, rotation, backup, revocation and service recovery.
- Keep independent signed-receipt verification, replay protection, and the rule against caller-writable evidence as release gates.

### Phase 22 — Cross-engine attack-path correlation

- Expand ingestion from the current findings-centered model so additional engines can contribute scope-labelled assets, endpoints, identity context, and evidence references without creating unsupported joins.
- Calibrate relationship freshness and confidence against real researcher-reviewed fixtures; keep inferred edges separate from observations and validated relationships.
- Add more complete chain scenarios to local test fixtures, including chains that are disproven because a prerequisite, identity, or scope boundary does not match.
- Preserve the existing rule that component severities stay distinct and a higher impact is reported only when the extra impact is demonstrated.
- Consider additional graph export formats only where they preserve provenance, scope labels, redaction, and reproducibility.

### Phase 23 — Research planning and coverage intelligence

Core offline coverage planning and `/Arise` metadata reconciliation are implemented. These are follow-on improvements:

- Add optional, narrowly scoped source adapters for feeds/APIs that permit public disclosure indexing; retain the explicit read-only search workflow when no adapter is available.
- Improve exact-hypothesis matching by storing research fingerprints with test records; current deduplication is based on current target and vulnerability category.
- Add an asset-by-vulnerability-family coverage view with dates, confidence and explicit exclusions, while keeping ranking factors explainable and researcher-editable.
- Calibrate ranking weights against researcher feedback and local fixture outcomes without presenting the score as exploitability probability.
- Add local fixture cases for recommendation quality, category boundaries, stale inventory and source removal/version changes.
- Preserve the Phase 23 rule that public research remains separate from target evidence and recommendations never authorize active testing.

### Phase 24 follow-on — Release assurance and workspace operations

Phase 24 has implemented much of its operational hardening. Historical Linux and Windows CI jobs passed for `b6308e8`; the current CI matrix targets Linux only. Closure still requires updated installed Linux dispatcher acceptance and explicit handling of the open audit issues. The following items are follow-on work after those gates are evidenced:

- Add automated dependency advisory review and decide whether a reproducible dependency lockfile is appropriate for the supported packaging model.
- Generate a software bill of materials and sign/tag release artifacts with a documented key custody and verification process.
- Add a versioned, encrypted workspace backup and restore tool, then test interrupted restore and compatibility migrations against copies of real-shaped state.
- Document key rotation and incident-response exercises for the Linux dispatcher and evidence signing keys.
- Decide whether Windows production service isolation or macOS support is worth implementing; keep both unsupported until their platform-specific trust boundaries pass acceptance.

### Phases 1–2 — Complete asset enrichment and clarify recon capabilities

- Add an optional ASN attribution source with privacy, rate, output, and failure bounds plus local fixtures. Bounded TLS SAN enrichment is already wired into asset discovery; keep its scope checks, IP pinning, SNI and handshake budget covered by fixtures.
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
