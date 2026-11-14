# BugBounty-Agent — 24-Phase Roadmap

This is the canonical status index. Detailed plans, implementation paths, safety boundaries and completion criteria live in [the per-phase guides](phases/) and [project handbook](PROJECT-HANDBOOK.md). Status describes the code and documentation currently present; historic test success does not establish live-target effectiveness.

**Current work:** Phase 21 is partially implemented and not accepted. The Linux dispatcher isolation and invalid-approval rejection check pass, but successful end-to-end capability and attestation issuance remain disabled. See [issue register](PROJECT-AUDIT-ISSUES.md). Phases 22–24 are planned.

| Phase | Name | Current status |
|---:|---|---|
| 1 | Asset Intelligence | Implemented; historic verification, operational limits apply |
| 2 | Reconnaissance | Implemented with operational limits |
| 3 | Web Application Intelligence | Implemented; read-only mapping |
| 4 | JavaScript Intelligence | Implemented; read-only analysis |
| 5 | API Intelligence | Implemented with documented limits |
| 6 | Security Validation Foundation | Implemented |
| 7 | XSS Intelligence | Implemented with documented limits |
| 8 | Authorization / BOLA / IDOR | Implemented with documented limits |
| 9 | SSRF Intelligence | Implemented; live OOB confirmation depends on provider availability |
| 10 | Injection Intelligence | Implemented with documented limits |
| 11 | HTTP Trust & Protocol Security | Implemented |
| 12 | Business Logic Intelligence | Implemented with human approval gates |
| 13 | Cloud Security | Implemented; read-only boundaries |
| 14 | Authentication, Session & Identity | Implemented; milestones 14.1 and 14.2 are submilestones |
| 15 | File Upload, Path Traversal & Local File Exposure | Implemented with safe proof limits |
| 16 | Browser Runtime & Client-Side Security | Implemented; browser runtime availability varies by host |
| 17 | Advanced API Security | Implemented with documented limits |
| 18 | SSRF, XXE & Server-Side Parsers | Implemented; live callback confirmation depends on provider availability |
| 19 | Infrastructure & Configuration Exposure | Implemented; read-only and size bounded |
| 20 | Race Conditions & Distributed Workflows | Implemented with low-volume bounds |
| 21 | Authentication & Authorization Correlation | **Partially implemented; acceptance blocked** |
| 22 | Cross-Engine Attack-Path Correlation and Vulnerability Chaining | Planned; required to identify and safely validate higher-impact chains |
| 23 | Autonomous Research Planning & Coverage Intelligence | Planned; human-directed recommendations required |
| 24 | Final Integration & Production Readiness | Planned |

## Roadmap-wide completion requirements

- Every target request must follow explicit authorization, offline scope evaluation and exclusion precedence.
- Active research must be hypothesis-driven, minimally invasive, bounded, auditable and stopped when impact or authorization is uncertain.
- Findings must be evidence-backed, redacted, deduplicated and honestly labeled as simulated, observed or confirmed.
- No destructive testing, uncontrolled scanning, credential attacks, automatic disclosure submission or target-data commits.
- Final production readiness requires documented supported platforms, setup/upgrade/recovery, operational dependencies, security review and reproducible acceptance evidence.

## Phase guides

Each phase guide is independently readable and linked to its implementation. Phase 14.1 and 14.2 are hardening milestones within Phase 14, not additional numbered roadmap phases.

- [01 Asset Intelligence](phases/PHASE-01-asset-intelligence.md) · [02 Reconnaissance](phases/PHASE-02-reconnaissance.md) · [03 Web Application Intelligence](phases/PHASE-03-web-application-intelligence.md) · [04 JavaScript Intelligence](phases/PHASE-04-javascript-intelligence.md)
- [05 API Intelligence](phases/PHASE-05-api-intelligence.md) · [06 Security Validation Foundation](phases/PHASE-06-security-validation-foundation.md) · [07 XSS Intelligence](phases/PHASE-07-xss-intelligence.md) · [08 Authorization / BOLA / IDOR](phases/PHASE-08-authorization-bola-idor.md)
- [09 SSRF Intelligence](phases/PHASE-09-ssrf-intelligence.md) · [10 Injection Intelligence](phases/PHASE-10-injection-intelligence.md) · [11 HTTP Trust & Protocol Security](phases/PHASE-11-http-trust-protocol-security.md) · [12 Business Logic Intelligence](phases/PHASE-12-business-logic-intelligence.md)
- [13 Cloud Security](phases/PHASE-13-cloud-security.md) · [14 Authentication, Session & Identity](phases/PHASE-14-authentication-session-identity.md) · [15 File Upload, Path Traversal & LFE](phases/PHASE-15-file-upload-path-traversal-local-file-exposure.md) · [16 Browser Runtime & Client-Side Security](phases/PHASE-16-browser-runtime-client-side-security.md)
- [17 Advanced API Security](phases/PHASE-17-advanced-api-security.md) · [18 SSRF, XXE & Server-Side Parsers](phases/PHASE-18-ssrf-xxe-server-side-parsers.md) · [19 Infrastructure & Configuration Exposure](phases/PHASE-19-infrastructure-configuration-exposure.md) · [20 Race Conditions & Distributed Workflows](phases/PHASE-20-race-conditions-distributed-workflows.md)
- [21 Authentication & Authorization Correlation](phases/PHASE-21-authentication-authorization-correlation.md) · [22 Attack-Path Correlation and Vulnerability Chaining](phases/PHASE-22-cross-engine-attack-path-correlation.md) · [23 Research Planning & Coverage](phases/PHASE-23-autonomous-research-planning-coverage-intelligence.md) · [24 Integration & Production Readiness](phases/PHASE-24-final-integration-production-readiness.md)
