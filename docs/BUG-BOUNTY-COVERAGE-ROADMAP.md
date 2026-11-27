# BugBounty-Agent Vulnerability Coverage Expansion Roadmap

**Status:** Proposed follow-on work. Partial groundwork already exists in the static class-to-engine/tool registry and offline `bb-coverage` CLI, but Phase 25 has not been accepted as complete. Full mapping review and per-program coverage tracking remain. This Phase 1–24 cleanup does not extend Phase 25 implementation. The registry is descriptive; it does not prove that a feature works against a target or that the agent finds every valid bug.

**Scope:** Authorized public bug bounty and coordinated disclosure testing of web applications, APIs, browser clients, and explicitly in-scope cloud assets. Mobile applications and source-code review are optional tracks when the program explicitly includes them. Active Directory, wireless, social engineering, exploit development, and general red-team operations are out of scope for this roadmap.

**Architecture constraint:** Keep one global `Bug-Bounty` primary agent and modular skills. Do not add subagents. Engines remain deterministic Python modules and CLI entry points; the agent selects them through explicit capability metadata and approval/scope gates.

## 1. Objective and definition of coverage

The objective is to make the agent systematically identify, safely validate, and report a broad set of in-scope bug bounty weaknesses. “Coverage” means the workflow can:

1. Recognize the relevant attack surface and formulate a testable hypothesis.
2. Select an implemented engine or clearly mark the case as manual guidance.
3. Check exact target scope and exclusions before any target request.
4. Use bounded, non-destructive probes appropriate to the program policy.
5. Compare against a baseline and collect reproducible, redacted evidence.
6. Distinguish an observation from a validated security boundary violation.
7. Report limitations, prerequisites, confidence, impact, and remediation without inflating severity.

No tool or checklist can guarantee discovery of every vulnerability. The OWASP Web Security Testing Guide itself describes its scenarios as a strong starting point rather than an exhaustive list. Coverage should therefore be measured by transparent workflow and fixture coverage, not by claims of universal detection.

## 2. Current implementation baseline

The repository already contains substantial engines. The names below refer to code present in this checkout; each engine’s current CLI path, policy, and limits must still be checked before expanding its claim.

| Area | Existing foundation | Work still needed for complete coverage claims |
|---|---|---|
| Scope, recon, web surface, JavaScript | `framework/scope`, `recon`, `webapp`, `javascript`; corresponding skills and CLIs | Connect every planned check to discovered assets/endpoints and retain provenance. Recon coverage is bounded and is not a complete inventory. |
| Authorization | `framework/authz`, `auth_correlation`; dual-principal and tenant concepts | Add property-level/API-specific cases, role matrices, and confidence/evidence requirements. Requires authorized test identities and known expected access. |
| Authentication/session | `framework/authentication`; login, MFA, reset, token and session models | Expand OAuth/OIDC/SAML and federation coverage; ensure every state-changing workflow is approval-gated and observable. |
| XSS and injection | `framework/xss`, `framework/injection`; SQLi, NoSQLi, SSTI, command validators | Verify per-context coverage and safely add LDAP/XPath and other parser families. Existing validator presence does not mean all variants are covered. |
| SSRF and XML | `framework/ssrf`, `framework/xxe`, OOB provider abstraction | Keep external callbacks explicit, exact-token correlated, scope-safe, and independently accepted against the live provider. Do not access sensitive internal resources to prove impact. |
| HTTP trust | `framework/http_trust`; Host/forwarded headers, CORS, HPP, cache foundations | Complete named check coverage for cache poisoning/deception, clickjacking/security headers, and carefully bounded protocol edge cases. Request smuggling should remain opt-in/manual until a harmless, program-approved validation method exists. |
| Business logic and races | `framework/business_logic`, `concurrency` | Add reusable workflow invariants and replay/race evidence. Require approval and zero-value/non-impacting fixtures for any state mutation. |
| Cloud and infrastructure | `framework/cloud_security`, `infrastructure`; storage exposure, takeover and exposure hypotheses | Separate public read-only checks from authenticated cloud configuration review. Add provider/IAM coverage only with explicit scope and least-privilege credentials. |
| API inventory and schema | `framework/api`; OpenAPI and GraphQL parsing, bounded introspection | Implement tests for API1–API10 risks as discrete cases, including resource limits, inventory/version drift, and unsafe upstream API consumption. Schema discovery is not vulnerability validation. |
| Validation, evidence, reporting | `framework/validation`, `findings`, `common/evidence`, `reporting` skill | Require family-specific proof predicates, reproducibility, negative controls, provenance, redaction, and explicit evidence grade in all findings. |

The 18 skills are methodology. They do not independently prove that a corresponding automated detector exists. Tool registry entries and `bb-doctor` availability are also not proof of invocation; the engine path must be documented and demonstrated.

## 3. Target vulnerability catalog

These are the bug bounty classes the agent should know how to triage. “Automated” below means bounded candidate generation or validation where evidence can be established safely; it does not mean blind scanning or guaranteed detection.

### 3.1 Identity, authentication, and authorization

- Broken object-level authorization (BOLA/IDOR), cross-user and cross-tenant access.
- Broken function-level authorization (BFLA), vertical privilege escalation, admin/API function exposure.
- Broken object-property authorization, mass assignment, sensitive property read/write, excessive data exposure.
- Authentication bypass, account enumeration where impact is meaningful, weak recovery/reset flows, reset token reuse or invalidation defects.
- MFA enrollment, transition, recovery, and bypass flaws; pre-authentication and post-authentication state confusion.
- Session fixation, session leakage, missing rotation/invalidation, logout/password-change revocation failures, cookie/security attribute weaknesses with demonstrated impact.
- JWT/JWS/JWE validation and claim authorization mistakes; OAuth/OIDC/SAML redirect, state, nonce, audience, issuer, scope, and account-linking flaws.
- Passwordless, invitation, magic-link, and email/phone ownership workflow flaws.

**Valid proof:** Show a concrete protected action or data boundary crossed with two controlled identities or a documented role transition. Token parsing, differing status codes, or a missing cookie flag alone is not sufficient impact proof.

### 3.2 Input handling, injection, and parser flaws

- Reflected, stored, and DOM XSS; context-specific HTML/attribute/JavaScript/URL injection.
- SQL and NoSQL injection; LDAP, XPath, and other query-language injection.
- Server-side template injection; OS/command injection; expression-language injection.
- XXE and unsafe XML processing; XML injection where it alters a security-relevant operation.
- Insecure deserialization and unsafe object binding when a non-destructive proof can establish a security boundary impact.
- Header, CRLF, HTTP parameter pollution, and content-type/parser discrepancies.
- Path traversal, local file exposure, unsafe file upload/download, archive extraction, and indirect object/file reference flaws.
- Prototype pollution and unsafe client-side object merging where an exploitable security impact is demonstrated.

**Valid proof:** Use harmless canaries, controlled arithmetic or syntax differentials, or inert synthetic data. Do not read secrets, execute destructive commands, write arbitrary files, or use denial-of-service payloads.

### 3.3 Web/browser and HTTP trust

- CSRF on meaningful state-changing actions; CORS trust errors with credential/data impact.
- Open redirect only where it creates a real trust or authentication impact.
- Clickjacking where a sensitive action can be induced and policy impact is clear.
- Host/forwarded-header trust, password-reset poisoning, cache poisoning/deception, and web cache key confusion.
- HTTP request smuggling/desynchronization, only through explicit program approval and a method that avoids impacting other users or shared infrastructure.
- Security misconfiguration: exposed debug/admin surfaces, unsafe methods, default or public files, permissive policy, unsafe redirects, TLS weaknesses, and error handling that reveals sensitive details.
- WebSocket authorization/origin mistakes and client-side trust in messages.
- Browser storage, source maps, source disclosure, and exposed frontend keys; distinguish public identifiers from privileged secrets.

**Valid proof:** Demonstrate a victim-relevant or security-boundary effect. A reflected header, permissive CORS response without sensitive credentialed data, missing header, or publicly visible client key is usually only a lead.

### 3.4 API and business logic

Cover the OWASP API Security Top 10 as explicit checklist families: BOLA, broken authentication, property-level authorization, unrestricted resource consumption, BFLA, sensitive business-flow abuse, SSRF, security misconfiguration, improper inventory management, and unsafe consumption of APIs.

Additional cases:

- REST method/route/version drift, undocumented endpoints, old API versions, and environment mix-ups.
- GraphQL introspection exposure where policy treats it as a finding, field-level authorization, batching/depth/cost controls, and mutation authorization.
- Rate-limit bypass only when it enables a meaningful abuse (for example, account takeover or economic impact); never run load/DoS tests.
- Workflow sequencing, replay, concurrency/race conditions, duplicate redemption, negative/precision values, quota and entitlement errors, and inconsistent state transitions.
- Webhook signature/replay/tenant binding issues and unsafe trust in downstream provider responses.

**Valid proof:** Use accounts and resources controlled by the researcher, low request counts, read-only or reversible operations, and business invariants supplied by product behavior. Financial or irreversible operations require explicit approval and a safe test fixture.

### 3.5 Cloud, deployment, and supply chain

- Public cloud object storage and unintended public access; exposed management endpoints and secrets.
- Excessive IAM/tenant permissions, metadata SSRF, cloud service trust boundaries, dangling DNS and takeover candidates.
- Container/image or deployment exposure only when the program includes those assets; registry/image disclosure, secrets, and unsafe configuration.
- CI/CD and source-control weaknesses only when explicitly in scope: exposed pipeline logs/artifacts, overly trusted workflow triggers, secret exposure, dependency confusion candidates, and unsafe build provenance.
- Third-party integrations: weak webhook verification, token leakage, callback trust, unsafe API response consumption.

**Valid proof:** Confirm asset ownership and scope before interacting with cloud providers. Prefer anonymous read-only checks. Never attempt to claim a third-party resource, alter IAM, access unrelated tenant data, or use discovered credentials.

## 4. Implementation phases

These are proposed coverage phases after the current Phase 24 baseline. They extend the existing single-agent design and do not renumber or rewrite the historical phases.

### Phase 25 — Coverage registry and workflow integration

**Status:** Partial groundwork present; Phase 25 remains an unaccepted follow-on. `config/vulnerability-coverage.yaml`, `framework/coverage/registry.py`, and `scripts/bb-coverage` provide an initial static inventory. The `Bug-Bounty` agent consults the map before claiming support and uses the actual finding lifecycle names. The registry labels classes as partial, manual-assisted, planned, or out-of-scope and identifies registry-only and unregistered tools. Validation passes, but each mapping still needs review against its callable path, and per-program tracking must distinguish available support from tests actually performed.

**Kali verification (2026-11-22):** `python3 scripts/bb-coverage --validate --json` reported `registry_valid: true`, zero validation errors, and 39 catalog entries. `python3 -m pytest tests/test_coverage_registry.py tests/test_tool_registry.py -rA` passed all 15 tests. This was focused validation, not a full-suite run.

**Goal:** Make every vulnerability class and tool claim auditable and routable.

**Implementation:**

- Maintain `config/vulnerability-coverage.yaml` with stable class ID, CWE/OWASP mapping, attack surface, prerequisites, engine/CLI, proof predicate, status, tool dependencies, and known blind spots. The initial file exists and passes focused Kali validation; mappings need ongoing review as workflows change.
- Add capability resolution for vulnerability families, not just external tools. Do not let capability metadata claim a workflow that has no callable implementation.
- Add agent routing guidance: scope → inventory → hypotheses → exact engine → evidence → validation → deduplication → report. Candidate planning must never send target traffic.
- `bb-coverage` prints partial, manual-assisted, planned, and out-of-scope status with proof limits and tool status. Initial CLI validation passed on Kali; machine-readable output and registry validation need further acceptance as the catalog grows.
- Each engine invocation records capability ID, engine version, policy, test fingerprint, asset provenance, result state, and omitted checks.

**Acceptance:** Registry schema validation rejects duplicate IDs and references to nonexistent engines/tools. A coverage report matches actual CLI wiring. Every class has an honest status; no class is labeled automated based only on a skill or registry entry.

### Phase 26 — Valid-finding quality and evidence gates

**Goal:** Improve precision so reports contain reproducible security bugs rather than scanner signals.

**Implementation:**

- Preserve the existing `FindingLifecycle` names: `OBSERVATION`, `HYPOTHESIS`, `CANDIDATE`, `TESTING`, `OBSERVED`, `SIMULATED`, `VALIDATED`, `REJECTED`, `DUPLICATE`, `NEEDS_MANUAL_REVIEW`, and `INFORMATIONAL`. Represent out-of-scope and insufficient-evidence reasons in disposition metadata rather than adding competing lifecycle names.
- Define per-family proof predicates: protected resource/action, principal context, baseline, changed request, observed boundary violation, impact evidence, reproducibility, and negative control.
- Add paired baseline/control support where appropriate, response normalization, redirect/caching/WAF detection, and false-positive reasons.
- Record request count, state changes, approval receipt, scope decision, and cleanup result. Redact before persistence and preserve raw sensitive material only under existing local evidence controls.
- Require a human-review state for findings needing victim interaction, destructive effects, third-party impact, or unverified impact assumptions.

**Acceptance:** Local deterministic fixtures include true positive, negative, ambiguous, and soft-404/WAF cases per family. A candidate cannot become `VALIDATED` without its family predicate and evidence bundle. Report generation distinguishes observed behavior from confirmed impact.

### Phase 27 — API and authorization coverage completion

**Goal:** Turn current API/schema and authorization foundations into a risk-based API security workflow.

**Implementation:**

- Create endpoint/action/property inventory with provenance from OpenAPI, GraphQL, web crawl, JavaScript, and researcher input.
- Build role/tenant matrices using only researcher-controlled accounts; compare object, function, and property authorization systematically.
- Add low-volume REST method/version checks, mass-assignment candidates, GraphQL field authorization and bounded depth/batch cost checks, and WebSocket identity/origin checks.
- Add API resource-consumption checks only as policy-reviewed rate-limit observations with very small request budgets; no load testing.
- Add inventory/version drift and third-party API trust hypotheses. Keep introspection gated by policy and scope.
- Support OAuth/OIDC/SAML flow modeling; never guess credentials, spray, or attempt account takeover beyond a controlled researcher account.

**Acceptance:** Every API risk category has a documented engine mapping or explicit manual/unavailable status. Fixture tests show a cross-tenant violation is found and same-tenant/expected-public behavior is rejected as a false positive. Active cases enforce scope and request budgets.

### Phase 28 — Web trust, client, and protocol coverage

**Goal:** Complete common browser and HTTP classes without unsafe generic scanning.

**Implementation:**

- Add clickjacking/frame policy analysis tied to a sensitive UI action; CSP and security-header checks that report context and impact.
- Expand cache analysis into cache key, cacheability, user-context, and poisoned-response evidence using isolated test markers and explicit cache-safety limits.
- Add WebSocket authorization, origin, and message-schema review, plus safe browser-side storage and postMessage analysis.
- Add a program-approved HTTP request smuggling assessment mode only if it can be tested against an isolated fixture or dedicated origin with strict connection/request caps. Otherwise expose a manual checklist only.
- Cover host/forwarded header, CORS, HPP, redirect, and cookie findings with endpoint-specific impact requirements.

**Acceptance:** No header-only or reflection-only finding is promoted without an impact predicate. Smuggling tests are disabled by default and cannot target shared production paths without an explicit program rule and human approval.

### Phase 29 — Injection, files, and server parser coverage

**Goal:** Close common gaps beyond existing SQLi/NoSQLi/SSTI/command/XSS/XXE coverage.

**Implementation:**

- Add safe LDAP/XPath injection candidate and validator families with synthetic marker data.
- Add parser/content-type differential checks for XML, JSON, multipart, archive, and file metadata handling.
- Expand upload/download and traversal checks to verify only researcher-provided synthetic files and controlled paths; do not read real system files.
- Add deserialization/prototype pollution analysis as static or inert-candidate checks first. Promote to active validation only when a safe, non-executing proof exists.
- Keep RCE as an impact category, not an instruction to run commands. Validate with inert callbacks/canaries or local fixtures; blind OOB results are evidence of interaction, not automatically proof of code execution.

**Acceptance:** Each new validator has local fixtures for supported parser contexts and no destructive payloads. The finding model states exactly what the proof demonstrates (for example, template evaluation vs arbitrary code execution).

### Phase 30 — Cloud, configuration, and optional program surfaces

**Goal:** Make cloud and deployment checks explicit, least-privilege, and conditional on program scope.

**Implementation:**

- Separate public unauthenticated cloud checks from authenticated configuration review. Authenticated review requires an explicitly configured read-only identity and provider/account scope.
- Add provider-specific exposure models for IAM, storage, public services, metadata protections, and resource ownership; do not infer proof from DNS/CNAME shape alone.
- Add container/CI/CD/source review as optional capabilities that run only when the program scope includes repositories, registries, images, or pipeline assets.
- Keep mobile testing as an optional future phase requiring a separate authorization model for app packages, APIs, and test devices.

**Acceptance:** All cloud/resource targets have ownership and scope provenance. Read-only credentials are verified as read-only where possible. No takeover, credential use, IAM mutation, or third-party asset interaction is automated.

### Phase 31 — Tool integration and operational coverage

**Goal:** Integrate only tools that materially improve a defined workflow, and prove invocation semantics.

**Implementation:**

- Extend registry metadata to distinguish `registered`, `detected`, `invoked`, `validated-output`, and `manual-only`.
- For each integration, document binary/version, capabilities, network behavior, target expansion, redirect behavior, rate limits, output parser, scope enforcement boundary, and fallback.
- Invoke tools through structured arguments and bounded subprocess policy. Do not shell-compose target-derived strings. Parse output into candidates; never treat tool severity as validated finding severity.
- Keep Burp Suite/ZAP as human-controlled/manual or passive-assisted unless an explicit, separately reviewed automation adapter exists. Keep Nuclei signal-only until each template and request is reviewed.
- Add `bb-doctor` checks for required vs optional capabilities without claiming a missing optional tool blocks unrelated checks.

**Acceptance:** Each integrated tool has a local mock/fixture proving exact arguments, timeout, scope, output parsing, and nonzero/error handling. Tool output always enters the candidate/validation lifecycle, never directly into reports as a confirmed issue.

## 5. Tooling inventory and recommendations

The registry currently includes tools such as Subfinder, httpx, Naabu, Katana, ffuf, Arjun, Nuclei, Dalfox, sqlmap, Interactsh, Playwright, Burp Suite, ZAP, Gitleaks, TruffleHog, Nmap, and testssl.sh. Availability in `config/tools.yaml` does not mean an engine invokes them. Before adding more tools, first finish invocation evidence for the tools already listed.

| Tool/capability | Current status in repo | Recommendation |
|---|---|---|
| Burp Suite, OWASP ZAP | Registry/recommendation/manual workflow; not a generic engine integration | Keep optional and researcher-operated. Integrate passive exports only with explicit scope and redaction. |
| Nuclei | Controlled signal-only wrapper exists | Maintain signal-only semantics; template allowlisting and per-template review before any active use. |
| Dalfox, sqlmap | Registry entries exist | Do not treat as proof or run broadly. Prefer current safe native validators; any adapter must disable destructive/high-volume options and use fixtures first. |
| Interactsh | OOB framework/provider integration exists | Keep optional; live provider acceptance and token correlation must be visible in coverage status. |
| Gitleaks, TruffleHog | Registry entries exist | Use only against explicitly in-scope source/repository content; leaked credential detection must never trigger credential use. |
| testssl.sh | Registry entry exists | Optional read-only TLS assessment for in-scope hosts; distinguish informational configuration from demonstrated program impact. |
| Prowler / ScoutSuite | Not currently in registry | Optional future integration for explicitly authorized cloud-account review using read-only credentials. Not needed for anonymous web bounty testing. |
| Trivy | Not currently in registry | Optional for in-scope container images, filesystem, or IaC. Requires a separate image/repository scope model and careful secret redaction. |
| MobSF, JADX, apktool, Frida | Not currently in registry | Defer to an optional mobile phase; only add if mobile apps are explicitly part of target programs. Keep runtime instrumentation researcher-controlled. |
| Request-smuggling-specific scanners | Not currently integrated | Do not add as a default active tool. Prefer manual/isolated fixture analysis because desynchronization can affect other users and shared infrastructure. |

**Tool selection rule:** A tool is required only when a defined class cannot be reasonably covered by current safe native logic or manual workflow and the integration has a documented proof/validation role. Prefer fewer well-integrated tools over a large unverified catalog.

## 6. Cross-cutting safety and validity requirements

- Offline scope validation is mandatory before network activity; exclusions override all inclusions. Recheck redirects, resolved addresses, callback domains, generated targets, and every target in a chain.
- Passive discovery first. Active requests require bounded rate, timeout, request count, exact target list, and explicit authorization. Never run unvetted broad scans.
- No denial-of-service, destructive writes, data deletion, real-user access, credential stuffing/spraying, persistence, lateral movement, or external submission.
- Use only researcher-controlled accounts and synthetic records for authorization and workflow tests. Stop when a test could expose another person's data.
- Findings require demonstrated impact and reproducibility. Severity reflects proven impact and program context, not theoretical chain possibilities.
- An OOB callback proves only that a callback occurred. It does not alone prove SSRF impact, XXE data access, or RCE.
- Keep target data, secrets, raw evidence, and reports local under the Git-ignored program path; never force-add them to Git. Redact credentials and personal data before display or export.
- Linux/Kali is the supported automated test platform. New automated workflows and acceptance criteria must be Linux-based; do not add Windows-only tests or CI.

## 7. Coverage states and reporting

Use these coverage labels consistently in `bb-coverage`, agent summaries, and docs:

- **Implemented:** engine and CLI path exist; scope, policy, evidence, and local fixture path are documented.
- **Partial:** some detection exists but important variants, evidence, or integration paths remain incomplete.
- **Manual-assisted:** agent can guide and organize researcher-controlled review; it does not claim automated detection.
- **Registry-only:** tool is listed but no engine invocation is proven.
- **Planned:** roadmap only; no current detection claim.
- **Out of scope:** not part of this product roadmap (for example, phishing, Active Directory red teaming, wireless testing, and exploit development).

Every program report should include a compact coverage summary listing classes considered, classes tested, classes skipped and why, credentials/prerequisites unavailable, tools missing or not invoked, request budgets, and unresolved hypotheses. Never present “not found” as “not vulnerable.”

## 8. References

- [OWASP Web Security Testing Guide](https://wstg.owasp.org/latest/) — testing scenarios and methodology; not exhaustive.
- [OWASP Web Security Testing Guide v4.2 categories](https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/) — information gathering, configuration, identity, authentication, authorization, sessions, input validation, errors, cryptography, business logic, and client-side testing.
- [OWASP Top 10:2025](https://top10.owasp.org/) — current broad web application risk categories.
- [OWASP API Security Top 10:2023](https://api-security.owasp.org/editions/2023/en/0x00-header/) — API-specific risk taxonomy.
- [Repository 24-phase roadmap](ROADMAP-24-PHASES.md), [tool registry](../config/tools.yaml), [skills catalog](skills.md), and [agent specification](../agents/Bug-Bounty.md).
