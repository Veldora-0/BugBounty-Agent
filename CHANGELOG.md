# Changelog

All notable changes to the BugBounty-Agent project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.14.1] - 2026-10-10

### Phase 14.1: Authentication Engine Hardening & Pipeline Integration

#### Added & Improved
* **Pipeline Execution & Scope Engine Integration (`framework/authentication/executor.py`, `framework/authentication/policy.py`)**:
  * Added `BoundedAuthenticationExecutor` and `AuthSafeRedirectHandler` implementing RFC-compliant HTTP execution capped at 10s timeout, 100KB body limit, and 5 redirect hops with anti-SSRF protections against private/loopback/cloud metadata ranges.
  * Canonical scope path resolution (`resolve_scope_file`) prioritizing `<program_dir>/scope/scope.yaml` and strict fail-closed enforcement using `ScopeEngine.check()` returning `ScopeDecision(status == ScopeStatus.IN_SCOPE)`.
  * Safe approval gating (`AuthenticationApprovalGate`) requiring `--approve` for test account state mutations; enforced invariant that operator approval never overrides scope restrictions.
* **Cross-Phase State Ingestion (`framework/authentication/discovery.py`, `framework/authentication/identity.py`)**:
  * Unified `AuthenticationSurfaceDiscoverer.discover_all()` ingesting 7 real multi-phase state files: `webapps.json`, `api.json`, `javascript.json`, `assets.json`, `recon.json`, `authorization.json`, and `workflows.json`.
  * Graceful degradation handling missing, empty, or partial state files.
  * Identity profile seeding from Phase 8 authorization principals (`seed_from_authorization_state`).
* **Operational Vulnerability Taxonomy & Heuristics (`framework/authentication/hypotheses.py`, `framework/authentication/validators.py`)**:
  * Full coverage of all 14 families from `AuthenticationFindingFamily`: 11 operational testing families and 3 observation-only families.
  * Differential baseline validation (anonymous vs authenticated vs pre-MFA) rejecting generic 200 OK login forms and WAF challenges.
  * Multi-trial differential validation for account enumeration distinguishing real signal variations from baseline noise.
* **Deduplication, Evidence Sanitization & Findings Persistence (`framework/authentication/engine.py`, `framework/authentication/evidence.py`, `framework/authentication/models.py`)**:
  * Test deduplication via `StateManager.record_test` and `StateManager.has_test_run` preventing redundant probes.
  * Support for `--resume` flag to merge existing engine run state.
  * Family-specific credential redaction (`[REDACTED_PASSWORD]`, `[REDACTED_COOKIE]`, `[REDACTED_TOKEN]`, `[REDACTED_SECRET]`) with SHA-256 provenance hashes.
  * Native findings integration persisting confirmed findings into `state/findings.json` using `FindingLifecycle.VALIDATED`.
* **Testing & Diagnostics**:
  * 18 new automated integration and safety test cases in `tests/test_authentication_engine.py` (total 42 tests in suite).
  * Category 23 diagnostic verification reporting `[HEALTHY]` in `bb-doctor`.

---

## [1.14.0] - 2026-10-08

### Phase 14: Authentication, Session & Identity Security Intelligence Engine

#### Added
* **Authentication Security Framework (`framework/authentication/`)**:
  * Structured identity models (`IdentityProfile`) and bi-directional bridge with Phase 8 `PrincipalProfile`. Strict redaction: passwords and live tokens are never stored.
  * Multi-flow surface discovery (`AuthenticationSurfaceDiscoverer`) ingesting login, logout, password change, reset, MFA, and refresh endpoints from previous phases.
  * Session lifecycle and fixation intelligence (`SessionAnalyzer`) tracking hashed/masked fingerprints (`sess_sha256_...`), rotation, logout invalidation, and password-change invalidation.
  * Token & JWT structural parser (`TokenAnalyzer`) locally decoding headers, algorithms, and claims without live signature tampering; detecting transport leaks in URL query parameters.
  * Password reset and differential account enumeration analyzer (`PasswordResetAnalyzer`) detecting token reuse, expiration enforcement, and repeatable differential signals.
  * Multi-factor authentication analyzer (`MFAAnalyzer`) identifying pre-MFA privilege exposure on sensitive account endpoints without OTP brute-forcing.
  * Active false positive rejection (`AuthenticationFalsePositiveClassifier`) eliminating HTTP 200 login pages, non-sensitive missing cookie attributes, and normal access controls.
  * Safety policy & approval gate (`AuthenticationSecurityPolicy`, `AuthenticationApprovalGate`) enforcing scope boundaries, blocking metadata addresses, and requiring `--approve` for sensitive mutations.
  * Atomic state persistence (`AuthenticationStateManager`) storing state at `state/authentication.json` with resume capability.
* **Deterministic Local Authentication Lab (`LocalAuthenticationSecurityLab`)**:
  * 21 deterministic, 100% offline scenarios demonstrating bypasses, pre-MFA exposures, session invalidation, fixation, token reuse, enumeration, and false positive rejections.
* **CLI Wrapper (`scripts/bb-auth`, `scripts/bb-auth.cmd`)**:
  * Commands for `--tree`, `--json`, `--passive-only`, `--dry-run`, `--resume`, `--hypotheses`, `--validate`, `--flow`, `--identity`, `--approve`, and `--lab`.
* **System Diagnostics & Skills Integration**:
  * Updated `framework/tools/doctor.py` and `scripts/bb-doctor` with Category 23: Authentication & Session Security.
  * Added permission rule `*bb-auth*` with `ask` effect to `opencode.jsonc`.
  * Created dedicated methodology skill [`skills/authentication/SKILL.md`](skills/authentication/SKILL.md), expanding modular skills to 18.

---

## [1.13.0] - 2026-10-08

### Phase 13: Cloud Security & Misconfiguration Intelligence Engine

#### Added
* **Cloud Security Framework (`framework/cloud_security/`)**:
  * Multi-signal provider fingerprinting (`ProviderFingerprinter`) supporting AWS, Azure, GCP, Cloudflare, Fastly, DigitalOcean, and Oracle.
  * Cloud service identification (`CloudServiceIdentifier`) recognizing S3, Blob storage, GCS, CloudFront, Azure App Service, Cloud Run, API Gateway, and admin interfaces.
  * Exposure hypothesis engine (`CloudExposureHypothesisEngine`) generating testable assertions for public object read, bucket listing, suspected write capability, cloud takeover, and admin access.
  * Safe non-destructive validator (`SafeCloudValidator`) and false positive classifier (`CloudFalsePositiveClassifier`) rejecting CDN normal endpoints, enforced access controls (HTTP 403 / `AccessDenied`), and HTML static website hosting.
  * Multi-factor exposure scoring (`CloudExposureScorer`) and priority rank engine (`CloudPrioritizationEngine`).
  * Non-destructive policy boundaries (`CloudSecurityPolicy`) enforcing allowed methods (`GET`, `HEAD`, `OPTIONS`), blocking metadata probing (`169.254.169.254`), and flagging write actions without executing uploads.
  * Atomic state persistence (`CloudStateManager`) storing state at `state/cloud.json` with sensitive token redaction.
* **Deterministic Local Cloud Security Lab (`LocalCloudSecurityLab`)**:
  * 15 deterministic, in-memory, 100% offline scenarios demonstrating S3/Blob/GCS read and listing, dangling CNAME takeovers, admin interfaces, and false positive rejections.
* **CLI Wrapper (`scripts/bb-cloud`, `scripts/bb-cloud.cmd`)**:
  * Native commands for `--tree`, `--json`, `--passive-only`, `--dry-run`, `--resume`, `--validate`, and `--lab`.
* **System Diagnostics & OpenCode Integration**:
  * Updated `framework/tools/doctor.py` and `scripts/bb-doctor` with Category 22: Cloud Security Intelligence.
  * Added permission rule `*bb-cloud*` with `ask` effect to `opencode.jsonc`.
  * Comprehensive update of `skills/cloud-security/SKILL.md`.

---

## [1.1.1] - 2026-10-04

### OpenCode V2 Runtime Compatibility & Permission Alignment

#### Changed
* **OpenCode V2 Permission Model (`opencode.jsonc`)**:
  * Migrated from legacy syntax to official OpenCode V2 ordered rules array (`action`, `resource`, `effect`, `description`).
  * Enforced OpenCode V2 "last matching rule wins" precedence logic.
  * Baseline safety: broad shell commands default to human approval (`ask`).
  * Safe local operations (`bb-scope-check`, `bb-target-normalize`, `bb-init`, `bb-doctor`, `bb-evidence`, `git status/diff/log`, `--dry-run`, `--check`) granted automatic execution (`allow`).
  * Active security reconnaissance, HTTP interactions, Nuclei, fuzzing, and host-modifying tool installations (`bb-install`, `bb-update`) strictly approval-gated (`ask`).
  * External report submission (`*submit*report*`, platform APIs for HackerOne, Bugcrowd, Intigriti) and unverified remote curl pipes strictly denied (`deny`).
  * Remote repository modifications (`git push`) strictly approval-gated (`ask`).
* **Agent Frontmatters (`.opencode/agents/`)**:
  * Configured `bb-hunter` with `mode: primary`.
  * Configured all 13 specialist agents with `mode: subagent`.
  * Restricted `bb-scope` to offline-only execution (`*` denied, only scope validation allowed).
  * Restricted `bb-report` to local report generation only (denied external submission and git push).
* **System Diagnostics (`framework/tools/doctor.py`, `scripts/bb-doctor`)**:
  * Added validation of OpenCode V2 configuration, agent modes, subagent depth, and permission rules count.
  * Explicitly reports OpenCode runtime status (`PENDING - requires Kali` when tested on development host).

#### Added
* **Automated OpenCode V2 Test Suite (`tests/test_opencode_runtime.py`)**:
  * 14 tests validating V2 configuration structure, last-matching-rule-wins permission evaluation, safe vs active operation categorization, dangerous command rejection, agent frontmatter compliance, skill discovery, and shell injection prevention (67 tests total, 100% passing).

---

## [1.1.0] - 2026-10-03

### Tool Intelligence, Auto-Install & API Provider Expansion — V1.1

#### Added
* **Central Tool Registry (`config/tools.yaml`)**:
  * 44 curated, actively maintained bug bounty tools indexed by tier (`CORE`, `SPECIALIST`, `PROVIDER-BACKED`, `OPTIONAL`, `LEGACY`).
  * Machine-readable metadata: binary names, categories, capabilities, dependencies, fallbacks, install options, verify commands, and documentation links.
* **Wordlist Registry (`config/wordlists.yaml`)**:
  * Curated wordlists for subdomains, web content, API routes, parameter discovery, and public trusted DNS resolvers.
* **Tool Intelligence & Architecture (`framework/tools/`)**:
  * `ToolRegistry`: Validates and indexes tools and capability tags.
  * `CapabilityGraph`: 23 capability domains, category matching, aliases, and intelligent fallback resolution (e.g. `katana` -> `hakrawler`, `subfinder` -> `amass`, `ffuf` -> `feroxbuster`).
  * `DependencyResolver`: Topological sorting for tool-to-tool prerequisites (`shuffledns` -> `massdns`) and runtime environments (`playwright` -> browser binaries, Go, Python/pipx).
  * `ToolDetector`: Host OS, architecture (`amd64`, `arm64`, `386`), binary path resolution, and semantic version validation.
  * `ProviderManager`: Secure credential discovery strictly outside Git (`~/.config/bugbounty-agent/secrets.env`), status reporting without secret exposure.
  * `ToolInstaller`: Safe, deterministic on-demand installation (`apt`, official releases, `go`, `pipx`, `cargo`) with provenance audit logging.
  * `SystemDoctor`: Complete environment diagnostic engine covering 9 categories.
  * `ToolUpdater`: Outdated version inspection and safe update planning.
* **CLI Additions (`scripts/`)**:
  * `bb-doctor` (+ `.cmd`): System health and diagnostic check across 9 categories.
  * `bb-install` (+ `.cmd`): On-demand tool installer supporting individual tools and capability-driven installs.
  * `bb-update` (+ `.cmd`): Tool version checker and updater.
* **13 Dedicated Provider Setup Guides (`docs/tools/`)**:
  * `subfinder.md`, `chaos.md`, `uncover.md`, `interactsh.md`, `shodan.md`, `censys.md`, `securitytrails.md`, `virustotal.md`, `urlscan.md`, `github.md`, `wpscan.md`, `notify.md`, `projectdiscovery-cloud.md`.
* **Master Documentation & README**:
  * Complete 44-tool catalog table with tiers, API key status, auto-install flags, and documentation links.
  * Tools grouped into 23 functional research domains.
  * Comprehensive documentation of automatic detection, installation, updates, credentials, and fallbacks.
* **Automated Test Suite Expansion**:
  * 27 new tests covering registry parsing, capability graph, dependencies, installer planning, security invariants, providers, and doctor diagnostics (53 tests total, 100% passing).

---

## [1.0.0] - 2026-10-03

### Initial Release — BugBounty-Agent V1

#### Added
* **OpenCode Native Architecture**:
  * 14 specialized agents in `.opencode/agents/` led by `bb-hunter`.
  * 14 modular methodology skills in `.opencode/skills/`.
  * Project configuration in `opencode.jsonc` with granular permission model.
  * Hierarchical documentation in `AGENTS.md`.
* **Scope Engine**:
  * Exact domain, wildcard (`*.example.com`), URL prefix, and CIDR/IP evaluation.
  * Arbitrary-depth recursive subdomain evaluation with configurable `max_depth`.
  * DNS-label boundary verification preventing substring spoofing.
  * Strict precedence: Explicit Exclusion > Specific Inclusion > Recursive/Wildcard Inclusion > Ambiguous.
* **Persistent Research State**:
  * Machine-readable state for assets, endpoints, technologies, hypotheses, and tests.
  * Stable test fingerprinting to eliminate redundant scans.
  * Finding deduplication across root cause, endpoint, and vulnerability class.
* **Controlled CLI Layer**:
  * `bb-init`, `bb-scope-check`, `bb-target-normalize`, `bb-recon`, `bb-http`, `bb-content`, `bb-js`, `bb-api`, `bb-nuclei`, and `bb-evidence`.
  * Windows CMD shims for cross-platform execution.
* **Evidence Management**:
  * Cryptographic SHA-256 integrity hashing of HTTP interactions.
  * Automatic regex redaction of Bearer tokens, API keys, and session cookies.
* **Reporting**:
  * 17-section standard disclosure report generator.
* **Automated Test Suite**:
  * Unit and integration test coverage across scope, recursive depth, normalization, deduplication, finding lifecycle, and runtime isolation.
