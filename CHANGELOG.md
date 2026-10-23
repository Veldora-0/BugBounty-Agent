# Changelog

All notable changes to the BugBounty-Agent project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Phase 20: Race Conditions & Distributed Workflows Intelligence (Accepted with Documented Limitations)

#### Added & Hardened
* **Concurrency & Race Conditions Subsystem (`framework/concurrency/`)**:
  * Implemented core models (`RaceCategory`, `RaceConfidence`, `SingleProbeExecution`, `ConcurrencyProbePlan`, `RaceConditionHypothesis`, `RaceConditionTestResult`).
  * Defined 6 core categories: `LIMIT_OVERRUN`, `TOCTOU`, `DOUBLE_SPEND`, `IDEMPOTENCY_BYPASS`, `PARTIAL_EXECUTION_DESYNC`, and `CONCURRENT_STATE_MUTATION`.
* **Precision Barrier Synchronization (`BarrierSynchronizer`)**:
  * Employs `threading.Barrier` to pre-arm parallel worker threads and trigger release simultaneously inside the microsecond server execution window.
  * Replaces volumetric flooding, algorithmic stress testing, and DoS attacks with surgical, bounded parallel probes.
* **Resource Identity, Counter Isolation & Candidate Invariant Calibration (Blocker B — `ResourceIdentityTracker`, `ConcurrencyInvariantEngine`)**:
  * Added `ResourceIdentityTracker` with category-prioritized primary key resolution (`order_id`, `redemption_id`, `vote_id`, `tx_id`, `id`).
  * Enforced field-alias deduplication (e.g. `order_id: ORD-1` and `id: ORD-1` in the same response resolve to a single resource entity).
  * Isolated resource identity sets from scalar counters (`items_count: 2`), response status counts, and nonces/timestamps.
  * Distinct provisional response identifiers (e.g. `order_id: ORD-1`, `ORD-2`) alone without authoritative post-state evidence are strictly evaluated as `RaceConfidence.SUSPECTED` (`FindingLifecycle.OBSERVED`, `"INFORMATIONAL"`), never `CONFIRMED`.
  * Invariant validation enforces category-specific counter mapping (`category_counter_map`: `coupon_redemptions` for `DOUBLE_SPEND`, `voting_count` for `LIMIT_OVERRUN`, `order_count` for `IDEMPOTENCY_BYPASS`, `account_balance` for `TOCTOU`) against server post-state.
  * Strictly disallows classifying findings as `CONFIRMED` based solely on HTTP status code counts; requires reliable business-state mutation proof or verified distributed rollback failure.
  * Distinguishes idempotent duplicate representations from duplicate processing (`CONCURRENCY_CONTROLLED` vs `CONFIRMED`).
  * Normal server concurrency defenses (HTTP 409 Conflict, 429 Too Many Requests, 423 Locked) and timeouts strictly evaluate as `CONCURRENCY_CONTROLLED` or `INCONCLUSIVE`.
* **Cryptographic Evidence Provenance Trust Boundary & Full Envelope Attestation (Critical Findings A & B — `EvidenceEnvelope`, `canonical_serialize_envelope()`, `PostStateEvidence`, `LocalConcurrencyLab`)**:
  * Completely eliminated public caller-supplied authoritative evidence factories (`create_authoritative_evidence()`), preventing any caller or test from signing arbitrary untrusted state.
  * Authoritative evidence is strictly issued through genuine observations from an active `LocalConcurrencyLab` instance (`start_observation()`, `complete_observation()`, `capture_evidence()`, `get_authoritative_state()`) bound to its server state and validated port.
  * Implemented `EvidenceEnvelope` (version `concurrency-evidence-v1`) binding all 9 decision-relevant fields (`schema_version`, `observation_id`, `source`, `endpoint`, `verified_at`, `pre_state`, `post_state`, `delta_metrics`, `provenance_details`).
  * Enforced canonical deterministic serialization (`canonical_serialize_envelope()`) with lexicographical key ordering, strict primitive type verification, and deterministic JSON separators.
  * Authenticated with HMAC-SHA256 using the process-private key `_LAB_TRUST_KEY`. Any post-attestation modification of any field or nested dictionary causes immediate verification failure (`is_authoritative() == False`).
  * Deserialized external payloads (`PostStateEvidence.from_dict()`) are strictly forced to `UNTRUSTED_CALLER_CLAIM` and stripped of attestation tokens.
  * Verified endpoint validation ensures evidence originates only from active local lab instances on loopback addresses.
* **Pre-State Baselines, Delta Calculations & Monotonic Progression (Critical Finding C — `ConcurrencyInvariantEngine`, `RaceIntelligenceEngine`)**:
  * Bound observations to unique per-execution identities (`observation_id = obs-{hypothesis.hypothesis_id}-{uuid}`), capturing trusted pre-state baselines prior to burst dispatch and extracting post-state directly upon completion while completely preventing cross-run baseline collisions.
  * Ensured every started observation reaches exactly one safe terminal outcome (Completed, Discarded, or Failed-Closed) via idempotent `LocalConcurrencyLab.discard_observation()` and execution engine `try...finally` guards, preventing state leakage on exceptions, timeouts, or externally supplied caller evidence.
  * Rejected duplicate active observation IDs safely with `ValueError` to prevent silent baseline replacement under concurrent starts.
  * State-based counter invariants (`LIMIT_OVERRUN`, `DOUBLE_SPEND`, `IDEMPOTENCY_BYPASS`) evaluate exact per-test counter deltas ($\Delta = \text{post} - \text{pre}$) rather than raw cumulative counters.
  * Unbaselined post-state counter observations strictly fail safe to `RaceConfidence.SUSPECTED` or `INCONCLUSIVE`, never `CONFIRMED`.
  * Decreasing counters for strictly increasing metrics violate monotonic progression invariants and immediately fail closed to `INCONCLUSIVE`.
  * Contradictory pre/post state fails consistency checks before authority checks, preventing untrusted contradictory state from bypassing validation.
* **Worker Lifecycle, Monotonic Deadlines & Container Sealing (Blocker C — `BurstExecutionContainer`, `WorkerLifecycleState`)**:
  * Modeled explicit lifecycle states: `COMPLETED`, `FAILED`, `TIMED_OUT_UNRESOLVED`, and `CANCELLED`.
  * Replaced cumulative linear worker thread joins with a single monotonic overall deadline (`time.monotonic() + timeout + 1.0`). Workers unresolved at deadline transition to `TIMED_OUT_UNRESOLVED` and propagate to `INCONCLUSIVE`.
  * Formally documented Python thread cancellation limits (lack of preemptive worker cancellation in stdlib threading).
  * `BurstExecutionContainer.seal()` permanently seals test containers upon join completion, preventing late-finishing background threads from mutating finalized test results.
  * Unique thread naming pattern `bb-race-worker-{i}-{burst_id}` eliminates thread tracking collisions across bursts.
* **Per-Hypothesis Request Budget Isolation (Blocker D — `HypothesisBudgetContext`)**:
  * Replaced shared instance counters with thread-safe `HypothesisBudgetContext` instances bound to individual hypotheses.
  * Enforces hard ceiling of 15 requests per test case (`MAX_REQUESTS_PER_TEST = 15`), preventing parallel hypotheses from leaking, starving, or resetting shared request allocations.
* **Fail-Closed DNS Resolution & Prohibited Address Ranges (Blocker E — `resolve_destination`)**:
  * Preflight DNS resolution enforces strict fail-closed safety: resolution errors, empty resolution results, and malformed IP strings raise `PolicyViolationError`.
  * Preflight resolution validates every resolved IP address against RFC 1918 private subnets, loopback (`127.0.0.0/8`), carrier-grade NAT (`100.64.0.0/10`), cloud metadata (`169.254.169.254`), IPv6 equivalents (`::1`, `fc00::/7`, `fe80::/10`), and IPv4-mapped IPv6 ranges (`::ffff:127.0.0.1`, etc.).
  * Added pluggable `resolver` hook to facilitate isolated, deterministic unit testing.
  * Formally documented DNS rebinding limitation: Python standard HTTP transport does not pin socket IPs, recommending validating egress proxies or network namespaces for high-risk targets.
* **Concurrent Observation Attribution & Overlap Guard (`LocalConcurrencyLab`, `ConcurrencyInvariantEngine`, `EvidenceEnvelope`)**:
  * Implemented `_measurement_lock` (`threading.RLock`) in `LocalConcurrencyLab` and acquired it in `RaceIntelligenceEngine.execute_hypothesis()` to serialize observation measurement critical sections across executions, ensuring clean sequential observation windows on shared mutable lab state while preserving full barrier-synchronized parallel worker execution within each burst.
  * Added fail-closed overlap attribution guard: `LocalConcurrencyLab.start_observation()` detects any concurrently active observations (`len(_active_observations) > 0`) and marks all overlapping observations with `has_overlap = True`.
  * Integrated `has_overlap` directly into canonical serialization (`canonical_serialize_envelope()`) and `EvidenceEnvelope`. Any post-attestation modification of `has_overlap` invalidates HMAC verification.
  * `ConcurrencyInvariantEngine.evaluate_burst_results()` logs overlapping measurement windows and immediately fails closed to `RaceConfidence.INCONCLUSIVE` (`is_vulnerable = False`, `FindingLifecycle.OBSERVED`) whenever `post_state_evidence.has_overlap == True`, preventing false positive findings from concurrent observation interference.
* **Deterministic Local Simulation Lab (`LocalConcurrencyLab`)**:
  * Multi-threaded `ThreadingHTTPServer` serving 8 deterministic concurrency scenarios on an ephemeral loopback port (`127.0.0.1:0`).
  * Scenarios: coupon double-spend, balance transfer overdraw, voting limit overrun, idempotency race, mutex serialization (409), rate limit defense (429), gateway timeout (504), and distributed desync (500).
  * Added `get_authoritative_state()` returning HMAC-attested `LAB_FIXTURE_AUTHORITATIVE` post-state evidence.
* **Safe State Management & Secret Scrubbing (`ConcurrencyStateManager`)**:
  * Atomic persistence of program-scoped state in `state/concurrency.json` with schema self-healing and Windows retry handling.
  * Recursive sanitization of credentials, passwords, tokens, and authorization parameters (`[REDACTED_BY_BB_AGENT]`).
  * Exception sanitization via `_classify_request_exception` ensuring zero raw exception strings or secrets leak into state, logs, findings, or reports.
* **CLI Wrapper, System Diagnostics & OpenCode Integration**:
  * Created CLI utility `scripts/bb-race` and `scripts/bb-race.cmd` supporting `--lab`, `--tree`, `--burst`, `--approve`, `--dry-run`, and `--json`.
  * Added Category 25 (`check_concurrency_engine`) to `framework/tools/doctor.py` and `scripts/bb-doctor`.
  * Added `*bb-race*` permission rule to `opencode.jsonc`.
  * Extended `framework/state/manager.py` with `DEFAULT_CONCURRENCY` and synchronized `concurrency.json` into canonical findings.
  * Linked `bb-race` across deployment utilities (total 28 utilities).
* **Automated Test Suite**:
  * Expanded to 107 unit and integration tests in `tests/test_concurrency_engine.py` (and 154 tests across the full repository test suite) covering taxonomy, barrier timing, invariant rules, evidence classification hardening, full-envelope HMAC attestation, pre-state baselines, counter deltas, observation lifecycle integrity, execution-bound unique observation IDs, cross-run baseline isolation, measurement window serialization, fail-closed `has_overlap` attribution guards on overlapping observations, scope fail-closed architecture, request budget bounds, worker lifecycle timeout handling, all 8 lab scenarios, secret scrubbing, and disk report inspection.

### Phase 19: Infrastructure & Configuration Exposure (Accepted with Documented Limitations)

#### Added & Hardened
* **Infrastructure Intelligence Engine (`framework/infrastructure/`)**:
  * Added core models, signatures, differential soft-404 analyzer, safe active evaluator, engine orchestrator, atomic state manager, and local lab simulation harness.
  * Added `INFRASTRUCTURE_EXPOSURE` and `CONFIGURATION_EXPOSURE` to `VulnerabilityFamily`.
  * Implemented support for 8 exposure classes: `VERSION_CONTROL` (`.git/HEAD`, `.svn/entries`), `CONFIG_FILE` (`.env`, `web.config`), `BACKUP_ARCHIVE` (`.zip`, `.tar.gz`), `ADMIN_INTERFACE` (`actuator/health`, `admin`), `DEPLOYMENT_MANIFEST` (`package.json`, `composer.json`), `SOURCE_MAP` (`*.js.map`), `DIRECTORY_LISTING` (`Index of /`), and `DEBUG_INTERFACE` (debug traces).
* **Differential Soft-404 Engine (`DifferentialSoft404Engine`)**:
  * Implemented differential comparison against application-subpath baselines with dynamic token stripping (nonces, timestamps, CSRF tokens, hashes) and token Jaccard similarity.
  * Strictly enforces the non-rejection invariant: candidates are never rejected solely because a baseline probe returned HTTP 200.
  * Handles SPA catch-all, distinct static files, dynamic error pages, and redirect catch-all patterns.
* **Evidence-Sufficiency Stopping Rules**:
  * Capped general HTTP response bodies at 32 KB (`max_response_bytes = 32_768`).
  * Evaluated configuration files within an 8 KB ceiling (`max_config_bytes = 8_192`).
  * Evaluated backup archives using strictly the first 1 KB binary magic bytes (`max_binary_magic_bytes = 1_024`); zero full archive downloads.
* **Fail-Closed Safety Policy & Transport Controls (`InfrastructureExposurePolicy`)**:
  * Restricted HTTP methods strictly to safe, idempotent read-only methods (`{"GET", "HEAD", "OPTIONS"}`).
  * Policy blocks state-changing GET queries and `POST`/`PUT`/`DELETE`/`TRACE` methods.
  * Enforced pre-dispatch ScopeEngine authorization and anti-SSRF loopback/private/metadata protections.
* **Sensitive Data Redaction & Zero Secret Persistence**:
  * Automated sanitization of discovered secret values, API keys, and passwords across state (`state/infrastructure.json`), finding objects, and markdown reports.
  * Authenticated evidence fingerprints over sanitized representation (SHA-256).
* **Deterministic Simulation Lab (`LocalInfrastructureLab`) & Regression Suite**:
  * Implemented 16 deterministic scenarios on ephemeral loopback ports.
  * Added 39 comprehensive tests in `tests/test_infrastructure_engine.py` covering all 16 scenarios, differential classes, stopping rules, secret scrub, and policy enforcement.
* **CLI Wrapper, System Diagnostics & OpenCode Integration**:
  * Created `scripts/bb-infra` (`scripts/bb-infra.cmd`) supporting `--tree`, `--passive-only`, `--dry-run`, `--approve`, `--json`, and `--lab`.
  * Added Category 24 (`check_infrastructure_engine`) to `framework/tools/doctor.py` and `scripts/bb-doctor`.
  * Added `*bb-infra*` permission rule to `opencode.jsonc`.

### Phase 18: SSRF, XXE & Server-Side Parser Expansion (Accepted with Documented Limitations)

#### Added & Hardened
* **Agent-Side XML Hardening (`framework/common/xml_safe.py`)**:
  * Implemented portable stdlib XML security (`safe_parse_xml`, `safe_extract_sitemap_urls`, `XmlBombSecurityError`, `ProhibitedDtdSecurityError`, `ExternalEntitySecurityError`) with strict cumulative expanded-character budgets (`max_expanded_chars`), Expat amplification factor defenses, and Billion Laughs protection.
  * Hardened webapp sitemap parser (`framework/webapp/engine.py`) to fail closed immediately on XML security errors with zero regex fallback.
* **SSRF Transport Hardening (`framework/common/transport.py`, `framework/validation/engine.py`)**:
  * Added `parse_alternate_ip` supporting dotted decimal, decimal scalars, hex scalars, octal scalars, dotted octal/hex, and inet_aton multi-part formats.
  * Hardened destination IP resolution to fail closed if any DNS answer resolves to loopback, private, carrier-grade NAT, or cloud metadata addresses.
  * Implemented continuous streaming byte accounting (`total_bytes_transferred`) across partial reads, redirects, and HTTP errors; added `max_total_bytes` policy control to `SecurityTestPolicy`.
* **SSRF Request Mutation (`framework/ssrf/engine.py`)**:
  * Expanded `_build_mutated_request()` supporting Query parameters, Path template parameters (`{param}`, `:param`), JSON bodies (flat and nested dotted keys), Form-encoded bodies, and XML bodies (DOM text replacement with XML entity escaping).
* **Conservative XXE Intelligence Subsystem (`framework/xxe/`)**:
  * Orchestrates non-destructive synthetic entity reflection, signal classification, deterministic local simulation harness (`LocalXxeLab`), state management (`xxe.json`), and deduplication.
  * Added `XXE = "XXE"` to `VulnerabilityFamily`, safe payloads `PL-XXE-REFL-01` and `PL-SSRF-CANARY-01`, and `XxeValidator` / `SsrfValidator` plugins in `SecurityValidationEngine`.
* **Evidence Semantics & Truthful OOB Availability**:
  * Internal entity reflection alone emits an `OBSERVATION` (`INFORMATIONAL`, `MEDIUM` confidence), never a false `HIGH`-severity `VALIDATED` XXE finding. Parser errors and secure DTD rejections emit zero findings.
  * Out-of-band correlation (`validate_oob_candidate`) differentiates mock test harness interactions (`SIMULATED`, `INFORMATIONAL`, `LOW` confidence) from live external target callbacks (`VALIDATED`, `HIGH`). Mock interactions can never produce live validated findings.
  * Truthful OOB Provider Availability: `InteractshOobProvider` and `CollaboratorOobProvider` report `CONFIG_REQUIRED` when unconfigured and `UNAVAILABLE` when configured (because live wire polling over network protocols is not implemented; storage is local in-memory only).
* **Enforced OOB Destination Trust Boundary & Method Verification**:
  * Prior to canary issuance or probe dispatch, verifies provider availability (`AVAILABLE`), failing closed for `UNAVAILABLE`, `CONFIG_REQUIRED`, or `ERROR` with zero network requests dispatched.
  * Validates generated canary destinations against `validate_oob_destination()` in `SecurityTestPolicy`, verifying that the method exists and is callable; fails closed with `PolicyViolationError`, sets `POLICY_VIOLATION` candidate state, and dispatches zero network requests if missing or non-callable.

### Phase 17: Advanced API Security (Accepted with Documented Limitations)

#### Added & Hardened
* **Bounded OpenAPI & GraphQL Specification Parsing (`framework/api/`)**:
  * Ingests OpenAPI 2.0, 3.0, and 3.1 specifications (JSON/YAML), recursively resolving RFC 6901 local and relative `$ref` pointers up to depth 10 with circular reference protection.
  * GraphQL surface detection and opt-in schema introspection (`allow_graphql_introspection=True`, default disabled), bounded to selection set depth $\le 6$, schema traversal depth $\le 3$, and max 5,000 parameters.
* **Continuous Streaming Byte-Budget Accounting**:
  * Tracks network egress continuously (`total_bytes_transferred`), ensuring malformed, oversized, truncated, or error responses deplete the global network byte budget (`max_bytes`).
* **Loopback Fixture Port Gating**:
  * Local testing against loopback fixtures strictly requires explicit unprivileged port registration (`1024-65535`) and scope authorization; production targets strictly forbid loopback, RFC 1918, and cloud metadata destinations. Dual-export state is maintained in `state/api.json`.

### Phase 16: Browser Runtime & Client-Side Security (Accepted with Documented Limitations)

#### Added & Hardened
* **Local Validating Egress Proxy (`ValidatingEgressProxy`)**:
  * Implemented an ephemeral loopback HTTP/CONNECT forward proxy with direct numeric IP pinning (`_connect_upstream`), closing the DNS TOCTOU rebinding window.
  * Enforced `--proxy-bypass-list=<-loopback>` to prevent Chromium from bypassing loopback proxying.
  * Pre-connection destination, SSRF, literal IP, DNS resolution, and scope checks across all HTTP, HTTPS, WS, and WSS requests before upstream connections can be created.
* **WebSocket Pre-Handshake & Pre-Connection Enforcement**:
  * Integrated Playwright's `BrowserContext.route_web_socket` to intercept `ws://` and `wss://` at the browser engine level; when `allow_websockets=False`, connections are closed with code 1008 without calling `connect_to_server()`, strictly preventing the WebSocket handshake from reaching the server.
  * Intercepted `Upgrade: websocket` and `CONNECT` requests at the transport proxy layer (`ValidatingEgressProxy`), validating destinations and pinning IPs before connection.
  * Configurable `allow_websockets` policy gating across proxy and browser contexts.
  * Retained `context.on("websocket")` as secondary post-handshake defense-in-depth audit/cleanup hook.
* **Execution Budgets & Safe Deadlines**:
  * Bounded browser session initialization with monotonic wall-clock deadlines.
  * Enforced multi-byte Unicode evidence byte limits (`truncate_to_max_bytes`) preserving evidence markers without memory growth.
* **Deterministic Test Suite (`tests/test_phase16_browser_runtime.py`)**:
  * Added 101 comprehensive unit and integration tests across Sections 15–19 verifying proxy fail-closed startup, anti-SSRF IP pinning, pre-handshake WebSocket routing, and Unicode truncation.

---

## [1.14.2] - 2026-10-10

### Phase 14.2: Authentication Validation Integrity & Executor Safety

#### Added & Improved
* **Request-Executor Safety & TLS Verification (`framework/authentication/executor.py`)**:
  * Restored standard TLS certificate and hostname verification (`ssl.create_default_context()`, `check_hostname=True`, `verify_mode=CERT_REQUIRED`) with fail-closed TLS error handling.
  * Destination-IP pinning at socket connection (`PinnedHTTPConnection`, `PinnedHTTPSConnection`) preserving TLS SNI and HTTP `Host` header, eliminating DNS rebinding / TOCTOU windows.
  * Safe environment proxy bypassing (`ProxyHandler({})`) preventing unauthorized ambient proxy interception.
  * Hardened anti-SSRF defenses including IPv4, IPv6, IPv4-mapped IPv6 (`::ffff:0:0/96`), link-local, and cloud metadata.
  * Per-redirect hop independent anti-SSRF and scope re-verification (`AuthSafeRedirectHandler`) with protocol downgrade prevention and 5-hop cap.
  * Zero-traffic guarantees in `--dry-run`, `--passive-only`, and `--hypotheses` modes.
* **Scope Resolution & Approval Gate Safety (`framework/authentication/policy.py`, `scripts/bb-auth`)**:
  * Eliminated unsafe current-working-directory scope fallbacks (`./scope/scope.yaml`, `./scope.yaml`); fail-closed on missing or ambiguous scope.
  * Tied approval gate to concrete operations (`PASSWORD_RESET_SUBMIT`, `PASSWORD_CHANGE`, `MFA_ENROLLMENT`); enforced strict invariant that operator approval never overrides scope boundaries.
* **Deterministic Fingerprints & State Storage (`framework/authentication/hypotheses.py`, `storage.py`, `models.py`)**:
  * Replaced random UUIDs with deterministic SHA-256 hypothesis IDs (`HYP-<family>-<hash>`) over family, endpoint, principal, and required state.
  * Resilient state loading distinguishing missing files from corrupted JSON, backing up corrupted files to `.corrupt.<timestamp>` and raising `CorruptedStateError`.
  * Recursive dictionary and JSON credential sanitization (`sanitize_dict`) in `AuthenticationEvidenceManager`.
  * Finding lifecycles assign `FindingLifecycle.VALIDATED` only on true operational differential proof; observation-only families remain `INFORMATIONAL`.
  * Surfaced finding persistence errors instead of silently discarding findings.
* **Genuine Validation Pipeline (`framework/authentication/engine.py`, `validators.py`)**:
  * Completely purged hardcoded synthetic mock strings (`sess_fixed_id`, synthetic JSON bodies) from real target evaluation paths.
  * Implemented authentic differential verification sequences for all 11 operational families.
  * Explicitly report `SKIPPED` / `MISSING_PREREQUISITES` or `CANDIDATE` when test credentials or sessions are missing.
  * Updated tree rendering and CLI summaries to visually distinguish verified findings, informational notes, unverified candidates, and skipped hypotheses.
* **Comprehensive Test Suite (`tests/test_authentication_engine.py`)**:
  * Added negative control tests with local HTTP fixture server.
  * Added zero-traffic assertions, proxy isolation, and DNS rebinding pinning tests (total 47 tests passing in suite; 346 passing repo-wide).

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
