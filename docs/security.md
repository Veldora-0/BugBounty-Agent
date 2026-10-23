# BugBounty-Agent — Safety, Ethics & Security Controls

BugBounty-Agent is intended **strictly for authorized security research** under established bug bounty programs or explicit written authorization.

---

## 1. Hard Architectural Safeguards

The framework code enforces the following non-negotiable architectural boundaries:

1. **No Automated Denial of Service**: The framework strictly prohibits stress testing, volumetric HTTP flooding, or algorithmic complexity exhaustion.
2. **No Destructive Exploitation**: No database drops (`DROP TABLE`), record deletions, disk overwrites, or operating system state alterations.
3. **No Credential Attacks**: Password spraying, credential stuffing, and brute-force dictionary attacks against authentication interfaces are forbidden.
4. **No Unauthorized Third-Party Probing**: Discovered dependencies (shared CDNs, SaaS services, analytics endpoints) are strictly filtered out unless explicitly authorized in `scope.yaml`.
5. **No Malware or Persistence**: No shellcode deployment, rootkits, backdoors, or persistence mechanisms are included or permitted.
6. **No Automated Report Submission**: The framework writes disclosure reports to local files (`reports/`) for manual human review and verification. It never interfaces with platform submission APIs without human review.

---

## 2. Sensitive Data & Secret Protection

1. **Automatic Redaction**:
   * Authorization tokens (`Bearer ...`), API keys, and session cookies (`sessionid=...`) are automatically sanitized to `[REDACTED_BY_BB_AGENT]` before persisting to disk or generating reports.
2. **Git Tracking Barrier**:
   * `.gitignore` covers `.env`, `credentials/`, `evidence/`, `scans/`, `targets/`, `*.burp`, `*.key`, and `*.token`.
   * Real target data and secrets must never be added to repository commits.
3. **Pre-Commit Verification**:
   * Before committing, verify git status to confirm no local target data or runtime files are tracked.

---

## 3. Authentication & Identity Testing Safeguards (Phase 14)

1. **Researcher-Controlled Accounts Only**:
   * All authentication, session, password-reset, and MFA testing is performed strictly against explicitly designated, researcher-controlled accounts.
   * Never send password reset requests or verification emails to third-party accounts.
2. **Explicitly Prohibited Operations**:
   * **Zero** password spraying, credential stuffing, password guessing, or dictionary attacks.
   * **Zero** token brute forcing, OTP brute forcing, or OTP flooding.
   * **Zero** CAPTCHA bypass, SIM swap attacks, or attacks against third-party Identity Providers (IdPs).
   * **Zero** mass account enumeration or automated account takeover attempts.
3. **Human Approval Gate (`AuthenticationApprovalGate`)**:
   * State-mutating operations (password reset submission, password changes, MFA enrollments, session revocations) require explicit `--approve` operator confirmation and produce an audit dossier before execution.
4. **Credential Redaction Invariant**:
   * Passwords, live session cookies, refresh tokens, and bearer tokens are never persisted in state files or reports; only cryptographic SHA-256 fingerprint references (`sess_sha256_...`) are tracked.

---

## 4. Browser Runtime & Client-Side Security Safeguards (Phase 16)

1. **Opt-In Headless Automation**:
   * Browser execution is strictly disabled by default (`browser_enabled=False`). It is only activated for canary-correlated proof confirmation and bounded SPA analysis.
2. **Local Validating Egress Proxy (`ValidatingEgressProxy`)**:
   * Egress traffic is directed to an ephemeral loopback proxy (`127.0.0.1:<port>`) with `--proxy-bypass-list=<-loopback>` to prevent Chromium from bypassing loopback proxying.
   * Eliminates the DNS TOCTOU rebinding window by resolving destination hostnames pre-flight, verifying all resolved IPs against private/metadata SSRF prohibitions, and connecting upstream sockets directly to the pinned numeric IP tuple.
3. **Pre-Handshake WebSocket & Transport Enforcement**:
   * Pre-handshake WebSocket routing (`BrowserContext.route_web_socket`) intercepts all `ws://` and `wss://` connections at the browser engine level. When `allow_websockets=False`, connections are closed with code 1008 without calling `ws_route.connect_to_server()`, strictly preventing the WebSocket handshake from reaching the server.
   * At the transport layer, `ValidatingEgressProxy` validates destination host/IP, enforces anti-SSRF literal and DNS checks, and pins the connection to the validated numeric IP tuple before establishing any upstream socket, blocking unauthorized destinations pre-connection.
   * `BrowserNetworkPolicy.handle_websocket` operates as secondary post-handshake defense-in-depth across child pages and unrouted contexts.
4. **Multi-Vector Routing & Service Worker Blocking**:
   * Centralized route interception covers main navigation, HTTP redirects, child iframes, background subresources, and popups.
   * Browser contexts block Service Workers (`service_workers="block"`) to prevent unintercepted background cache network requests.
5. **Bounded Deadlines & Unicode-Safe Evidence**:
   * Enforces monotonic wall-clock execution deadlines and strict caps on requests, redirects, and SPA route transitions.
   * Evidence summaries enforce UTF-8 encoded byte ceilings (`truncate_to_max_bytes`) to prevent multi-byte Unicode memory leaks while preserving evidence markers.
6. **Application-Level vs. OS-Level Network Isolation**:
   * Proxy routing and Chromium isolation flags enforce strict application-level boundaries against web-tier SSRF and XSS callbacks.
   * Operating system network isolation (e.g., Linux network namespaces `ip netns`) should be deployed in production environments requiring protection against native browser escape vulnerabilities.

---

## 5. API Security & Streaming Byte-Budget Safeguards (Phase 17)

1. **Continuous Streaming Byte-Budget Accounting**:
   * Global network-byte accounting (`total_bytes_transferred`) tracks every consumed byte continuously.
   * Failed, malformed, oversized, truncated, or rejected responses consume the budget to prevent runaway bandwidth consumption.
   * Streaming responses exceeding `max_bytes` are aborted mid-flight.
2. **Loopback Fixture Port Authorization**:
   * Testing against local loopback ports requires explicit unprivileged integer port registration (`1024-65535`) and scope authorization.
   * Production targets strictly forbid loopback, private RFC 1918, carrier-grade NAT, or cloud metadata addresses.
   * Explicit scope exclusions take strict precedence over fixture port allowances and target inclusions.
3. **Bounded GraphQL & OpenAPI Reference Ingestion**:
   * Active GraphQL introspection is strictly opt-in (`allow_graphql_introspection=True`, default disabled) with depth and parameter bounds.
   * OpenAPI reference resolution (`$ref`) is restricted to local/relative pointers up to depth 10 with circularity detection; external network references fail closed.

---

## 6. SSRF, XXE & Server-Side Parser Safeguards (Phase 18)

1. **Agent-Side XML Parser Hardening**:
   * Internal XML parsing (`framework/common/xml_safe.py`) enforces strict cumulative character expansion ceilings (`max_expanded_chars`), Expat amplification factor defenses, and Billion Laughs / quadratic blowup protection.
   * Sitemap and XML parser errors fail closed immediately with zero insecure fallback.
2. **Anti-SSRF Transport & Alternate Numeric IP Protection**:
   * `parse_alternate_ip` unmaps and validates alternate numeric representations (dotted decimal, decimal scalars, hex scalars, octal scalars, dotted octal/hex, and inet_aton multi-part formats).
   * Destination IP resolution fails closed if any DNS answer resolves to loopback, private RFC 1918, carrier-grade NAT, or cloud metadata addresses (`169.254.169.254`, `metadata.google.internal`).
3. **Out-of-Band Canary Gating & Destination Trust Boundary**:
   * OOB provider availability verification: provider status must be `AVAILABLE` before canary issuance or probe dispatch; fails closed for `UNAVAILABLE`, `CONFIG_REQUIRED`, or `ERROR` with zero network requests dispatched.
   * Generated canary destinations are validated against `validate_oob_destination()` in `SecurityTestPolicy`, which verifies that the method exists and is callable; missing or non-callable methods fail closed with `PolicyViolationError`, record `POLICY_VIOLATION` candidate state, and dispatch zero requests.
   * Canary destinations strictly forbid unauthorized domains, IP literals (including alternate encodings and IP-suffix tricks), and cloud metadata destinations.
4. **Truthful Evidence Classification**:
   * Mock provider interactions strictly emit `SIMULATED` (`INFORMATIONAL`, `LOW` confidence) findings and can never become live validated findings.
   * Internal entity reflection alone emits an `OBSERVATION` (`INFORMATIONAL`, `MEDIUM` confidence), never a false `HIGH`-severity `VALIDATED` XXE finding.
   * Parser errors and secure DTD prohibitions emit zero findings.
   * Zero sensitive local file extraction (`file://`, `/etc/passwd`, `/etc/shadow`, `win.ini`) or cloud metadata probing (`169.254.169.254`, `metadata.google.internal`) is permitted; any matching target fails closed immediately.
   * All active SSRF and XXE validation requires prior explicit human approval (`approval_status == 'APPROVED'`). Automated exploitation and automatic report submission are strictly prohibited.

---

## 7. Infrastructure & Configuration Exposure Safeguards (Phase 19)

1. **Strictly Safe Read-Only Methods**:
   * Probing is strictly limited to safe, idempotent HTTP methods (`GET`, `HEAD`, `OPTIONS`).
   * `POST`, `PUT`, `DELETE`, `PATCH`, and `TRACE` methods are strictly prohibited.
   * State-changing GET query parameters (e.g., `?action=delete`, `?logout=true`, `?drop=true`) are blocked by policy.
2. **Evidence-Sufficiency Stopping Rules**:
   * General HTTP responses are capped at a 32 KB ceiling (`max_response_bytes = 32_768`).
   * Configuration files (`.env`, `web.config`) are evaluated within an 8 KB ceiling (`max_config_bytes = 8_192`).
   * Backup archives (`.zip`, `.tar.gz`) are verified using only the first 1 KB binary magic bytes (`max_binary_magic_bytes = 1_024`) to establish archive structure without downloading the archive file.
   * Streaming response consumption continuously decrements the byte budget.
3. **Secret Redaction & Sanitization Invariant**:
   * Discovered configuration values, tokens, database passwords, and API secrets are automatically replaced with `[REDACTED_BY_BB_AGENT]` before persistence to state (`state/infrastructure.json`), inclusion in finding objects, or report generation.
   * Cryptographic SHA-256 evidence fingerprints authenticate the sanitized record representation, guaranteeing zero secret persistence.
4. **Conservative Classification & False-Positive Defenses**:
   * Standard administrative login interfaces (forms with username/password inputs) are expected functionality and are classified strictly as `OBSERVATION` (`INFORMATIONAL`, `HIGH` confidence), never as high-severity exposures.
   * HTTP 403 Forbidden responses are classified as `OBSERVED` / `ACCESS_RESTRICTED` (confirming active authorization controls), preventing false exposure reports.
   * Differential soft-404 comparisons against application-subpath baselines strip volatile nonces/timestamps and require structural distinctness before any candidate is promoted.
   * Local simulation lab findings are strictly marked `SIMULATED` (`INFORMATIONAL`, `CONFIRMED` confidence) and can never produce live validated findings.
   * Broad directory brute-forcing, password guessing, and automated vulnerability report submissions are strictly forbidden.

---

## 8. Concurrency & Distributed Workflows Safeguards (Phase 20)

1. **Precision Barrier Synchronization Over Volumetric Flooding**:
   * Race condition testing uses precision barrier synchronization (`threading.Barrier`) to hold pre-armed parallel worker threads and release them simultaneously into the server-side microsecond execution window.
   * Eliminates the need for high-volume request floods, stress testing, or volumetric denial-of-service.
2. **Strict Concurrency Bounds & Clamping**:
   * Probes are strictly bounded to 2–5 parallel threads (`DEFAULT_BURST_SIZE = 4`), with a hard, un-overrideable safety cap of 10 (`MAX_BURST_SIZE = 10`).
   * Maximum requests per test are capped at 15 (`MAX_REQUESTS_PER_TEST = 15`), preventing runaway retry loops or server-side exhaustion.
   * Prohibits destructive HTTP methods (`TRACE` is strictly blocked by policy).
3. **Contention vs. Vulnerability Invariant Discrimination & Evidence Standards**:
   * Findings are strictly disallowed from being classified as `CONFIRMED` based solely on HTTP status code counts (`success_count > allowed_limit`).
   * Confirmation requires reliable proof of business-state mutation:
     * Distinct committed resource identifiers returned across concurrent responses (e.g. distinct `order_id`, `redemption_id`, `vote_id`, `tx_id`).
     * Server post-state verification confirming multiple mutations (e.g. server counter > limit, or negative balance).
     * Verified inconsistent state or failed rollback evidence for distributed workflows (`inconsistent_state: true`).
   * Idempotent duplicate responses returning cached results or identical representations are classified as `CONCURRENCY_CONTROLLED`.
   * Identical responses with no mutation proof and missing/malformed post-state evidence are classified strictly as `INCONCLUSIVE`, never `CONFIRMED`.
   * Valid server-side serialization defenses (HTTP 409 Conflict, 429 Too Many Requests, 423 Locked) and mutex lock rejections are recognized as evidence of proper concurrency controls (`CONCURRENCY_CONTROLLED`) and are never reported as vulnerabilities.
   * Network timeouts (504 Gateway Timeout, connection drops) are classified strictly as `INCONCLUSIVE` without false positive alarms.
4. **Offline & Transport Scope Enforcement & Anti-SSRF Protections**:
   * Scope verification executes offline before dispatching any concurrent probes; out-of-scope targets fail closed immediately.
   * In production mode, active probe dispatching strictly fails closed if `ScopeEngine` is missing, throws errors, or target is out of scope. Checks execute immediately before each dispatch in `_send_request_safe()`.
   * Destination IPs and hostnames are validated against private RFC 1918, carrier-grade NAT, and cloud metadata addresses (`169.254.169.254`, `metadata.google.internal`).
   * Local test fixtures require explicit unprivileged integer port whitelisting (`allow_fixture_port()`).
   * Worker lifecycle timeout and late-response lockout: completion of worker threads is tracked explicitly; late-finishing threads are locked out via completion events and cannot mutate finalized test state.
5. **Operator Approval Gate & Zero Plaintext Secret Persistence**:
   * Concurrent state mutation testing requires explicit operator approval (`--approve`) when `require_approval=True`.
   * Passwords, tokens, API keys, and sensitive parameters are recursively scrubbed to `[REDACTED_BY_BB_AGENT]` before persistence to `state/concurrency.json`.
   * Network and transport exceptions are mapped to sanitized generic categories via `_classify_request_exception` without exposing raw URLs, query strings, headers, or credentials in reasons, evidence, logs, findings, or reports.

