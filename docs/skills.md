# BugBounty-Agent — Skills Catalog

BugBounty-Agent equips the unified `Bug-Bounty` agent with 18 modular OpenCode skills maintained in the repository under `skills/` and deployed globally to `~/.config/opencode/skills/`. Each skill provides specialized methodology, decision trees, criteria, and safety constraints.

---

## 18 Modular Skills Directory

### 1. `scope-management`
* **Purpose**: Scope boundary validation and offline verification.
* **Network Access**: **Zero network traffic**. Pure logic checking against `scope.yaml`.
* **Methodology**: Evaluates precedence (Exclusions > Specific targets > Wildcards > Ambiguous entries). Computes recursive subdomain depth and DNS label boundaries.

### 2. `asset-intelligence`
* **Purpose**: Production-grade recursive asset graph construction, arbitrary-depth subdomain enumeration, infrastructure attribution, and multi-source provenance calibration.
* **CLI Utility**: `bb-assets` (`--domain`, `--program`, `--scope`, `--tree`, `--json`, `--depth`, `--budget`, `--passive-only`).
* **Methodology**: Supports arbitrary subdomain recursion without artificial ceilings (`example.com` $\to$ `api` $\to$ `dev` $\to$ `internal` $\to$ `service`). Maps directional semantic graph relationships (`HAS_SUBDOMAIN`, `RESOLVES_TO`, `CNAME_TO`, `PRESENT_IN_CERT`, `HOSTED_BY`, `BELONGS_TO_ASN`). Implements wildcard DNS mitigation, X.509 TLS certificate SAN extraction with recursive re-queueing, CDN/cloud edge attribution (Cloudflare, Akamai, CloudFront, Fastly, Azure, GCP), and multi-source provenance tracking with calibrated confidence ratings (`LOW`, `MEDIUM`, `HIGH`, `CONFIRMED`).

### 3. `reconnaissance`
* **Purpose**: Controlled passive and active reconnaissance.
* **Methodology**: Passive CT logs and DNS intelligence first (`crt.sh`, `subfinder`), followed by controlled active probing (`httpx`). Rate-limiting enforcement and tool fallback mechanisms.

### 4. `web-security`
* **Purpose**: Web application attack surface analysis.
* **Methodology**: Maps login/registration workflows, evaluates session cookie attributes (`HttpOnly`, `Secure`, `SameSite`), tests CORS origin reflections, analyzes CSRF token architectures, assesses open redirects and file upload controls.

### 5. `javascript`
* **Purpose**: Client-side JavaScript static analysis and route discovery.
* **Methodology**: Analyzes packed scripts, extracts client routes and API endpoints, reconstructs source maps (`.map`), audits DOM sinks for client-side XSS, and triages public frontend keys vs privileged secrets.

### 6. `api-security`
* **Purpose**: REST, GraphQL, and WebSocket API analysis.
* **Methodology**: Tests HTTP verb tampering (`OPTIONS`, `PUT`, `DELETE`, `PATCH`), evaluates API version differences (`/v1/` vs `/v2/`), tests GraphQL introspection and query depth limits, and identifies parameter schema disparities (mass assignment).

### 7. `authorization`
* **Purpose**: Access control, BOLA/IDOR, and multi-tenant isolation testing.
* **Methodology**: Rigorous dual-account testing (Tenant A vs Tenant B). Tests horizontal/vertical object reference tampering, function-level authorization (BFLA), and verifies tenant boundary isolation.

### 8. `injection`
* **Purpose**: Non-destructive injection vulnerability testing.
* **Methodology**: Tests SQLi, NoSQLi, XSS, SSTI, and command injection using strictly benign proof markers (time delays `sleep(3)`, arithmetic evaluation `{{7*7}}`, safe delimiters). Zero destructive payloads.

### 9. `business-logic`
* **Purpose**: Workflow logic and state machine evaluation.
* **Methodology**: Tests multi-step workflow bypasses, sequence skipping, decimal rounding flaws, negative quantity/price manipulation, and concurrency race conditions. Zero financial impact on production targets.

### 10. `cloud-security`
* **Purpose**: Cloud asset and configuration assessment.
* **Methodology**: Audits public S3/GCS bucket permissions, evaluates cloud metadata endpoints via SSRF (`169.254.169.254`), and verifies dangling CNAME records for subdomain takeovers. Strictly prohibits testing unrelated third-party cloud infrastructure.

### 11. `browser`
* **Purpose**: Dynamic web analysis via headless browser automation.
* **Methodology**: Utilizes Playwright to render Single Page Applications (SPAs), inspect client DOM transformations, monitor client WebSockets, evaluate local storage / session storage, and observe client runtime behavior.

### 12. `oob`
* **Purpose**: Out-of-band interaction testing.
* **Methodology**: Leverages ProjectDiscovery Interactsh for detecting blind vulnerabilities (blind SSRF, blind XXE, blind RCE). Correlates unique DNS/HTTP tokens with test requests.

### 13. `validation`
* **Purpose**: Adversarial candidate finding verification.
* **Methodology**: Treats all findings as untrusted until confirmed through the 6-gate checklist. Eliminates scanner false positives, generic 200 OK pages, CDN challenge pages, and cached responses. Assigns calibrated confidence scores.

### 14. `deduplication`
* **Purpose**: Test fingerprinting and root-cause consolidation.
* **Methodology**: Calculates SHA-256 test fingerprints to prevent repetitive testing. Clusters findings sharing the same underlying root cause, endpoint, or vulnerable code component.

### 15. `evidence`
* **Purpose**: Evidence integrity and credential sanitization.
* **Methodology**: Cryptographic SHA-256 hashing of request/response artifacts, automatic masking of authorization tokens, session cookies, and passwords. Enforces local storage outside the Git repository.

### 16. `reporting`
* **Purpose**: Standardized vulnerability disclosure generation.
* **Methodology**: Converts validated findings into 17-section Markdown disclosure reports. Employs realistic CVSS scoring and remediation guidance. Strictly zero automated external submissions to bug bounty platforms.

### 17. `knowledge-research`
* **Purpose**: Public vulnerability intelligence and research.
* **Methodology**: Queries public vulnerability databases (HackerOne disclosed reports, CVE, CWE, CISA KEV, OWASP guides) to formulate targeted testing hypotheses against modern architectures.

### 18. `authentication`
* **Purpose**: Authentication, session & identity security intelligence.
* **Methodology**: Evaluates login/logout flows, session fixation, session invalidation after logout and password changes, MFA state transitions, password-reset token one-time use and expiration, differential account enumeration, and JWT structural claims without credential guessing, spraying, or brute forcing. Employs human approval gating for state-changing operations.

