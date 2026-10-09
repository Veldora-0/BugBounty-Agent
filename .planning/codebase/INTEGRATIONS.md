# External Integrations

**Analysis Date:** 2026-10-09

## APIs & External Services

**Threat Intelligence & Reconnaissance APIs:**
- ProjectDiscovery Cloud Platform (PDCP) - Centralized cloud orchestration and scan synchronization.
  - SDK/Client: Direct REST API via `urllib` / PDCP CLI.
  - Auth: API key configured via `PDCP_API_KEY` in `~/.config/bugbounty-agent/secrets.env`.
  - Managed in: `framework/tools/providers.py`.
- Shodan API - Host discovery, banner grabbing, and open port intelligence.
  - Auth: API key in `SHODAN_API_KEY`.
  - Endpoints used: Host search, facet queries, service summaries.
- Censys Search API - Internet-wide scan data and TLS certificate search.
  - Auth: Credentials via `CENSYS_API_TOKEN` and `CENSYS_ORGANIZATION_ID`.
- SecurityTrails API - Historical DNS records and IP timeline tracking.
  - Auth: API key via `SECURITYTRAILS_API_KEY`.
- VirusTotal API - Passive DNS resolutions, subdomains, and threat metadata.
  - Auth: API key via `VT_API_KEY`.
- urlscan.io API - Automated web page inspection and DOM snapshot intelligence.
  - Auth: API key via `URLSCAN_API_KEY`.
- GitHub Search API - Passive secret and code disclosure reconnaissance.
  - Auth: Personal Access Token via `GITHUB_TOKEN`.
- WPScan Vulnerability Database - WordPress core, theme, and plugin CVE lookups.
  - Auth: API token via `WPSCAN_API_TOKEN`.

**Out-of-Band (OOB) Testing Services:**
- ProjectDiscovery Interactsh - OOB server for blind SSRF, blind XXE, and blind RCE detection.
  - Client: `interactsh-client` CLI wrapper orchestrated via `scripts/bb-ssrf`.
  - Auth: Token via `INTERACTSH_TOKEN` or cloud key `PDCP_API_KEY` (supports self-hosted or default servers).
  - Protocol support: HTTP callbacks, DNS interactions, SMTP interactions, and LDAP lookups.

**Notification & Alerting Services:**
- Discord Webhooks - Security event and high-severity finding notifications.
  - Auth: Webhook URL via `DISCORD_WEBHOOK_URL`.
- Slack Webhooks - Finding alerts and operation completion notices.
  - Auth: Webhook URL via `SLACK_WEBHOOK_URL`.
- Telegram Bot API - Mobile push notifications for critical findings.
  - Auth: Bot token via `TELEGRAM_API_KEY` and chat ID via `TELEGRAM_CHAT_ID`.

## Data Storage

**Databases & Persistent Local State:**
- Local Filesystem State Engine: JSON document stores per program located in `state/` (isolated from Git).
  - Managed by: `framework/state/manager.py` with atomic write semantics (`tempfile.NamedTemporaryFile` + `os.replace`).
  - Core State Files:
    - `state/assets.json` - Complete normalized asset graph and subdomain hierarchy.
    - `state/recon.json` - Passive/active discovery results, IP attribution, and DNS records.
    - `state/webapps.json` - Web endpoints, technologies, forms, cookies, and CORS policies.
    - `state/javascript.json` - Client-side routes, AST analysis, source maps, and secret triage.
    - `state/api.json` - API inventory, parameters, methods, and schema definitions.
    - `state/authz.json` - Access control matrices and dual-tenant test records.
    - `state/ssrf.json` - Out-of-band interaction callbacks and SSRF candidate tests.
    - `state/injection.json` - Non-destructive injection test logs and proofs.
    - `state/http_trust.json` - Host header, smuggling, and proxy trust evaluation results.
    - `state/business_logic.json` - Workflow state models and race condition tests.
    - `state/cloud_security.json` - Bucket permissions and cloud resource configurations.
    - `state/authentication.json` - Session tracking, fixation proofs, and token lifecycle audits.
    - `state/tests.json` - SHA-256 test fingerprints preventing redundant network probes.
    - `state/findings.json` - Deduplicated finding candidate objects conforming to standard schema.
    - `state/coverage.json` - Subsystem test coverage metrics and completed phases.

**Evidence Vault:**
- Cryptographic Artifact Storage: Request/response raw captures stored in `evidence/` outside Git.
  - Managed by: `framework/common/evidence.py`.
  - Hashing: SHA-256 digests generated for every evidentiary interaction.
  - Sanitization: Passwords, authorization tokens (`Bearer ...`), and session cookies automatically redacted prior to storage.

## Authentication & Identity

**Target Identity Management:**
- Multi-Principal Testing Engine: `framework/authentication/identity.py` and `framework/authz/model.py`.
  - Profile Types: `ANONYMOUS`, `STANDARD`, `ADMIN`, `SERVICE`, `EXTERNAL`.
  - Credential Protection: Passwords, live bearer tokens, and session cookies are sanitized to `[REDACTED_BY_BB_AGENT]` or tracked via SHA-256 fingerprints (`sess_sha256_...`).
  - Storage: In-memory runtime profiles with metadata bridging via `masked_metadata`.
  - Approval Gating: `AuthenticationApprovalGate` in `framework/authentication/policy.py` requiring explicit human approval (`--approve`) for state-changing mutations (password changes, reset token requests).

## Monitoring & Observability

**System Health & Diagnostics:**
- System Doctor (`scripts/bb-doctor` / `framework/tools/doctor.py`):
  - Inspects 23 diagnostic categories: system specs, build dependencies, 44 security tools, API providers, browser readiness, wordlists, and all 15 native intelligence engines.
  - OpenCode V2 validation verifying default agent, subagent depth, rule count, and runtime binaries.

**Logging:**
- Standard CLI stdout/stderr logging with colored status indicators (`[+]`, `[*]`, `[!]`, `[-]`).
- Local run logs stored in `~/BugBounty-Workspace/programs/<name>/logs/`.
- No telemetry or external cloud logging to third parties.

## CI/CD & Deployment

**Global OpenCode Deployment:**
- Global Sync Tool (`scripts/bb-deploy` / `framework/tools/deployer.py`):
  - Canonical source of truth: `agents/Bug-Bounty.md` and `skills/`.
  - Target deployment directory: `~/.config/opencode/` (symlinked or copied).
  - Global scripts: Linked to `~/.local/bin/` on Linux/Kali.
  - Agent Discovery: Globally registers `Bug-Bounty` as the default agent across all directories (`cd ~ && opencode`).

**Test & Quality Pipeline:**
- Local automated regression testing: `pytest` executing 32 test suites across 323 test cases.
- Python compilation validation: `python -m compileall framework scripts`.

## Environment Configuration

**Development & Operations:**
- Required configuration files:
  - `~/.config/bugbounty-agent/secrets.env` - Secret environment variables (never committed).
  - `scope.yaml` - Per-program target boundary definitions in root or program workspace.
  - `opencode.jsonc` - Root OpenCode engine configuration.
- Local Mock & Test Labs:
  - Built-in self-contained offline security labs in `framework/*/lab.py` (e.g. `LocalAuthenticationSecurityLab`, `LocalCloudSecurityLab`, `LocalBusinessLogicLab`, `LocalInjectionLab`) providing 100% deterministic testing without internet access.

## Webhooks & Callbacks

**Incoming:**
- OOB Interaction Listeners: ProjectDiscovery Interactsh listener handling incoming DNS, HTTP, and SMTP callbacks from target applications.

**Outgoing:**
- Notification Webhooks: Dispatched via `framework/tools/` when findings are validated (Discord, Slack, Telegram).
- Zero automated vulnerability submissions to external bug bounty platforms (HackerOne, Bugcrowd, Intigriti); reports are written locally to Markdown for human researcher verification.

---

*Integration audit: 2026-10-09*
*Update when adding/removing external services*
