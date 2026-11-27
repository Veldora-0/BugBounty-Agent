# BugBounty-Agent

[![OpenCode Ready](https://img.shields.io/badge/OpenCode-Native-blue.svg)](https://opencode.ai)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-brightgreen.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Safety: Authorized Only](https://img.shields.io/badge/Testing-Authorized_Only-red.svg)](docs/security.md)

A professional, modular Bug Bounty Security Research Agent framework for **OpenCode**.

BugBounty-Agent is an orchestrated security research system designed to operate with the rigor of a senior penetration tester. Instead of indiscriminately running vulnerability scanners, the agent applies **deterministic scope enforcement**, **hypothesis-driven testing**, **cryptographic evidence validation**, and **local research state persistence**.

## Project handbook and phase status

This project is intended to find and document vulnerabilities on **explicitly authorized bug bounty targets**. Start with the [Project Handbook](docs/PROJECT-HANDBOOK.md) for a newcomer-oriented overview and operating workflow. The [24-Phase Roadmap](docs/ROADMAP-24-PHASES.md) links to one detailed guide per phase; the proposed [Bug Bounty Coverage Expansion Roadmap](docs/BUG-BOUNTY-COVERAGE-ROADMAP.md) maps vulnerability classes, current foundations, tool gaps, proof requirements, and implementation phases. Unresolved risks and blockers are maintained in the [Project Audit Issues](docs/PROJECT-AUDIT-ISSUES.md), candidate work is listed in [Future Improvements](docs/FUTURE-IMPROVEMENTS.md), and optional Kali-oriented tools are discussed in [Tooling Recommendations](docs/TOOLING-RECOMMENDATIONS.md). Phase 24 adds the [support matrix](docs/supported-environments.md), [threat model](docs/THREAT-MODEL.md), and [release checklist](docs/release-checklist.md).

**Current status:** Phase 24 closure remains in progress. Kali is the primary platform: the full Linux-only suite passed on Kali at `628b4d2` (**1,357 passed** in 411.96 seconds). GitHub Actions uses Ubuntu Linux runners only for supplementary Python 3.10/3.14 code checks; those jobs do not replace Kali acceptance. The installed dispatcher isolation verifier passed, but the current service status reports no configured scope or approval key, so production dispatch is not ready and no successful approved action has been verified. A scope audit using CleanShot's published policy found and fixed wildcard-apex over-authorization: wildcard entries now cover descendants only, and each generated DNS wildcard probe is checked individually. Prior Windows results are historical; current automated tests target Linux only. ASN attribution is `UNKNOWN` by default, with bounded opt-in Team Cymru lookup available; IPv6 query construction was fixed in `b212bff` and has offline regression coverage. Live OOB callback acceptance remains open, and Phase 22 chain validation remains simulation-only. Program data is stored under `programs/<name>/` within the directory opened in OpenCode. The project remains beta; see the [issue register](docs/PROJECT-AUDIT-ISSUES.md) for remaining acceptance work. For CleanShot, only public policy/marketing pages were fetched; no vulnerability probes or authenticated tests were performed.

Run `scripts/bb-deploy` to install the single global `Bug-Bounty` agent, its 18 skills, CLI tools, and the `/Arise` command. OpenCode discovers project slash commands from `.opencode/commands/` and global commands from `~/.config/opencode/commands/` ([command documentation](https://opencode.ai/docs/commands)).

---

## Key Principles & Architectural Invariants

* **One Reusable Framework Repository**: Contains only the agent specifications, methodology skills, controlled CLI tools, tests, and documentation.
* **Local Runtime Data**: Program scope, state, evidence, credentials, and reports are stored under `programs/<name>/` in the directory opened in OpenCode. That directory is Git-ignored; do not force-add runtime data. Use a separate OpenCode directory when physical separation from the source checkout is required.
* **Never Silently Assume Authorization**: Every domain, IP, CIDR, and URL must pass through the Scope Engine before any network interaction.
* **Hypothesis-Driven Research**:
  $$\text{Observation} \longrightarrow \text{Hypothesis} \longrightarrow \text{Targeted Test} \longrightarrow \text{Evidence} \longrightarrow \text{Validation} \longrightarrow \text{Report}$$
* **No Automated Exploits or DoS**: Zero tolerance for denial-of-service, data destruction, password spraying, or unauthorized third-party probing.
* **No Auto-Submit**: Reports are generated in Markdown for human review and validation before disclosure.

---

## Repository Structure

A representative overview of the repository structure is shown below:

```text
BugBounty-Agent/
├── AGENTS.md                  # Agent directory, hierarchy, and interaction flow
├── README.md                  # Master documentation and quickstart
├── LICENSE                    # MIT Open Source License
├── CHANGELOG.md               # Version history and release notes
├── CONTRIBUTING.md            # Guidelines for framework contributors
├── SECURITY.md                # Responsible disclosure and ethical safety policy
├── .gitignore                 # Enforces exclusion of runtime, target, and secret data
├── opencode.jsonc             # OpenCode native project configuration & permissions
├── pyproject.toml             # Standard PEP 517/621 Python packaging specification
│
├── agents/                    # Canonical Bug-Bounty agent definition
│   └── Bug-Bounty.md          # Primary orchestrator (deployed globally to ~/.config/opencode/agents/)
│
├── skills/                    # 18 modular OpenCode methodology skills (deployed globally)
│   ├── scope-management/
│   ├── asset-intelligence/
│   ├── reconnaissance/
│   ├── web-security/
│   ├── javascript/
│   ├── api-security/
│   ├── authorization/
│   ├── injection/
│   ├── business-logic/
│   ├── cloud-security/
│   ├── authentication/
│   ├── browser/
│   ├── oob/
│   ├── validation/
│   ├── deduplication/
│   ├── evidence/
│   ├── reporting/
│   └── knowledge-research/
│
├── framework/                 # Reusable Python 3 core engine
│   ├── assets/                # Scoped graph, DNS/IP, bounded TLS SAN enrichment; ASN is not wired
│   ├── scope/                 # Scope engine, DNS boundary verification, normalizer
│   ├── state/                 # Persistent state manager, test fingerprinting, dedup
│   ├── validation/            # Security validation foundation, policy, test cases & baseline comparison
│   ├── xss/                   # Context-aware XSS intelligence, DOM sources/sinks, stored correlation
│   ├── authz/                 # Authorization intelligence, BOLA/IDOR baseline validation, human approval gate
│   ├── ssrf/                  # SSRF intelligence, out-of-band canary correlation, alternate IP parsing
│   ├── xxe/                   # Conservative XXE intelligence, XML bomb protection, local simulation lab
│   ├── injection/             # Injection intelligence, prioritization, SQLi/NoSQLi/SSTI/Command validators
│   ├── api/                   # OpenAPI 2.0/3.x & GraphQL parser, streaming byte budget, loopback fixture ports
│   ├── webapp/                # Web application attack surface mapping, forms, links, cookies
│   ├── recon/                 # Reconnaissance orchestrator, DNS/HTTP/TLS/tech service enrichment
│   ├── http_trust/            # HTTP / Header trust intelligence, Host injection, CORS, HPP, cache foundation
│   ├── business_logic/        # Business logic state machines, invariant engine, replay, approval gate
│   ├── cloud_security/        # Cloud security & misconfiguration intelligence, S3/Blob/GCS, takeover
│   ├── authentication/        # Authentication, session & identity security intelligence, MFA, reset
│   ├── auth_correlation/     # Authentication & Authorization correlation engine, preflight, revocation, tenant
│   ├── infrastructure/        # Infrastructure & configuration exposure intelligence, differential soft-404
│   ├── concurrency/           # Concurrency & race conditions intelligence, barrier synchronization, invariants
│   ├── findings/              # Finding schema, lifecycle state machine, markdown report generator
│   ├── tools/                 # Tool registry, installer, doctor, deployer
│   └── common/                # Safe XML parsing, transport, evidence store, sanitization, config
│
├── scripts/                   # Controlled CLI wrappers with mandatory scope checks
│   ├── bb-deploy              # Deploy and sync agent and skills to global OpenCode
│   ├── bb-sync                # Synchronization alias for bb-deploy
│   ├── bb-init                # Workspace and program initializer
│   ├── bb-doctor              # Diagnostics utility across 26 system categories
│   ├── bb-coverage            # Offline vulnerability-class and tool coverage inventory
│   ├── bb-install             # Automated tool installer using declared registry tiers
│   ├── bb-update              # Optional external security-tool version updater
│   ├── bb-report              # Standalone disclosure report compiler
│   ├── bb-assets              # Scoped asset graph CLI; optional passive Subfinder integration
│   ├── bb-scope-check         # Scope verification utility
│   ├── bb-target-normalize    # Target canonicalization & DNS boundary check
│   ├── bb-recon               # Bounded built-in DNS/TLS/HTTP/port reconnaissance
│   ├── bb-http                # HTTP / Header Trust & Protocol Security validation engine
│   ├── bb-workflow            # Business logic and multi-step workflow intelligence engine
│   ├── bb-cloud               # Cloud security & misconfiguration intelligence engine
│   ├── bb-auth                # Authentication, session & identity security intelligence engine
│   ├── bb-auth-correlate      # Authentication & Authorization correlation engine CLI
│   ├── bb-infra               # Infrastructure & configuration exposure intelligence engine
│   ├── bb-race                # Concurrency & distributed workflows intelligence engine
│   ├── bb-webapp              # Web application intelligence & surface mapping engine
│   ├── bb-content             # Bounded, scope-checked content discovery (built-in)
│   ├── bb-js                  # JavaScript endpoint & secret analyzer
│   ├── bb-api                 # REST/GraphQL API method and schema prober
│   ├── bb-validate            # Controlled security validation & baseline comparison engine
│   ├── bb-xss                 # XSS intelligence, context analysis & validation engine
│   ├── bb-authz               # Authorization & Access-Control Intelligence Engine (BOLA/IDOR)
│   ├── bb-ssrf                # SSRF & Out-of-Band Server-Side Interaction Intelligence Engine
│   ├── bb-inject              # Injection intelligence & controlled validation engine
│   ├── bb-nuclei              # Signal-only Nuclei scanner wrapper
│   └── bb-evidence            # Evidence collector with automatic token redaction
│
├── config/                    # Authoritative tool and wordlist specifications
│   ├── tools.yaml             # Machine-readable tool registry, installation, and tiers
│   ├── vulnerability-coverage.yaml # Vulnerability classes, implementation status, and proof limits
│   └── wordlists.yaml         # Wordlist specifications and path definitions
│
├── templates/                 # Reusable templates
│   ├── scope.yaml             # Complete program scope definition template
│   ├── program.yaml           # Program metadata and preferences template
│   ├── finding.json           # Finding JSON schema
│   ├── report.md              # 17-section markdown report template
│   └── config.example.yaml    # Global framework configuration template
│
├── tests/                     # Automated regression suite; see Phase 24 for commit-specific results
│   ├── test_scope.py          # Scope boundaries and DNS resolution tests
│   ├── test_asset_engine.py   # Asset graph and subdomain intelligence tests
│   ├── test_api_engine.py     # OpenAPI, GraphQL, and streaming byte budget tests
│   ├── test_ssrf_engine.py    # SSRF transport, alternate IP, and provider tests
│   ├── test_phase18_xxe_engine.py # XXE intelligence, entity limits, and lab tests
│   ├── test_validation_engine.py  # Security validation foundation and baseline tests
│   └── ...                    # Additional unit, transport, and subsystem test suites
│
├── docs/                      # Comprehensive technical documentation
│   ├── architecture.md
│   ├── agents.md
│   ├── skills.md
│   ├── scope.md
│   ├── runtime.md
│   ├── installation.md
│   ├── workflow.md
│   └── security.md
│
└── examples/
    └── example-scope.yaml     # Realistic example scope with exclusions and limits
```

---

## Installation & Setup

### 1. Requirements
* **Primary environment:** Kali Linux. Runtime and test evidence is Linux-first; see [supported environments](docs/supported-environments.md) for platform-specific limits.
* Python 3.10+
* OpenCode for global agent/skill deployment; framework CLIs can run independently

### 2. Quickstart
```bash
# Clone the repository
git clone https://github.com/Veldora-0/BugBounty-Agent.git
cd BugBounty-Agent

# Install the framework's required Python runtime dependencies
python -m pip install -e .
# For development and testing:
python -m pip install -e ".[dev]"
# Optional browser automation support:
python -m pip install -e ".[browser]"

# Run the test suite
python -m pytest -v
```

`bb-update` inspects or updates external tools from `config/tools.yaml`; it does not pull this Git repository or synchronize the global agent. Update the checkout with Git, then run `scripts/bb-deploy` to synchronize its agent, skills, command and CLI wrappers. See the [installation guide](docs/installation.md) before changing a global OpenCode configuration.

## Supported Security Tools Catalog

BugBounty-Agent maintains an authoritative, machine-readable tool registry in [`config/tools.yaml`](config/tools.yaml). Tools are organized by operational tiers (**CORE**, **SPECIALIST**, **PROVIDER-BACKED**, **OPTIONAL**, **LEGACY**) and mapped to specific research capabilities.

### Master Tools Reference Table

| Tool | Category | Purpose | Tier | API Key | Auto-Install | Setup |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **subfinder** | Subdomain Enumeration | Passive subdomain discovery via 40+ datasets | CORE | Optional Providers | Yes | [subfinder.md](docs/tools/subfinder.md) |
| **amass** | Asset Discovery | In-depth attack surface mapping & ASN correlation | CORE | Optional Providers | Yes | Native CLI |
| **assetfinder** | Subdomain Enumeration | Fast passive subdomain scraping | CORE | None | Yes | Native CLI |
| **chaos** | Asset Discovery | ProjectDiscovery indexed public DNS dataset client | PROVIDER-BACKED | Required | Yes | [chaos.md](docs/tools/chaos.md) |
| **dnsx** | DNS | Multi-purpose DNS resolver & wildcard filter | CORE | None | Yes | Native CLI |
| **shuffledns** | DNS | High-speed active subdomain bruteforce wrapper | CORE | None | Yes | Native CLI |
| **massdns** | DNS | High-performance raw DNS stub resolver engine | CORE | None | Yes | Native CLI |
| **alterx** | Subdomain Enumeration | Subdomain wordlist permutation generator | CORE | None | Yes | Native CLI |
| **dnsgen** | Subdomain Enumeration | Python wordlist alteration generator | SPECIALIST | None | Yes | Native CLI |
| **httpx** | HTTP Probing | Live service probe, tech stack & title grabber | CORE | None | Yes | Native CLI |
| **tlsx** | TLS / Network | TLS certificate intelligence & SAN extractor | CORE | None | Yes | Native CLI |
| **cdncheck** | Cloud Intelligence | Identifies CDN, WAF, and Cloud provider IP ranges | CORE | None | Yes | Native CLI |
| **mapcidr** | Pipeline Utility | Subnetting, slicing, and CIDR range handling | CORE | None | Yes | Native CLI |
| **naabu** | Port Discovery | Fast SYN/CONNECT port scanner | CORE | None | Yes | Native CLI |
| **urlfinder** | URL Discovery | Passive URL and endpoint discovery | CORE | Optional Providers | Yes | Native CLI |
| **katana** | Web Crawling | Next-gen crawling engine with headless JS support | CORE | None | Yes | Native CLI |
| **gau** | URL Discovery | GetAllUrls - Historical archive URL aggregator | SPECIALIST | None | Yes | Native CLI |
| **waybackurls** | URL Discovery | Wayback Machine URL harvester | SPECIALIST | None | Yes | Native CLI |
| **ffuf** | Content Discovery | Fast web, vhost, and parameter fuzzer | CORE | None | Yes | Native CLI |
| **feroxbuster** | Content Discovery | Fast recursive content scanner written in Rust | SPECIALIST | None | Yes | Native CLI |
| **dirsearch** | Content Discovery | Python web path scanner | SPECIALIST | None | Yes | Native CLI |
| **wfuzz** | Content Discovery | Web application fuzzer (legacy fallback) | LEGACY | None | No | Native CLI |
| **hakrawler** | Web Crawling | Lightweight web crawler for endpoint extraction | SPECIALIST | None | Yes | Native CLI |
| **gospider** | Web Crawling | Fast spider with automated JavaScript link parsing | SPECIALIST | None | Yes | Native CLI |
| **arjun** | Parameter Discovery | HTTP parameter discovery suite (GET/POST/JSON) | CORE | None | Yes | Native CLI |
| **qsreplace** | Pipeline Utility | Query string value replacement and normalization | CORE | None | Yes | Native CLI |
| **uro** | Pipeline Utility | URL decluttering, deduplication, and cleaning | CORE | None | Yes | Native CLI |
| **anew** | Pipeline Utility | Line-oriented stream deduplication | CORE | None | Yes | Native CLI |
| **nuclei** | Vulnerability Scanning | Signal source based on declarative YAML templates | CORE | Optional Providers | Yes | [projectdiscovery-cloud.md](docs/tools/projectdiscovery-cloud.md) |
| **dalfox** | XSS Analysis | Parameter analysis & XSS scanner with DOM parser | SPECIALIST | None | Yes | Native CLI |
| **sqlmap** | Injection Analysis | Automatic SQL injection analysis (read-only mode) | SPECIALIST | None | Yes | Native CLI |
| **interactsh** | OOB / SSRF | Out-of-band interaction gatherer (DNS, HTTP, SMTP) | SPECIALIST | Optional | Yes | [interactsh.md](docs/tools/interactsh.md) |
| **wpscan** | CMS Security | WordPress security & plugin vulnerability scanner | SPECIALIST | Optional Providers | Yes | [wpscan.md](docs/tools/wpscan.md) |
| **uncover** | Search Engine Intel | Aggregator for Shodan, Censys, FOFA, Hunter, etc. | PROVIDER-BACKED | Required | Yes | [uncover.md](docs/tools/uncover.md) |
| **notify** | Notifications | Stream alerts to Discord, Slack, Telegram | OPTIONAL | Required | Yes | [notify.md](docs/tools/notify.md) |
| **playwright** | Browser Automation | Headless browser automation for complex SPAs | SPECIALIST | None | Yes | Native CLI |
| **proxify** | Proxy / Traffic | HTTP/HTTPS/SOCKS Swiss Army knife proxy | SPECIALIST | None | Yes | Native CLI |
| **burpsuite** | Proxy / Traffic | Interactive proxy and web vulnerability scanner | SPECIALIST | None | No (Manual) | Native GUI/API |
| **zap** | Proxy / Traffic | OWASP Zed Attack Proxy automated daemon & GUI | SPECIALIST | Optional | No (Manual) | Native Daemon |
| **gitleaks** | Secret Auditing | Git repo secret and credential detector | SPECIALIST | None | Yes | Native CLI |
| **trufflehog** | Secret Auditing | Finds credentials and secrets with verification | SPECIALIST | None | Yes | Native CLI |
| **nmap** | Network Scanning | Network exploration and port scanner | SPECIALIST | None | Yes | Native CLI |
| **testssl.sh** | TLS / Network | Command-line TLS/SSL cipher suite tester | SPECIALIST | None | Yes | Native CLI |
| **jq** | Pipeline Utility | Command-line JSON processor | CORE | None | Yes | Native CLI |

---

## Tool Capabilities by Research Domain (23 Groups)

1. **Asset Discovery**: `subfinder`, `amass`, `assetfinder`, `chaos`
2. **DNS Resolution & Filtering**: `dnsx`, `shuffledns`, `massdns`, `alterx`, `dnsgen`
3. **HTTP Probing & Fingerprinting**: `httpx`, `tlsx`
4. **Port & Service Discovery**: `naabu`, `nmap`
5. **URL Discovery & Archives**: `urlfinder`, `gau`, `waybackurls`
6. **Web Crawling & Spidering**: `katana`, `hakrawler`, `gospider`
7. **Content & Directory Discovery**: `ffuf`, `feroxbuster`, `dirsearch`, `wfuzz`
8. **Parameter Discovery**: `arjun`, `ffuf`
9. **JavaScript Analysis**: `katana` (JS mode), `playwright`, `bb-js`
10. **API Analysis**: `arjun`, `bb-api`, `httpx`
11. **XSS Analysis**: `dalfox`, `bb-xss`
12. **Injection & Parser Flaws**: `sqlmap`, `nuclei`, `bb-inject`
13. **Authorization (BOLA/IDOR)**: `bb-authz` (dual-account reasoning), `proxify`
14. **Business Logic & Workflows**: `bb-workflow`, `playwright`
15. **Out-of-Band (OOB) & SSRF**: `interactsh`
16. **Vulnerability Signals**: `nuclei` (signals ingested strictly as unverified candidates)
17. **Cloud & External Intelligence**: `uncover`, `cdncheck`, `mapcidr`
18. **Content Management Systems (CMS)**: `wpscan`
19. **TLS & Network Auditing**: `tlsx`, `testssl.sh`, `nmap`
20. **Proxy & Traffic Interception**: `proxify`, `burpsuite`, `zap`
21. **Source & Secret Auditing**: `gitleaks`, `trufflehog`
22. **Pipeline & Data Normalization**: `anew`, `uro`, `qsreplace`, `jq`
23. **Milestone Notifications**: `notify`

---

## Tool Intelligence & Management

### 1. Automatic Diagnostics (`bb-doctor`)
Run deep diagnostics across 26 system categories:
```bash
./scripts/bb-doctor
```
Checks:
* **System**: OS, architecture, Python version, workspace root
* **Dependencies**: Go, Python3, Pipx, Git, Cargo, Docker, Jq
* **Tools**: Status of registered tools, version compatibility, and tiering
* **Providers**: API keys for ProjectDiscovery Cloud, Shodan, Censys, SecurityTrails, VirusTotal, etc.
* **Browser**: Playwright and Chromium sandbox readiness
* **Wordlists**: SecLists presence on Kali (`/usr/share/seclists`) or user local directory
* **Configuration**: `secrets.env` file presence and permissions
* **Scope Engine**: Recursive subdomain validation and boundary security integrity
* **Asset Intelligence**: Arbitrary-depth recursive graph engine and relationship models
* **Reconnaissance Engine**: Passive-first reconnaissance and HTTP observation models
* **Web Application Engine**: Web surface mapping, HTML form/link parsing, and crawl policy
* **JavaScript Engine**: Client-side route and endpoint analysis, sensitive string detection
* **API Security Engine**: REST parameter classification, OpenAPI/GraphQL schema prober
* **Validation Foundation**: Security test foundation, payload registry, test case fingerprints
* **XSS Intelligence**: DOM, Reflected, Stored, and Context Analysis
* **Authorization Engine**: Dual-account BOLA/IDOR matrix and approval gate
* **SSRF / OOB Engine**: In-band SSRF, alternate IP parsing, and Interactsh OOB callback engine
* **Injection Intelligence**: SQLi, NoSQLi, SSTI, and Command injection validators
* **HTTP Trust Engine**: Host injection, CORS, HPP, and protocol security foundations
* **Business Logic Engine**: Workflow state machines, 24 invariant evaluations, safe replay, and approval gate
* **Cloud Security Engine**: Cloud provider classification, object storage exposure, takeover signatures, and false positive elimination
* **Authentication Engine**: Session analyzers, JWT token inspection, and authentication laboratory
* **Infrastructure Engine**: Differential soft-404 detection, structural file signatures, and safe exposure intelligence
* **Concurrency Engine**: Precision barrier synchronization, TOCTOU race testing, invariant discrimination, and safe state management
* **Auth Correlation Engine**: Preflight validation, revocation intelligence, tenant desync, and simulation transport
* **OpenCode Integration**: Canonical agent definition, modular skills, V2 permissions, and deployment

### 2. Safe On-Demand Installation (`bb-install`)
Install approved tools when needed, either individually or by capability:
```bash
# Install a specific tool
./scripts/bb-install katana

# Install tools required for a capability
./scripts/bb-install --required-for web-crawling

# Inspect installation plan without executing
./scripts/bb-install --dry-run subfinder
```
**Safety Invariants**:
* Rejects unapproved tools not listed in `config/tools.yaml`.
* Never executes unvetted shell scripts (`curl | bash` is strictly forbidden).
* Favors official Kali/Debian packages (`apt`) or verified official GitHub releases.
* Installs binaries to `~/.local/bin` (non-root execution preferred).
* Logs provenance into `~/.config/bugbounty-agent/tool_provenance.json`.

### 3. Tool Version & Update Management (`bb-update`)
Inspect installed tools and apply safe updates:
```bash
# Check for outdated tools against registry minimums
./scripts/bb-update --check

# Update a specific tool
./scripts/bb-update subfinder
```

### 4. API Credentials Management (Outside Git)
Store credentials safely in `~/.config/bugbounty-agent/secrets.env` (never in Git):
```bash
mkdir -p ~/.config/bugbounty-agent
cat << 'EOF' > ~/.config/bugbounty-agent/secrets.env
PDCP_API_KEY="your_pdcp_token"
SHODAN_API_KEY="your_shodan_key"
CENSYS_API_TOKEN="your_censys_token"
CENSYS_ORGANIZATION_ID="your_censys_org_id"
SECURITYTRAILS_API_KEY="your_securitytrails_key"
VT_API_KEY="your_virustotal_key"
URLSCAN_API_KEY="your_urlscan_key"
WPSCAN_API_TOKEN="your_wpscan_token"
GITHUB_TOKEN="your_github_token"
EOF
chmod 600 ~/.config/bugbounty-agent/secrets.env
```
Consult dedicated setup guides in [`docs/tools/`](docs/tools/) for each provider.

### 5. Graceful Tool Degradation & Fallback
If a preferred tool is unavailable:
* `katana` falls back to `hakrawler` or `gospider`.
* `subfinder` falls back to `amass` or `assetfinder`.
* `ffuf` falls back to `feroxbuster` or `dirsearch`.
* Missing optional API keys (e.g. Chaos, Shodan) cause the agent to continue in degraded mode using unauthenticated sources, rather than aborting research.

---

## Implemented Research Capabilities & Security Subsystems (Phases 1–21)

BugBounty-Agent has built research foundations across Phases 1–21, with bounded discovery and validation capabilities whose limits and acceptance gaps are documented below:

### 1. Asset Intelligence, Graph & Reconnaissance (Phases 1–3)
* **Asset Graph (`bb-assets`)**: Builds a scoped graph from program roots and supplied seeds. `--depth 0` removes the graph's depth ceiling; it does not discover names by itself. `--subfinder` opts into a bounded passive Subfinder run per root and stores validated in-scope results with provider-source attribution. Active discovery also performs bounded TLS SAN enrichment using scope checks, public-IP pinning, SNI, and a 100-handshake discovery-wide ceiling. ASN attribution remains `UNKNOWN` by default; opt-in `--asn-lookup` sends at most 25 public-IP queries to Team Cymru using `dig` (private/non-global addresses are never queried). Certificate names are metadata, not proof of endpoint identity. See [Phase 1](docs/phases/PHASE-01-asset-intelligence.md).
* **Reconnaissance Intelligence (`bb-recon`)**: Runs the project's own bounded DNS, TLS, HTTP, port, technology, and endpoint probes over its scoped asset graph. Installing `httpx`, `nmap`, or other entries in the tool catalog does not make `bb-recon` invoke them. External tools are separate capabilities unless a phase guide identifies an implemented invocation path.
* **Web Application Mapping (`bb-webapp`)**: Converts web service observations into a structured attack surface relationship model stored atomically in `state/webapps.json`, indexing static and dynamic resources (scripts, stylesheets, fonts), form structures, input parameters, and link graphs.

### 2. Client-Side & JavaScript Intelligence (Phase 4)
* **Static JavaScript Analysis (`bb-js`)**: Statically parses packed frontend JavaScript bundles without executing untrusted code. Extracts API endpoints (`fetch`, `axios`, `ajax`, `xhr`), Single-Page Application (SPA) client routes (React Router, Vue Router), parameters (`URLSearchParams`), framework dependencies, and source map references (`//# sourceMappingURL=...`).
* **Secret Triage & Sanitization**: Categorizes candidate strings into public frontend keys (e.g., Firebase public keys, Algolia search keys) versus high-risk privileged secrets, automatically masking sensitive values.

### 3. API Security & Parameter Intelligence (Phases 5 & 17)
* **OpenAPI & Swagger Specification Ingestion (`bb-api`)**: Ingests OpenAPI 2.0 and 3.x specifications (JSON/YAML), recursively resolving local RFC 6901 fragment `$ref` pointers up to depth 5 with circular reference protection. Relative path and remote references are not resolved.
* **REST Path Parameter Inference**: Normalizes parameterized routes (`/api/v1/users/123` $\to$ `/api/v1/users/{user_id}`) while preserving static operational paths (`/users/me`, `/status`).
* **GraphQL Surface Detection & Bounded Introspection**: Automatically detects GraphQL endpoints; active schema introspection is strictly opt-in (`--allow-graphql-introspection`, default disabled), structurally bounded to selection set depth $\le 6$, schema traversal depth $\le 3$, and max 5,000 parameters.
* **Continuous Streaming Byte-Budget Accounting**: Tracks network egress continuously (`total_bytes_transferred`), ensuring malformed, oversized, truncated, or error responses deplete the global network byte budget (`max_bytes`).
* **Loopback Fixture Port Gating**: Local testing against loopback fixtures strictly requires explicit unprivileged port registration (`1024-65535`) and scope authorization; production targets strictly forbid loopback, RFC 1918, and cloud metadata destinations. Dual-export state is maintained in `state/api.json`.

### 4. Security Validation Foundation & Adversarial QC (Phase 6)
* **Baseline Differential Validation (`bb-validate`)**: Bounded, hypothesis-driven security validation foundation comparing candidate responses against benign baselines (`BaselineComparison`) to eliminate false positives from custom 404 pages, WAF block pages, and CDN challenge responses.
* **Standard Finding Lifecycle**: Enforces strict finding states: `OBSERVATION`, `CANDIDATE`, `TESTED`, `VALIDATED`, `REJECTED`, `SIMULATED`, `INFORMATIONAL`, and `NEEDS_MANUAL_REVIEW`.
* **Conservative Safety Policy (`SecurityTestPolicy`)**: Enforces allowed HTTP methods, request budgets, maximum response byte limits, and state-changing endpoint detection.

### 5. Cross-Site Scripting (XSS) Intelligence (Phase 7)
* **Context-Aware XSS Analysis (`bb-xss`)**: Analyzes injection context (HTML body, attribute values, script blocks, event handlers, URL attributes, JSON strings), detecting HTML entity, URL, and JS escaping; defended reflections are discarded as `REJECTED`.
* **DOM XSS Intelligence**: Tracks client sources (`location.search`, `location.hash`, `window.name`) to dangerous framework sinks (`dangerouslySetInnerHTML`, `v-html`, jQuery `html()`), accounting for client-side sanitizers (`DOMPurify`).
* **Stored XSS Modeling**: Correlates input endpoints with retrieval endpoints, generating human verification plans without automated form submission.

### 6. Authorization & Access Control (BOLA / IDOR) (Phase 8)
* **3-Point Comparative Baseline Model (`bb-authz`)**: Evaluates Broken Object Level Authorization (BOLA/IDOR), Broken Function Level Authorization (BFLA), and multi-tenant isolation by comparing:
  1. Baseline A: Owner Principal access $\to$ HTTP 200 (Valid Data).
  2. Baseline B: Non-owner Principal access to invalid resource $\to$ HTTP 404 / Soft-404.
  3. Testing Probe: Non-owner Principal cross-access $\to$ evaluated against Baselines A & B.
* Eliminates soft-404s, generic 200 denial responses, and login redirects; requires human approval before active differential testing.

### 7. SSRF & Out-of-Band (OOB) Interaction Intelligence (Phases 9 & 18)
* **Safe SSRF Request Mutation (`bb-ssrf`)**: Constructs non-destructive mutated requests across Query parameters, Path template parameters (`{param}`, `:param`), JSON bodies (flat and nested keys), Form-encoded bodies, and XML bodies (DOM text replacement with XML entity escaping).
* **SSRF Transport Hardening**: Added `parse_alternate_ip` supporting alternate numeric notations (dotted decimal, decimal scalars, hex scalars, octal scalars, dotted octal/hex, and inet_aton multi-part formats); enforces multi-record DNS resolution anti-SSRF checks blocking loopback, private, carrier-grade NAT, and cloud metadata addresses.
* **OOB Canary Correlation & Destination Policy Enforcement**: When the official `interactsh-client` is installed, the adapter creates one canary, polls bounded JSONL output, and accepts only an exact callback correlation ID. Private-service tokens stay in a private temporary config file. SSRF and XXE stop before target dispatch if provider registration fails or the OOB destination is not trusted by policy.
* **Truthful Mock vs. Live Classification**: Mock provider use is explicit and remains `SIMULATED`; it cannot produce a live-confirmed finding. An unavailable live integration is not silently replaced with a mock. A Kali self-check on 2026-11-19 found the installed Interactsh client but it exited before registering a canary, so live provider reachability and target-side callback delivery remain unverified; Burp Collaborator polling is not implemented.

### 8. Injection Intelligence & Controlled Validation (Phases 10 & 18)
* **Non-Destructive Injection Probes (`bb-inject`)**: Prioritizes parameters (0–100 score) and executes safe, canary-driven probes for SQLi (quote syntax fault, boolean differential, numeric identity), NoSQLi (`$ne`/`$eq` operators), and SSTI (`{{7*7}}` $\to$ `49`). Strictly prohibits destructive SQL (`DROP`, `DELETE`, `UPDATE`) or command execution (`curl`, `wget`, `bash`, `rm`).
* **Conservative Server-Side XML & XXE Intelligence**: Portable stdlib XML parser security (`framework/common/xml_safe.py`) enforcing Billion Laughs and quadratic blowup defenses (`safe_parse_xml`, cumulative `max_expanded_chars`). Probes XML endpoints using safe synthetic internal entity reflection (`CONFIRMED_ENTITY_EXPANSION_<token>`). Internal entity reflection alone emits `OBSERVATION` (`INFORMATIONAL`, `MEDIUM` confidence), never a false `HIGH`-severity `VALIDATED` XXE finding. Parser errors and secure DTD prohibitions emit zero findings. Prohibits reading local system files (`file://`, `/etc/passwd`, `win.ini`) and metadata probing (`169.254.169.254`, `metadata.google.internal`).

### 9. HTTP / Header Trust & Protocol Security (Phase 11)
* **Metadata & Header Boundary Auditing (`bb-http`)**: Evaluates whether server-generated URLs trust client-supplied `Host`, `X-Forwarded-Host`, or `Forwarded` headers; evaluates credentialed CORS reflection (`Access-Control-Allow-Credentials: true` with reflected `Origin`); tests HTTP Parameter Pollution (HPP) precedence; models unkeyed cache-poisoning hypotheses without polluting shared caches.

### 10. Business Logic & Workflow Intelligence (Phase 12)
* **State Machine Invariants (`bb-workflow`)**: Evaluates multi-step workflow transitions, step skipping, forced state transitions, quantitative manipulation (negative quantities, decimal precision), and race condition windows across 24 invariant classes. Human approval gate (`--approve`) is mandatory; execution is supported by single replay, sequence replay, and bounded concurrent replay ($\le 5$ requests).

### 11. Cloud Security & Misconfiguration Intelligence (Phase 13)
* **Cloud Infrastructure Assessment (`bb-cloud`)**: Multi-signal provider fingerprinting (AWS, Azure, GCP, Cloudflare, Fastly, DigitalOcean, Oracle) identifying S3/Blob/GCS buckets, CDNs, serverless function URLs, and administrative consoles. Safely validates public object reads and bucket listings; tests dangling CNAME records for subdomain takeover. Strictly prohibits direct metadata probing (`169.254.169.254`) and unauthorized testing of third-party cloud infrastructure.

### 12. Authentication, Session & Identity Security (Phase 14)
* **Authentication Security & Session Lifecycle (`bb-auth`)**: 14-family authentication taxonomy (11 operational differential families, 3 observation-only families) evaluating login/logout flows, session fixation, session invalidation after logout and password changes, pre-MFA privilege exposure, password reset token reuse, differential account enumeration, and JWT structural decoding.
* **Executor Safety & Anti-SSRF**: Standard TLS certificate/hostname verification, destination-IP pinning at socket connection (retaining SNI and `Host` header to eliminate DNS rebinding), safe proxy bypassing, per-redirect hop scope and anti-SSRF re-verification. Zero password spraying, dictionary attacks, OTP brute forcing, or CAPTCHA bypasses.

### 13. File Handling, Path Traversal & Upload Security (Phase 15)
* **Safe File Handling Assessment**: Detects upload forms and file handling parameters; evaluates extension, content-type, and storage controls using harmless plain-text synthetic files (`test_<token>.txt`). Path traversal validation utilizes synthetic canary tokens (`bb_canary_<token>.txt`), strictly prohibiting requests for real sensitive system files (`/etc/passwd`, `win.ini`, `.env`).

### 14. Browser Runtime & Dynamic Analysis (Phase 16)
* **Opt-In Headless Automation**: Disabled by default (`browser_enabled=False`); truth-first capability detection evaluates actual browser launchability before dispatch.
* **Validating Egress Proxy & Pre-Handshake WebSocket Routing**: Chunnels browser egress through an ephemeral loopback proxy (`127.0.0.1:<port>`) with `--proxy-bypass-list=<-loopback>` and numeric IP pinning. Playwright route interception (`BrowserContext.route_web_socket`) blocks unauthorized `ws://` and `wss://` connections before handshakes reach upstream servers. Enforces strict execution budgets (5s timeout, max 50 requests, max 5 redirects).

### 15. Infrastructure & Configuration Exposure Intelligence (Phase 19)
* **Differential Soft-404 Calibration (`bb-infra`)**: Calibrates target-specific non-standard 404 responses (status code, body hash, structural length differential) to prevent false-positive exposure findings across dynamic cloud environments.
* **Safe Configuration & Backup Probing**: Probes for exposed version control repositories (`.git/HEAD`, `.svn/entries`), server configuration files (`web.config`, `.env`), and temporary editor backups using bounded byte ceilings (32 KB response, 8 KB config, 1 KB binary magic bytes) and cryptographic canary validation without downloading entire directories or private keys.

### 16. Concurrency & Race Conditions Intelligence (Phase 20)
* **Precision Barrier Synchronization (`bb-race`)**: Implements coordinated multi-worker burst probing using precision synchronization barriers to execute requests within sub-millisecond arrival windows.
* **Invariant & TOCTOU State Modeling**: Tests concurrency hypotheses (e.g., balance overdrafts, coupon multi-use, rate limit exhaustion, resource double-allocation) through strictly bounded replay cycles with atomic measurement locks and deterministic state rollback in `LocalConcurrencyLab`.
* **Safe Diagnostic Isolation**: Preserves primary execution exceptions while safely sanitizing and isolating secondary cleanup failures.

### 17. Authentication & Authorization Correlation Engine (Phase 21)
* **Isolated Execution Dispatcher Authority (`bb-dispatcher`)**: Controlled actions use framed IPC (Windows Named Pipes for local development; Unix Domain Sockets `/run/bugbounty/dispatcher.sock` for the Linux systemd service). The Linux service requires an explicit program ID, scope file, and approval key; `production_dispatch_ready` is true only when these are loaded. Its HMAC approval key is assigned to a service-only group separate from the agent's IPC group. The dispatcher holds its private receipt-signing key and `authority_token`, emits signed execution receipts, and applies single-use consumption under cross-process file locks. On Kali, the installed service's identity, key/data isolation, IPC access, and rejection of an invalid approval were verified; a successful approved action through that service remains unverified. See [AUD-08](docs/PROJECT-AUDIT-ISSUES.md).
* **Dual-Control Preflight Validation (`bb-auth-correlate`)**: Implements sequential 3-probe differential preflight verification (Principal A $\rightarrow$ Principal B $\rightarrow$ Anonymous Control) to eliminate false positives from public landing pages, login redirects, WAF challenges, or SPA shells returning HTTP 200 OK. Fail-closed on anonymous control errors (5xx/transport faults).
* **FIRST CVSS 3.1 Base Metric Scorer**: Implements exact FIRST specification equations across all 8 base metrics (AV, AC, PR, UI, S, C, I, A), producing verified vector strings and base scores.
* **Post-Revocation Resource Probing**: Audits resource access persistence across two distinct modes: Mode A (observation-only monitoring requiring verified invalidation-event attestations (`ATT-...`) bound to authentic execution records registered in a tamper-evident `ExecutionLedger` (`EXEC-...`), signed with dedicated HMAC keys and immediate ScopeEngine authorization at dispatch) and Mode B (dual-account differential probe with cryptographically signed operator approval dossiers, mandatory EvidenceStore validation, fail-closed approval receipts across 16 failure conditions, genuine transport capture tagging `capture_source == "CONTROLLED_TRANSPORT_DISPATCH"`, disk byte digest recomputation, and cross-process single-use enforcement).
* **Pre-MFA & Step-Up Boundary Auditing**: Detects premature access to sensitive administrative or user endpoints prior to multi-factor authentication completion, requiring mandatory comparison with a verified fully authenticated session and enforcing zero network dispatch on invalid or ambiguous session states.
* **Multi-Tenant Cross-Channel Desynchronization**: Tests route path (`/tenants/{id}/`), query parameter (`?tenant_id=`), and header (`X-Tenant-ID`) substitution in both directions (`A_TO_B`, `B_TO_A`) with 3-state cache classification (`CACHE_CONFIRMED`, `CACHE_NOT_INDICATED`, `CACHE_UNKNOWN`) and cache-busting corroboration.
* **Hardened State Persistence & Confinement**: Manages `state/auth_correlation.json` with atomic descriptor-based writes (`os.fdopen`), symlink and reparse point rejection, POSIX private permissions (`0o700` dirs / `0o600` files), hard-link checks (`st_nlink == 1`), Windows Win32 `advapi32` protected DACL validation (`SE_DACL_PROTECTED`), and schema enforcement.
* **Deterministic Simulation Transport**: Communicates strictly with numeric `127.0.0.1:<lab_port>` in `LocalAuthCorrelationLab` (6 deterministic scenarios).

### 18. Deterministic Local Security Labs
* In-memory offline simulation environments for deterministic verification with zero external network traffic:
  * `LocalXxeLab`: Reflection, secure DTD reject, parser error, and mock OOB modes.
  * `LocalSsrfLab`: Direct, blind, redirect, and header SSRF scenarios.
  * `LocalAuthenticationSecurityLab`: 21 offline authentication and session scenarios.
  * `LocalBusinessLogicLab`: 15 business logic and workflow scenarios.
  * `LocalCloudSecurityLab`: 15 cloud storage and takeover scenarios.
  * `LocalInfrastructureLab`: 16 infrastructure, version control, and backup exposure scenarios.
  * `LocalConcurrencyLab`: 8 deterministic race condition, TOCTOU, limit overrun, and distributed workflow scenarios.
  * `LocalAuthCorrelationLab`: 6 deterministic authentication & authorization correlation scenarios.

### 19. Attack-Path Chaining, Research Planning & Release Readiness (Phases 22–24)
* **Vulnerability chaining (`bb-chain`)**: Correlates findings into candidate attack paths and creates scope-bound, reviewable plans. The current validation command is simulation-only; it cannot prove that chain links work, promote simulated links, or justify higher severity. Empirical promotion needs trusted Phase 21 dispatch receipts bound to verified evidence (AUD-09).
* **Research planning (`bb-plan`)**: Ranks advisory hypotheses from the current program's scope-filtered inventory and prior test state. Planning makes no target requests. `/Arise` learns target-independent public methodology and stores only concise context and source links under the global Bug-Bounty agent data directory (`~/.config/opencode/bug-bounty-agent/knowledge/` by default). Later target plans attach related references by vulnerability family; public research is not target evidence and does not authorize testing.
* **Operational readiness (Phase 24)**: Adds environment support boundaries, deployment/update/rollback and removal controls, diagnostics, threat-model and release checklists, plus Linux CI. The current code passed Kali full-suite and Ubuntu Python 3.10/3.14 CI; the updated Linux service passed installed isolation and invalid-approval checks on Kali. A successful approved service mutation remains unverified. Historical hosted Windows results are not current support evidence. The project is beta; see the [audit register](docs/PROJECT-AUDIT-ISSUES.md) for remaining acceptance gaps.

### 20. Roadmap Status & Verification Baseline
Execution-capability issuance uses independent Ed25519 receipt verification. Linux production service code supports one configured program and scope at a time. On Kali, the updated service is installed with the service-only `bbdispatcher-keys` group; root-run verification passed for process identity, key/data isolation, IPC, and invalid-approval rejection. No program approval key or authorized test program is provisioned, so a successful approved mutation remains unverified. Windows production service isolation is unsupported. See the [canonical roadmap](docs/ROADMAP-24-PHASES.md), [Phase 21 guide](docs/phases/PHASE-21-authentication-authorization-correlation.md), and [project issue register](docs/PROJECT-AUDIT-ISSUES.md). The old roadmap path is retained only for historical references.

---

## OpenCode V2 Runtime & Security Architecture

BugBounty-Agent is architected natively for **OpenCode V2** on Kali/Linux research workstations.

### 1. Permission Model & Precedence
The framework's `opencode.jsonc` implements OpenCode V2's ordered rule evaluation: **the last matching rule wins**. This guarantees safe defaults with surgical overrides:

| Operation Category | Action | Resource Pattern | Effect | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Default Baseline** | `shell` | `*` | `ask` | Unspecified shell commands default to human approval |
| **Subagent Delegation** | `subagent` | `*` | `deny` | Disabled: single-agent architecture uses modular skills |
| **Code & File Read** | `read`, `glob`, `grep` | `*` | `allow` | Permits reading codebase, config, and local state |
| **Safe Local Utilities** | `shell` | `*bb-scope-check*` | `allow` | Offline scope verification runs without prompt |
| **Target Normalization** | `shell` | `*bb-target-normalize*` | `allow` | URL/hostname normalization runs without prompt |
| **Workspace Setup** | `shell` | `*bb-init*` | `allow` | Workspace folder creation runs without prompt |
| **System Diagnostics** | `shell` | `*bb-doctor*` | `allow` | Health checks and tool audit run without prompt |
| **Evidence Logging** | `shell` | `*bb-evidence*` | `allow` | Evidence capture and redaction run without prompt |
| **Plan Inspections** | `shell` | `*--dry-run*`, `*--check*` | `allow` | Install dry-runs and update checks run without prompt |
| **Git Local Inspection** | `shell` | `git status *`, `git diff *` | `allow` | Read-only repository state inspection without prompt |
| **Asset Intelligence**   | `shell` | `*bb-assets*` | `ask` | Human confirmation required before running recursive discovery |
| **Active Reconnaissance**| `shell` | `*bb-recon*`, `subfinder *` | `ask` | Human confirmation required before probing assets |
| **Active HTTP Probing** | `shell` | `*bb-http*`, `httpx *` | `ask` | Human confirmation required before sending web traffic |
| **Nuclei Scanning** | `shell` | `*bb-nuclei*`, `nuclei *` | `ask` | Human confirmation required before vulnerability scanning |
| **Web App Crawling** | `shell` | `*bb-webapp*`, `katana *` | `ask` | Human confirmation required before crawling web applications |
| **JavaScript Analysis** | `shell` | `*bb-js*` | `ask` | Human confirmation required before running JavaScript endpoint extraction |
| **API Intelligence** | `shell` | `*bb-api*` | `ask` | Human confirmation required before probing API specifications or endpoints |
| **Workflow Intelligence** | `shell` | `*bb-workflow*` | `ask` | Human confirmation required before executing multi-step business logic tests |
| **Cloud Intelligence** | `shell` | `*bb-cloud*` | `ask` | Human confirmation required before executing active cloud security tests |
| **Authentication Intelligence** | `shell` | `*bb-auth*` | `ask` | Human confirmation required before executing active authentication/session tests |
| **Auth Correlation** | `shell` | `*bb-auth-correlate*` | `ask` | Human confirmation required before launching active authentication correlation tests |
| **Infrastructure Intelligence** | `shell` | `*bb-infra*` | `ask` | Human confirmation required before launching active infrastructure exposure tests |
| **Concurrency Intelligence** | `shell` | `*bb-race*` | `ask` | Human confirmation required before launching active concurrency or race condition testing |
| **Tool Installation** | `shell` | `*bb-install*` | `ask` | Human confirmation required before modifying system tools |
| **Tool Updates** | `shell` | `*bb-update*` | `ask` | Human confirmation required before updating system tools |
| **Remote Git Push** | `shell` | `git push *` | `ask` | Confirmation required before modifying remote repository |
| **External Submission** | `shell` | `*submit*report*`, `*hackerone*submit*`, `*bugcrowd*submit*` | `deny` | **Strictly denied**: Automated platform submissions prohibited |
| **Remote Script Pipes** | `shell` | `curl * \| *sh*`, `wget * \| *sh*` | `deny` | **Strictly denied**: Arbitrary remote shell piping prohibited |

### 2. Global Agent & Modular Skills Deployment
* **Global Availability**: `Bug-Bounty` is deployed globally into `~/.config/opencode/agents/Bug-Bounty.md` and `~/.config/opencode/skills/` using `./scripts/bb-deploy`. It is selectable as the default primary agent from **any working directory** (`cd ~ && opencode`, `cd /tmp && opencode`, `cd ~/Desktop/BugBounty-Agent && opencode`).
* **Canonical Source of Truth**: The Git repository remains the source-controlled source of truth (`agents/Bug-Bounty.md` and `skills/`). Updates in the repo are synchronized globally with `./scripts/bb-deploy` (or `bb-sync`).
* **Duplicate Prevention**: No project-local `.opencode/agents/` exists in the repository root, ensuring OpenCode discovers exactly one custom agent without duplicates.
* **Direct Orchestration (`subagent_depth: 1`)**: Separate subagent spawning is disabled in favor of focused, reproducible skill execution by `Bug-Bounty`.
* **Multi-Agent Distinction**: The previous 14-agent multi-agent architecture will be explored in a separate, dedicated repository in the future. It is intentionally not merged into this repository.

### 3. Environment & Runtime Status
* **Development & Evaluation Environments**: Kali/Linux is the test target. Windows may be used to edit the repository, but Windows-only tests and CI jobs are not part of this project.
* **Historical regression evidence:** Kali Linux x86-64 / Python 3.14.10: full suite at `b6308e8`, 1,329 passed and 2 tests skipped in 382.29 seconds; focused dispatcher/provider selection, 46 passed in 2.45 seconds. Hosted Ubuntu Python 3.10 and 3.14, and Windows Server 2025 Python 3.14, full-suite jobs passed at `b6308e8` in [GitHub Actions run 44584566317](https://github.com/Veldora-0/BugBounty-Agent/actions/runs/44584566317). The two skips were Windows-only cases, later removed under the Linux-only test policy. Current-code verification is recorded in the [Phase 24 guide](docs/phases/PHASE-24-final-integration-production-readiness.md). These results are code and fixture evidence; no bounty target was contacted and they do not establish live-target detection effectiveness.
* **Target Runtime**: Kali/Debian Linux with OpenCode installed, deploying `Bug-Bounty` globally via `bb-deploy`.

---

## Research Workflow in 4 Steps

### Step 1: Initialize a Local Program
Initialize program data under the directory currently opened in OpenCode:
```bash
./scripts/bb-init my-target-program
```
This creates `./programs/my-target-program/` under the current directory, containing `scope/`, `recon/`, `state/`, `evidence/`, `findings/`, and `reports/`.

### Step 2: Configure Authorized Scope
Edit `./programs/my-target-program/scope/scope.yaml`:
```yaml
program:
  name: "my-target-program"
targets:
  domains:
    - "target.com"
  recursive_subdomains:
    enabled: true
    max_depth: 0 # Unlimited recursive subdomains
out_of_scope:
  domains:
    - "admin.target.com"
```

Verify scope logic:
```bash
./scripts/bb-scope-check --scope ./programs/my-target-program/scope/scope.yaml dev.api.target.com
```

### Step 3: Run OpenCode
Start OpenCode in the directory where you want the program workspace stored:
```bash
opencode .
```
Program state remains under `./programs/my-target-program/` for this OpenCode session. `Bug-Bounty` automatically orchestrates reconnaissance, hypothesis formulation, on-demand tool verification, targeted testing, and deduplication.

### Step 4: Review Markdown Reports
Validated findings are stored in:
`./programs/my-target-program/reports/`

Each report includes all 17 standard bug bounty disclosure sections:
1. Title
2. Summary
3. Affected Asset
4. Affected Endpoint
5. Vulnerability Type
6. Severity
7. Description
8. Root Cause
9. Prerequisites
10. Reproduction Steps
11. Expected Result
12. Observed Result
13. Security Impact
14. Evidence (Sanitized HTTP request & response)
15. Remediation
16. Confidence
17. Scope Reference

---

## What Belongs in Git vs What Stays Local

| Belongs in Git Repository | Stays Local to Machine (Ignored) |
| :--- | :--- |
| Framework source code (`framework/`) | Target domain and URL lists |
| Agent definitions (`agents/`) | Reconnaissance scan logs (`recon/`, `scans/`) |
| Methodology skills (`skills/`) | Raw HTTP requests and responses (`evidence/`) |
| Controlled CLI wrappers (`scripts/`) | Vulnerability findings (`findings/`) |
| Scope templates (`templates/`) | Generated disclosure reports (`reports/`) |
| Unit tests (`tests/`) | Authorization tokens, API keys, credentials (`secrets.env`) |
| Architecture documentation (`docs/`) | Burp project files and browser sessions |

---

## License

This project is licensed under the [MIT License](LICENSE).
BugBounty-Agent is intended **strictly for authorized bug bounty programs and ethical security research**. Unauthorized testing against infrastructure without prior written consent is illegal.
