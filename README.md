# BugBounty-Agent

[![OpenCode Ready](https://img.shields.io/badge/OpenCode-Native-blue.svg)](https://opencode.ai)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-brightgreen.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Safety: Authorized Only](https://img.shields.io/badge/Testing-Authorized_Only-red.svg)](docs/security.md)

A professional, modular Bug Bounty Security Research Agent framework for **OpenCode**.

BugBounty-Agent is an orchestrated security research system designed to operate with the rigor of a senior penetration tester. Instead of indiscriminately running vulnerability scanners, the agent applies **deterministic scope enforcement**, **hypothesis-driven testing**, **cryptographic evidence validation**, and **local research state persistence**.

---

## Key Principles & Architectural Invariants

* **One Reusable Framework Repository**: Contains only the agent specifications, methodology skills, controlled CLI tools, tests, and documentation.
* **Complete Runtime Data Separation**: Real targets, recon logs, HTTP captures, credentials, and vulnerability reports remain **strictly local** on your machine (e.g. `~/BugBounty-Workspace/`) and are never committed to Git.
* **Never Silently Assume Authorization**: Every domain, IP, CIDR, and URL must pass through the Scope Engine before any network interaction.
* **Hypothesis-Driven Research**:
  $$\text{Observation} \longrightarrow \text{Hypothesis} \longrightarrow \text{Targeted Test} \longrightarrow \text{Evidence} \longrightarrow \text{Validation} \longrightarrow \text{Report}$$
* **No Automated Exploits or DoS**: Zero tolerance for denial-of-service, data destruction, password spraying, or unauthorized third-party probing.
* **No Auto-Submit**: Reports are generated in Markdown for human review and validation before disclosure.

---

## Repository Structure

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
│
├── agents/                    # Canonical Bug-Bounty agent definition
│   └── Bug-Bounty.md          # Primary orchestrator (deployed globally to ~/.config/opencode/agents/)
│
├── skills/                    # 17 modular OpenCode methodology skills (deployed globally)
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
│   ├── browser/
│   ├── oob/
│   ├── validation/
│   ├── deduplication/
│   ├── evidence/
│   ├── reporting/
│   └── knowledge-research/
│
├── framework/                 # Reusable Python 3 core engine
│   ├── assets/                # Recursive asset graph engine, DNS/IP/ASN/TLS/CDN models
│   ├── scope/                 # Scope engine, DNS boundary verification, normalizer
│   ├── state/                 # Persistent state manager, test fingerprinting, dedup
│   ├── validation/            # Security validation foundation & baseline comparison
│   ├── xss/                   # Context-aware XSS intelligence, DOM sources/sinks, stored correlation
│   ├── authz/                 # Authorization intelligence, BOLA/IDOR baseline validation, human approval gate
│   ├── ssrf/                  # SSRF intelligence, out-of-band canary correlation, blind verification
│   ├── injection/             # Injection intelligence, prioritization, SQLi/NoSQLi/SSTI/Command validators
│   ├── tools/                 # Tool registry, installer, doctor, deployer
│   └── common/                # Evidence store, sanitization, tool detection, config
│
├── scripts/                   # Controlled CLI wrappers with mandatory scope checks
│   ├── bb-deploy              # Deploy and sync agent and skills to global OpenCode
│   ├── bb-sync                # Synchronization alias for bb-deploy
│   ├── bb-init                # Workspace and program initializer
│   ├── bb-doctor              # Diagnostics utility across 19 system categories
│   ├── bb-assets              # Recursive asset intelligence & graph engine CLI
│   ├── bb-scope-check         # Scope verification utility
│   ├── bb-target-normalize    # Target canonicalization & DNS boundary check
│   ├── bb-recon               # Controlled recon (subfinder, assetfinder, httpx)
│   ├── bb-http                # Rate-limited HTTP client with evidence logging
│   ├── bb-content             # Controlled content fuzzer wrapper (ffuf)
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
├── templates/                 # Reusable templates
│   ├── scope.yaml             # Complete program scope definition template
│   ├── program.yaml           # Program metadata and preferences template
│   ├── finding.json           # Finding JSON schema
│   ├── report.md              # 17-section markdown report template
│   └── config.example.yaml    # Global framework configuration template
│
├── tests/                     # 100% automated test suite
│   ├── test_asset_model.py
│   ├── test_asset_graph.py
│   ├── test_asset_engine.py
│   ├── test_scope.py
│   ├── test_recursive_subdomains.py
│   ├── test_target_normalization.py
│   ├── test_deduplication.py
│   ├── test_finding_schema.py
│   └── test_runtime_isolation.py
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
* Linux / Kali Linux or Windows / macOS
* Python 3.10+
* OpenCode

### 2. Quickstart
```bash
# Clone the repository
git clone https://github.com/Veldora-0/BugBounty-Agent.git
cd BugBounty-Agent

# Install lightweight dependencies
pip install pyyaml pytest

# Run the test suite
python -m pytest -v
```

## Supported Security Tools Catalog

BugBounty-Agent maintains an authoritative, machine-readable tool registry in [`config/tools.yaml`](config/tools.yaml). Tools are organized by operational tiers (**CORE**, **SPECIALIST**, **PROVIDER-BACKED**, **OPTIONAL**, **LEGACY**) and mapped to specific research capabilities.

### Master Tools Reference Table

| Tool | Category | Purpose | Tier | API Key | Auto-Install | Setup |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **subfinder** | Subdomain Enumeration | Passive subdomain discovery via 40+ datasets | CORE | Optional Providers | Yes | [subfinder.md](docs/tools/subfinder.md) |
| **amass** | Asset Discovery | In-depth attack surface mapping & ASN correlation | CORE | Optional Providers | Yes | [subfinder.md](docs/tools/subfinder.md) |
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
| **urlfinder** | URL Discovery | Passive URL and endpoint discovery | CORE | Optional Providers | Yes | [subfinder.md](docs/tools/subfinder.md) |
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
11. **XSS Analysis**: `dalfox`, `bb-injection`
12. **Injection & Parser Flaws**: `sqlmap`, `nuclei`, `bb-injection`
13. **Authorization (BOLA/IDOR)**: `bb-authz` (dual-account reasoning), `proxify`
14. **Business Logic & Workflows**: `bb-business-logic`, `playwright`
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
Run deep diagnostics across 10 system categories:
```bash
./scripts/bb-doctor
```
Checks:
* **System**: OS, architecture, Python version, workspace root
* **Dependencies**: Go, Python3, Pipx, Git, Cargo, Docker, Jq
* **Tools**: Status of all 44 registered tools, version compatibility, and missing tools
* **Providers**: API keys for ProjectDiscovery Cloud, Shodan, Censys, SecurityTrails, VirusTotal, etc.
* **Browser**: Playwright and Chromium sandbox readiness
* **Wordlists**: SecLists presence on Kali (`/usr/share/seclists`) or user local directory
* **Configuration**: `secrets.env` file presence and permissions
* **Scope Engine**: Recursive subdomain validation and boundary security integrity
* **Asset Intelligence**: Arbitrary-depth recursive graph engine and relationship models
* **OpenCode**: Agent prompts and modular skills readiness

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

## Phase 1: Recursive Asset Intelligence Engine

The **Asset Intelligence Engine** (`framework/assets/` & `scripts/bb-assets`) constructs and maintains an authoritative, recursive asset graph for authorized security research targets:

* **Arbitrary-Depth Recursion**: Dynamically traverses subdomains down to arbitrary depths (depth 1, 2, 3, 4, 5, ...), preventing artificial discovery caps.
* **Network & Infrastructure Graph**: Tracks directional semantic relationships:
  * `HAS_SUBDOMAIN`: Apex domain or parent subdomain $\longrightarrow$ child subdomain
  * `RESOLVES_TO`: Hostname $\longrightarrow$ IPv4/IPv6 address
  * `CNAME_TO`: Hostname $\longrightarrow$ canonical name target
  * `PRESENT_IN_CERT`: TLS certificate $\longrightarrow$ Subject Alternative Name (SAN)
  * `HOSTED_BY`: Hostname or IP $\longrightarrow$ CDN edge or Cloud provider
  * `BELONGS_TO_ASN`: IP address $\longrightarrow$ Autonomous System Number (ASN)
* **DNS & Wildcard Mitigation**: Automatic active probing of randomized non-existent subdomains (`_bb_probe_<uuid>.<domain>`) to detect wildcard DNS and prevent synthetic wildcard subdomain explosion.
* **TLS Certificate SAN Extraction**: Analyzes X.509 Subject Alternative Names and re-queues newly discovered in-scope hostnames into recursive traversal.
* **CDN & Cloud Edge Attribution**: Classifies CDN reverse proxies (Cloudflare, CloudFront, Akamai, Fastly, Azure, Google Cloud) via CNAME fingerprints and BGP ASN mapping with confidence ratings (`CONFIRMED`, `PROBABLE`, `UNKNOWN`).
* **Multi-Source Provenance & Confidence Scoring**: Calibrates confidence from `LOW` (unverified third-party passive feed) to `HIGH` ($\ge 2$ independent sources) and `CONFIRMED` (active DNS verification or verified network probe).
* **Deterministic Scope Integration**: Offline validation through `ScopeEngine` gates every node before active resolution or recursion; out-of-scope nodes are recorded and skipped without further descent.
* **CLI Utility**:
  ```bash
  # Discover recursive subdomains with ASCII tree visualization
  ./scripts/bb-assets --domain example.com --scope scope.yaml --tree

  # Execute for an initialized program workspace
  ./scripts/bb-assets --program acme-corp --tree

  # Passive analysis only (disables active DNS and TLS SAN probes)
  ./scripts/bb-assets --program acme-corp --passive-only --json
  ```

---

## Phase 2: Reconnaissance Intelligence & Enrichment Engine

The **Reconnaissance Intelligence Engine** (`framework/recon/` & `scripts/bb-recon`) consumes confirmed assets from the `AssetGraph` and enriches them with structured, normalized observations:

* **Capability-Driven Orchestration**: Dynamically orchestrates recon capabilities (`dns`, `tls`, `http`, `ports`, `tech`, `endpoints`) instead of blindly chaining static security tools.
* **HTTP Service Intelligence**: Captures URLs, status codes, page titles, server banners, security headers, content lengths, response times, and redirect chains.
* **Port & Network Service Discovery**: Identifies open TCP ports and protocols with bounded safety budgets, preventing disruptive port flooding.
* **DNS & TLS Certificate Enrichment**: Maps A, AAAA, CNAME, MX, and NS records, enriching IPs directly into the `AssetGraph`. Extracted in-scope TLS SAN names are dynamically promoted to graph nodes connected via `PRESENT_IN_CERT` edges.
* **Technology Fingerprinting**: Identifies servers (Nginx, Apache, IIS, Caddy), frameworks (Next.js, Express, ASP.NET, PHP), and CMS platforms (WordPress, Drupal) with calibrated confidence (`OBSERVED`, `PROBABLE`, `CONFIRMED`).
* **Endpoint & Route Discovery**: Structured mapping of web routes and API paths (`METHOD URL`), status codes, and content types with strict deduplication.
* **Atomic State Persistence**: Persists observations atomically to `~/BugBounty-Workspace/programs/<name>/state/recon.json`, ensuring zero file corruption. Supports resumable execution (`--resume`) to skip already-probed assets.
* **CLI Utility**:
  ```bash
  # Enrich attack surface for an initialized program workspace
  ./scripts/bb-recon --program acme-corp --tree

  # Passive analysis only without active network probes
  ./scripts/bb-recon --program acme-corp --passive-only

  # Target specific capabilities on a single asset
  ./scripts/bb-recon --program acme-corp --asset api.example.com --capabilities "http,tls,tech"

  # Resume previous scan and output JSON observations
  ./scripts/bb-recon --program acme-corp --resume --json
  ```

---

## Phase 3: Web Application Intelligence & Attack Surface Mapping

The **Web Application Intelligence Engine** (`framework/webapp/` & `scripts/bb-webapp`) converts Phase 2 web service observations into an authoritative, structured attack surface relationship model:

* **Application Attack Surface Topology**: Models relationships between `WebApplication`, `WebPage`, `WebEndpoint`, `ParameterObservation`, `FormObservation`, `CookieObservation`, `ResourceObservation`, and `LinkObservation` via `WebAppGraph`.
* **Bounded Crawl Policies**: Centralized safety ceilings (`CrawlPolicy`) enforcing conservative bounds: maximum 500 pages, maximum crawl depth 3, maximum 2000 requests, 2 MB response limits, and strict same-origin filtering by default.
* **Deterministic URL Normalization**: Canonicalizes URLs via `canonicalize_url()` (resolves path traversal, strips default ports and fragments, sorts query parameters deterministically).
* **HTML Element & Form Extraction**: Parses HTML deterministically to capture links, forms (action, method, field types, password and file upload indicators), buttons, and query/body parameters without automatic form submission or payload execution.
* **Robots.txt & Sitemap Intelligence**: Discovers valid in-scope endpoint routes from `/robots.txt` and XML sitemaps without recursive expansion loops.
* **Cookie & Security Header Metadata**: Extracts and documents Set-Cookie flags (`Secure`, `HttpOnly`, `SameSite`) and security response headers.
* **Static & Dynamic Resource Inventory**: Inventories scripts, stylesheets, fonts, and images, creating a clean dataset for Phase 4 JavaScript analysis.
* **Atomic State Persistence**: Writes observations atomically to `~/BugBounty-Workspace/programs/<name>/state/webapps.json`. Supports resumable execution (`--resume`).
* **CLI Utility**:
  ```bash
  # Map web applications in a program workspace with ASCII attack surface tree
  ./scripts/bb-webapp --program acme-corp --tree

  # Map a specific application with customized crawl depth
  ./scripts/bb-webapp --program acme-corp --asset app.example.com --max-pages 100 --max-depth 2

  # Passive analysis only using existing reconnaissance observations
  ./scripts/bb-webapp --program acme-corp --passive-only

  # Resume previous crawl and output JSON state
  ./scripts/bb-webapp --program acme-corp --resume --json
  ```

---

## Phase 4: JavaScript Intelligence & Client Analysis Engine

The **JavaScript Intelligence Engine** (`framework/javascript/` & `scripts/bb-js`) analyzes client-side JavaScript resources collected during web crawling and attack surface discovery:

* **Pure Static Analysis**: Analyzes script source code via deterministic regex matching and parsing without arbitrary code execution (`eval`, `exec`, or browser runtime execution of target scripts are forbidden).
* **API & Endpoint Extraction**: Discovers relative and absolute HTTP endpoints, API paths, and realtime communication channels from standard client libraries (`fetch`, `axios`, `$.ajax`, `XMLHttpRequest`, `WebSocket`, and REST route patterns).
* **Client-Side SPA Routing**: Maps frontend single-page application routes across modern frameworks (React Router `<Route path="...">`, Vue Router `path: '...'`, and client links), uncovering hidden views and admin paths.
* **Parameter Discovery**: Extracts query and payload parameter names referenced in `URLSearchParams`, query string templates, and request object builders, feeding downstream testing.
* **Client Dependency Identification**: Detects frontend libraries and utility frameworks (React, Vue.js, Angular, jQuery, Axios, Lodash, Next.js, Webpack, Vite) with extracted version numbers when embedded.
* **Source Map Detection**: Identifies source map directives (`//# sourceMappingURL=...`) and resolves source map targets deterministically against base script URLs.
* **Sensitive String Classification & Automatic Masking**: Classifies sensitive configuration strings, tokens, and endpoints into calibrated risk tiers (`HIGH_CONFIDENCE_SECRET`, `SENSITIVE_LOOKING`, `INTERESTING`, `INFORMATIONAL`). High-confidence credentials (AWS keys, JWTs, private keys, bearer tokens) are **automatically masked** before persistence or display to prevent secret exposure.
* **Atomic State Persistence**: Persists observations atomically to `~/BugBounty-Workspace/programs/<name>/state/javascript.json`. Supports incremental and resumable execution (`--resume`).
* **CLI Utility**:
  ```bash
  # Analyze JavaScript resources for a program workspace with ASCII tree visualization
  ./scripts/bb-js --program acme-corp --tree

  # Target a specific domain or host
  ./scripts/bb-js --program acme-corp --domain app.example.com

  # Analyze a specific JavaScript resource URL directly
  ./scripts/bb-js --program acme-corp --resource https://app.example.com/static/js/main.js

  # Preview actions without fetching new resources
  ./scripts/bb-js --program acme-corp --dry-run

  # Resume previous analysis and output structured JSON
  ./scripts/bb-js --program acme-corp --resume --json
  ```

---

## Phase 5: API Security & Parameter Intelligence Engine

The **API Security & Parameter Intelligence Engine** (`framework/api/` & `scripts/bb-api`) transforms multi-source observations into an authoritative, normalized API attack surface model:

* **Multi-Source Intelligence Correlation**: Correlates API endpoints across Phase 2 HTTP reconnaissance, Phase 3 web crawling, Phase 4 JavaScript bundle analysis, and authoritative API specifications into unified endpoint entities with rich multi-source provenance.
* **OpenAPI 2.0 & 3.x Specification Ingestion**: Safely parses OpenAPI 2.0 (Swagger) and OpenAPI 3.x specifications in JSON and YAML formats. Extracts servers/base paths, operations, query/path/header/cookie/body parameters, request bodies, response schemas, and authentication schemes (`basic`, `bearer`, `api-key`, `oauth2`, `openid-connect`).
* **REST Intelligence & Path Parameter Inference**: Recognizes and normalizes REST path parameter patterns (`/api/v1/users/123` $\longrightarrow$ `/api/v1/users/{user_id}`, `/api/orders/<uuid>` $\longrightarrow$ `/api/orders/{order_id}`), preserving concrete observed URLs alongside generalized route templates.
* **GraphQL Intelligence**: Automatically detects GraphQL endpoints and operations from URLs, content types, and script bodies. Supports controlled, safe schema introspection checks under strict request limits.
* **Parameter Intelligence & Semantic Classification**: Unifies parameters across query strings, path templates, forms, request payloads, and client scripts. Classifies semantic roles (`user_id`, `account_id`, `resource_id`, `redirect`, `callback`, `search`, `filter`, `sort`, `page`, `limit`, `token`, `session`, `file`).
* **Bounded Schema Representations**: Builds bounded structural models of request and response payloads, enforcing maximum depth and field limits to prevent recursion and memory exhaustion.
* **Integrated API Graph**: Direct semantic graph relationships (`WebApplication` $\longrightarrow$ `ApiApplication` $\longrightarrow$ `ApiEndpoint` $\longrightarrow$ `ApiParameter`, `ApiSpecification` $\longrightarrow$ `ApiEndpoint`, `JavaScriptResource` $\longrightarrow$ `ApiEndpoint`).
* **Atomic State Persistence**: Writes observations atomically to `~/BugBounty-Workspace/programs/<name>/state/api.json`. Supports incremental and resumable execution (`--resume`).
* **CLI Utility**:
  ```bash
  # Render visual ASCII API attack surface tree for a program workspace
  ./scripts/bb-api --program acme-corp --tree

  # Target a specific domain or host
  ./scripts/bb-api --program acme-corp --domain api.example.com --tree

  # Ingest and parse an OpenAPI / Swagger specification
  ./scripts/bb-api --program acme-corp --spec https://api.example.com/openapi.json

  # Filter and inspect GraphQL services
  ./scripts/bb-api --program acme-corp --graphql --json

  # Passive analysis only using existing observations
  ./scripts/bb-api --program acme-corp --passive-only
  ```

---

## Phase 6: Security Validation & Vulnerability Analysis Foundation

The **Security Validation Foundation Engine** (`framework/validation/` & `scripts/bb-validate`) transforms reconnaissance, webapp, JS, and API intelligence into controlled, hypothesis-driven security validation attempts and structured security findings:

* **Formal Finding Lifecycle**: Enforces immutable state transitions (`CANDIDATE` $\longrightarrow$ `TESTING` $\longrightarrow$ `OBSERVED` $\longrightarrow$ `VALIDATED` / `REJECTED` / `DUPLICATE` / `NEEDS_MANUAL_REVIEW`). A finding is never confirmed solely because a payload was dispatched.
* **Controlled Request Mutation**: `RequestBuilder` performs deterministic, single-parameter mutations across query strings, path variables, headers, cookies, JSON bodies, and form data without collateral alterations.
* **Safe Testing Policy (`SecurityTestPolicy`)**: Centralized policy engine enforcing method restrictions (defaults to safe methods `GET`, `HEAD`, `OPTIONS`), blocking destructive actions, screening state-changing GET endpoints, and capping request counts, timeouts, payload sizes, and response bytes.
* **Strict Anti-SSRF & Scope Enforcement**: Every validation request is verified by `ScopeEngine`. Private IP ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`) and `localhost` are strictly rejected.
* **Empirical Baseline Comparison**: Takes an untouched baseline snapshot of target behavior before mutation, evaluating differential signals (status changes, size deltas, content type variations, body similarity, marker reflections, and error signatures).
* **Proof-of-Concept Validators**:
  * **`ReflectedXSSValidator`**: Detects harmless marker (`XSHIELD_TEST_<token>`) reflection in HTML/JSON responses without executing JavaScript or launching a browser.
  * **`OpenRedirectValidator`**: Detects unvalidated external redirection to a controlled canary URL (`https://canary.bugbounty-agent.local/redirect_<token>`) via 3xx status codes and `Location` headers without navigating victim browsers.
* **Dual-Principal Authorization Foundation**: Formal data models (`Principal`, `SessionContext`, `ResourceIdentifier`, `ExpectedAccessPolicy`) for comparing resource access divergence without destructive testing or credential harvesting.
* **Sanitized Cryptographic Evidence**: Integrates `EvidenceStore` with automatic token and cookie redaction (`Authorization: [REDACTED]`, `Cookie: [REDACTED]`), assigning SHA-256 digests.
* **State Persistence & Deduplication**: Atomic storage in `~/BugBounty-Workspace/programs/<name>/state/security.json` with signature-based finding deduplication (`FindingDeduplicator`).
* **CLI Utility**:
  ```bash
  # Render visual ASCII validation attack tree
  ./scripts/bb-validate --program acme-corp --tree

  # Targeted validator execution on specific parameter
  ./scripts/bb-validate --program acme-corp --endpoint "https://app.example.com/search" --parameter q --validator reflected-xss

  # Offline candidate prioritization from existing state
  ./scripts/bb-validate --program acme-corp --passive-only --json

  # Dry-run plan without issuing network requests
  ./scripts/bb-validate --program acme-corp --dry-run
  ```

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
* **Development Machine**: Windows 10/11 x86_64 running Google Antigravity. Static configuration, schema compliance, and permission rule matching are validated locally via Python test suites.
* **Target Runtime**: Kali/Debian Linux with OpenCode installed. Actual interactive terminal execution on a live Kali workstation is recorded as **PENDING — requires Kali**.

---

## Research Workflow in 4 Steps

### Step 1: Initialize a Local Program
Initialize an isolated local workspace directory outside Git:
```bash
./scripts/bb-init my-target-program
```
This creates `~/BugBounty-Workspace/programs/my-target-program/` containing `scope/`, `recon/`, `state/`, `evidence/`, `findings/`, and `reports/`.

### Step 2: Configure Authorized Scope
Edit `~/BugBounty-Workspace/programs/my-target-program/scope/scope.yaml`:
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
./scripts/bb-scope-check --scope ~/BugBounty-Workspace/programs/my-target-program/scope/scope.yaml dev.api.target.com
```

### Step 3: Run OpenCode
Start OpenCode in the repository:
```bash
opencode .
```
`Bug-Bounty` automatically orchestrates reconnaissance, hypothesis formulation, on-demand tool verification, targeted testing, and deduplication.

### Step 4: Review Markdown Reports
Validated findings are stored in:
`~/BugBounty-Workspace/programs/my-target-program/reports/`

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
| Agent definitions (`.opencode/agents/`) | Reconnaissance scan logs (`recon/`, `scans/`) |
| Methodology skills (`.opencode/skills/`) | Raw HTTP requests and responses (`evidence/`) |
| Controlled CLI wrappers (`scripts/`) | Vulnerability findings (`findings/`) |
| Scope templates (`templates/`) | Generated disclosure reports (`reports/`) |
| Unit tests (`tests/`) | Authorization tokens, API keys, credentials (`secrets.env`) |
| Architecture documentation (`docs/`) | Burp project files and browser sessions |

---

## License

This project is licensed under the [MIT License](LICENSE).
BugBounty-Agent is intended **strictly for authorized bug bounty programs and ethical security research**. Unauthorized testing against infrastructure without prior written consent is illegal.
