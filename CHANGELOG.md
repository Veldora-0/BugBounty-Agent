# Changelog

All notable changes to the BugBounty-Agent project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
