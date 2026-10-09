# Technology Stack

**Analysis Date:** 2026-10-09

## Languages

**Primary:**
- Python 3.10+ (tested through 3.14 on Windows and Linux/Kali) - Core framework logic, testing engines, data models, state management, CLI wrappers, and verification harnesses across `framework/`.

**Secondary:**
- POSIX Shell (bash) - Linux/Kali execution wrappers and CLI entrypoints in `scripts/`.
- Windows Command Script / Batch (.cmd) - Windows execution wrappers in `scripts/`.
- YAML - Tool registry (`config/tools.yaml`), wordlist catalog (`config/wordlists.yaml`), and program scope contracts (`scope.yaml`).
- JSONC / JSON - OpenCode agent permission definitions (`opencode.jsonc`) and persistent program research state in `state/*.json`.
- Markdown - Canonical OpenCode agent specification (`agents/Bug-Bounty.md`), modular skill directives (`skills/*/SKILL.md`), and architecture documentation (`docs/`).

## Runtime

**Environment:**
- Python 3.10+ Standard Runtime (`dataclasses`, `typing`, `json`, `hashlib`, `urllib.parse`, `ipaddress`, `socket`, `ssl`, `subprocess`, `re`, `pathlib`).
- OpenCode V2 Runtime - Primary orchestration host providing agent discovery, tool policy enforcement, and skill integration.
- Playwright Headless Browser Runtime - Chromium / Firefox / WebKit headless automation for dynamic DOM evaluation and single-page app (SPA) security testing.

**Package Manager:**
- Python pip / pipx - Standard Python package management for framework dependencies and CLI utilities.
- Debian/Ubuntu APT - System package management on Kali Linux for security tools (`nmap`, `sqlmap`, `ffuf`, `wpscan`, `jq`).
- Go toolchain (`go install`) - ProjectDiscovery and modern Go-based security tooling installation (`subfinder`, `httpx`, `nuclei`, `katana`, `amass`, `interactsh`).
- Cargo / Rust - Binary package management for high-speed scanners (`feroxbuster`).

## Frameworks

**Core:**
- Native Modular Python Framework (19 domain packages under `framework/`): Single-agent hypothesis-driven bug bounty research engine.
- OpenCode Single-Agent Platform: Orchestration runtime hosting the canonical `Bug-Bounty` agent (`agents/Bug-Bounty.md`).

**Testing:**
- Pytest 8.x - Comprehensive automated test suite runner across unit, integration, and security invariant tests in `tests/`.

**Build/Dev:**
- Standard Python Bytecode Compiler (`python -m compileall`) - Static verification and syntax integrity checking.
- Native Git - Source code version control maintaining framework code while enforcing strict data isolation for runtime state and targets.

## Key Dependencies

**Critical:**
- `pyyaml` (6.x) - High-performance YAML parser for loading tool definitions (`config/tools.yaml`), wordlists (`config/wordlists.yaml`), and program scope configurations.
- `playwright` (1.40+) - Headless browser automation engine powering client-side JavaScript execution, SPA crawling, and DOM XSS sink analysis.
- `pytest` (8.x) - Unit and integration test execution framework verifying all 14 research phases and 323 automated test cases.

**Infrastructure:**
- Python Standard Library (`urllib`, `socket`, `ssl`, `ipaddress`) - Network communication, TLS certificate inspection, and scope normalization.
- Python `subprocess` & `shutil` - Process orchestration and binary detection for external security tools (strictly without `shell=True`).
- Python `hashlib` & `tempfile` - Cryptographic SHA-256 evidence digests, session token masking, and atomic file replacements.

## Configuration

**Environment:**
- `~/.config/bugbounty-agent/secrets.env` - Secure credential vault for external API keys and tokens (strictly ignored by Git).
- Environment Variables:
  - `PDCP_API_KEY` - ProjectDiscovery Cloud Platform API integration.
  - `SHODAN_API_KEY` - Shodan host and service reconnaissance.
  - `CENSYS_API_TOKEN`, `CENSYS_ORGANIZATION_ID` - Censys search engine intelligence.
  - `SECURITYTRAILS_API_KEY` - SecurityTrails historical DNS datasets.
  - `VT_API_KEY` - VirusTotal threat and URL intelligence.
  - `URLSCAN_API_KEY` - urlscan.io automated browser scan data.
  - `GITHUB_TOKEN` - GitHub API repository and secret reconnaissance.
  - `WPSCAN_API_TOKEN` - WPScan vulnerability database API.
  - `INTERACTSH_TOKEN` - Private out-of-band interaction server authentication.
  - Webhook URLs: `SLACK_WEBHOOK_URL`, `DISCORD_WEBHOOK_URL`, `TELEGRAM_API_KEY`.

**Build & Tooling:**
- `opencode.jsonc` - OpenCode V2 engine configuration enforcing single-agent mode, rule permission hierarchies, and command confirmation gates.
- `config/tools.yaml` - Comprehensive registry of 44 bug bounty security tools with verification commands, install methods, and capabilities.
- `config/wordlists.yaml` - Curated dictionary paths and fallbacks for content and parameter discovery.

## Platform Requirements

**Development:**
- Windows 10/11 or Linux (Debian / Ubuntu / Kali Linux 2024+).
- Python 3.10+ installed and on system `PATH`.
- Git 2.30+.

**Production / Operation:**
- Kali Linux 2024+ (primary target research operating system) or standard Linux with Go/Python/Rust toolchains.
- OpenCode CLI (`opencode`) installed globally (`~/.opencode/bin/opencode`).
- Local isolated research workspace outside the Git repository: `~/BugBounty-Workspace/programs/<program-name>/`.

---

*Stack analysis: 2026-10-09*
*Update after major dependency changes*
