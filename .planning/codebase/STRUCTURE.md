# Codebase Structure

**Analysis Date:** 2026-10-09

## Directory Layout

```
BugBounty-Agent/
├── agents/             # Canonical OpenCode agent definitions
│   └── Bug-Bounty.md   # Primary orchestrator agent (source of truth)
├── config/             # Framework configuration & metadata registries
│   ├── tools.yaml      # Catalog of 44 curated security tools
│   └── wordlists.yaml  # Curated wordlist dictionary mapping
├── docs/               # Technical documentation & architectural specifications
│   ├── tools/          # Individual tool guides & API key documentation
│   ├── architecture.md # High-level architecture specification
│   ├── security.md     # Safety controls & ethical boundaries
│   └── skills.md       # 18 modular skills catalog documentation
├── evidence/           # Local evidence storage (ignored by Git)
├── examples/           # Example configurations and scope templates
├── framework/          # Native Python core framework packages (19 subpackages)
│   ├── api/            # API surface intelligence (REST, GraphQL, WebSocket)
│   ├── assets/         # Recursive asset discovery graph & CDN attribution
│   ├── authentication/ # Session lifecycle, JWT claims, MFA, token reuse
│   ├── authz/          # Access control, BOLA/IDOR, tenant isolation
│   ├── business_logic/ # State machine workflows, race conditions
│   ├── cloud_security/ # Cloud storage, metadata SSRF, dangling CNAMEs
│   ├── common/         # Configuration, cryptographic evidence, tools
│   ├── findings/       # Finding schemas, CVSS v3.1, 17-section reports
│   ├── http_trust/     # Host header, cache poisoning, request smuggling
│   ├── injection/      # Non-destructive SQLi, NoSQLi, SSTI, CMDi proofs
│   ├── javascript/     # Static JS analysis, route extraction, DOM sinks
│   ├── recon/          # Passive and active reconnaissance engine
│   ├── scope/          # Scope verification, normalization, boundary logic
│   ├── ssrf/           # SSRF & Out-of-band interaction engine (Interactsh)
│   ├── state/          # Persistent program state, fingerprinting, dedup
│   ├── tools/          # Doctor, detector, installer, deployer, providers
│   ├── validation/     # Adversarial 6-gate checklist & FP classification
│   ├── webapp/         # Web attack surface mapping, CORS, forms, cookies
│   └── xss/            # Context-aware XSS validation & DOM verification
├── scripts/            # Dual-platform CLI wrapper entrypoints (25 utilities)
│   ├── bb-*            # POSIX Shell executable scripts (Linux/Kali)
│   └── bb-*.cmd        # Windows Batch command scripts
├── skills/             # 18 modular OpenCode skills (deployed globally)
│   ├── api-security/
│   ├── asset-intelligence/
│   ├── authentication/
│   ├── authorization/
│   ├── browser/
│   ├── business-logic/
│   ├── cloud-security/
│   ├── deduplication/
│   ├── evidence/
│   ├── injection/
│   ├── javascript/
│   ├── knowledge-research/
│   ├── oob/
│   ├── reconnaissance/
│   ├── reporting/
│   ├── scope-management/
│   ├── validation/
│   └── web-security/
├── state/              # Local program state files (ignored by Git)
├── templates/          # Templates for program initialization and reports
├── tests/              # Automated Pytest suite (32 test files, 323 tests)
├── .gitignore          # Strict isolation rules ignoring target data and secrets
├── AGENTS.md           # Single-agent architecture and skills specification
├── CHANGELOG.md        # Complete version and phase release history
├── CONTRIBUTING.md     # Contributor guidelines
├── LICENSE             # MIT License
├── opencode.jsonc      # OpenCode V2 engine configuration and permissions
├── README.md           # Primary user documentation, installation, and CLI reference
└── SECURITY.md         # Framework safety rules, ethical use, and safeguards
```

## Directory Purposes

**`agents/`:**
- Purpose: Houses canonical OpenCode agent specifications.
- Contains: `Bug-Bounty.md` (the sole primary agent in the repository).
- Key files: `agents/Bug-Bounty.md` - Source of truth synchronized globally via `bb-deploy`.

**`config/`:**
- Purpose: Machine-readable specifications for tools and dictionary wordlists.
- Contains: YAML configuration files.
- Key files: `config/tools.yaml` (44 tool definitions with installation, verification, and API requirements), `config/wordlists.yaml` (paths to Seclists and standard dictionaries).

**`docs/`:**
- Purpose: Developer, architecture, and security documentation.
- Key files: `docs/architecture.md`, `docs/security.md`, `docs/skills.md`, `docs/tools/`.

**`framework/`:**
- Purpose: Python source code implementing all 14 research phases and domain capabilities.
- Contains: 19 modular packages. Each package encapsulates models, analyzers, validators, engines, and offline labs.
- Subdirectories: `api/`, `assets/`, `authentication/`, `authz/`, `business_logic/`, `cloud_security/`, `common/`, `findings/`, `http_trust/`, `injection/`, `javascript/`, `recon/`, `scope/`, `ssrf/`, `state/`, `tools/`, `validation/`, `webapp/`, `xss/`.

**`scripts/`:**
- Purpose: Controlled CLI wrapper entrypoints executed by researchers or the `Bug-Bounty` agent.
- Contains: 25 POSIX shell scripts (`bb-*`) paired with 25 Windows batch scripts (`bb-*.cmd`).
- Key files: `bb-doctor`, `bb-init`, `bb-deploy`, `bb-scope-check`, `bb-assets`, `bb-recon`, `bb-webapp`, `bb-js`, `bb-api`, `bb-authz`, `bb-ssrf`, `bb-inject`, `bb-http`, `bb-workflow`, `bb-cloud`, `bb-auth`, `bb-validate`, `bb-evidence`.

**`skills/`:**
- Purpose: 18 modular OpenCode skills deployed globally to `~/.config/opencode/skills/`.
- Contains: One directory per skill, each containing a `SKILL.md` with YAML frontmatter.

**`tests/`:**
- Purpose: Pytest automated test suite ensuring high reliability and zero regressions.
- Contains: 32 test files covering all 14 phases, runtime isolation, and OpenCode V2 integration.

## Key File Locations

**Entry Points:**
- `agents/Bug-Bounty.md` - Primary OpenCode agent definition.
- `scripts/bb-doctor` / `scripts/bb-doctor.cmd` - Diagnostic and health check entrypoint.
- `scripts/bb-deploy` / `scripts/bb-deploy.cmd` - Global OpenCode synchronization tool.
- `scripts/bb-init` / `scripts/bb-init.cmd` - Target program workspace initializer.

**Configuration:**
- `opencode.jsonc` - OpenCode V2 configuration, tool permissions, and single-agent depth.
- `config/tools.yaml` - Tool metadata, binary paths, tiers, install instructions.
- `config/wordlists.yaml` - Wordlist locations and fallback discovery paths.
- `scope.yaml` (in target program directory) - Scope definition and rules.

**Core Logic:**
- `framework/scope/engine.py` - Scope evaluation engine enforcing authorization invariants.
- `framework/state/manager.py` - Isolated program state manager with atomic writes.
- `framework/findings/schema.py` - Finding schemas, CVSS v3.1 calculations, 17-section reporting.
- `framework/tools/doctor.py` - 23-category system doctor implementation.
- `framework/*/engine.py` - Domain engines for each of the 14 research capabilities.

**Testing:**
- `tests/test_opencode_runtime.py` - OpenCode V2 schema, permissions, and agent discovery tests.
- `tests/test_runtime_isolation.py` - Subprocess safety tests (verifying zero `shell=True`).
- `tests/test_authentication_engine.py` - Phase 14 authentication and session engine tests.
- `tests/test_doctor.py` - Diagnostic engine tests.

**Documentation:**
- `README.md` - Primary user guide and CLI reference.
- `AGENTS.md` - Single-agent architectural model and skills catalog.
- `CHANGELOG.md` - Detailed release history across all 14 phases.

## Naming Conventions

**Files:**
- `bb-<action>`: Controlled CLI wrapper script (e.g. `scripts/bb-recon`, `scripts/bb-auth`).
- `bb-<action>.cmd`: Windows CLI launcher script.
- `<module>.py`: Python module in `snake_case`.
- `test_<subsystem>.py`: Automated test file in `tests/`.
- `SKILL.md`: Skill methodology contract inside `skills/<skill-name>/`.

**Code Identifiers:**
- `PascalCase`: Python classes, dataclasses, and custom exceptions (`ScopeEngine`, `IdentityProfile`, `NormalizationError`).
- `snake_case`: Functions, methods, and variables (`calculate_subdomain_depth`, `render_tree`).
- `UPPER_SNAKE_CASE`: Constants and enum member names (`ScopeStatus.IN_SCOPE`, `MFAState.PENDING`).

## Where to Add New Code

**New Research Domain / Capability Engine:**
- Framework engine: `framework/<new_domain>/` (implementing `models.py`, `engine.py`, `lab.py`, `__init__.py`).
- CLI script: `scripts/bb-<new_domain>` and `scripts/bb-<new_domain>.cmd`.
- OpenCode skill: `skills/<new_domain>/SKILL.md`.
- Automated test: `tests/test_<new_domain>_engine.py`.
- Tool doctor check: Add category check method in `framework/tools/doctor.py`.
- Permissions: Update `opencode.jsonc` and `agents/Bug-Bounty.md` with CLI permissions.

**New Tool in Registry:**
- Specification: Add tool definition block in `config/tools.yaml`.
- Tool documentation: Add guide in `docs/tools/<tool-name>.md`.

**New Shared Utility:**
- Framework common: `framework/common/` (e.g., helper functions in `framework/common/tools.py`).

## Special Directories

**`state/`:**
- Purpose: Stores local runtime JSON files during execution.
- Committed: No (strictly excluded in `.gitignore` to prevent leaking target intelligence).

**`evidence/`:**
- Purpose: Stores cryptographic raw request/response captures.
- Committed: No (strictly excluded in `.gitignore`).

**`~/.config/opencode/`:**
- Purpose: Global OpenCode directory on the host where `Bug-Bounty` and the 18 skills are deployed.
- Managed by: `scripts/bb-deploy` via symlinks or copies.

---

*Structure analysis: 2026-10-09*
*Update when directory structure changes*
