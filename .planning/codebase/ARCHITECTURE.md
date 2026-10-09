# Architecture

**Analysis Date:** 2026-10-09

## Pattern Overview

**Overall:** Single-Agent Orchestration with Modular Methodology Skills, Subprocess-Isolated Tool Wrappers, and Atomic Local State Management.

**Key Characteristics:**
- **Single-Agent Decision**: A single unified OpenCode agent (`Bug-Bounty`) orchestrates research workflows using 18 modular capability skills (`skills/`), eliminating multi-agent coordination overhead, token fragmentation, and state desynchronization.
- **Strict Data Isolation**: Reusable code, skills, and configuration reside in Git. Target intelligence, scans, credentials, and evidence remain strictly local (`~/BugBounty-Workspace/programs/<name>/` or local `state/`), ignored by Git.
- **Deterministic Scope Invariant**: Every active network interaction is pre-validated through `framework/scope/engine.py` against `scope.yaml`. Silently assuming authorization is architecturally impossible.
- **Hypothesis-Driven Scientific Methodology**: Replaces unvetted, broad-spectrum vulnerability scanners with structured research hypotheses validated through non-destructive probes:
  $$\text{Observation} \longrightarrow \text{Hypothesis} \longrightarrow \text{Targeted Test} \longrightarrow \text{Evidence} \longrightarrow \text{Validation} \longrightarrow \text{Report}$$

## Layers

```text
┌────────────────────────────────────────────────────────┐
│               OpenCode Single-Agent Layer              │
│       (Bug-Bounty unified orchestrator agent)          │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│                 Modular Skills Catalog                 │
│      (18 methodology SKILL.md guides and rules)        │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│              Controlled CLI Wrappers                   │
│   (bb-scope-check, bb-recon, bb-http, bb-auth, etc.)   │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│               Framework Core (Python 3)                │
│   ├── framework/scope (Engine, Normalizer, Boundary)   │
│   ├── framework/state (Manager, Fingerprint, Dedup)    │
│   ├── framework/findings (Schema, Lifecycle, Report)   │
│   ├── framework/authentication (Models, Sessions, MFA) │
│   └── framework/common (Evidence, Tools, Config)       │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│         Local Runtime Workspace (Outside Git)          │
│   ~/BugBounty-Workspace/programs/<PROGRAM_NAME>/       │
│      (targets, recon, scans, evidence, findings)       │
└────────────────────────────────────────────────────────┘
```

**1. Orchestrator Layer (`agents/Bug-Bounty.md`):**
- Purpose: Primary OpenCode agent definition orchestrating bug bounty research.
- Responsibilities: Directing research workflows, interpreting researcher intent, formulating hypotheses, selecting relevant skills, and synthesizing findings.
- Configuration: Configured in `opencode.jsonc` with `mode: primary` and `subagent_depth: 1`.

**2. Skills Catalog Layer (`skills/`):**
- Purpose: 18 modular capability directories containing `SKILL.md` methodology contracts.
- Responsibilities: Defining step-by-step security testing procedures, edge-case criteria, safety boundaries, and evidence requirements across 18 distinct research domains.
- Examples: `skills/scope-management`, `skills/asset-intelligence`, `skills/reconnaissance`, `skills/authentication`, `skills/authorization`, `skills/injection`, `skills/validation`, `skills/reporting`.

**3. Controlled Command Layer (`scripts/`):**
- Purpose: Dual-platform CLI wrapper scripts (`bb-*` for Linux/Kali, `bb-*.cmd` for Windows).
- Responsibilities: Input sanitization, pre-execution scope verification, rate limiting, external tool orchestration, and human-approval enforcement (`--approve`).

**4. Framework Core Layer (`framework/`):**
- Purpose: Native Python domain logic, data models, state management, and offline test labs.
- Packages:
  - `framework/scope`: Target normalization, DNS label checking, CIDR bounds, exclusion precedence.
  - `framework/assets`: Recursive asset discovery graph, infrastructure attribution, TLS SAN analysis.
  - `framework/recon`: Passive/active reconnaissance orchestration with rate limits and fallbacks.
  - `framework/webapp`: Web endpoint cataloging, CORS policy analysis, cookie audits.
  - `framework/javascript`: Static JS analysis, route extraction, AST parsing, DOM sink mapping.
  - `framework/api`: REST, GraphQL, and WebSocket surface analysis and parameter fuzzing.
  - `framework/authz`: Horizontal/vertical BOLA/IDOR and multi-tenant isolation testing.
  - `framework/injection`: Safe, non-destructive proof marker injection (SQLi, NoSQLi, SSTI, CMDi).
  - `framework/http_trust`: Host header injection, cache poisoning, and request smuggling analysis.
  - `framework/business_logic`: Workflow state machines, race condition detection, quantity tampering.
  - `framework/cloud_security`: Cloud storage bucket permissions, metadata SSRF, and dangling CNAMEs.
  - `framework/authentication`: Session fixation, invalidation, MFA transitions, JWT claims, reset token reuse.
  - `framework/validation`: Adversarial 6-gate checklist verifying candidate findings and filtering FPs.
  - `framework/findings`: Structured finding schemas, CVSS v3.1 calculation, 17-section report rendering.
  - `framework/state`: JSON persistence per program, SHA-256 test fingerprinting, root-cause deduplication.
  - `framework/tools`: System diagnostics (`doctor.py`), registry (`registry.py`), detector, installer, deployer.
  - `framework/common`: Cryptographic evidence signing, secret redaction, and configuration parsing.

**5. Local Runtime Workspace (`~/BugBounty-Workspace/programs/<name>/`):**
- Purpose: Isolated working directories for active target programs.
- Structure: Houses `scope.yaml`, `state/`, `evidence/`, `scans/`, `logs/`, and generated `reports/`.

## Data Flow

**1. Program Initialization & Scope Binding:**
1. Researcher runs `bb-init <program-name>`.
2. Workspace initialized with `scope.yaml`.
3. `bb-scope-check` verifies targets offline using `framework/scope/engine.py`.

**2. Attack Surface Discovery & Asset Modeling:**
1. Passive asset intelligence executes (`bb-assets --passive-only`).
2. Recursive DNS, SAN extraction, and CDN attribution build asset graph.
3. Endpoints and client logic mapped (`bb-webapp`, `bb-js`, `bb-api`).
4. Normalized asset state atomically saved to `state/assets.json` and `state/webapps.json`.

**3. Hypothesis Formulation & Targeted Testing:**
1. `Bug-Bounty` agent generates structured hypothesis:
   `HYP-AUTH-001: /api/v1/user/profile endpoint accessible prior to secondary MFA validation`
2. Engine checks `state/tests.json` using SHA-256 fingerprint to prevent redundant probing.
3. Controlled test executed via wrapper script (e.g., `bb-auth --flow mfa`).
4. Raw HTTP request/response signed with SHA-256 and redacted into `evidence/`.

**4. Adversarial Validation & Reporting:**
1. Candidate finding evaluated against 6-gate checklist in `framework/validation/`.
2. False-positive classifier eliminates generic 200 OKs, WAF challenges, or normal login pages.
3. Deduplicator merges findings sharing identical root cause in `framework/state/dedup.py`.
4. Final Markdown report rendered in standard 17-section disclosure format in `reports/`.

## Key Abstractions

**1. `ScopeEngine` (`framework/scope/engine.py`):**
- Evaluates target validity with rule precedence: Exclusions > Specific targets > Wildcards > Ambiguous.
- Pattern: Evaluator / Policy Engine.

**2. `StateManager` (`framework/state/manager.py`):**
- Manages program-level JSON state files using atomic tempfile replacement.
- Pattern: Unit of Work / Repository.

**3. `Finding` (`framework/findings/schema.py`):**
- Immutable data model representing verified security findings with CVSS v3.1 scoring.
- Pattern: Domain Entity / Value Object.

**4. `SecurityEngine` (Subsystem Engines, e.g. `framework/authentication/engine.py`):**
- Standardized lifecycle: Surface Discovery $\to$ Hypothesis Generation $\to$ Targeted Validation $\to$ Candidate Production.
- Pattern: Orchestrator / Pipeline.

**5. `LocalSecurityLab` (`framework/*/lab.py`):**
- Deterministic, self-contained offline test suites validating engine behavior without external network access.
- Pattern: Mock Harness / Test Double.

## Entry Points

**OpenCode Agent Entry:**
- Location: `agents/Bug-Bounty.md` (deployed to `~/.config/opencode/agents/Bug-Bounty.md`).
- Triggers: OpenCode CLI invocation (`opencode`).
- Responsibilities: High-level reasoning, user interaction, skill invocation, and reporting.

**CLI Script Entries:**
- Location: `scripts/` (25 dual-platform wrapper scripts, e.g., `scripts/bb-doctor`, `scripts/bb-init`, `scripts/bb-deploy`, `scripts/bb-auth`, `scripts/bb-recon`).
- Triggers: Command-line execution by user or agent.
- Responsibilities: Argument parsing, scope verification, execution of underlying Python framework modules.

**Framework Python Entry Points:**
- `framework/tools/doctor.py` - Health diagnostics.
- `framework/tools/deployer.py` - Global deployment.
- `framework/*/engine.py` - Primary engines for each testing domain.

## Error Handling

**Strategy:** Fail closed, fail early, never proceed with ambiguous authorization.

**Patterns:**
- Custom typed exceptions: `NormalizationError`, `ScopeError`, `ValidationError`.
- Subprocess isolation: All external tool executions wrapped with timeout caps, rate limits, and non-zero exit code inspection; never using `shell=True`.
- Atomic state writes: Write to `.tmp` file in the same filesystem and replace atomically to prevent file corruption during interrupts.

## Cross-Cutting Concerns

**Security & Safety:**
- Strictly non-destructive testing payloads (e.g. arithmetic markers `{{7*7}}`, safe time delays `sleep(3)`).
- Human approval gates (`--approve`) on state-mutating actions (password resets, credential changes).
- Cryptographic redaction of sensitive credentials (`sess_sha256_...`, `[REDACTED_BY_BB_AGENT]`).

**Portability & Platform Support:**
- Dual execution paths: Native bash scripts on Linux/Kali and `.cmd` wrappers on Windows.
- Standard ASCII rendering (`\--`, `|--`) for tree views to prevent `UnicodeEncodeError` on Windows consoles with `cp1252` encoding.

---

*Architecture analysis: 2026-10-09*
*Update when major patterns change*
