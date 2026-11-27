# Phase 22 — Cross-Engine Attack-Path Correlation and Vulnerability Chaining

**Status:** Candidate graph, correlation, reporting, and approval planning are implemented. The current Linux-only Kali suite at `628b4d2` passed; older hosted Windows results are historical and do not define current support. The `validate` CLI is simulation-only: it cannot send a target request or empirically promote a graph link. Trusted empirical chain validation remains open as AUD-09.

**Priority outcome:** Starting from a validated bug, identify whether it can be safely combined with other in-scope weaknesses to demonstrate greater real-world impact.
**Implementation foundation:** `framework/findings/`, `framework/assets/`, `framework/auth_correlation/`, `framework/attack_path/`, and outputs from Phases 1–21.

## Phase 22 Milestone Structure

Phase 22 is organized into four sequential top-level milestones:
1. **Milestone 22.1**: Attack Graph Model, State Management & Finding Normalization (Completed & Hardened).
2. **Milestone 22.2**: Cross-Engine Path Correlation & Feasibility Rules (Completed & Hardened).
   - **22.2.1**: Architecture & Acceptance Criteria — Candidate Relationship Discovery & Bounded Traversal (Completed).
   - **22.2.2**: Core Implementation — Candidate Relationship Discovery & Bounded Traversal (Completed).
   - **22.2.3**: Attack Path Correlator & Feasibility Evaluation Engine (Completed).
   - **22.2.4**: Milestone 22.2 Integration Hardening, Edge-Case Auditing & State Persistence Validation (Completed & Hardened).
3. **Milestone 22.3**: Safe Validation Planning & Approval Gates (`framework/attack_path/validator.py`) (Planning and scope gates implemented; empirical evidence integration remains open).
4. **Milestone 22.4**: CLI and Reporting (`scripts/bb-chain`, `framework/attack_path/reporter.py`) (Implemented; validation command runs a deterministic simulation only).

---

## Milestone 22.1 Implementation Summary (Completed & Hardened)

Milestone 22.1 delivers the foundational data models, state persistence, and finding normalization engine:
- **Attack Graph Model (`framework/attack_path/model.py`)**:
  - Strongly typed graph node classes (`ASSET`, `ENDPOINT`, `PRINCIPAL`, `FINDING`, `CAPABILITY`) and directional edge classes (`EXPOSES`, `SATISFIES_PREREQUISITE`, `AUTHENTICATES_AS`, `CROSSES_BOUNDARY`, `HOSTED_ON`, `TARGETS`, `DEPENDS_ON`).
  - Decoupled 3-tier validation state architecture: finding lifecycle (`VALIDATED`), relationship state (`THEORETICAL`, `CONTEXTUALLY_ALIGNED`, `LINK_VALIDATED`, `LINK_REFUTED`), and chain state (`HYPOTHESIS`, `PARTIALLY_VALIDATED`, `FULLY_VALIDATED`, `BLOCKED`, `REFUTED`).
  - Strict zero-secret sanitization (`assert_no_raw_secrets`) asserting zero raw credentials, JWT tokens, Bearer tokens, API key prefixes, AWS keys, or private keys across graph nodes and edges.
  - In-memory graph with capacity limits (`MAX_NODES = 5000`, `MAX_EDGES = 25000`), fast adjacency lookups, secondary indices by node type, asset, and tenant context, tenant isolation query methods, and referential pruning (`remove_edge`, `remove_node`).
- **Attack Path State Manager (`framework/attack_path/state.py`)**:
  - Decoupled state management writing `state/attack_graph.json` with POSIX `0700` and Windows DACL permissions.
  - Atomic temporary-file persistence with transient Windows lock retries, mandatory pre-write zero-secret assertions, and automatic corruption recovery backup (`.corrupt.<timestamp>`).
- **Finding Normalizer (`framework/attack_path/normalizer.py`)**:
  - Deterministic identifier generation for assets, endpoints, findings, capabilities, and edges.
  - Extracts evidence-backed capabilities from validated findings and `EvidenceStore`. Distinguishes observed (`OBSERVED`/`SIMULATED`) from inferred (`INFERRED`) capabilities based on disk-backed byte integrity (SHA-256) and verified hash matching.
  - Dynamic clock handling and freshness recalculation with a 30-second skew safety window and future-dated timestamp rejection.
  - Sanitization of finding parameters and descriptors via `sanitize_sensitive_data`.
- **Unit and Adversarial Acceptance Tests**:
  - `tests/test_phase22_graph_model.py`: 8 comprehensive tests covering model structures, decoupled states, secret assertions, capacity caps, and atomic persistence.
  - `tests/test_phase22_normalizer.py`: 5 tests covering normalization, observed vs. inferred capabilities, clock skew, secret stripping, and batch ingestion.
  - `tests/test_phase22_audit_hardening.py`: 9 focused adversarial tests covering disk tampering, claimed hash mismatch, caller metadata containment, credential pattern detection, clock boundary conditions, enum deserialization rejection, and index consistency.

---

## Milestone 22.2 Sub-Milestones Summary

Milestone 22.2 implements cross-engine path correlation, bounded traversal, and feasibility rule evaluation:

### Sub-Milestone 22.2.1 — Architecture & Acceptance Criteria (Completed)
- Designed the `CandidateRelationshipEngine` and `BoundedTraversalEngine` specifications.
- Established complexity limits (`MAX_TRAVERSAL_DEPTH = 5`, `MAX_VISITED_NODES = 2000`, `MAX_EXAMINED_EDGES = 10000`, `MAX_CANDIDATE_PATHS = 100`, `MAX_PATHS_PER_ENTRY = 10`, `MAX_WALL_CLOCK_SECONDS = 5.0`).
- Formulated the 10 acceptance criteria (AC-22.2-01 through AC-22.2-10).

### Sub-Milestone 22.2.2 — Core Discovery & Bounded Traversal (Completed)
- **Candidate Relationship Engine (`framework/attack_path/discovery.py`)**:
  - Implemented `CandidateRelationshipEngine` with semantic capability-to-precondition matching rules (`KNOWLEDGE_EXPOSURE`, `SESSION_HIJACK`, `TOKEN_ACQUISITION`, `SSRF_PIVOT`, `OPEN_REDIRECT`, `ARBITRARY_FILE_READ`, `PRIVILEGE_ESCALATION`, `WORKFLOW_BYPASS`).
  - Strict edge-state boundary: discovered edges are initialized strictly as `RelationshipState.THEORETICAL` or `RelationshipState.CONTEXTUALLY_ALIGNED`.
  - Supported cross-tenant flaw whitelist (`SUPPORTED_TENANT_ISOLATION_FLAWS`).
- **Bounded Traversal Engine (`framework/attack_path/traversal.py`)**:
  - Implemented `BoundedTraversalEngine` executing deterministic, shortest-path-first BFS traversal with branch-level cycle elimination.
  - Generates deterministic `path_id` (`PATH-<sha256>`) and semantic vulnerability transition fingerprints.
  - Anti-inflation invariant: generated attack paths are strictly initialized with `ChainState.HYPOTHESIS`.
- **Milestone 22.2.2 Acceptance Test Suite (`tests/test_phase22_traversal.py`)**:
  - 10 rigorous acceptance tests validating criteria AC-22.2-01 through AC-22.2-10 with 100% pass rate.

### Sub-Milestone 22.2.3 — Attack Path Correlator & Feasibility Engine (Completed)
- **Attack Path Correlator (`framework/attack_path/correlator.py`)**:
  - Implemented `AttackPathCorrelator` orchestrating finding ingestion, candidate relationship discovery, bounded traversal, feasibility evaluation, and state persistence.
  - Implemented `evaluate_path_feasibility` enforcing semantic checks:
    - **ADV-22-01 (Parameter Format Compatibility)**: Prunes paths with incompatible parameter bindings or formats.
    - **ADV-22-02 (Privilege Progression Consistency)**: Prunes paths requiring unearned elevated roles without privilege escalation.
    - **ADV-22-03 (Tenant Isolation Consistency)**: Prunes unauthorized cross-tenant transitions lacking supported flaw types.
    - **ADV-22-04 (Principal / Session Alignment)**: Prunes cross-principal transitions lacking session hijack capabilities.
    - **ADV-22-05 (Capability Freshness)**: Prunes paths relying on expired capabilities.
    - **ADV-22-06 (Decoupled State Invariant)**: Enforces that all emitted paths remain strictly in `ChainState.HYPOTHESIS`.
- **Milestone 22.2.3 Acceptance Test Suite (`tests/test_phase22_correlator.py`)**:
  - 10 comprehensive tests covering criteria AC-22.3-01 through AC-22.3-10 with 100% pass rate.

### Sub-Milestone 22.2.4 — Milestone 22.2 Integration Hardening & Verification (Completed & Hardened)
- **Integration Hardening & Edge-Case Audit**:
  - Validated dense multigraph resilience (50+ nodes/edges, multigraph edges between identical pairs, competing paths of varying lengths, and cycle branches).
  - Validated idempotency under repeated correlation runs: zero duplicate nodes/edges, stable path IDs and fingerprints, and zero count inflation.
  - Hardened multi-tenant isolation across complex multi-hop paths: supported tenant-isolation flaws (`SUPPORTED_TENANT_ISOLATION_FLAWS`) permit boundary crossing, while unsupported flaws fail closed.
  - Hardened scope enforcement: nodes with `scope_status != "IN_SCOPE"` (`OUT_OF_SCOPE`, `EXCLUDED`, `BLOCKED`, `None`) are immediately pruned or rejected with `SCOPE_VIOLATION`.
  - Hardened principal consistency (ADV-22-04): `TOKEN_ACQUISITION` alone does not authorize cross-principal transition unless explicit target principal binding evidence is present.
  - Hardened state persistence & corruption recovery in `AttackPathStateManager`: atomic replacement, corruption backup (`.corrupt.<timestamp>`), clean reinitialization, and strict zero-secret barrier before write.
  - Zero-secret guarantee: added `"authorization"` to sensitive key sanitization; verified rejection messages never echo raw secrets.
- **Milestone 22.2.4 Acceptance Test Suite (`tests/test_phase22_correlator_hardening.py`)**:
  - 10 comprehensive tests covering criteria AC-22.2.4-01 through AC-22.2.4-10 with 100% pass rate.

---

## Milestone 22.3 — Safe Validation Planning & Approval Gates (Planning and Scope Gates Implemented)

Milestone 22.3 establishes controlled validation planning, human approval, and anti-TOCTOU scope authorization. Its current simulation path deliberately cannot promote graph relationships. Empirical promotion awaits a trusted Phase 21 receipt and disk-backed EvidenceStore integration (AUD-09):
- **Validation Plan Architecture (`framework/attack_path/validator.py`)**:
  - Implemented `SafeChainValidationPlanner`, generating non-destructive `ChainValidationPlan` instances from correlated attack paths (`AttackPath`).
  - Strict separation of concern across discovery, planning, human approval, dispatch, execution, evidence verification, and chain promotion.
  - Deterministic cryptographic binding: `compute_plan_hash()` generates a SHA-256 digest covering all canonical parameters, including every `scope_targets` entry derived from path assets, edge endpoints, and endpoint URLs. Any field mutation invalidates approval. Older saved plans without bound scope targets remain inspectable but cannot be dispatched; recreate and approve a fresh plan.
- **Explicit Validation Lifecycle & State Machine**:
  - Guarded state transitions across 15 states: `HYPOTHESIS`, `PLANNED`, `PENDING_APPROVAL`, `APPROVED`, `REJECTED`, `EXPIRED`, `REVOKED`, `DISPATCHED`, `PARTIALLY_COMPLETED`, `COMPLETED`, `FAILED`, `EVIDENCE_PENDING`, `EVIDENCE_VERIFIED`, `RELATIONSHIP_VALIDATED`, `CHAIN_VALIDATED`.
  - Transitions strictly enforced via `validate_state_transition()`; illegal or backward jumps raise `InvalidStateTransitionError`.
- **Human Approval & Revocation Controls**:
  - `PlanApproval` records unique approval ID, operator identity, approved timestamps, expiration timestamp, and revocation metadata.
  - Revocation (`revoke_approval`) immediately sets the `revoked` flag and moves the plan to terminal `REVOKED` status.
  - Expiration (`is_expired`) dynamically recalculates freshness against clock timestamps with skew tolerance.
- **Anti-TOCTOU Dispatch Authorization Gate (`authorize_dispatch`)**:
  - Evaluates mandatory security gates before execution:
    1. Plan status gate (`status == APPROVED`).
    2. Approval metadata existence gate.
    3. Revocation gate (`revoked is False`).
    4. Expiration gate (`not is_expired()`).
    5. Plan integrity & version gate (`compute_plan_hash() == approval.plan_hash` and version match).
    6. Validation method allowlist & permission match.
    7. Target asset and endpoint identity match.
    8. Scope gate: a real `ScopeEngine` instance is required; missing or malformed scope never falls back to a plan label or default `IN_SCOPE` value. Every plan-bound asset and URL is checked against current scope, exclusions included, and checked again immediately before the execution callback to block a scope change after authorization.
    9. Tenant and principal consistency.
  - Fails closed with `DispatchSecurityError` and records sanitized audit log on any failure.
- **Safe Validation Method Registry (`ValidationMethodRegistry`)**:
  - Registered standard read-only, non-destructive validation methods: `PREREQUISITE_SATISFACTION_CHECK`, `PASSIVE_RESOURCE_METADATA_VERIFY`, `NON_DESTRUCTIVE_REDIRECT_CHECK`, `CONTROLLED_AUTH_BOUNDARY_PROBE`, `HISTORICAL_ARTIFACT_REVALIDATE`, `EVIDENCE_PROVENANCE_REVERIFY`.
  - Prohibits registering or executing destructive or unverified state-modifying actions.
- **Evidence and promotion boundary (`verify_evidence_and_promote`)**:
  - The default `execute_dispatched_plan` path returns an explicitly simulated fixture result. It sends no target request and contains no fabricated evidence ID, digest, or observed impact.
  - Simulated results cannot promote edges or chains. A result assembled by a caller is also rejected unless it carries the in-memory provenance from the same live planner, plan, and authorization; serialized status fields and a supplied EvidenceStore cannot create that provenance.
  - The current Phase 22 CLI therefore reports “not empirically validated” and leaves paths as hypotheses. It does not yet connect the Phase 21 signed dispatch receipt and verified disk evidence to this promotion boundary. This is an open capability, not a successful evidence verification feature.
  - When empirical promotion is integrated, partial chains must remain partial and a chain may become fully validated only after every impact-relevant edge has bound, fresh evidence. Finding severities and path impact ratings must never be inflated by inference.
- **Audit Logging & State Persistence (`AttackPathStateManager`)**:
  - Records immutable `ValidationAuditEvent` entries to `state/validation_audit.jsonl`.
  - Atomically persists validation plans to `state/validation_plans.json` with DACL / POSIX 0600 permissions and zero-secret assertions.
- **Milestone 22.3 Acceptance Test Suite (`tests/test_phase22_validator.py`)**:
  - 30 tests cover plan lifecycle, approval, scope binding, dispatch provenance, simulation non-promotion, and adversarial attempts to forge or replay results. These tests verify the present fail-closed boundary; they do not demonstrate empirical chain validation.

---

## Milestone 22.4 — CLI, Reporting & Regression Acceptance

Milestone 22.4 delivers the final operational CLI commands, reporting engine, and cross-environment verification:
- **CLI Subsystem (`scripts/bb-chain`, `scripts/bb-attack-path`)**:
  - Implemented unified command-line tools for graph inspection, correlation, plan creation, approval management, reporting, and simulated validation. The CLI does not provide empirical chain confirmation.
  - Subcommands:
    - `status`: Displays authoritative aggregate statistics (nodes, edges, candidate paths, hypotheses, validated chains, and validation plans).
    - `list`: Lists discovered attack paths with optional `--state` filter (`HYPOTHESIS`, `PARTIALLY_VALIDATED`, `FULLY_VALIDATED`) and `--json`.
    - `show <path_id>`: Displays full traversal sequence, constituent nodes, and directional edges with relationship states.
    - `analyze` / `correlate`: Runs correlation engine on findings in workspace and persists attack graph state.
    - `plan <path_id>`: Synthesizes a safe `ChainValidationPlan` in `PLANNED` status.
    - `plans`: Lists all validation plans with optional `--status` filter.
    - `show-plan <plan_id>`: Displays complete sanitized plan details, approval metadata, version, and plan hash.
    - `approve <plan_id> --operator <name>`: Binds human operator approval to exact plan parameters.
    - `reject <plan_id> --operator <name> --reason <text>`: Rejects a plan with recorded rationale.
    - `revoke <plan_id> --operator <name> --reason <text>`: Revokes an approved plan, permanently blocking dispatch.
    - `validate <plan_id>`: Exercises the approved plan through the deterministic fixture path; sends no target request, creates no evidence, and leaves edges and chains unvalidated. The CLI exits non-zero and labels the result as a simulation.
    - `report`: Generates multi-format reports (`markdown`, `json`, `terminal`).
  - Strict input sanitization: regex validation for `path_id`, `plan_id`, and `operator` identifiers; clear non-zero exit codes.
  - Prohibits `--force` or `--yes` authorization bypass flags.
- **Reporting Engine (`framework/attack_path/reporter.py`)**:
  - `AttackPathReporter` and `AttackPathReportData` render deterministic, report-ready outputs in Markdown, JSON, and Terminal formats.
  - Invariants strictly preserved:
    - **Anti-Inflation Policy**: Individual finding severities and compound attack-path impacts are never inflated.
    - **Provenance Transparency**: Clearly distinguishes between `OBSERVED`, `SIMULATED`, and `INFERRED` evidence.
    - **Zero-Secret Compliance**: Validated with `assert_no_raw_secrets` before output or write.
- **Milestone 22.4 Acceptance Test Suite (`tests/test_phase22_cli_reporting.py`)**:
  - 25 comprehensive unit, adversarial, concurrency, and integration tests validating criteria AC-22.4-01 through AC-22.4-25 with 100% pass rate.
  - **Historical regression evidence**: the Phase 22 and scope fail-closed suites passed **125 tests** on Kali Linux at code commit `48d1f7e`. The full Kali suite passed 1,277 tests with two Windows-only skips; hosted Ubuntu Python 3.10/3.14 and Windows Server 2025 Python 3.14 full-suite jobs passed in [GitHub Actions run 44494335350](https://github.com/Veldora-0/BugBounty-Agent/actions/runs/44494335350). These are historical results; the current CI matrix targets Linux. Exact commands and results are in the [Phase 24 verification record](PHASE-24-final-integration-production-readiness.md#post-audit-regression-verification).

---

## Purpose and bounty value

Real bounty impact can depend on a sequence of weaknesses. For example, an exposed low-privilege resource may reveal an identifier that makes a separate authorization flaw exploitable, or a weak access boundary may expose a sensitive workflow. Phase 22 correlates evidence already in the workspace to identify candidate paths and propose a safe follow-up. Its current CLI cannot itself prove that a path works against a target.

The integrated engine is implemented in `framework/attack_path/` and exposed through `scripts/bb-chain` and `scripts/bb-attack-path`. Candidate chains remain hypotheses until their impact-relevant links are verified through trusted empirical evidence. Current Phase 22 simulation does not provide that evidence; the engine does not raise component finding severity based on theoretical paths.

## Required researcher workflow

1. Begin with a validated finding or high-confidence observation from an explicitly authorized program. Preserve its evidence, root cause, affected principal, asset, endpoint, and scope provenance.
2. Search existing in-scope assets, endpoints, identities, findings and observations for relationships that could make one weakness enable or amplify another.
3. Build an explainable candidate chain: ordered steps, preconditions, trust-boundary transitions, supporting evidence, missing evidence, likely impact, confidence and safe validation plan.
4. Separate established facts from inferred links. A chain remains a **hypothesis** until every impact-relevant edge is supported by evidence.
5. Recommend the smallest non-destructive follow-up that could prove or reject the chain. Require explicit operator approval before any active request; re-check every bound asset against current scope at authorization and immediately before execution. The current CLI only simulates this step.
6. If confirmed, produce a report-ready narrative showing the individual vulnerabilities, how they combine, the demonstrated end impact and exact reproduction steps. Keep component finding severities distinct from the chain-level impact assessment.

## Graph and chain model requirements

- Typed nodes for authorized assets, endpoints, principals/sessions, observations, hypotheses, findings, evidence and actions.
- Typed, directional edges such as `reveals`, `enables`, `authenticates_as`, `crosses_tenant_boundary`, `reaches`, and `depends_on`; each edge records source, evidence reference, confidence, timestamp/freshness and whether it is observed, inferred or validated.
- A chain records ordered steps, required privileges, attacker starting position, target impact, assumptions, blocking controls, confidence, scope provenance and validation state.
- Evidence references must resolve to sanitized local evidence; secrets and raw credentials never enter the graph or reports.
- Graph traversal must handle cycles, duplicate root causes, stale observations and uncertain identity/asset joins without manufacturing a path.

## Safety and severity rules

- Every asset and action in a candidate path must remain inside the program's current authorized scope. Exclusions take precedence. A chain cannot use a third-party service, account, tenant or asset that is not explicitly authorized.
- Analysis of existing evidence may be passive. A proposed follow-up is not permission to run it; active validation requires human approval, a narrow hypothesis, safe test identities/canaries, and the existing request/time/byte limits.
- Do not access unrelated user data, extract secrets, bypass payment through real transactions, change or delete customer data, cause denial of service, or execute a destructive payload to prove chain impact.
- Never add severities arithmetically or raise an individual finding solely because a theoretical path exists. Report component severities independently. A higher chain impact may be stated only when the additional privilege or impact is directly demonstrated with authorized, minimal evidence.
- Clearly label simulations, inferred links, unverified steps, and live-confirmed steps. If a safe proof is impossible, retain the path as a hypothesis and state the limitation.

## Acceptance criteria

- Tests demonstrate valid two-or-more-issue chains, rejected false joins, cycles, duplicate roots, stale evidence, missing edges, cross-tenant identity mismatches, and scope/exclusion inheritance.
- The engine can explain why each step is connected, show the evidence behind it, expose unverified assumptions, and suggest one bounded validation action.
- An out-of-scope node, missing scope provenance, invalid approval, or exhausted budget prevents active follow-up before network dispatch.
- Reports distinguish individual finding severity from demonstrated aggregate impact; hypothetical chaining never silently upgrades a confirmed finding.
- Local fixture scenarios cover a harmless chain from initial access to a constrained impact, plus negative controls proving that correlation does not invent exploitability.
- The feature is integrated into the single `Bug-Bounty` orchestrator and existing skills without adding subagents or automatic disclosure submission.

## Acceptance status and verification limits

Candidate correlation, bounded traversal, graph reporting, plan creation, human approval, and fail-closed scope gates are implemented. At code commit `48d1f7e`, `python3 -m pytest tests/test_phase22_*.py tests/test_scope_fail_closed_validation.py -ra` passed **125 tests** on Kali. The full Kali suite passed **1,277 tests with 2 Windows-only skips**; hosted Ubuntu and Windows full-suite jobs passed in [GitHub Actions run 44494335350](https://github.com/Veldora-0/BugBounty-Agent/actions/runs/44494335350). This verifies code paths and fixtures, not real bounty findings.

The two reproduced audit defects are fixed: Phase 22 no longer manufactures evidence-shaped values from simulation, and dispatch requires a real scope engine that checks every path-bound target at authorization and again before execution. However, the current `validate` command is a deterministic simulation only. No target request is sent, no evidence is created, and no graph relationship is promoted. A trusted Phase 21 receipt plus verified disk evidence is not yet integrated; empirical chain validation remains open under AUD-09. Older saved plans without bound `scope_targets` cannot be dispatched and must be regenerated and approved.

Historical hosted Windows testing covered repository behavior but does not mean Windows production dispatcher isolation is supported; that remains unsupported under Phase 21. Windows is no longer a current automated test target. The CLI refuses dispatch when scope is missing or invalid. Remaining system limits are tracked in [Future Improvements](../FUTURE-IMPROVEMENTS.md) and the [issue register](../PROJECT-AUDIT-ISSUES.md).

## Source references

Relevant acceptance tests: `tests/test_phase22_*.py`. See [the project handbook](../PROJECT-HANDBOOK.md) for the full research process.
