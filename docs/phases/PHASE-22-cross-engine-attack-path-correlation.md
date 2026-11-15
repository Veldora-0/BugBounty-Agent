# Phase 22 — Cross-Engine Attack-Path Correlation and Vulnerability Chaining

**Status:** In Progress (Milestone 22.1 completed & hardened; Milestone 22.2 fully completed & hardened; Milestones 22.3 and 22.4 pending)

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
3. **Milestone 22.3**: Safe Validation Planning & Approval Gates (`framework/attack_path/validator.py`) (Pending / Not Started).
4. **Milestone 22.4**: CLI, Reporting & Dual-Environment Acceptance (`scripts/bb-chain`, `framework/attack_path/reporter.py`, full verification) (Pending / Not Started).

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

## Milestone 22.3 — Safe Validation Planning & Approval Gates (Pending / Not Started)
- **Planned deliverable**: `framework/attack_path/validator.py` (`SafeChainValidationPlanner`).
- Generates non-destructive `ChainValidationPlan` using existing Phase 6/8/21 engines; mandatory human confirmation before active dispatch; strict scope checks.

---

## Milestone 22.4 — CLI, Reporting & Dual-Environment Acceptance (Pending / Not Started)
- **Planned deliverables**: `scripts/bb-chain`, `framework/attack_path/reporter.py`, documentation updates.
- CLI integration, Markdown reporting of chained attacks, and full Windows/Kali dual-environment verification.

---

## Purpose and bounty value

Real bounty impact can depend on a sequence of weaknesses. For example, an exposed low-privilege resource may reveal an identifier that makes a separate authorization flaw exploitable, or a weak access boundary may expose a sensitive workflow. Phase 22 will connect evidence across engines and tell the researcher when a confirmed issue creates a credible path to a more serious outcome.

This capability is **not implemented today**. Existing `framework/findings/` and `tests/test_capability_graph.py` provide foundations, but the repository does not yet contain an integrated, evidence-backed attack-path engine. Phase 22 makes vulnerability chaining a required feature of that planned engine.

## Required researcher workflow

1. Begin with a validated finding or high-confidence observation from an explicitly authorized program. Preserve its evidence, root cause, affected principal, asset, endpoint, and scope provenance.
2. Search existing in-scope assets, endpoints, identities, findings and observations for relationships that could make one weakness enable or amplify another.
3. Build an explainable candidate chain: ordered steps, preconditions, trust-boundary transitions, supporting evidence, missing evidence, likely impact, confidence and safe validation plan.
4. Separate established facts from inferred links. A chain remains a **hypothesis** until every impact-relevant edge is supported by evidence.
5. Recommend the smallest non-destructive follow-up that can prove or reject the chain. Require explicit operator approval before any active request; re-check scope and budgets for every step.
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

## Remaining work

Design and implement the graph schema, provenance-bearing edge model, bounded path search, human-readable chain explanation, approval-gated validation planner, and report integration. See [Future Improvements](../FUTURE-IMPROVEMENTS.md), the [issue register](../PROJECT-AUDIT-ISSUES.md), and [the 24-phase roadmap](../ROADMAP-24-PHASES.md).

## Source references

Foundation tests: `tests/test_capability_graph.py`. They do not yet verify the integrated chain workflow. See [the project handbook](../PROJECT-HANDBOOK.md) for the full research process.
