# Phase 23 — Autonomous Research Planning & Coverage Intelligence

**Status:** Implemented; Kali Linux acceptance verified. Windows acceptance was not run in this workspace. Recommendations are advisory and never authorize target activity.
**Implementation:** `.opencode/commands/Arise.md`, `framework/research_planning/`, `scripts/bb-plan`, `scripts/bb-arise`, and the existing `knowledge-research` skill.

## Purpose and bounty value
Use validated inventory and findings to recommend prioritized next hypotheses and expose coverage gaps for researcher review. The `/Arise` command adds curated public disclosure research as an explainable input to those recommendations. The goal is to produce actionable, reproducible evidence for a vulnerability on an explicitly authorized program, not to maximize scan volume. A researcher must confirm program authorization and scope before any target network activity.

## `/Arise` — public disclosure research intelligence
`/Arise` searches approved public disclosure sources (for example, HackerOne, Bugcrowd, YesWeHack, Google Bug Hunters, Intigriti, and Microsoft) for reports whose underlying technique plausibly applies to the current program's in-scope assets, technologies, versions, findings, or coverage gaps. It stores links and concise methodology notes, not downloaded copies of full reports.

Every invocation must reassess **all locally recorded `/Arise` entries** against the current program context and available source metadata, then search for additional candidates. Keep an entry only when the applicability rationale is explicit and there is a plausible opportunity to investigate the vulnerability class on a current in-scope surface. Relevance is an explainable research-priority estimate, not evidence that the target is vulnerable or a guarantee of success. A report's age alone is not grounds for removal if its general technique remains applicable.

Each retained entry records, when available: source URL and platform, report title and author, publication date, last successful source-check time, local relevance recheck time, relevant product/technology/version, extracted technique summary, matched in-scope asset or coverage gap, applicability rationale, and unresolved assumptions. Attribute source claims and clearly label agent inferences. Respect source access terms and rate limits; do not bypass access controls or claim freshness when a source could not be checked.

At each run, delete local report entries that no longer meet the relevance rules, such as a confirmed technology/version mismatch, out-of-scope-only applicability, a resolved issue, or adequate prior coverage of the same hypothesis. An inconclusive or failed test does not by itself make a report redundant. A temporary source outage is not proof of irrelevance: record the failed recheck and retain the entry for reassessment. Show a concise added/retained/removed/unchecked summary and removal reasons. Keep only a minimal local pruning audit record (identifier, timestamp, reason), not deleted report content. If nothing is relevant, return no recommendations instead of lowering the threshold.

`/Arise` produces research hypotheses and safe proposed next steps only. It does not authorize or execute target tests. Any active follow-up remains subject to current offline scope validation, explicit operator approval, existing dispatch controls, and applicable request/time/response budgets.

## Implemented components

- **Coverage index (`CoverageIndex`)** reads existing local asset, endpoint, technology, test, finding, and coverage state without creating or modifying those source files. It requires a valid current program scope and filters discovered targets through `ScopeEngine`; excluded, ambiguous, and out-of-scope records cannot support recommendations. Malformed JSON and symlinked state inputs fail closed.
- **Recommendation engine (`ResearchPlanner`)** proposes category-level hypotheses on inventoried endpoints (or on an inventoried asset when endpoint discovery is empty). It uses explicit signals from technologies and endpoint names, skips recent conclusive duplicate tests and matching validated findings, and labels stale/inconclusive prior attempts. Its deterministic 0–100 priority score uses potential impact (30%), evidence-backed applicability (25%), safety (20%), lower estimated effort (15%), and freshness (10%). Relevant `/Arise` metadata may add a small priority tie-breaker; it never increases confidence in a target vulnerability. Each item includes its rationale, estimated request budget, deduplication fingerprint, source references, `RECOMMENDATION_ONLY` status, and `active_testing_authorized: false`.
- **Budget and pause controls (`bb-plan`)** cap the sum of estimated request costs, report skipped hypotheses, persist a local pause/resume flag, and support a coverage-only view. These are planning controls, not a dispatcher or a substitute for existing approval gates.
- **Public research lifecycle (`AriseResearchManager`)** persists only allowlisted HTTPS source URLs and bounded title/author/date/tag fields plus a maximum 600-character sanitized methodology summary. It strips URL queries/fragments, never fetches report URLs, marks public references as non-evidence, and rechecks each stored item against current in-scope technology and test coverage. Confirmed mismatches and recent conclusive coverage are pruned with a minimal ID/time/reason JSONL audit. Inconclusive results and unavailable sources do not cause pruning. State is kept under the local program `state/` directory with POSIX 0700/0600 permissions or the Windows private-directory DACL helper.
- **`/Arise` orchestration** is a native OpenCode [project command](https://opencode.ai/docs/commands) in `.opencode/commands/Arise.md`, extended through the existing `knowledge-research` skill rather than adding an agent or skill. `bb-deploy` installs it globally as `~/.config/opencode/commands/Arise.md` beside the one global primary agent and 18 skills; `bb-deploy --status` checks it, and uninstall removes only this repository-owned command. The orchestrator uses an available read-only public research tool to discover only publicly disclosed material, exports short attributed metadata to the program workspace, runs `bb-arise` to reconcile it, and uses `bb-plan` to rank the resulting hypotheses. If public search is unavailable, it must report that source checks were not performed. The two CLIs themselves are offline and never make target or source network requests.

## Phase 23 CLI

```text
bb-plan --program <name> --coverage-only [--json]
bb-plan --program <name> --budget 20 [--limit 50] [--json]
bb-plan --program <name> --pause
bb-plan --program <name> --resume
bb-arise --program <name> --discoveries <workspace-local-json> [--checked-source <host>] [--unchecked-source <host>] [--json]
```

`--discoveries` accepts a JSON array of researcher-reviewed records with `source_url`, `disclosure_status: "PUBLICLY_DISCLOSED"`, `title`, `technique_summary`, `technologies`, and `vulnerability_families`; `author`, `published_at`, and `source_attribution` are optional. Reports without explicit public disclosure status are rejected. Its URL domain allowlist includes HackerOne, Bugcrowd, Google, YesWeHack, Intigriti, Microsoft, GitHub, OWASP, and CISA. Other sources are rejected until deliberately reviewed and added. The caller reports successfully rechecked source hosts with `--checked-source` and failures with `--unchecked-source`. Unchecked or unreported sources are never falsely marked fresh and do not cause stored entries to be pruned.

## Workflow and expected outputs
1. Load the program workspace and validate the target against its scope configuration before network access.
2. Reuse existing asset, endpoint, identity, finding, coverage and test-fingerprint records; formulate specific hypotheses with reasons to test or skip them.
3. When `/Arise` is invoked, re-evaluate every saved disclosure entry against current context, prune irrelevant local entries, and discover relevant linked reports from configured public sources.
4. Rank hypotheses by explainable impact potential, evidence confidence, safety, cost, freshness and duplicate coverage. Identify source-derived methodology separately from target-specific evidence.
5. Present a bounded plan for researcher review. Selection is not authorization; any active check still requires existing scope, approval and dispatch gates. Stop when evidence is sufficient or a boundary is uncertain.
6. Store redacted evidence and provenance locally, validate results, deduplicate by root cause, and prepare a human-reviewed report. Do not submit automatically.

Expected outputs are phase-specific observations/hypotheses, state updates, and where confirmed, a finding with reproducible steps and minimal supporting evidence. Runtime targets, credentials, captures and reports belong in the local workspace and must not be committed.

## Safety and scope gates
- Explicit program authorization and the current scope rules are prerequisites; exclusions take precedence.
- Prefer passive analysis. Active checks must be bounded, non-destructive, and use the approved transport and human approval gates required by the engine.
- Do not access unrelated user data, cause service disruption, brute-force credentials, or perform financial/state-changing actions outside an explicitly safe approved workflow.
- Preserve redaction, local-only evidence storage, and honest separation of simulated, observed, and confirmed results.
- Store only report links and concise attributed methodology notes; do not download or retain full public reports.
- Do not treat a historical report, technology match, or relevance score as proof of a vulnerability on the current target.
- Do not purge entries merely because a source is temporarily unavailable; distinguish unknown freshness from confirmed irrelevance.
- Do not infer authorization, raise relevance scores to force results, or run a test because `/Arise` found a similar report.

## Acceptance criteria
- Unit and integration coverage exercises normal, boundary, failure, and out-of-scope behavior on supported platforms.
- The engine fails closed on missing scope, invalid configuration, exceeded budgets, unsafe destinations, or unavailable trust dependencies.
- Results link to reproducible evidence and state their confidence, limitations, and whether they came from simulation or a live authorized test.
- `/Arise` rechecks every saved entry on every invocation, applies deterministic relevance and pruning rules, reports cleanup reasons, and returns an empty result when no candidates meet the threshold.
- Tests prove that in-scope and technique-relevant entries are retained; confirmed mismatches, resolved issues and adequately covered duplicates are pruned; inconclusive tests and temporary source failures are handled without false pruning.
- Source attribution, publication/last-checked dates, applicability rationale and uncertainty are visible, and source-derived methods are never represented as target evidence.
- Generating, selecting, or prioritizing a recommendation cannot bypass scope validation, operator approval, dispatch controls or budgets.
- Documentation, CLI/skill integration, and current verification evidence agree. A passing mock suite alone does not establish live-target effectiveness.

## Remaining work and limitations
The repository CLI deliberately does not scrape public sites; discovery depends on the orchestrator's available read-only search capability. If that capability is unavailable, it cannot find new reports automatically. The score is a transparent prioritization heuristic, not an exploitability probability. Coverage is limited by the completeness and freshness of local program state; the engine does not infer missing endpoint details or run tests. Windows verification must be reported separately from Linux acceptance because this workspace has no working Windows Python launcher; no Windows Phase 23 test result is claimed. Phase acceptance reflects repository evidence and does not imply authorization to test any target.

## Verification record

Verified on Kali Linux at commit `0a2d7a8` on 2026-11-18:

- `python3 -m pytest tests/test_phase23_research_planning.py tests/test_deploy.py -q`: **28 passed**.
- `python3 -m pytest tests/ -ra`: **1,245 passed, 1 skipped**. The skipped test is the Windows-only DACL check.
- The local `voting-limit` concurrency fixture passed **10 consecutive** isolated runs after its simulation-only race window was widened to 500 ms to reduce scheduler-sensitive false negatives under suite load.
- `bb-plan --help` and `bb-arise --help` both returned successfully on Kali.

These checks verify local fixtures and command/deployment behavior; they do not establish live-target vulnerability discovery effectiveness. No Windows test result is claimed.

## Source references
Phase 23 acceptance tests: `tests/test_phase23_research_planning.py` and `tests/test_deploy.py`. See [the project handbook](../PROJECT-HANDBOOK.md) and [the 24-phase roadmap](../ROADMAP-24-PHASES.md).
