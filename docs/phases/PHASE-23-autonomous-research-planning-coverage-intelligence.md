# Phase 23 — Research Planning & Agent-Wide Methodology Learning

**Status:** Implemented in code; public source discovery still depends on the available read-only research capability. The methodology library is global to the installed Bug-Bounty agent and independent of any target. Planning remains offline and advisory.
**Implementation:** `.opencode/commands/Arise.md`, `framework/research_planning/`, `framework/common/config.py`, `scripts/bb-plan`, `scripts/bb-arise`, `agents/Bug-Bounty.md`, and `skills/knowledge-research/SKILL.md`.

## Purpose

Phase 23 combines two related workflows. `bb-plan` uses a program's local, scope-filtered inventory and test history to recommend areas for researcher review. `/Arise` builds the agent's reusable public methodology knowledge: it searches for useful, publicly disclosed vulnerability research that is absent or underrepresented in the agent's current skills and library, without tying the search to a particular target. When planning research for a later target, methodology notes are retrieved by vulnerability family and shown with their source links.

The design keeps target evidence and public learning in separate places. Program scope, inventory, tests, findings, and evidence stay in that program's workspace. The agent-wide methodology library lives at `<OPENCODE_CONFIG_DIR>/bug-bounty-agent/knowledge/methodology.json`, normally `~/.config/opencode/bug-bounty-agent/knowledge/methodology.json`. It is shared across programs and OpenCode working directories using the same global config. It is outside the repository and is not deployed or removed by `bb-deploy`.

## `/Arise`: target-independent learning

`/Arise` does not ask which target the user wants to test, load target scope, or prune knowledge based on one program's technologies or test history. It compares the agent's 18 skills and saved methodology references with publicly available research. The goal is to find useful techniques the agent does not already describe well: practical variants, underrepresented vulnerability classes, and improvements to safe evidence gathering or validation. A source that discusses an unfamiliar product can still teach a transferable vulnerability-family method.

The command uses only an available read-only public research/search capability. It may consult publicly disclosed bounty reports, security writeups, standards, advisories, and other reputable public methodology references. It must distinguish reports that are actually public from activity feeds or summaries whose underlying report is private. If research capability is unavailable, it must say no new sources were checked and leave the saved library unchanged. It must not claim to have searched when it did not.

For each useful, nonduplicate method, the agent stores only a compact reference: HTTPS source URL, title, author or source attribution, publication date when available, vulnerability family, optional technology tags, and a sanitized methodology note of at most 600 characters. It never stores full reports, screenshots, copied long passages, target-specific data, credentials, or raw evidence. The short note provides enough context to decide whether the link is useful; the public report can be consulted on demand later. Source links and notes are methodology references, never evidence that a target is vulnerable. A researcher-reviewed staging JSON file is kept outside the repository and removed after successful import. The library has a 1,000-reference cap; a full library fails closed and requires researcher curation instead of automatic deletion.

Source discovery and source rechecking happen through the assistant's read-only research capability. `bb-arise` itself is offline. Caller-supplied `--checked-source` and `--unchecked-source` flags must reflect actual checks. A source outage or absence of a target technology does not cause a methodology reference to be deleted. The source allowlist includes HackerOne, Bugcrowd, Google, YesWeHack, Intigriti, Microsoft, GitHub, OWASP, CISA, Exploit-DB, PortSwigger, MITRE, NIST, and ProjectDiscovery. The Google Hacking Database is a reference for methodology categories; it is not a vulnerability report. Do not run broad dorks or retrieve sensitive indexed material.

## Using learned methods on a target

When asked to investigate a target, the agent first resolves the program and validates current scope offline. It then uses `bb-plan` to build recommendations from only the current program's in-scope assets, endpoints, technologies, findings, and test records. The planner attaches saved public references to recommendations by vulnerability family, regardless of which product or target the source report covered. Technology tags remain context for the researcher; they do not prevent a useful method from being surfaced on another stack.

The agent reviews the short methodology note and may open the linked public source on demand through its read-only research capability. It then adapts the idea to the current in-scope surface and program rules. It must distinguish source-derived method from observed local facts, avoid copying report text, and never present a historical report as proof of a current vulnerability. A recommendation or source match cannot authorize a test. Active follow-up remains subject to the current scope check, human approval, dispatcher controls, and request/time/response budgets.

## Offline planner implementation

- **Coverage index (`CoverageIndex`)** reads local assets, endpoints, technologies, test history, findings, and coverage state. It filters assets and endpoints through the current `ScopeEngine`; out-of-scope entries cannot support recommendations. Missing or malformed scope fails closed.
- **Recommendation engine (`ResearchPlanner`)** proposes vulnerability-family hypotheses on inventoried endpoints, or on an asset when endpoint discovery is empty. It considers endpoint and technology signals, prior test freshness, validated findings, expected effort, safety, and potential impact. Recent conclusive coverage and an existing validated finding suppress duplicate recommendations. It produces source references separately from target evidence and sets `active_testing_authorized: false` and `requires_operator_approval: true`.
- **Planning controls (`bb-plan`)** support bounded request estimates, a result limit, coverage-only mode, and a local pause/resume flag. These controls organize planning; they do not dispatch or approve requests.
- **Methodology manager (`AriseResearchManager`)** validates public source URLs, public-disclosure status, attribution, summary length, and source-check hostnames. It deduplicates entries by normalized source URL, strips query strings and fragments, sanitizes metadata, and uses private local file permissions. Data is stored in the global agent knowledge directory, not in a target program folder. The manager does not prune entries based on target-specific technology or test coverage.
- **Integration** uses the existing single `Bug-Bounty` agent and `knowledge-research` skill. `bb-deploy` deploys the `/Arise` command but does not copy, overwrite, or delete the agent's personal methodology data.

## Commands

```text
bb-plan --program <name> --coverage-only [--json]
bb-plan --program <name> --budget 20 [--limit 50] [--json]
bb-plan --program <name> --pause
bb-plan --program <name> --resume
bb-arise --discoveries <local-json> [--checked-source <host>] [--unchecked-source <host>] [--json]
```

`bb-arise` saves to the global agent knowledge path by default. `OPENCODE_CONFIG_DIR` selects the same OpenCode config root used by deployment. `--knowledge-dir` is an explicit override for controlled environments and tests. `--discoveries` is a JSON array with records containing `source_url`, `disclosure_status` (`PUBLICLY_DISCLOSED` for reports or `PUBLICLY_AVAILABLE` for official public methodology references), `title`, `technique_summary`, `vulnerability_families`, and `author` or `source_attribution`; `published_at` and `technologies` are optional. Each technique summary is limited to 600 characters. A record cannot be marked checked unless its public host was explicitly passed with `--checked-source`.

## Safety properties and limits

- `/Arise` and the Phase 23 CLIs send no target requests. The CLI also performs no source-network checks.
- A public reference is not target evidence, proof of applicability, permission, or authorization.
- Public research availability, search quality, and source access terms depend on the active research capability and the provider.
- `bb-plan` is only as complete as the program's local scope, inventory, and prior test records. Its scores are prioritization hints, not exploitability probabilities.
- References are linked by vulnerability family, so a method may be useful across different stacks but still needs researcher judgment and safe adaptation.
- The library stores compact notes and links; it does not automatically crawl reports or build a full text/vector index.

## Acceptance and verification

Tests should verify the library is stored under the global agent config rather than a program directory; saved methodology survives target changes, technology mismatches, and target test coverage; source URLs and disclosure status are validated; metadata is sanitized and bounded; target-specific plans retrieve related references by vulnerability family; and planning remains non-executing and scope-filtered. Supported test/CI platform policy is Linux only.

Current implementation tests are in `tests/test_phase23_research_planning.py`; deployment behavior is covered by `tests/test_deploy.py`. A test pass verifies local fixtures and orchestration contracts, not live vulnerability discovery. Actual public source discovery is not performed by `bb-arise` or `bb-plan`.
