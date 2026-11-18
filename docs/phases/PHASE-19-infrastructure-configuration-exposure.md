# Phase 19 — Infrastructure and Configuration Exposure

**Status:** Implemented for read-only, bounded exposure discovery and hypotheses; path coverage and context-specific baselines remain incomplete.
**Implementation:** **framework/infrastructure/**, **scripts/bb-infra**, and the **reconnaissance** skill
**State file:** **state/infrastructure.json**.

## What this phase looks for

Applications sometimes publish diagnostic pages, source maps, directory listings, backup files, deployment manifests, or version-control metadata by mistake. Phase 19 organizes these possibilities into exposure categories and checks a bounded set of paths. It is intended to identify a safe clue that a researcher can review, not to download a repository or collect secrets.

A path that returns HTTP 200 is not enough. Many servers return the same “not found” page for every path, known as a soft 404. The engine compares candidate responses with ordinary baselines and limits how many bytes it reads.

## How it works

The engine consumes in-scope assets and observations from earlier phases, derives candidate locations, and records a hypothesis for each plausible exposure. Passive-only mode uses local state and does not probe. Dry-run previews checks. Active verification requires both a valid scope and explicit operator approval. The default checks are read-oriented and response-size bounded; the engine must not write, upload, delete, execute, or extract files.

Results and test fingerprints are persisted in **infrastructure.json**. Review the response type and a sanitized snippet, compare it with the baseline, and confirm that the endpoint belongs to the program. Never download secrets, customer information, or complete backup archives to prove a finding.

## How to use it

~~~bash
# Review existing candidate paths without requests.
bb-infra --program <program-name> --passive-only --tree

# Preview exposure checks.
bb-infra --program <program-name> --dry-run --json

# Exercise local expected behavior in the infrastructure lab.
bb-infra --program <program-name> --lab --json

# Live verification requires current scope and explicit approval.
bb-infra --program <program-name> --approve --json
~~~

Use active mode only after reviewing the exact candidate set and program rules.

## Understanding a finding

A good report shows the exact in-scope URL, why the returned response differs from a normal missing-path response, and the smallest safe information needed to demonstrate exposure. A source-map URL is not necessarily sensitive. A backup-looking filename is not enough if its contents are inaccessible. Do not include copied secrets or complete configuration files in the report.

## Safety and limitations

Path lists cannot cover every framework or deployment. Authentication, CDN behavior, custom error pages, and time-dependent responses can create false positives or false negatives. A lab result is not evidence about a live target.

Tests: **tests/test_infrastructure_engine.py**. See the [scope guide](../scope.md), [Phase 4 JavaScript guide](PHASE-04-javascript-intelligence.md), and [roadmap](../ROADMAP-24-PHASES.md).