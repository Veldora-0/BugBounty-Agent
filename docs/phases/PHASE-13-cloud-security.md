# Phase 13 — Cloud Security

**Status:** Implemented for read-only cloud exposure hypotheses and bounded checks; provider coverage and attribution are limited.
**Implementation:** **framework/cloud_security/**, **scripts/bb-cloud**, and the **cloud-security skill**
**State file:** **state/cloud.json**.

## Why this phase exists

A program may use cloud storage, content delivery, or managed services as part of its application. Misconfigured storage can expose files; a forgotten cloud hostname may point to an abandoned service; and a public resource may reveal information the program intended to keep private. Phase 13 looks for these exposure patterns using public observations and bounded read-only checks.

The phase is not a cloud account scanner. It must not log in to infrastructure, enumerate private tenant data, probe cloud metadata, claim an unowned service, upload or delete objects, or test unrelated providers.

## How the phase works

The engine reads assets and technology observations already collected for the program, applies provider fingerprints and creates exposure hypotheses. A passive run only models candidates. A dry run previews which checks would be considered. Active validation is an explicit mode; the cloud policy permits only GET, HEAD, and OPTIONS and caps requests and response size. It blocks metadata targets and destructive operations.

A public bucket or provider-looking hostname is not automatically a vulnerability. The researcher must determine whether the resource belongs to the in-scope program, whether the exposed content is intentionally public, and whether the evidence shows meaningful unauthorized access. State and reviewed findings are saved in **cloud.json**.

## How to run it

~~~bash
# List cloud exposure hypotheses from existing state.
bb-cloud --program <program-name> --hypotheses --passive-only --tree

# Preview the bounded checks for a specific program asset.
bb-cloud --program <program-name> --asset assets.example.org --dry-run --json

# Use the deterministic local cloud lab.
bb-cloud --program <program-name> --lab --json

# Active validation is explicit and must be allowed by the program.
bb-cloud --program <program-name> --asset assets.example.org --validate --json
~~~

The active example is not a recommendation to probe any particular bucket. Confirm the exact asset and test boundaries first.

## Understanding results

A fingerprint is a clue about the provider or resource type. A hypothesis says what exposure might exist. A validated result should show only the minimum harmless fact needed to establish access, such as a public listing or a synthetic object that the program intentionally created for testing. Do not download personal records or secret files to demonstrate severity.

Report whether the finding is observed or confirmed, what resource was checked, what permission was present, and how scope ownership was established. If the resource is managed by a third party, do not test it directly unless the program explicitly includes it.

## Safety and limitations

The engine enforces read-only methods, request limits, and metadata restrictions, but public-provider behavior changes over time. Its provider fingerprints do not cover every cloud service or every tenant configuration. A local lab test verifies code paths, not a real cloud provider’s authorization boundary.

Tests: **tests/test_cloud_security_engine.py**. See the [security policy](../security.md), **cloud-security skill**, and [roadmap](../ROADMAP-24-PHASES.md).