# Phase 6 — Security Validation Foundation

**Status:** Implemented as shared validation, finding-lifecycle, and evidence-handling foundations; quality still depends on phase-specific validators and human review.
**Implementation:** **framework/validation/**, **framework/findings/**, **framework/common/evidence.py**, **scripts/bb-validate**, **scripts/bb-evidence**, **scripts/bb-report**, and validation/evidence/reporting skills
**State:** Validation and finding records are kept in local program state; evidence files are stored in the private program workspace.

## Why this phase exists

A scanner warning or a suspicious response is not yet a bounty finding. It may be a false positive, a harmless reflection, expected behavior, or a problem that cannot be reproduced. Phase 6 provides shared pieces for turning an idea into a repeatable test, preserving enough safe evidence to review it, tracking the finding’s status, and preparing a report that a human can submit.

Validation means testing whether the evidence supports the stated security claim. Evidence management means recording what happened in a way that another person can check later while removing secrets and unnecessary personal data. Neither step authorizes additional testing. Only use the target and test accounts allowed by the program.

## How the phase works

A validator builds candidate test cases from a target, endpoint, parameter, and category. It can compare a response with a baseline, apply request, time, and byte limits, and label a result according to that validator. Passive-only mode evaluates existing state without sending requests. Dry-run mode constructs a plan without dispatching probes or persisting new test results. Resume mode avoids repeating cases already recorded.

The evidence command accepts request and response files plus a note describing what they demonstrate. Evidence handling sanitizes sensitive values in the HTTP capture and recursively sanitizes string metadata; metadata fields whose names indicate credentials are redacted as well. It stores local metadata including a digest so changes can be detected. A hash does not encrypt a file: raw captures and credentials still require private file permissions and must never be committed. They live under the Git-ignored `programs/<name>/` path in the current OpenCode directory; use a separate directory when physical separation from source code is required. Finding records then move through a lifecycle such as candidate, validated, reported, or closed. The report command renders a draft from reviewed finding and evidence records; it does not submit it.

## How to use it

~~~bash
# Inspect known candidates without issuing network requests.
bb-validate --program <program-name> --passive-only --json

# Plan a narrowly scoped check for an already reviewed endpoint.
bb-validate --program <program-name> --asset app.example.org --endpoint https://app.example.org/item --dry-run --tree

# Use smaller test and request ceilings for a first review.
bb-validate --program <program-name> --max-tests 5 --max-requests 10 --json

# Preserve a sanitized capture in the local evidence store.
bb-evidence --program <program-name> --request-file ./request.txt --response-file ./response.txt --note "Baseline and control comparison"

# List report readiness, then render a draft for a specific finding.
bb-report --program <program-name> --list
bb-report --program <program-name> --finding-id <finding-id>
~~~

Keep captures local under the current program workspace, inspect sanitized output, and check each CLI’s help before using options in a particular release. Do not force-add them to Git.

## How to judge a result

A positive validator result should have a clear reproduction, a baseline or control where appropriate, and evidence that supports the stated impact. A result marked inconclusive is not a confirmed bug. A digest proves that the saved bytes have not changed since the digest was calculated; it does not prove that the capture is truthful or that the test was authorized.

Before preparing a disclosure, remove secrets, verify the affected asset is still in scope, explain who can perform the action and what boundary failed, and make sure the evidence demonstrates the reported impact. Then have a person review the report and submit it through the program’s approved channel.

## Safety and limitations

The shared foundation does not make every engine equally mature. A validator can only test the scenarios it knows, and fixture tests are not a substitute for independent reproduction on an authorized target. Raw evidence can contain credentials, personal data, or tokens; keep it local, restrict access, and avoid attaching more than the report needs.

Relevant tests include **tests/test_validation_engine.py**, **tests/test_validation_engine_transport.py**, **tests/test_finding_lifecycle_readiness.py**, and the evidence/reporting coverage. See the [workflow guide](../workflow.md), [security policy](../security.md), and [roadmap](../ROADMAP-24-PHASES.md).
