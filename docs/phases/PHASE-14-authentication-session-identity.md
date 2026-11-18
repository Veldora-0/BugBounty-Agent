# Phase 14 — Authentication, Session, and Identity

**Status:** Implemented for bounded authentication-flow modeling and validation; operator-managed identities and explicit approval are required for sensitive changes.
**Implementation:** **framework/authentication/**, **scripts/bb-auth**, and the **authentication skill**
**State file:** **state/authentication.json**.

## What this phase studies

Authentication answers “who are you?” Authorization answers “what are you allowed to do?” Phase 14 focuses on the first question and on the lifecycle of the identity proof: login, logout, session creation and rotation, password reset, multi-factor authentication (MFA), and token handling.

A defect may occur when logging out fails to invalidate a session, a reset link can be reused, or an account crosses an MFA boundary incorrectly. A token’s structure alone is not a vulnerability. The researcher must show a specific security property that failed using only accounts created or supplied for the assessment.

## How the phase works

The engine models authentication surfaces and flows, creates hypotheses, and can validate selected behavior with a baseline and a controlled comparison. The policy requires current scope, prohibits password spraying and brute force, blocks cloud metadata and local infrastructure, and caps each hypothesis by request count, timeout, and response size. Password changes, reset submissions, MFA enrollment or disablement, revocation, and similar state mutations require human approval. A deterministic local lab is available.

Identity profiles and session records are references to researcher-controlled test identities. Never put reusable passwords, cookies, or bearer tokens in Git, examples, or ordinary command arguments. The state store masks sensitive evidence, but the actual credentials still need private storage and careful handling.

## How to use it

~~~bash
# List hypotheses without sending requests.
bb-auth --program <program-name> --hypotheses --passive-only --tree

# Inspect one authentication flow from local state.
bb-auth --program <program-name> --flow session --passive-only --json

# Exercise the local authentication lab.
bb-auth --program <program-name> --lab --json

# Active validation is separate and requires valid scope; sensitive changes also need explicit approval.
bb-auth --program <program-name> --asset app.example.org --validate --flow logout --json
~~~

Before active validation, inspect the resulting dossier and confirm that the selected identity is a disposable program-approved account. The command example does not imply that the target permits the test.

## Evaluating results

Compare what the application should do with what happens to the same controlled session. For example, after logout, make one safe request using the test account’s own session and see whether it is still accepted. Keep the account, action, timestamps, and sanitized response tied together. A status-code change alone may not establish whether the old session remains valid.

A report should state the preconditions, identity role, state transition, observed result, and impact. Do not claim account takeover from token parsing or a guessed reset weakness; show only the minimum safe evidence needed.

## Safety and limitations

Do not brute-force, spray, bypass CAPTCHAs, attack third-party identity providers, or test accounts that do not belong to the researcher or program. State-mutation approval is not a substitute for a rollback plan. Multi-device, federated-provider, and application-specific session behaviors may not be fully represented.

Tests: **tests/test_authentication_engine.py** and Phase 14 hardening tests in **tests/test_phase21_***. See [Phase 21](PHASE-21-authentication-authorization-correlation.md), [security policy](../security.md), and [roadmap](../ROADMAP-24-PHASES.md).