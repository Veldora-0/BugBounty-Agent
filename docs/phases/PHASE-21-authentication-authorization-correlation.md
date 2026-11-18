# Phase 21 — Authentication & Authorization Correlation

**Status:** Implemented; Accepted with Documented Limitations (Windows service isolation unsupported; live Linux systemd mutation execution unverified due to key provisioning prerequisite)
**Implementation:** framework/auth_correlation/, skills/authentication/, skills/authorization/, scripts/bb-auth-correlate

## What this phase is for

Many serious application bugs happen between identity and access control. An application may authenticate a user correctly but continue to accept a revoked session, apply the wrong user's permissions, or confuse accounts across tenants. Phase 21 helps the researcher compare those related states and preserve trustworthy evidence about which identity performed an action.

This phase also secures the optional local dispatcher used by the project to control approved validation actions. The dispatcher is a separate, restricted service. It can reject an action unless the operator approval and the current program scope match the exact request. A signed execution receipt lets the framework check that the dispatcher really accepted and performed the action; caller-written JSON alone is not trusted evidence.

## How the researcher uses it

1. Set up an authorized program workspace and confirm its current scope file. Record which test accounts and roles the program permits you to use.
2. Describe one concrete question, such as whether logging out invalidates a session, whether a lower-privileged account can read another test account's record, or whether a session remains usable after a permission change.
3. Use only researcher-controlled accounts and harmless records. Record the starting identity, action, response, and expected access rule. Do not use another person's account or data.
4. Compare the result with the same action under the other authorized identity or state. Keep each request narrowly scoped and stop if the test would change sensitive or financial data.
5. Save redacted evidence locally, validate the finding, and report the exact boundary that failed. Any dispatcher action still needs a current human approval and scope re-check.

Expected outputs are phase-specific observations/hypotheses, state updates, and where confirmed, a finding with reproducible steps and minimal supporting evidence. Runtime targets, credentials, captures and reports belong in the local workspace and must not be committed.

## The dispatcher trust path

The Linux service runs under a dedicated unprivileged service identity. Its private signing key is isolated from the researcher account; the public verification key is used by the framework to verify receipts. The IPC socket is protected by operating-system ownership and permissions. The service checks the approval, request fields, freshness, nonce/replay state, and scope before accepting a dispatch. The framework then independently verifies the signed receipt before it issues an execution capability or promotes related evidence.

This boundary is distinct from application testing. It protects the local control channel; it does not prove that a target has a vulnerability, and it does not grant permission to test a target.

## Safety and scope gates
- Explicit program authorization and the current scope rules are prerequisites; exclusions take precedence.
- Prefer passive analysis. Active checks must be bounded, non-destructive, and use the approved transport and human approval gates required by the engine.
- Do not access unrelated user data, cause service disruption, brute-force credentials, or perform financial/state-changing actions outside an explicitly safe approved workflow.
- Preserve redaction, local-only evidence storage, and honest separation of simulated, observed, and confirmed results.

## What is verified and what remains limited

The Linux dispatcher identity, socket access, protected key/data permissions, pinned public key, and rejection of invalid approval have been checked on Kali. Unit and adversarial tests also cover signed receipt verification, altered or missing receipts, replay, expiry, future timestamps, unauthorized evidence writes, and provenance status. These checks verify the implementation's trust rules; they do not prove application vulnerability detection or live operation in every environment.

## Remaining work and limitations
Provenance gates have been resolved via independent Ed25519 execution receipt verification and dynamic capability assessment. Outstanding limitations:
1. Windows production service isolation remains a documented platform limitation (Named Pipes used for local development/testing; production service isolation under dedicated service account active on Linux).
2. Live authorized mutation execution through the installed Linux systemd service was NOT RUN because provisioning operator test keys in `/var/lib/bugbounty/keys` requires root/sudo privileges unavailable to the unprivileged test account. Live socket connectivity, STATUS, Ed25519 public key loading, and negative rejection of unapproved mutations were verified against the live service; end-to-end execution was verified in standalone isolated process mode.

Outstanding limits are important. Production service isolation is implemented for Linux; equivalent Windows service isolation is unsupported. On the installed Kali system, the live service's ping/status, public key, and rejection of invalid mutations were verified, but a successful authorized mutation was not run because the operator test-key setup required privileged provisioning. Standalone isolated-process tests cover successful receipt creation and verification. A current full-suite run on Kali is recorded in the [Phase 24 verification record](PHASE-24-final-integration-production-readiness.md#verification-record). See the [issue register](../PROJECT-AUDIT-ISSUES.md) and [roadmap](../ROADMAP-24-PHASES.md). Phase 22's hosted Windows full-suite now passes; this does not provide Windows production dispatcher isolation. Phase acceptance does not imply authorization to test any target.

## Source references
Relevant tests: `tests/test_phase21_*.py`, `tests/test_dispatcher*.py`, and the Kali isolation check `tests/verify-dispatcher-isolation.sh`. See the [project handbook](../PROJECT-HANDBOOK.md) and [24-phase roadmap](../ROADMAP-24-PHASES.md).
