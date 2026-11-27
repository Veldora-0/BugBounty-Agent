# Phase 21 — Authentication & Authorization Correlation

**Status:** Partially implemented. The updated Linux systemd service is installed on Kali and its identity, service-only key group, private-key/data isolation, agent IPC, and cross-process rejection of invalid approval were verified. A read-only status check on 2026-11-27 confirmed that the running service has no configured scope or operator key and is not production-dispatch-ready. A successful operator-approved dispatch remains unverified because no disposable local acceptance program/key is provisioned, and a real bounty target is not a safe substitute for that fixture. Windows production service isolation is unsupported.
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

The Linux service runs under a dedicated unprivileged service identity. Its private receipt-signing key is isolated from the researcher account; the public verification key is used by the framework to verify receipts. The IPC socket is accessible to the agent through `bbgroup`. The operator approval key is stored separately under a service-only `bbdispatcher-keys` group, so joining `bbgroup` for IPC does not grant access to that system copy. The service checks the approval, request fields, freshness, nonce/replay state, and scope before accepting a dispatch. The payload program ID, signed dossier program ID, and program ID configured for the dispatcher must agree. The framework independently verifies the signed receipt before it issues an execution capability or promotes related evidence.

The systemd service is deliberately bound to one program configuration at a time. Install the current unit, then provision the scope and 32-byte approval key as root:

~~~bash
sudo bash scripts/install-dispatcher.sh
sudo bash scripts/configure-dispatcher-program.sh <program-id> <scope.yaml> <auth_approval.key>
scripts/bb-dispatcher --status
~~~

The provisioning command validates both input files before replacing configuration, installs the scope read-only, stores the HMAC key for the service-only group, and restarts the service. Status reports `production_dispatch_ready` only when a program ID, valid scope engine, and approval key are loaded. A missing or invalid value leaves production dispatch unavailable. Re-run provisioning to switch the service to a different program; do not assume the service holds several program scopes at once. The source approval key must be a regular 32-byte file with private permissions and must be the key used to sign the operator's action dossiers.

This boundary is distinct from application testing. It protects the local control channel; it does not prove that a target has a vulnerability, and it does not grant permission to test a target.

### Replay protection and evidence integrity

The dispatcher treats its approval and nonce files as security state. It validates their schema and every record before use; malformed, duplicate, or unsafe state is rejected rather than silently reset. A request nonce is durably reserved under a cross-process lock before approval is consumed and before the approved transport is called. The write uses an atomic replacement and flushes the file and parent directory. If the process stops after reservation, that nonce is burned: the same request cannot be replayed after restart. The registry does not discard old entries to make room, because that would reopen replay opportunities.

After dispatch, a receipt's evidence identifiers are not accepted as proof by themselves. `ControlledDispatchWorkflow` requires an evidence store that can write and read persisted evidence, then independently retrieves both referenced records and checks their identifiers and SHA-256 digests against the receipt. Missing stores, unreadable or altered evidence, mismatched identifiers, and digest errors stop the workflow. These checks protect the local approval/evidence chain; they do not prove that the remote application behaved securely.

## Safety and scope gates
- Explicit program authorization and the current scope rules are prerequisites; exclusions take precedence.
- Prefer passive analysis. Active checks must be bounded, non-destructive, and use the approved transport and human approval gates required by the engine.
- Do not access unrelated user data, cause service disruption, brute-force credentials, or perform financial/state-changing actions outside an explicitly safe approved workflow.
- Preserve redaction, local-only evidence storage, and honest separation of simulated, observed, and confirmed results.

## What is verified and what remains limited

Unit and adversarial tests cover signed receipt verification, altered or missing receipts, replay, expiry, future timestamps, unauthorized evidence writes, program binding, and production-readiness status. On 2026-11-21, the Kali installer updated the systemd service; `SupplementaryGroups=bbdispatcher-keys` was present and the service was active with its socket and public verification key installed. `sudo bash tests/verify-dispatcher-isolation.sh veldora` passed. The verifier checked service UID/GID and supplementary group, agent separation from the private signing key and protected data, socket/public-key permissions, agent IPC, and cross-process rejection of invalid approval without mutation. The operator approval key was not provisioned, so a successful approved dispatch was not attempted. These host checks do not establish live-target effectiveness or authorization.

## Remaining work and limitations
Outstanding limitations:
1. Windows production service isolation remains unsupported (Named Pipes are used for local development and testing; the production service boundary is Linux systemd).
2. Provisioning a program scope and 32-byte operator approval key remains unverified on the installed host. Use a dedicated local acceptance program and disposable test key; do not use a bounty target to close this infrastructure test.
3. A successful authorized mutation through the installed systemd service has not been run. Standalone isolated-process tests cover receipt creation and verification, but are not equivalent to the installed service boundary.

The installed Linux service isolation checks now pass, but program-key provisioning and successful approved dispatch remain release acceptance gaps. Windows production dispatcher isolation remains unsupported. No bounty target was contacted. See the [issue register](../PROJECT-AUDIT-ISSUES.md), [Phase 24 verification record](PHASE-24-final-integration-production-readiness.md), and [roadmap](../ROADMAP-24-PHASES.md). Phase acceptance does not imply authorization to test any target.

## Source references
Relevant tests: `tests/test_phase21_*.py`, `tests/test_dispatcher*.py`, and the Kali isolation check `tests/verify-dispatcher-isolation.sh`. See the [project handbook](../PROJECT-HANDBOOK.md) and [24-phase roadmap](../ROADMAP-24-PHASES.md).
