# Phase 21 — Authentication & Authorization Correlation

**Status:** Partially implemented. The Linux dispatcher can be configured with one trusted program scope and operator key, and fails closed when configuration is absent. The updated service isolation and successful dispatch path are not yet live-verified on Kali; Windows production service isolation is unsupported.
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

## Safety and scope gates
- Explicit program authorization and the current scope rules are prerequisites; exclusions take precedence.
- Prefer passive analysis. Active checks must be bounded, non-destructive, and use the approved transport and human approval gates required by the engine.
- Do not access unrelated user data, cause service disruption, brute-force credentials, or perform financial/state-changing actions outside an explicitly safe approved workflow.
- Preserve redaction, local-only evidence storage, and honest separation of simulated, observed, and confirmed results.

## What is verified and what remains limited

Before the latest configuration hardening, Kali checks verified the Linux dispatcher identity, socket access, signing-key/data permissions, pinned public key, and rejection of invalid approval. Unit and adversarial tests cover signed receipt verification, altered or missing receipts, replay, expiry, future timestamps, unauthorized evidence writes, program binding, and production-readiness status. The updated files add explicit service-only approval-key group checks. On 2026-11-19, the Kali checkout's installed systemd unit did not yet include this new group, no program approval key was provisioned, and noninteractive `sudo` was unavailable. Therefore the revised installed-service permissions and a successful authorized mutation have not been verified live. Repository tests verify the configuration contract; they do not prove that the current host has been upgraded.

## Remaining work and limitations
Outstanding limitations:
1. Windows production service isolation remains unsupported (Named Pipes are used for local development and testing; the production service boundary is Linux systemd).
2. The updated Linux installation and program provisioning path still needs a privileged host upgrade and live isolation check. Kali's noninteractive `sudo` was unavailable during this audit, and the installed service had not yet been configured with a program scope or approval key.
3. A successful authorized mutation through the installed systemd service has not been run. Standalone isolated-process tests cover receipt creation and verification, but are not equivalent to the installed service boundary.

These limits remain release gates. Linux production service isolation is implemented in code, but the updated approval-key group and program configuration have not been installed and checked on the current Kali host. Windows production dispatcher isolation remains unsupported. No successful authorized mutation has been run through the installed service. See the [issue register](../PROJECT-AUDIT-ISSUES.md), [Phase 24 verification record](PHASE-24-final-integration-production-readiness.md), and [roadmap](../ROADMAP-24-PHASES.md). Phase acceptance does not imply authorization to test any target.

## Source references
Relevant tests: `tests/test_phase21_*.py`, `tests/test_dispatcher*.py`, and the Kali isolation check `tests/verify-dispatcher-isolation.sh`. See the [project handbook](../PROJECT-HANDBOOK.md) and [24-phase roadmap](../ROADMAP-24-PHASES.md).
