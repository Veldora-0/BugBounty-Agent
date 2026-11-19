# Interactsh OOB Testing Setup

## Purpose
Interactsh is an open-source tool for detecting out-of-band (OOB) interactions (blind SSRF, blind XSS, blind SQLi, and out-of-band remote code execution) through DNS, HTTP, SMTP, and LDAP callbacks.

## Integration status
`framework/ssrf/provider.py` integrates the official `interactsh-client` CLI for live canary creation and JSONL event polling. `bb-ssrf` and the Phase 18 XXE engine use it only after their own approval, scope, and OOB-destination policy checks pass. The public ProjectDiscovery server is the default and does not require an account or token. A protected private server can use `INTERACTSH_TOKEN`.

The adapter keeps each session inside a private temporary directory. A private-server token is written to a mode-0600 config file inside a mode-0700 directory; it is not placed in command arguments. The adapter disables PDCP authentication, creates one payload per session, limits registration to 8 seconds, polling to 10 seconds, each process to 120 seconds, and event output to 2 MiB. It correlates only an exact Interactsh `full-id`, records a small normalized event, then removes raw session output after polling. Mock mode must be selected explicitly; an unavailable live provider is not silently replaced by simulation.

The tests replace the client process with a local fake. They verify argument secrecy, permissions, exact callback correlation, redaction, and fail-closed behavior. A Kali self-check on 2026-11-19 found `interactsh-client` 1.4.1 installed, but the client exited before it registered a canary; live server reachability remains unverified. The tests do not establish that an external Interactsh server is reachable or that an authorized target produced a callback. Burp Collaborator still has no live polling adapter.

## Account Required
**OPTIONAL** (The default public ProjectDiscovery server does not require an account; protected self-hosted servers require their own token).

## API Key Required
**OPTIONAL** (Only required for a protected self-hosted Interactsh server).

## Required Environment Variables
```bash
# Optional: Authentication token for a protected private Interactsh server
INTERACTSH_TOKEN="your_custom_auth_token"
INTERACTSH_SERVER="your.custom.interactsh.server"
```

## Where to Obtain Credentials
* Public server: No token needed.
* Protected self-hosted instance: Obtain its client token from the server administrator.

## Official Documentation
* [Interactsh GitHub Repository](https://github.com/projectdiscovery/interactsh)
* [Interactsh Documentation](https://docs.projectdiscovery.io/tools/interactsh)

## Setup
Install Interactsh client:
```bash
bb-install interactsh
```

## Configuration
For public server use, leave `INTERACTSH_TOKEN` unset. For a protected server, add its host and token to the local program's `secrets.env` or export them in the environment. The adapter reads `INTERACTSH_TOKEN`; it deliberately does not reuse `PDCP_API_KEY` as an Interactsh server token:
```text
INTERACTSH_SERVER=oob.myresearchdomain.com
INTERACTSH_TOKEN=secret_interactsh_token
```

## Verification
Check that the optional binary is installed:
```bash
interactsh-client -version
bb-doctor
```
The framework adapter starts the client only when an approved SSRF or XXE test needs a canary. Its automated tests use a fake CLI and do not issue live requests. Use a researcher-controlled, in-scope test endpoint and the exact program rules for any live callback acceptance check.

## Rate Limits / Quotas
* The public service may change, rate-limit, or reject client connections.
* Each framework session creates one canary. The provider caps concurrent sessions at four and polling at ten seconds.
* Do not flood the public server with high-frequency fuzzing payloads.

## Privacy / Terms Considerations
Public `interact.sh` servers log DNS, HTTP, and SMTP transactions. For sensitive private bug bounty programs, deploying a self-hosted private Interactsh instance is strongly recommended.

## Failure Behavior
If the binary is missing, the server is unreachable, the token is rejected, or no payload is produced within the registration bound, the framework records the provider as unavailable or registration failure and sends no target request. The [Phase 9 and Phase 18 guides](../phases/PHASE-09-ssrf-intelligence.md) describe the distinction between mocked unit coverage and live acceptance.

> [!NOTE]
> **Callback evidence**: An installed binary means the provider can attempt registration; it does not prove the remote server accepted the session or that a target made a callback. Only a timestamped interaction with the exact canary ID is evidence of a callback. Simulation never upgrades to a live finding.
