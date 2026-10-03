# Interactsh OOB Testing Setup

## Purpose
Interactsh is an open-source tool for detecting out-of-band (OOB) interactions (blind SSRF, blind XSS, blind SQLi, and out-of-band remote code execution) through DNS, HTTP, SMTP, and LDAP callbacks.

## Why BugBounty-Agent Uses It
BugBounty-Agent uses Interactsh to safely test for blind server-side vulnerabilities without requiring arbitrary remote shell access or destructive exfiltration.

## Account Required
**OPTIONAL** (The default public ProjectDiscovery server `interact.sh` operates without an account; private or authenticated self-hosted servers require credentials).

## API Key Required
**OPTIONAL** (Only required when using authenticated self-hosted servers or PDCP cloud features).

## Required Environment Variables
```bash
# Optional: Authentication token for custom or private Interactsh server
INTERACTSH_TOKEN="your_custom_auth_token"
INTERACTSH_SERVER="your.custom.interactsh.server"

# Optional: ProjectDiscovery Cloud Platform token
PDCP_API_KEY="your_pdcp_api_key"
```

## Where to Obtain Credentials
* Public server: No token needed.
* Self-hosted instance: Configured during server deployment.
* PDCP Cloud: [https://cloud.projectdiscovery.io](https://cloud.projectdiscovery.io)

## Official Documentation
* [Interactsh GitHub Repository](https://github.com/projectdiscovery/interactsh)
* [Interactsh Documentation](https://docs.projectdiscovery.io/tools/interactsh)

## Setup
Install Interactsh client:
```bash
bb-install interactsh
```

## Configuration
For public server usage, no configuration is required.
For private server usage, add settings to `~/.config/bugbounty-agent/secrets.env`:
```text
INTERACTSH_SERVER=oob.myresearchdomain.com
INTERACTSH_TOKEN=secret_interactsh_token
```

## Verification
Test client registration:
```bash
interactsh-client -n 1
```
A valid session outputs a unique OOB callback domain (e.g. `c12345678.oast.fun`).

## Rate Limits / Quotas
* Public server applies rate limits to prevent volumetric abuse.
* Do not flood the public server with high-frequency fuzzing payloads.

## Privacy / Terms Considerations
Public `interact.sh` servers log DNS, HTTP, and SMTP transactions. For sensitive private bug bounty programs, deploying a self-hosted private Interactsh instance is strongly recommended.

## Failure Behavior
If the public server is blocked or unreachable:
* Client exits with connection error.
* BugBounty-Agent flags OOB testing as unavailable and skips blind callback validations.
