# Interactsh OOB Testing Setup

## Purpose
Interactsh is an open-source tool for detecting out-of-band (OOB) interactions (blind SSRF, blind XSS, blind SQLi, and out-of-band remote code execution) through DNS, HTTP, SMTP, and LDAP callbacks.

## Integration status
The standalone Interactsh client can provide out-of-band callbacks for a researcher-managed test. BugBounty-Agent's Python OOB adapter does not currently poll live Interactsh servers; it reports an unavailable/configuration state rather than treating a local simulation as a real callback. The standalone client is not automatically invoked by the research engines.

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
For public server usage, the standalone client may not need a token. For private server usage, configure the standalone client according to its own documentation. `secrets.env` lets BugBounty-Agent's doctor report key presence; it does not configure or invoke the client:
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
If the server is blocked or unreachable, the standalone client reports its connection failure. The framework adapter remains unavailable for live polling; see the [Phase 9/18 OOB issue](../PROJECT-AUDIT-ISSUES.md).

> [!NOTE]
> **Framework Adapter Status (Phase 18)**: While the standalone `interactsh-client` CLI interacts with live servers, the Python framework provider adapter (`InteractshOobProvider` in `framework/ssrf/provider.py`) uses local in-memory storage and truthfully reports `CONFIG_REQUIRED` when unconfigured and `UNAVAILABLE` when configured because live wire polling over network protocols is not implemented. A configured token or hostname alone does not establish operational live polling.
