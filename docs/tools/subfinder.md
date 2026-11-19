# Subfinder Provider Setup

## Purpose
Subfinder is a fast passive subdomain enumeration tool that queries over 40+ public datasets and intelligence providers to discover valid subdomains without sending direct traffic to the target.

## Integration status
Subfinder is an optional, explicitly selected passive provider for `bb-assets --subfinder`. `bb-recon` does not invoke it. The framework checks each root and result against the configured scope, records source names for accepted hosts, and enforces fixed output and time limits. Provider coverage still depends on Subfinder's native source configuration and does not imply complete discovery.

## Account Required
**NO** (Basic discovery functions out of the box using free, unauthenticated sources such as crt.sh, HackerTarget, and Wayback Machine). Optional accounts unlock additional commercial datasets (SecurityTrails, Censys, Shodan, BinaryEdge, Chaos).

## API Key Required
**OPTIONAL** (Not required for default passive operations; recommended for maximum coverage).

## Required Environment Variables
To supply commercial API keys, BugBounty-Agent checks either your shell environment or `~/.config/bugbounty-agent/secrets.env`:

```bash
# ProjectDiscovery Cloud Platform (unlocks Chaos and PD sources)
PDCP_API_KEY="your_pdcp_api_key_here"

# Individual provider keys used by subfinder
SHODAN_API_KEY="your_shodan_key_here"
CENSYS_API_TOKEN="your_censys_token_here"
CENSYS_ORGANIZATION_ID="your_censys_org_id_here"
SECURITYTRAILS_API_KEY="your_securitytrails_key_here"
VT_API_KEY="your_virustotal_key_here"
GITHUB_TOKEN="your_github_token_here"
```

## Where to Obtain Credentials
* **ProjectDiscovery Cloud**: [https://cloud.projectdiscovery.io](https://cloud.projectdiscovery.io)
* **SecurityTrails**: [https://securitytrails.com/app/account/credentials](https://securitytrails.com/app/account/credentials)
* **Shodan**: [https://account.shodan.io/](https://account.shodan.io/)
* **Censys**: [https://search.censys.io/account/api](https://search.censys.io/account/api)
* **VirusTotal**: [https://www.virustotal.com/gui/user/apiKey](https://www.virustotal.com/gui/user/apiKey)

## Official Documentation
* [Subfinder GitHub Repository](https://github.com/projectdiscovery/subfinder)
* [Subfinder Provider Configuration Docs](https://docs.projectdiscovery.io/tools/subfinder/provider-configuration)

## Setup
Subfinder manages API keys locally in `~/.config/subfinder/provider-config.yaml`.
Configure Subfinder directly according to its current upstream documentation:
```bash
subfinder -pc ~/.config/subfinder/provider-config.yaml
```
BugBounty-Agent does not copy values from `secrets.env` into Subfinder. Configure provider keys using Subfinder's own `provider-config.yaml`; the integrated invocation reads the native provider configuration. The tool registry may report key presence for diagnosis, but this does not prove a key is valid or that a source will return results.

## Integrated usage
Use the explicit flag with an initialized program and a current scope file:
```bash
bb-assets --program <program-name> --subfinder --passive-only --tree
```
The adapter queries each in-scope root once. It applies a 2-requests-per-second provider limit, 8-second per-source timeout, 1-minute Subfinder maximum, 75-second process ceiling, and a 1,000-result ceiling. Results outside scope, malformed hostnames, and excluded names are dropped. The default output path is a private temporary file that is removed after parsing. `--passive-only` prevents active DNS/TLS probes against discovered hosts, but the domain is still sent to Subfinder's configured data providers.

## Configuration
If you want `bb-doctor` to report that credentials are present, you may store their names and values in `~/.config/bugbounty-agent/secrets.env`:
```text
PDCP_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
SECURITYTRAILS_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```
Set strict permissions:
```bash
chmod 600 ~/.config/bugbounty-agent/secrets.env
```

## Verification
For a separate manual run, use only an authorized root domain, with a small query budget and provider terms in mind:
```bash
subfinder -d example.com -silent -v
```
Review output to confirm which commercial sources were activated.

## Rate Limits / Quotas
Provider coverage, request limits, quotas and free tiers change. Check the current Subfinder and provider documentation before querying.

## Privacy / Terms Considerations
Queries to third-party providers reveal the domain name being investigated. Ensure the program policy permits passive intelligence queries against authorized root domains.

## Failure Behavior
If credentials are missing, Subfinder uses only sources that work without them. If the binary, provider config, command, or output fails, `bb-assets` reports a provider error and exits nonzero; it does not invent candidates or fall back to another scanner. `bb-recon` remains separate and never invokes Subfinder.
