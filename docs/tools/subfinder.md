# Subfinder Provider Setup

## Purpose
Subfinder is a fast passive subdomain enumeration tool that queries over 40+ public datasets and intelligence providers to discover valid subdomains without sending direct traffic to the target.

## Integration status
Subfinder is listed in the optional tool catalog, but the normal `bb-assets` and `bb-recon` commands do not invoke it. Installing it does not add provider-backed discovery to those engines. The project has no end-to-end Subfinder CLI integration at this time; see [AUD-06 and AUD-07](../PROJECT-AUDIT-ISSUES.md).

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
BugBounty-Agent's provider manager can read `secrets.env` to report whether a key is present in `bb-doctor`. It does not export or map those values into Subfinder's process or native configuration. For a manual Subfinder run, configure the provider through Subfinder itself and invoke it separately.

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
Verify Subfinder manually only against an authorized root domain, with a small query budget and provider terms in mind:
```bash
subfinder -d example.com -silent -v
```
Review output to confirm which commercial sources were activated.

## Rate Limits / Quotas
Provider coverage, request limits, quotas and free tiers change. Check the current Subfinder and provider documentation before querying.

## Privacy / Terms Considerations
Queries to third-party providers reveal the domain name being investigated. Ensure the program policy permits passive intelligence queries against authorized root domains.

## Failure Behavior
If credentials are missing or invalid, Subfinder's own current behavior applies. BugBounty-Agent does not run Subfinder or provide a fallback through `bb-recon`.
