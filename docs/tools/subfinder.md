# Subfinder Provider Setup

## Purpose
Subfinder is a fast passive subdomain enumeration tool that queries over 40+ public datasets and intelligence providers to discover valid subdomains without sending direct traffic to the target.

## Why BugBounty-Agent Uses It
BugBounty-Agent relies on Subfinder during initial asset discovery to map root domain attack surfaces passively. It provides high-confidence candidate hostnames before any active HTTP probing or DNS resolution takes place.

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
You can configure Subfinder directly via:
```bash
subfinder -pc ~/.config/subfinder/provider-config.yaml
```
Alternatively, BugBounty-Agent automatically detects environment variables set in `~/.config/bugbounty-agent/secrets.env` and maps them.

## Configuration
Add your credentials to `~/.config/bugbounty-agent/secrets.env`:
```text
PDCP_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
SECURITYTRAILS_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```
Set strict permissions:
```bash
chmod 600 ~/.config/bugbounty-agent/secrets.env
```

## Verification
Verify configured providers without making excessive queries:
```bash
subfinder -d example.com -silent -v
```
Review output to confirm which commercial sources were activated.

## Rate Limits / Quotas
* Free, non-authenticated sources are rate-limited per IP (typically 1-5 req/s).
* Commercial providers apply individual quota tiers (e.g. SecurityTrails free tier allows 50 queries/month).

## Privacy / Terms Considerations
Queries to third-party providers reveal the domain name being investigated. Ensure the program policy permits passive intelligence queries against authorized root domains.

## Failure Behavior
If credentials are missing or invalid:
* Subfinder outputs a warning for that specific provider and continues querying all other free, unauthenticated providers.
* BugBounty-Agent continues reconnaissance in degraded mode without halting the workflow.
