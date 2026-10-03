# Uncover Multi-Engine Provider Setup

## Purpose
Uncover is a search engine API wrapper that queries internet-wide scanning engines (Shodan, Censys, FOFA, ZoomEye, Hunter, Netlas, CriminalIP, PublicWWW, etc.) to discover exposed network services, hosts, and certificates.

## Why BugBounty-Agent Uses It
BugBounty-Agent utilizes Uncover to identify exposed cloud infrastructure, dangling IPs, internal staging portals, and specific software banners without performing direct high-speed network port scans.

## Account Required
**YES** (Requires individual accounts with each respective search engine provider you wish to query).

## API Key Required
**YES** (At least one provider credential must be configured).

## Required Environment Variables
Configure one or more of the following in `~/.config/bugbounty-agent/secrets.env`:

```bash
# Shodan
SHODAN_API_KEY="your_shodan_key"

# Censys
CENSYS_API_TOKEN="your_censys_token"
CENSYS_ORGANIZATION_ID="your_censys_org_id"

# FOFA
FOFA_EMAIL="your_fofa_email"
FOFA_KEY="your_fofa_key"

# Hunter.how
HUNTER_API_KEY="your_hunter_key"

# ZoomEye
ZOOMEYE_API_KEY="your_zoomeye_key"

# Netlas
NETLAS_API_KEY="your_netlas_key"

# CriminalIP
CRIMINALIP_API_KEY="your_criminalip_key"
```

## Where to Obtain Credentials
* **Shodan**: [https://account.shodan.io/](https://account.shodan.io/)
* **Censys**: [https://search.censys.io/account/api](https://search.censys.io/account/api)
* **FOFA**: [https://fofa.info/](https://fofa.info/)
* **ZoomEye**: [https://www.zoomeye.org/](https://www.zoomeye.org/)
* **Hunter**: [https://hunter.how/](https://hunter.how/)

## Official Documentation
* [Uncover GitHub Repository](https://github.com/projectdiscovery/uncover)
* [Uncover Documentation](https://docs.projectdiscovery.io/tools/uncover)

## Setup
Install Uncover:
```bash
bb-install uncover
```

## Configuration
Store credentials in `~/.config/bugbounty-agent/secrets.env`.
Uncover gracefully activates whichever search engines have configured credentials and skips unconfigured ones.

## Verification
Test query with a harmless domain search:
```bash
uncover -q "ssl:example.com" -e shodan,censys -limit 5
```

## Rate Limits / Quotas
* Shodan: Query credits deducted per search (1 credit per 100 results).
* Censys: Monthly allowance based on free or paid research tier.
* Consult each provider's dashboard to monitor API consumption.

## Privacy / Terms Considerations
Search engine queries are subject to the acceptable use policies of each commercial provider. Do not run mass automated queries exceeding your tier limits.

## Failure Behavior
If a specific engine's key is missing or quota is exhausted:
* Uncover displays an authentication/quota warning for that provider.
* Uncover continues querying other configured engines.
* Results from remaining engines are aggregated normally.
