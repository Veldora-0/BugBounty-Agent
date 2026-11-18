# Uncover Multi-Engine Provider Setup

## Purpose
Uncover is a search engine API wrapper that queries internet-wide scanning engines (Shodan, Censys, FOFA, ZoomEye, Hunter, Netlas, CriminalIP, PublicWWW, etc.) to discover exposed network services, hosts, and certificates.

## Integration status
Uncover is a standalone catalog tool. The normal BugBounty-Agent reconnaissance commands do not invoke it or pass provider keys to it. A researcher can install and run it manually, subject to explicit authorization, provider terms, and the actual scope of each query.

## Account Required
**YES** (Requires individual accounts with each respective search engine provider you wish to query).

## API Key Required
**YES** (At least one provider credential must be configured).

## Required Environment Variables
These are examples of provider variables recognized for diagnostics. Storing a value in BugBounty-Agent's `secrets.env` does not configure Uncover or export the value to its process:

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
For a separate Uncover run, configure credentials using its current native instructions or set the required variables in the process environment. BugBounty-Agent's `secrets.env` reader only checks for the presence of named values.

## Verification
Test query with a harmless domain search:
```bash
uncover -q "ssl:example.com" -e shodan,censys -limit 5
```

## Rate Limits / Quotas
Each provider applies its own current rate limits and terms. Check its account dashboard before use.

## Privacy / Terms Considerations
Search engine queries are subject to the acceptable use policies of each commercial provider. Do not run mass automated queries exceeding your tier limits.

## Failure Behavior
Missing credentials or exhausted quota are handled by Uncover and each provider according to their current behavior. BugBounty-Agent makes no query and does not implement provider fallback.
