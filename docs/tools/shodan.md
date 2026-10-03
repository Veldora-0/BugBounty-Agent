# Shodan API Integration Setup

## Purpose
Shodan is a search engine for Internet-connected devices, servers, webcams, industrial control systems, and open network ports.

## Why BugBounty-Agent Uses It
BugBounty-Agent uses Shodan via `uncover` and `subfinder` to discover internet-facing IP addresses, open ports, historical SSL/TLS certificates, and service banners associated with in-scope domains and CIDRs.

## Account Required
**YES**

## API Key Required
**YES**

## Required Environment Variables
```bash
SHODAN_API_KEY="your_shodan_api_key"
```

## Where to Obtain Credentials
1. Register an account at [https://account.shodan.io/](https://account.shodan.io/).
2. Your API Key is displayed on your account dashboard.

## Official Documentation
* [Shodan API Reference](https://developer.shodan.io/api)
* [Shodan Help Center](https://help.shodan.io/)

## Setup
Save your API key into `~/.config/bugbounty-agent/secrets.env`:
```text
SHODAN_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## Configuration
BugBounty-Agent passes `SHODAN_API_KEY` to `uncover` and `subfinder` automatically when invoked during reconnaissance phases.

## Verification
Test your Shodan API key via curl or uncover:
```bash
curl -s "https://api.shodan.io/api-info?key=${SHODAN_API_KEY}"
```
Expected response:
```json
{"scan_credits": 100, "usage_limits": {...}, "plan": "dev", "unlocked": true}
```

## Rate Limits / Quotas
* Free accounts: Limited query credits (typically 100 query credits per month).
* 1 credit is consumed per search page (100 results).

## Privacy / Terms Considerations
Do not share or commit Shodan keys. Respect query rate limits (maximum 1 request per second for standard developer plans).

## Failure Behavior
If the key is invalid or credits are depleted:
* API queries return `401 Unauthorized` or `402 Payment Required`.
* BugBounty-Agent logs an informational warning and falls back to other configured search engines (Censys, FOFA) or passive DNS sources.
