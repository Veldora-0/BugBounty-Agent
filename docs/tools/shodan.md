# Shodan API Integration Setup

## Purpose
Shodan is a search engine for Internet-connected devices, servers, webcams, industrial control systems, and open network ports.

## Integration status
Shodan is a data provider for separate tools such as Uncover or Subfinder when those tools are manually configured. BugBounty-Agent records the key name for `bb-doctor` diagnostics, but neither `bb-recon` nor its other engines currently invoke those tools or pass this key to them.

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
Saving a key in BugBounty-Agent's `secrets.env` only lets `bb-doctor` report whether it is present. It is not exported to a separate tool. Configure the tool's native provider file or its process environment yourself before a manual run.

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
Plan limits and query costs can change; check Shodan's current account dashboard and terms before use.

## Privacy / Terms Considerations
Do not share or commit Shodan keys. Respect query rate limits (maximum 1 request per second for standard developer plans).

## Failure Behavior
If the key is invalid or a quota is exhausted, the separate tool/provider reports its own error. BugBounty-Agent does not perform an automatic provider fallback.
