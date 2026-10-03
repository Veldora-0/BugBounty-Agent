# Censys API Integration Setup

## Purpose
Censys scans the IPv4 and IPv6 address spaces and monitors certificate logs, providing comprehensive internet-wide asset intelligence and attack surface maps.

## Why BugBounty-Agent Uses It
BugBounty-Agent uses Censys via `uncover` and `subfinder` to discover virtual hosts sharing certificates, exposed non-standard ports, and cloud service deployments.

## Account Required
**YES**

## API Key Required
**YES** (Requires both API ID/Token and Organization Secret).

## Required Environment Variables
```bash
CENSYS_API_TOKEN="your_censys_api_id"
CENSYS_ORGANIZATION_ID="your_censys_secret"
```

## Where to Obtain Credentials
1. Create an account at [https://search.censys.io/register](https://search.censys.io/register).
2. Go to **Account Settings** -> **API**.
3. Generate an API ID and Secret.

## Official Documentation
* [Censys Search 2.0 API Docs](https://search.censys.io/api)
* [Censys Python / CLI](https://censys-python.readthedocs.io/)

## Setup
Store credentials in `~/.config/bugbounty-agent/secrets.env`:
```text
CENSYS_API_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CENSYS_ORGANIZATION_ID=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## Configuration
BugBounty-Agent loads these variables automatically into the environment when tools like `uncover` or `subfinder` execute.

## Verification
Test authentication using curl:
```bash
curl -u "${CENSYS_API_TOKEN}:${CENSYS_ORGANIZATION_ID}" -s "https://search.censys.io/api/v1/account"
```
Returns your account email and remaining query quota.

## Rate Limits / Quotas
* Community/Free Tier: 250 search queries per month.
* Academic/Paid Tiers: Higher volume limits.

## Privacy / Terms Considerations
Queries to Censys are logged by Censys. Adhere to Censys Terms of Service regarding commercial vs security research usage.

## Failure Behavior
If credentials are not set or expired:
* Censys returns `401 Unauthorized` or `403 Forbidden`.
* BugBounty-Agent flags Censys as unavailable and continues with other search engines.
