# Censys API Integration Setup

## Purpose
Censys scans the IPv4 and IPv6 address spaces and monitors certificate logs, providing comprehensive internet-wide asset intelligence and attack surface maps.

## Integration status
Censys credentials are listed for the optional Uncover/Subfinder ecosystem, but BugBounty-Agent does not run those clients from `bb-recon` and does not pass credentials to them. The provider manager can report whether expected key fields are present.

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
Values in BugBounty-Agent's `secrets.env` are used for presence diagnostics only. They are not loaded into a child process. Configure a separate manually invoked client using its native documented mechanism.

## Verification
Test authentication using curl:
```bash
curl -u "${CENSYS_API_TOKEN}:${CENSYS_ORGANIZATION_ID}" -s "https://search.censys.io/api/v1/account"
```
Returns your account email and remaining query quota.

## Rate Limits / Quotas
Limits depend on the current Censys plan and API version. Check the vendor dashboard and current documentation.

## Privacy / Terms Considerations
Queries to Censys are logged by Censys. Adhere to Censys Terms of Service regarding commercial vs security research usage.

## Failure Behavior
If credentials are missing or expired, the separate client/provider may reject its request. BugBounty-Agent does not make a Censys request or automatically switch data sources.
