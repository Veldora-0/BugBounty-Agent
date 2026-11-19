# urlscan.io API Integration Setup

## Purpose
urlscan.io is a scanner for websites that analyzes web pages, resources requested, DOM contents, IP contacts, and TLS certificates.

## Integration status
urlscan.io is listed as a possible Subfinder provider. `bb-assets --subfinder` can invoke the passive Subfinder CLI when explicitly selected, but BugBounty-Agent does not map secrets from `secrets.env` into Subfinder's native provider configuration. `bb-doctor` can report whether the key is present.

## Account Required
**YES** (Free account unlocks automated API search).

## API Key Required
**YES**

## Required Environment Variables
```bash
URLSCAN_API_KEY="your_urlscan_api_key"
```

## Where to Obtain Credentials
1. Register at [https://urlscan.io/user/signup](https://urlscan.io/user/signup).
2. Go to **Settings** -> **API Keys**.
3. Generate a new key.

## Official Documentation
* [urlscan.io API Documentation](https://urlscan.io/docs/api/)

## Setup
Add the key to `~/.config/bugbounty-agent/secrets.env`:
```text
URLSCAN_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

## Configuration
The provider manager reads `secrets.env` for key-presence diagnostics only. Configure a separate manually invoked tool with its native provider instructions; no urlscan query is made by BugBounty-Agent.

## Verification
Test authentication via curl:
```bash
curl -s -H "API-Key: ${URLSCAN_API_KEY}" "https://urlscan.io/api/v1/search/?q=domain:example.com&size=1"
```

## Rate Limits / Quotas
Check current urlscan.io plan limits and API terms before querying.

## Privacy / Terms Considerations
Note that urlscan.io scans submitted as "Public" are visible to the world. BugBounty-Agent only queries the Search API for historical scans and does not initiate public scans of private targets.

## Failure Behavior
If credentials are absent or invalid, the standalone client/provider determines its behavior. BugBounty-Agent does not issue the query or perform provider fallback.
