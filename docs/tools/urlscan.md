# urlscan.io API Integration Setup

## Purpose
urlscan.io is a scanner for websites that analyzes web pages, resources requested, DOM contents, IP contacts, and TLS certificates.

## Why BugBounty-Agent Uses It
BugBounty-Agent queries urlscan.io historical scan archives via `subfinder` and passive search tools to locate previously scanned subdomains, API endpoints, and historical DOM structures.

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
BugBounty-Agent loads `URLSCAN_API_KEY` for tools requesting urlscan.io datasets.

## Verification
Test authentication via curl:
```bash
curl -s -H "API-Key: ${URLSCAN_API_KEY}" "https://urlscan.io/api/v1/search/?q=domain:example.com&size=1"
```

## Rate Limits / Quotas
* Community/Free Tier: 5,000 search queries per day, 60 queries per minute.

## Privacy / Terms Considerations
Note that urlscan.io scans submitted as "Public" are visible to the world. BugBounty-Agent only queries the Search API for historical scans and does not initiate public scans of private targets.

## Failure Behavior
If credentials are not configured or invalid, urlscan.io queries are omitted and subfinder proceeds with remaining providers.
