# Chaos Dataset Provider Setup

## Purpose
Chaos is a ProjectDiscovery service that continuously indexes public DNS data, certificates, and subdomains across the internet, providing near-instant reconnaissance retrieval without active scanning.

## Why BugBounty-Agent Uses It
BugBounty-Agent queries Chaos during passive reconnaissance to immediately retrieve thousands of indexed subdomains for in-scope bug bounty programs before running slower permutation or DNS brute-forcing scripts.

## Account Required
**YES** (Requires a free or paid ProjectDiscovery Cloud Platform account).

## API Key Required
**YES**

## Required Environment Variables
```bash
PDCP_API_KEY="your_projectdiscovery_cloud_api_key"
```

## Where to Obtain Credentials
1. Register at [https://cloud.projectdiscovery.io](https://cloud.projectdiscovery.io).
2. Navigate to **Settings** -> **API Keys**.
3. Generate a new API token.

## Official Documentation
* [Chaos ProjectDiscovery Site](https://chaos.projectdiscovery.io)
* [Chaos Client GitHub](https://github.com/projectdiscovery/chaos-client)

## Setup
Install the official chaos client:
```bash
bb-install chaos
```

## Configuration
Store your API key in `~/.config/bugbounty-agent/secrets.env`:
```text
PDCP_API_KEY=your_actual_key_here
```

## Verification
Run a test query against an authorized public domain:
```bash
chaos -d hackerone.com -silent -count
```
A successful query outputs an integer count of indexed subdomains.

## Rate Limits / Quotas
* Free tier: Generous daily quota for public bug bounty scopes.
* Paid tier: Full access to the complete internet-wide dataset.

## Privacy / Terms Considerations
Chaos only tracks public domain names and public bug bounty scopes registered on platforms like HackerOne and Bugcrowd.

## Failure Behavior
If `PDCP_API_KEY` is missing or invalid:
* `bb-doctor` reports `[NOT SET] ProjectDiscovery Cloud Platform (PDCP)`.
* BugBounty-Agent skips Chaos and automatically falls back to `subfinder` and `assetfinder` using local passive collectors.
