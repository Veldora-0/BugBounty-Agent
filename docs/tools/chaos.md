# Chaos Dataset Provider Setup

## Purpose
Chaos is a ProjectDiscovery service that continuously indexes public DNS data, certificates, and subdomains across the internet, providing near-instant reconnaissance retrieval without active scanning.

## Integration status
The Chaos client is in the optional tool catalog. The regular `bb-assets` and `bb-recon` workflows do not invoke it. Installing the binary or adding a PDCP key does not make Chaos part of those engines.

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
`bb-doctor` can report whether a PDCP key is present. It does not test the key with ProjectDiscovery, export it to Chaos, run Chaos, or select an automatic fallback. Run the standalone client manually only for an authorized program and observe its current provider terms.
