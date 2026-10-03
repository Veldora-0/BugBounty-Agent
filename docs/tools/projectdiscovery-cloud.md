# ProjectDiscovery Cloud Platform (PDCP) Setup

## Purpose
The ProjectDiscovery Cloud Platform (PDCP) provides centralized cloud scanning, authenticated Chaos asset datasets, Nuclei template syncing, and cloud-hosted Interactsh capabilities.

## Why BugBounty-Agent Uses It
A single `PDCP_API_KEY` provides enhanced capability across multiple tools:
* **Chaos**: Unlocks access to the complete internet-wide subdomain database.
* **Subfinder**: Prioritized high-speed ProjectDiscovery passive reconnaissance sources.
* **Nuclei**: Syncs official and community template libraries seamlessly.
* **Interactsh**: Provides authenticated, dedicated OOB interaction servers.
* **URLFinder**: Grants enhanced passive endpoint discovery.

## Account Required
**YES** (Free or commercial PDCP tier).

## API Key Required
**YES**

## Required Environment Variables
```bash
PDCP_API_KEY="your_pdcp_api_key_here"
```

## Where to Obtain Credentials
1. Register at [https://cloud.projectdiscovery.io/](https://cloud.projectdiscovery.io/).
2. Navigate to **Settings** -> **API Keys**.
3. Generate a new API key.

## Official Documentation
* [ProjectDiscovery Cloud Documentation](https://docs.projectdiscovery.io/cloud/overview)

## Setup
Save your key in `~/.config/bugbounty-agent/secrets.env`:
```text
PDCP_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```
Ensure permissions are restricted:
```bash
chmod 600 ~/.config/bugbounty-agent/secrets.env
```

## Configuration
BugBounty-Agent injects `PDCP_API_KEY` into Subfinder, Chaos, Nuclei, and URLFinder when executed.

## Verification
Verify your key with the Chaos client:
```bash
chaos -d hackerone.com -silent -count
```
Or with Nuclei:
```bash
nuclei -auth
```

## Rate Limits / Quotas
* Free Community Tier: Access to public bug bounty programs and standard template libraries.
* Enterprise Tier: Continuous asset monitoring and private workspace scanning.

## Privacy / Terms Considerations
All interactions with PDCP are governed by the ProjectDiscovery Privacy Policy and Terms of Service.

## Failure Behavior
If `PDCP_API_KEY` is not configured:
* `subfinder`, `nuclei`, and `interactsh` fall back to their default unauthenticated operation.
* `chaos` reports that the provider requires an API key and skips queries.
* The researcher is notified of degraded optional provider status.
