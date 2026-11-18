# ProjectDiscovery Cloud Platform (PDCP) Setup

## Purpose
The ProjectDiscovery Cloud Platform (PDCP) provides centralized cloud scanning, authenticated Chaos asset datasets, Nuclei template syncing, and cloud-hosted Interactsh capabilities.

## Integration status
The tool catalog records `PDCP_API_KEY` as a provider credential for separately invoked ProjectDiscovery tools:
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
BugBounty-Agent's provider manager can report whether `PDCP_API_KEY` is present. It does not inject the value into Subfinder, Chaos, Nuclei, or URLFinder, and `bb-assets`/`bb-recon` do not invoke those clients. Configure each standalone tool using its current native instructions before a manual, authorized use.

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
Features, access, and quotas depend on current ProjectDiscovery plans and terms. Check the current vendor documentation.

## Privacy / Terms Considerations
All interactions with PDCP are governed by the ProjectDiscovery Privacy Policy and Terms of Service.

## Failure Behavior
If a key is missing or invalid, the standalone client determines its behavior. BugBounty-Agent does not start those clients, attempt authentication, or select an automatic fallback.
