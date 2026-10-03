# WPScan Vulnerability Database Integration Setup

## Purpose
WPScan is a specialized security scanner designed specifically for WordPress content management systems.

## Why BugBounty-Agent Uses It
When `bb-recon` or `bb-web` discovers a WordPress installation (`wp-login.php`, `wp-content`), WPScan can enumerate installed plugins, active themes, and known CVEs.

## Account Required
**OPTIONAL** (Scanning without an API token detects core version and plugin names; an API token enables CVE matching against the WPScan vulnerability database).

## API Key Required
**OPTIONAL** (Required for vulnerability database matching; optional for basic version enumeration).

## Required Environment Variables
```bash
WPSCAN_API_TOKEN="your_wpscan_api_token"
```

## Where to Obtain Credentials
1. Register at [https://wpscan.com/register](https://wpscan.com/register).
2. Go to **Profile** -> **API Token**.

## Official Documentation
* [WPScan Official Documentation](https://github.com/wpscanteam/wpscan)
* [WPScan CLI User Guide](https://github.com/wpscanteam/wpscan/wiki/WPScan-User-Documentation)

## Setup
Install WPScan on Kali:
```bash
bb-install wpscan
```
Or via apt: `sudo apt install wpscan`.

## Configuration
Add your API token to `~/.config/bugbounty-agent/secrets.env`:
```text
WPSCAN_API_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## Verification
Verify the token with a quick version check:
```bash
wpscan --api-token "${WPSCAN_API_TOKEN}" --version
```

## Rate Limits / Quotas
* Free API Tier: 25 API requests per day.
* Paid Tiers: Higher daily allowances for active security consultancies.

## Privacy / Terms Considerations
Only execute WPScan against confirmed in-scope targets after WordPress signatures are positively verified.

## Failure Behavior
If `WPSCAN_API_TOKEN` is not configured:
* WPScan runs in fallback mode without the vulnerability database.
* It reports discovered plugins and versions but advises configuring `WPSCAN_API_TOKEN` for CVE vulnerability matching.
