# WPScan Vulnerability Database Integration Setup

## Purpose
WPScan is a specialized security scanner designed specifically for WordPress content management systems.

## Integration status
WPScan is an optional standalone scanner in the tool catalog. `bb-recon` and `bb-web` do not launch it, and BugBounty-Agent does not pass `WPSCAN_API_TOKEN` to it. A researcher may invoke WPScan manually after verifying the WordPress host is explicitly in scope and the program permits that scan.

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
BugBounty-Agent's `secrets.env` reader can report whether the token is present, but does not inject it into WPScan. For a manual WPScan run, provide the token through WPScan's documented option or native configuration:
```text
WPSCAN_API_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## Verification
Verify the token with a quick version check:
```bash
wpscan --api-token "${WPSCAN_API_TOKEN}" --version
```

## Rate Limits / Quotas
Check the current WPScan account documentation for API limits and terms.

## Privacy / Terms Considerations
Only execute WPScan against confirmed in-scope targets after WordPress signatures are positively verified.

## Failure Behavior
If the token is missing, consult WPScan's current behavior for vulnerability data. BugBounty-Agent does not run WPScan or apply an automatic fallback.
