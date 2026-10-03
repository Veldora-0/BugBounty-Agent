# VirusTotal API Integration Setup

## Purpose
VirusTotal inspects URLs, domains, IPs, and file samples, aggregating intelligence from 70+ antivirus engines and scanning tools alongside passive DNS datasets.

## Why BugBounty-Agent Uses It
BugBounty-Agent queries VirusTotal via `subfinder` to gather historical passive DNS resolutions, sibling subdomains, and identified web certificates.

## Account Required
**YES**

## API Key Required
**YES**

## Required Environment Variables
```bash
VT_API_KEY="your_virustotal_api_key"
```

## Where to Obtain Credentials
1. Register at [https://www.virustotal.com/](https://www.virustotal.com/).
2. Click your profile avatar and select **API Key**.

## Official Documentation
* [VirusTotal v3 API Docs](https://developers.virustotal.com/reference/overview)

## Setup
Add the key to `~/.config/bugbounty-agent/secrets.env`:
```text
VT_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## Configuration
BugBounty-Agent injects `VT_API_KEY` into subfinder's execution environment.

## Verification
Test your API key using curl:
```bash
curl --request GET \
     --url "https://www.virustotal.com/api/v3/domains/example.com" \
     --header "x-apikey: ${VT_API_KEY}"
```

## Rate Limits / Quotas
* Public API: 4 requests per minute, 500 requests per day.
* Commercial/Premium API: Custom high-frequency thresholds.

## Privacy / Terms Considerations
All submissions and queries to VirusTotal may be shared with its security research partners.

## Failure Behavior
If the daily quota (500 req/day) is reached:
* VirusTotal returns HTTP `429 QuotaExceededError`.
* BugBounty-Agent skips VirusTotal queries and relies on other passive DNS providers.
