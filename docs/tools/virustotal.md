# VirusTotal API Integration Setup

## Purpose
VirusTotal inspects URLs, domains, IPs, and file samples, aggregating intelligence from 70+ antivirus engines and scanning tools alongside passive DNS datasets.

## Integration status
VirusTotal is listed as a possible Subfinder provider. `bb-assets --subfinder` can invoke the passive Subfinder CLI when explicitly selected, but BugBounty-Agent does not map secrets from `secrets.env` into Subfinder's native provider configuration. `bb-doctor` can report only whether a key is present.

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
The provider manager reads `secrets.env` for key-presence diagnostics; it does not inject the value into another process. Configure Subfinder through its current native provider setup before a separate manual run.

## Verification
Test your API key using curl:
```bash
curl --request GET \
     --url "https://www.virustotal.com/api/v3/domains/example.com" \
     --header "x-apikey: ${VT_API_KEY}"
```

## Rate Limits / Quotas
Check the current VirusTotal documentation and plan limits before using the API; public and commercial entitlements can differ.

## Privacy / Terms Considerations
All submissions and queries to VirusTotal may be shared with its security research partners.

## Failure Behavior
If the quota is reached, the manually used provider may reject or throttle requests. BugBounty-Agent does not issue VirusTotal queries or select a fallback.
