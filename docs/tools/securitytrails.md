# SecurityTrails API Integration Setup

## Purpose
SecurityTrails provides extensive historical and real-time DNS datasets, passive DNS records, WHOIS history, and comprehensive subdomain listings.

## Why BugBounty-Agent Uses It
BugBounty-Agent queries SecurityTrails via `subfinder` to discover subdomains that may not appear in recent certificate logs or active zone transfers, including historical development and staging hosts.

## Account Required
**YES**

## API Key Required
**YES**

## Required Environment Variables
```bash
SECURITYTRAILS_API_KEY="your_securitytrails_api_key"
```

## Where to Obtain Credentials
1. Register an account at [https://securitytrails.com/](https://securitytrails.com/).
2. Navigate to your Account Dashboard and copy the API Key.

## Official Documentation
* [SecurityTrails API Documentation](https://docs.securitytrails.com/)

## Setup
Add the key to `~/.config/bugbounty-agent/secrets.env`:
```text
SECURITYTRAILS_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## Configuration
BugBounty-Agent detects `SECURITYTRAILS_API_KEY` and passes it to `subfinder` via environment mapping.

## Verification
Test using curl:
```bash
curl --request GET \
     --url "https://api.securitytrails.com/v1/ping" \
     --header "apikey: ${SECURITYTRAILS_API_KEY}"
```
Expected response:
```json
{"success": true}
```

## Rate Limits / Quotas
* Free Tier: 50 queries per month.
* Over-quota requests return HTTP `429 Too Many Requests`.

## Privacy / Terms Considerations
Queries disclose the root domain being evaluated to SecurityTrails.

## Failure Behavior
If quota is exceeded or the key is absent:
* Subfinder logs an informational error and queries remaining passive sources.
* Reconnaissance continues without interruption.
