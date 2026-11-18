# SecurityTrails API Integration Setup

## Purpose
SecurityTrails provides extensive historical and real-time DNS datasets, passive DNS records, WHOIS history, and comprehensive subdomain listings.

## Integration status
SecurityTrails is listed as a possible Subfinder provider, but BugBounty-Agent does not invoke Subfinder from its normal asset or reconnaissance CLI and does not pass this credential to Subfinder. `bb-doctor` can only report whether a key is present.

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
BugBounty-Agent reads `secrets.env` for key-presence diagnostics; it does not export the value to another process. For a separate manual Subfinder run, configure the key using Subfinder's current native provider configuration instructions.

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
Check current account documentation for quotas and API response behavior; provider terms and plans can change.

## Privacy / Terms Considerations
Queries disclose the root domain being evaluated to SecurityTrails.

## Failure Behavior
If quota is exceeded or the key is absent, the manually invoked client/provider determines its behavior. BugBounty-Agent does not run this provider or make an automatic fallback.
