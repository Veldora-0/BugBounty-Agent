# Notify Webhook Integration Setup

## Purpose
Notify is a command-line tool that streams script and tool outputs to communication platforms including Discord, Slack, Telegram, Pushover, and custom webhooks.

## Integration status
Notify is an optional standalone utility. BugBounty-Agent does not send milestone notifications or invoke Notify automatically. If a researcher chooses to use it manually, send only non-sensitive status text.

## Account Required
**YES** (Requires an account on the destination platform: Discord, Slack, Telegram, etc.).

## API Key Required
**YES** (Webhook URL or Bot token required depending on platform).

## Required Environment Variables
Configure destination webhook URLs in `~/.config/bugbounty-agent/secrets.env`:

```bash
# Discord
DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/xxxx/yyyy"

# Slack
SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T00/B00/XXXX"

# Telegram
TELEGRAM_API_KEY="bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
TELEGRAM_CHAT_ID="12345678"
```

## Where to Obtain Credentials
* **Discord**: Server Settings -> Integrations -> Webhooks.
* **Slack**: Workspace -> Apps -> Incoming Webhooks.
* **Telegram**: Message `@BotFather` to create a bot token.

## Official Documentation
* [Notify GitHub Repository](https://github.com/projectdiscovery/notify)
* [Notify Documentation](https://docs.projectdiscovery.io/tools/notify)

## Setup
Install Notify:
```bash
bb-install notify
```

## Configuration
Add webhook URLs to `~/.config/bugbounty-agent/secrets.env`.
Notify uses its own native provider configuration. BugBounty-Agent's `secrets.env` reader only checks whether configured variable names have values; it does not translate those values into Notify's provider file or invoke the binary.

## Verification
Send a harmless test notification:
```bash
echo "BugBounty-Agent Notification Test" | notify -silent
```

## Rate Limits / Quotas
* Discord: 5 requests per second per webhook.
* Slack: 1 request per second per webhook.

## Privacy / Terms Considerations
**CRITICAL SECURITY INVARIANT**: BugBounty-Agent notifications **NEVER** contain sensitive credentials, raw session cookies, customer personal data (PII), or exploit payloads. Only milestone status alerts are sent.

## Failure Behavior
The behavior for missing or rejected webhooks is defined by the standalone Notify client. BugBounty-Agent has no automatic notification operation to skip.
