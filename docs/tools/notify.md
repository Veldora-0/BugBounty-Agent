# Notify Webhook Integration Setup

## Purpose
Notify is a command-line tool that streams script and tool outputs to communication platforms including Discord, Slack, Telegram, Pushover, and custom webhooks.

## Why BugBounty-Agent Uses It
BugBounty-Agent can optionally send milestone notifications (e.g. reconnaissance complete, high-priority finding validated) to a private researcher channel.

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
Notify uses `~/.config/notify/provider-config.yaml` natively; BugBounty-Agent automatically bridges environment variables to this file when invoked.

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
If webhooks are missing or return errors, notification operations are silently skipped without impacting ongoing security research.
