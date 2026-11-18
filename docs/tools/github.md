# GitHub API Integration Setup

## Purpose
The GitHub REST API enables programmatic searching of public code repositories, commits, and pull requests.

## Integration status
The tool catalog and provider diagnostics recognize `GITHUB_TOKEN`, but BugBounty-Agent does not run GitHub code search or pass this token to Subfinder. A researcher may use a separate, manually configured public-code search tool when permitted by program rules.

## Account Required
**YES** (Requires a GitHub personal account).

## API Key Required
**OPTIONAL** (Unauthenticated queries are heavily rate-limited to 60 req/hour; an authenticated token increases the limit to 5,000 req/hour).

## Required Environment Variables
```bash
GITHUB_TOKEN="your_personal_access_token"
```

## Where to Obtain Credentials
1. Log in to GitHub and go to **Settings** -> **Developer settings** -> **Personal access tokens** -> **Fine-grained tokens**.
2. Select **Generate new token**.
3. Grant **Public Repositories (read-only)** permissions only. **Do NOT** grant write or administrative permissions.

## Official Documentation
* [GitHub REST API Documentation](https://docs.github.com/en/rest)
* [Managing your personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)

## Setup
Add your token to `~/.config/bugbounty-agent/secrets.env`:
```text
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## Configuration
The local `secrets.env` file is read by BugBounty-Agent for key-presence diagnostics only. It does not configure GitHub CLI, Subfinder, or another external process. Set up any manually used tool using its documented credential mechanism.

## Verification
Test your token with curl:
```bash
curl -H "Authorization: Bearer ${GITHUB_TOKEN}" https://api.github.com/rate_limit
```
Review GitHub's returned rate-limit data; current limits depend on authentication and endpoint policy.

## Rate Limits / Quotas
GitHub's rate limits vary by API and account context. Check the current official documentation before automating queries.

## Privacy / Terms Considerations
Use only fine-grained tokens with minimal read-only permissions. Never scan or clone private repositories without explicit authorization.

## Failure Behavior
If credentials are absent, a separate manually invoked tool may be limited or skip its GitHub provider. BugBounty-Agent does not initiate GitHub searches.
