# GitHub API Integration Setup

## Purpose
The GitHub REST API enables programmatic searching of public code repositories, commits, and pull requests.

## Why BugBounty-Agent Uses It
BugBounty-Agent uses GitHub API access via `subfinder` and source auditing tools to discover organization subdomains referenced in public documentation, developer repositories, or configuration files.

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
BugBounty-Agent passes `GITHUB_TOKEN` to Subfinder and related repository intelligence tools.

## Verification
Test your token with curl:
```bash
curl -H "Authorization: Bearer ${GITHUB_TOKEN}" https://api.github.com/rate_limit
```
Verify that the `core.limit` shows `5000`.

## Rate Limits / Quotas
* Authenticated users: 5,000 requests per hour.
* Unauthenticated: 60 requests per hour.

## Privacy / Terms Considerations
Use only fine-grained tokens with minimal read-only permissions. Never scan or clone private repositories without explicit authorization.

## Failure Behavior
If `GITHUB_TOKEN` is not set, Subfinder skips GitHub search or operates at the low 60 req/hour rate limit.
