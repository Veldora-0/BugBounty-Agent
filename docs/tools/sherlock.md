# Sherlock

## What it does

Sherlock checks a researcher-supplied username against public profile URLs on many social networks. It reports likely matches and can save results to text, JSON, CSV, or other formats. A match is a lead, not proof that the profile belongs to a particular person.

## How it can help an authorized bug-bounty workflow

Use it only when a program explicitly supplies a test username or a public organization-owned account that is relevant to the authorized assessment. It may help confirm whether an account alias appears on an in-scope service or help a researcher understand public account reuse. It does not find a software vulnerability and does not establish ownership or authorization.

## Safe use

- Limit searches to a program-provided or otherwise authorized username.
- Do not search for employees, customers, or unrelated individuals.
- Review program rules and each site's terms and rate limits before making requests.
- Do not use proxy options to hide prohibited activity.
- Treat results as possibly stale or false; manually verify using public profile metadata only.
- Keep output local and remove unrelated personal information before it enters evidence or reports.

## Installation and integration status

Upstream documents a Python package installation through pipx. Check upstream instructions before installing, and use an isolated environment on Kali. The registry marks Sherlock as optional and manual-only; BugBounty-Agent does not install it automatically, invoke it from a research engine, or import its results into target state.

The upstream project uses the MIT License. [Sherlock repository](https://github.com/sherlock-project/sherlock)