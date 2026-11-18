# Mr.Holmes

## What it does

Mr.Holmes is a third-party OSINT application that gathers public information related to domains, usernames, and phone numbers. Its upstream README describes search-engine queries, public-source lookups, optional proxy use, and a WHOIS data provider. That is broad information gathering, not vulnerability validation.

## How it can help an authorized bug-bounty workflow

It may help a researcher understand public information about a program-owned domain or a program-provided test account. Use findings only as background for a specific, in-scope hypothesis. A phone number, username match, or indexed page is not evidence that a target application has a security flaw.

## Safe use

- Do not investigate unrelated individuals, employees, or customers.
- Do not collect or retain sensitive personal data.
- Never use proxies to conceal prohibited activity or bypass a site's access controls.
- Do not follow search results into an excluded system or retrieve exposed sensitive files.
- Review the current source, dependencies, and installer before running it. Upstream installation instructions include privileged package installation; do not run an unreviewed installer with sudo.
- Keep the tool isolated from the BugBounty-Agent repository and do not import its raw results into reports.
- Treat all matches as unverified leads and recheck source dates and scope.

## Installation and integration status

The project is licensed under GPL-3.0 and describes Linux, macOS, and Windows use. Its Python dependencies and optional WHOIS provider may change. The registry marks it optional and manual-only. BugBounty-Agent does not install it automatically, invoke it from a research engine, or load its output into local program state. Review the current upstream repository and license before use.

[Mr.Holmes repository](https://github.com/Lucksi/Mr.Holmes) · [Upstream README](https://github.com/Lucksi/Mr.Holmes#readme)