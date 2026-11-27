# Tooling Recommendations for Authorized Research

The project already has a large CLI registry in [`config/tools.yaml`](../config/tools.yaml). These recommendations focus on gaps where a researcher benefits from a human-operated workbench or a distinct analysis mode; they are optional, not required dependencies. Install and use tools only under the target program's current rules and scope.

## Suggested additions to a Kali workstation

### Intercepting proxy and manual request workbench

Choose **one** of these for interactive web/API testing:

- **Burp Suite** — strong general-purpose intercepting proxy and request editor. Use Proxy to inspect browser traffic and Repeater to make deliberate, one-at-a-time changes. Automated Scanner and Intruder tasks can generate significant traffic; configure exact target scope, conservative resource pools and a narrow scan policy before any approved use. [PortSwigger Proxy docs](https://portswigger.net/burp/documentation/desktop/settings/tools/proxy) · [Repeater docs](https://portswigger.net/burp/documentation/desktop/tools/repeater)
- **Caido** — a modern alternative with traffic interception and Replay sessions for controlled request edits. It can complement the framework's evidence workflow; manually redact exported traffic before placing it in local evidence. [Caido Replay docs](https://docs.caido.io/app/quickstart/replay) · [Sending requests to Replay](https://docs.caido.io/app/guides/replay_requests)

Keep listeners bound to loopback unless there is a deliberate, secured need for remote access. Do not proxy unrelated browsing or other users' traffic into a bounty project.

### Passive web assessment

- **OWASP ZAP** — useful as a passive HTTP/WebSocket analyzer and for importing API descriptions. Its Automation Framework supports declarative YAML plans. Start with passive-only plans and explicit contexts. ZAP documents that active scanning sends attack requests and should only be used on applications you own or have permission to test; active scan is not a default BugBounty-Agent workflow. [Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/) · [Active scan safety notice](https://www.zaproxy.org/docs/desktop/start/features/ascan/) · [Passive scan and scope controls](https://www.zaproxy.org/docs/api/)

## Already represented in the project registry

Before adding more binaries, review existing entries: `subfinder`, `amass`, `dnsx`, `httpx`, `katana`, `gau`, `waybackurls`, `ffuf`, `arjun`, `nuclei`, `dalfox`, `sqlmap`, `interactsh-client`, `testssl.sh`, and others are already declared. Do not run active scanners merely because they are installed. In particular, templates, wordlists, concurrency, rate, and request methods need per-program review and scope gating.

### Optional OSINT and graph workbenches

These requested tools are now in `config/tools.yaml` as **optional, manual-only entries**. They are not dependencies and are not invoked by the framework engines.

- **Sherlock** checks researcher-supplied usernames against public social-network profile URLs. It can help with an organization-owned or program-provided test alias, but it is not a vulnerability scanner. Restrict requests to authorized identities, respect site terms, expect false positives, and do not search unrelated people. See [Sherlock setup and safe use](tools/sherlock.md).
- **Mr.Holmes** is a broad public-source OSINT application covering domains, usernames, and phone numbers. Its queries can expose sensitive personal or indexed material. Use it only when that collection is necessary and permitted, review its source and installer first, and do not run an unreviewed installer as root. See [Mr.Holmes setup and safe use](tools/mr-holmes.md).
- **Maltego Graph** is a separate graphical link-analysis workbench, not an automated command-line scanner. Review each transform’s network destinations, terms, licensing, and data handling. Keep its graphs limited to relevant, permitted entities. See [Maltego setup and safe use](tools/maltego.md).

The **Google Hacking Database (GHDB)** is an Exploit-DB reference of search queries, not an executable tool or a list of target vulnerabilities. The single `Bug-Bounty` agent may consult it as public methodology context when `/Arise` or `knowledge-research` is relevant, then formulate a narrow hypothesis for an authorized asset. It must not run broad dorks, fetch sensitive search results, or treat an indexed result as target evidence. [Official GHDB index](https://www.exploit-db.com/google-hacking-database/).

## Integration gate before adding any tool to `config/tools.yaml`

1. Confirm upstream, license, supported Kali/Linux install method, release integrity and maintenance health.
2. Determine whether it sends traffic, follows redirects, resolves DNS itself, honors proxies, or expands targets. If the framework cannot enforce scope and budgets, keep it as a manual external tool rather than an automated engine dependency.
3. Prefer passive or read-only use; require explicit human approval and bounded rate/host/request limits for active features.
4. Redact credentials and target-sensitive data from output; keep raw captures local under the Git-ignored program workspace and never force-add them to Git.
5. Test the exact command against a local fixture and a deliberately out-of-scope fixture, proving the latter generates zero requests.

Tool choices change over time. Recheck official documentation and program rules before adoption. These are recommendations for human-led authorized work, not claims that the tools have been integrated or tested by this repository audit.
