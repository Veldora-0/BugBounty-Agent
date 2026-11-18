# Maltego

## What it does

Maltego Graph is a graphical link-analysis tool. It displays entities such as domains, IP addresses, organizations, email addresses, and public profiles as nodes, then uses relationships from selected data sources or transforms to help a researcher explore connections. A relationship in the graph is a lead to review, not proof that an entity is in scope or that a vulnerability exists.

Maltego is not a command-line scanner and is not part of the BugBounty-Agent runtime. It is a separate analyst workbench for organizing public or researcher-provided information.

## How it can help an authorized bug-bounty workflow

A researcher can use it to organize program-owned domains, public infrastructure references, and other permitted public context. Keep the graph focused on assets relevant to the written program scope. Do not add private customer data, secrets, or unrelated personal information. Before testing any connected host, confirm the asset against the current scope file and program rules.

## Safe use and limits

- A transform may send data to Maltego or third-party provider services. Review its destination, terms, and privacy policy before running it.
- Check whether a data provider or transform will contact the target, query search engines, or access third-party systems.
- Use only transformations and data sources allowed by the program and your privacy obligations.
- Maltego connections do not establish target ownership or authorization. Exclusions still apply to every follow-up.
- Review current pricing, licensing, credit limits, and terms before use. Plans and entitlements can change.

## Installation and integration status

Maltego Graph Desktop supports Linux, macOS, and Windows. The official install instructions list Debian packages, RPM packages, and a ZIP archive; the desktop client requires a supported 64-bit Java runtime. Follow the current vendor instructions rather than an old package command.

The tool catalog lists Maltego as optional and manual-only. It does not provide an installer, invoke the desktop app, or synchronize graph data with BugBounty-Agent. [Official downloads](https://www.maltego.com/downloads/) · [Linux installation help](https://docs.maltego.com/en/support/solutions/articles/15000008704-installing-maltego) · [Desktop requirements](https://docs.maltego.com/en/support/solutions/articles/15000008703-client-requirements) · [Plans and limits](https://www.maltego.com/pricing/)