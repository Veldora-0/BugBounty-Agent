# Phase 1 — Asset Intelligence

**Status:** Partially implemented. The graph, scope checks, optional bounded passive Subfinder integration, and bounded in-scope TLS SAN enrichment are implemented. ASN attribution remains unavailable and is reported as `UNKNOWN`.
**Implementation:** **framework/assets/**, **framework/scope/**, **scripts/bb-assets**, and the **asset-intelligence skill**
**State file:** **state/assets.json** in the local program workspace.

## Why this phase exists

A bug bounty program may list a company’s main website while its real applications live on names such as **api.company.example**, **accounts.company.example**, or **staging.company.example**. Asset intelligence is the process of building a trustworthy list of the systems the program has authorized you to examine. It helps a researcher avoid missing an application and, just as importantly, avoid touching a system that belongs to someone else.

An asset record is an observation about a domain, host, IP address, or infrastructure relationship. It is not a vulnerability finding. For example, a discovered hostname can be relevant to a program, but its presence does not prove that it is vulnerable or even currently online. The graph records how an item was found, its relationship to a parent or IP, and its scope status so later phases can make better decisions.

## What you need before running it

Create a local program workspace with **bb-init**, then enter the program’s current in-scope and excluded domains in its **scope/scope.yaml**. Read the program’s rules yourself: a technical scope file cannot grant permission that the program has not granted. The scope engine is an offline policy check; it applies exclusions before inclusions and should be treated as the gate for any network activity.

You can seed the graph with a root domain and known hostnames from the program page or another source you are allowed to use. A root is the program’s starting domain. A seed is a specific hostname already known to the researcher. Keep source and date notes for externally collected seeds so you can revisit stale data.

## How the phase works

The CLI normalizes hostnames, creates root and seed nodes, associates children with their parent, and stores the resulting graph. When a configured scope is available, it checks candidate names before live DNS resolution. It can record DNS addresses and aliases, create relationships such as “resolves to,” and classify a candidate as in scope, out of scope, or ambiguous. A maximum-depth setting and asset-count budget put a ceiling on graph growth. Wildcard detection is an optional live DNS check intended to stop random names that all resolve to the same wildcard address from looking like real assets.

The CLI can optionally invoke Subfinder when `--subfinder` is supplied. Each in-scope root is queried once with Subfinder's passive mode, fixed rate and time limits, and JSON output. Results must be valid descendant hostnames and pass the local scope engine before they enter the graph. Each accepted asset stores the provider source names. Subfinder uses its own local provider configuration; BugBounty-Agent does not transfer values from `secrets.env` into that configuration. The output file is private and removed after parsing.

TLS SAN extraction is wired into active asset discovery. For an in-scope host, the engine resolves candidate addresses, ignores non-public IP addresses, and connects to a numeric public address while sending the hostname as TLS SNI. Each host is limited to four candidate addresses and a five-second deadline; each discovery engine is limited to 100 TLS handshakes. At most 256 DNS names are read from the certificate. Wildcard names are discarded, and each remaining name must independently pass the scope rules before it can be added. The certificate is treated as public metadata; an untrusted certificate is not proof of endpoint identity. `--passive-only` disables this TLS and DNS enrichment. ASN attribution still has no provider and remains **UNKNOWN**.

**--depth 0** means “do not impose a depth ceiling on discoveries that are supplied,” not “automatically enumerate every subdomain.” Without `--subfinder`, the CLI builds roots and explicit seeds with its built-in DNS enrichment. Even with Subfinder, findings depend on the provider's available sources, credentials, response, and terms; this is not a complete asset inventory.

## How to use it

~~~bash
# Start from the scope configured for an initialized program.
bb-assets --program <program-name> --tree

# Add hostnames you already collected from an allowed source.
bb-assets --program <program-name> --seeds "api.example.org,login.example.org" --tree

# Opt in to bounded passive enumeration, while keeping host probes disabled.
bb-assets --program <program-name> --subfinder --passive-only --tree

# Limit the graph size and save machine-readable output for review.
bb-assets --program <program-name> --budget 300 --json

# Disable live wildcard checks and other active enrichment.
bb-assets --program <program-name> --passive-only --tree

# Exercise the pipeline without saving its result to program state.
bb-assets --program <program-name> --dry-run --json
~~~

Replace placeholders with your own initialized program name and only use a domain the program has authorized. A command that prints an asset tree does not establish that the assets are live or eligible for testing.

## Understanding the output

The tree is a convenient view of parent and child relationships. JSON includes the graph records and relationships and is better for scripts or later review. The persistent graph is written under the program’s local state directory, outside the Git repository. Review each item’s scope status and provenance before passing it to active phases. A source may be stale, a DNS answer may be shared by a CDN, and a hostname may be explicitly excluded even when its parent is in scope.

A useful result is a reviewed, deduplicated inventory with known provenance and clear scope labels. A useful next step is Phase 2 reconnaissance for in-scope hosts, followed by web and API mapping. Do not report an asset as a bug by itself.

## Safety and current limitations

The phase must never use an out-of-scope or ambiguous asset for active probing. Keep the budget conservative, do not expand beyond the program’s written scope, and do not infer that a third-party CDN or hosting provider is authorized for direct testing. Passive-only and dry-run modes are useful when you are reviewing configuration or importing existing information.

The remaining ASN attribution gap is tracked in the **project audit issues**. TLS SAN tests use mocked sockets and certificates to exercise SNI, public-IP pinning, in-scope filtering, exclusions, and the discovery-wide handshake budget; they do not contact a target or establish real-world asset coverage. Subfinder tests use a fake executable/provider output and prove filtering, attribution, and state persistence; they do not demonstrate live enumeration coverage. `--passive-only` disables target DNS/TLS activity but does not suppress the provider queries made by `--subfinder`; those queries disclose the root domain to configured third-party data sources. Check current provider terms and the **roadmap** before treating the inventory as complete.

## Source references

Tests: **tests/test_asset_engine.py**, **tests/test_asset_graph.py**, **tests/test_asset_model.py**, and relevant safeguards in **tests/test_stage_c_remediations.py**. See also the **scope guide**, **handbook**, and **asset-intelligence skill**.
