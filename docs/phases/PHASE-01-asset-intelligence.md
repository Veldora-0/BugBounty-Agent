# Phase 1 — Asset Intelligence

**Status:** Partially implemented. The graph and safety checks exist, but the normal CLI is not connected to a subdomain-discovery provider; several advertised enrichment paths are hook-only.
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

The code also contains extension points for subdomain sources, TLS certificate names, and ASN data. The repository CLI does not currently configure those extension points. Without an injected discovery hook, child subdomain discovery returns no candidates; without an ASN provider, attribution is **UNKNOWN**; and the asset engine’s TLS SAN extraction only works through its hook. As a result, **--depth 0** means “do not impose a depth ceiling on discoveries that are supplied,” not “automatically enumerate every subdomain.” In normal use today, the CLI builds roots and explicit seeds, with only the enrichment that is actually connected and scope-approved.

## How to use it

~~~bash
# Start from the scope configured for an initialized program.
bb-assets --program <program-name> --tree

# Add hostnames you already collected from an allowed source.
bb-assets --program <program-name> --seeds "api.example.org,login.example.org" --tree

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

The missing provider wiring is a material implementation gap, tracked in the **project audit issues**. The present tests exercise the graph and provider hooks with local fixtures; they do not demonstrate production subdomain enumeration, useful ASN attribution, or live certificate-name discovery through **bb-assets**. The **future improvements** list provider integration work. Check the phase status in the **roadmap** before treating the asset graph as complete.

## Source references

Tests: **tests/test_asset_engine.py**, **tests/test_asset_graph.py**, **tests/test_asset_model.py**, and relevant safeguards in **tests/test_stage_c_remediations.py**. See also the **scope guide**, **handbook**, and **asset-intelligence skill**.