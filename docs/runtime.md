# BugBounty-Agent — Runtime Data Separation & Workspace

A foundational rule of BugBounty-Agent is that **no sensitive target data, scans, findings, credentials, or HTTP logs may ever be committed to the Git repository.**

---

## 1. Physical Directory Separation

By default, the framework creates and operates inside a dedicated local workspace located in the user's home directory:

```text
~/BugBounty-Workspace/
└── programs/
    ├── program-alpha/
    ├── program-beta/
    └── acme-corp/
```

The workspace location can be customized via the `BUGBOUNTY_WORKSPACE` environment variable:

```bash
export BUGBOUNTY_WORKSPACE="/mnt/secure-storage/bb-workspace"
```

---

## 2. Program Subdirectory Structure

Each bug bounty program receives an isolated workspace directory initialized via `bb-init <program-name>`:

```text
~/BugBounty-Workspace/programs/<PROGRAM_NAME>/
├── scope/
│   ├── scope.yaml           # Program scope rules, inclusions, exclusions
│   └── program.yaml         # Program metadata, policy links, preferences
├── targets/
│   ├── domains.txt          # Discovered in-scope domain targets
│   └── urls.txt             # Verified target endpoints
├── recon/
│   ├── subfinder_*.txt      # Passive subdomain outputs
│   └── httpx_live.json      # Live HTTP service probing results
├── web/                     # Web application maps, form definitions
├── js/                      # Extracted JavaScript routes & bundles
├── api/                     # API schemas, Swagger/GraphQL dumps
├── scans/                   # Tool outputs (nuclei, ffuf, etc.)
├── evidence/                # Cryptographically hashed & sanitized HTTP logs
├── findings/                # Candidate and validated finding JSON records
├── reports/                 # Markdown disclosure reports ready for review
├── state/
│   ├── assets.json          # Correlated asset inventory with provenance
│   ├── endpoints.json       # Discovered endpoints and methods
│   ├── technologies.json    # Detected technology stacks per asset
│   ├── hypotheses.json      # Formulated security hypotheses
│   ├── tests.json           # Deduplicated test fingerprints
│   ├── findings.json        # Finding records across lifecycle states
│   └── coverage.json        # Test coverage tracking matrix
└── logs/                    # Audit and execution logs
```

---

## 3. Git Protection & Isolation Guarantees

* `.gitignore` explicitly ignores `runtime/`, `programs/`, `BugBounty-Workspace/`, `evidence/`, `scans/`, `*.burp`, `*.token`, `*.key`, and `.env`.
* Automated unit tests (`tests/test_runtime_isolation.py`) enforce that repository files and runtime directories remain strictly separated.
