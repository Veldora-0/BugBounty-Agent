# BugBounty-Agent

[![OpenCode Ready](https://img.shields.io/badge/OpenCode-Native-blue.svg)](https://opencode.ai)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-brightgreen.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Safety: Authorized Only](https://img.shields.io/badge/Testing-Authorized_Only-red.svg)](docs/security.md)

A professional, modular Bug Bounty Security Research Agent framework for **OpenCode**.

BugBounty-Agent is an orchestrated security research system designed to operate with the rigor of a senior penetration tester. Instead of indiscriminately running vulnerability scanners, the agent applies **deterministic scope enforcement**, **hypothesis-driven testing**, **cryptographic evidence validation**, and **local research state persistence**.

---

## Key Principles & Architectural Invariants

* **One Reusable Framework Repository**: Contains only the agent specifications, methodology skills, controlled CLI tools, tests, and documentation.
* **Complete Runtime Data Separation**: Real targets, recon logs, HTTP captures, credentials, and vulnerability reports remain **strictly local** on your machine (e.g. `~/BugBounty-Workspace/`) and are never committed to Git.
* **Never Silently Assume Authorization**: Every domain, IP, CIDR, and URL must pass through the Scope Engine before any network interaction.
* **Hypothesis-Driven Research**:
  $$\text{Observation} \longrightarrow \text{Hypothesis} \longrightarrow \text{Targeted Test} \longrightarrow \text{Evidence} \longrightarrow \text{Validation} \longrightarrow \text{Report}$$
* **No Automated Exploits or DoS**: Zero tolerance for denial-of-service, data destruction, password spraying, or unauthorized third-party probing.
* **No Auto-Submit**: Reports are generated in Markdown for human review and validation before disclosure.

---

## Repository Structure

```text
BugBounty-Agent/
├── AGENTS.md                  # Agent directory, hierarchy, and interaction flow
├── README.md                  # Master documentation and quickstart
├── LICENSE                    # MIT Open Source License
├── CHANGELOG.md               # Version history and release notes
├── CONTRIBUTING.md            # Guidelines for framework contributors
├── SECURITY.md                # Responsible disclosure and ethical safety policy
├── .gitignore                 # Enforces exclusion of runtime, target, and secret data
├── opencode.jsonc             # OpenCode native project configuration & permissions
│
├── .opencode/
│   ├── agents/                # 14 specialized OpenCode agent definitions
│   │   ├── bb-hunter.md       # Primary orchestrator
│   │   ├── bb-scope.md        # Offline scope & authorization verification
│   │   ├── bb-recon.md        # Controlled reconnaissance
│   │   ├── bb-asset.md        # Asset normalization and correlation
│   │   ├── bb-web.md          # Web application mapping and surface analysis
│   │   ├── bb-js.md           # JavaScript analysis and route extraction
│   │   ├── bb-api.md          # REST/GraphQL/WebSocket API testing
│   │   ├── bb-authz.md        # Authorization (BOLA/IDOR, BFLA, Multi-tenant)
│   │   ├── bb-injection.md    # Safe, non-destructive input testing
│   │   ├── bb-business-logic.md # Workflow and state machine analysis
│   │   ├── bb-cloud.md        # Cloud bucket and metadata review
│   │   ├── bb-validator.md    # Adversarial candidate finding validator
│   │   ├── bb-dedup.md        # Test & finding deduplication
│   │   └── bb-report.md       # 17-section disclosure report generator
│   │
│   └── skills/                # 14 modular OpenCode methodology skills
│       ├── scope-management/
│       ├── asset-discovery/
│       ├── asset-correlation/
│       ├── web-mapping/
│       ├── javascript-analysis/
│       ├── api-analysis/
│       ├── authorization-analysis/
│       ├── injection-analysis/
│       ├── business-logic-analysis/
│       ├── cloud-review/
│       ├── evidence-management/
│       ├── validation/
│       ├── deduplication/
│       └── reporting/
│
├── framework/                 # Reusable Python 3 core engine
│   ├── scope/                 # Scope engine, DNS boundary verification, normalizer
│   ├── state/                 # Persistent state manager, test fingerprinting, dedup
│   ├── findings/              # Finding schema, lifecycle state machine, reports
│   └── common/                # Evidence store, sanitization, tool detection, config
│
├── scripts/                   # Controlled CLI wrappers with mandatory scope checks
│   ├── bb-init                # Workspace and program initializer
│   ├── bb-scope-check         # Scope verification utility
│   ├── bb-target-normalize    # Target canonicalization & DNS boundary check
│   ├── bb-recon               # Controlled recon (subfinder, assetfinder, httpx)
│   ├── bb-http                # Rate-limited HTTP client with evidence logging
│   ├── bb-content             # Controlled content fuzzer wrapper (ffuf)
│   ├── bb-js                  # JavaScript endpoint & secret analyzer
│   ├── bb-api                 # REST/GraphQL API method and schema prober
│   ├── bb-nuclei              # Signal-only Nuclei scanner wrapper
│   └── bb-evidence            # Evidence collector with automatic token redaction
│
├── templates/                 # Reusable templates
│   ├── scope.yaml             # Complete program scope definition template
│   ├── program.yaml           # Program metadata and preferences template
│   ├── finding.json           # Finding JSON schema
│   ├── report.md              # 17-section markdown report template
│   └── config.example.yaml    # Global framework configuration template
│
├── tests/                     # 100% automated test suite
│   ├── test_scope.py
│   ├── test_recursive_subdomains.py
│   ├── test_target_normalization.py
│   ├── test_deduplication.py
│   ├── test_finding_schema.py
│   └── test_runtime_isolation.py
│
├── docs/                      # Comprehensive technical documentation
│   ├── architecture.md
│   ├── agents.md
│   ├── skills.md
│   ├── scope.md
│   ├── runtime.md
│   ├── installation.md
│   ├── workflow.md
│   └── security.md
│
└── examples/
    └── example-scope.yaml     # Realistic example scope with exclusions and limits
```

---

## Installation & Setup

### 1. Requirements
* Linux / Kali Linux or Windows / macOS
* Python 3.10+
* OpenCode

### 2. Quickstart
```bash
# Clone the repository
git clone https://github.com/Veldora-0/BugBounty-Agent.git
cd BugBounty-Agent

# Install lightweight dependencies
pip install pyyaml pytest

# Run the test suite
python -m pytest -v
```

### 3. Kali Linux Tooling Integration (Optional)
Install standard reconnaissance utilities:
```bash
sudo apt update && sudo apt install -y subfinder amass httpx-toolkit ffuf nuclei
```
Check detected tools:
```bash
python -c "from framework.common.tools import ToolDetector; print(ToolDetector.get_summary())"
```

---

## Research Workflow in 4 Steps

### Step 1: Initialize a Local Program
Initialize an isolated local workspace directory outside Git:
```bash
python scripts/bb-init my-target-program
```
This creates `~/BugBounty-Workspace/programs/my-target-program/` containing `scope/`, `recon/`, `state/`, `evidence/`, `findings/`, and `reports/`.

### Step 2: Configure Authorized Scope
Edit `~/BugBounty-Workspace/programs/my-target-program/scope/scope.yaml`:
```yaml
program:
  name: "my-target-program"
targets:
  domains:
    - "target.com"
  recursive_subdomains:
    enabled: true
    max_depth: 0 # Unlimited recursive subdomains
out_of_scope:
  domains:
    - "admin.target.com"
```

Verify scope logic:
```bash
python scripts/bb-scope-check --scope ~/BugBounty-Workspace/programs/my-target-program/scope/scope.yaml dev.api.target.com
```

### Step 3: Run OpenCode
Start OpenCode in the repository:
```bash
opencode .
```
`bb-hunter` automatically orchestrates reconnaissance, hypothesis formulation, targeted validation, and deduplication.

### Step 4: Review Markdown Reports
Validated findings are stored in:
`~/BugBounty-Workspace/programs/my-target-program/reports/`

Each report includes all 17 standard bug bounty disclosure sections:
1. Title
2. Summary
3. Affected Asset
4. Affected Endpoint
5. Vulnerability Type
6. Severity
7. Description
8. Root Cause
9. Prerequisites
10. Reproduction Steps
11. Expected Result
12. Observed Result
13. Security Impact
14. Evidence (Sanitized HTTP request & response)
15. Remediation
16. Confidence
17. Scope Reference

---

## What Belongs in Git vs What Stays Local

| Belongs in Git Repository | Stays Local to Machine (Ignored) |
| :--- | :--- |
| Framework source code (`framework/`) | Target domain and URL lists |
| Agent definitions (`.opencode/agents/`) | Reconnaissance scan logs (`recon/`, `scans/`) |
| Methodology skills (`.opencode/skills/`) | Raw HTTP requests and responses (`evidence/`) |
| Controlled CLI wrappers (`scripts/`) | Vulnerability findings (`findings/`) |
| Scope templates (`templates/`) | Generated disclosure reports (`reports/`) |
| Unit tests (`tests/`) | Authorization tokens, API keys, credentials |
| Architecture documentation (`docs/`) | Burp project files and browser sessions |

---

## License

This project is licensed under the [MIT License](LICENSE).
BugBounty-Agent is intended **strictly for authorized bug bounty programs and ethical security research**. Unauthorized testing against infrastructure without prior written consent is illegal.
