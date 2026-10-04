---
name: evidence
description: Cryptographic integrity hashing, raw HTTP capture standards, token redaction, and local evidence preservation.
---

# Evidence Management Methodology

## Core Objective
Capture, sanitize, and preserve tamper-evident proof of security findings. Maintain full cryptographic provenance (SHA-256) and ensure sensitive credentials, tokens, and victim PII are strictly redacted and never committed to version control.

## 1. Evidence Artifact Types
* **Raw HTTP Transactions**: Complete, verbatim HTTP request and response text files including request line, headers, and body.
* **Command Execution Logs**: Exact CLI commands, execution arguments, system environment context, and standard output/error streams.
* **Differential Comparisons**: Side-by-side response diffs proving authorization bypass or boolean injection differentials.
* **Screenshots & Recordings**: Visual proof for complex multi-step UI flows or DOM-based execution.

## 2. Mandatory Sensitive Data Redaction
Before any evidence artifact is written to disk or included in documentation, sensitive values MUST be redacted:

```text
Authorization: Bearer [REDACTED_BEARER_TOKEN]
Cookie: session=[REDACTED_SESSION_COOKIE]
X-Api-Key: [REDACTED_API_KEY]
Password: [REDACTED_CREDENTIAL]
```

* **Target Token Masking**: Only preserve the first 4 and last 4 characters if needed to demonstrate token rotation: `eyJh...9xZq`.
* **Personal Data Protection**: Redact personal email addresses, phone numbers, credit card numbers, and social security identifiers.

## 3. Cryptographic Provenance & Storage
* For every evidence file, compute a SHA-256 checksum upon creation:
  $$\text{Hash} = \text{SHA-256}(\text{raw\_evidence\_content})$$
* Store evidence in local, isolated program directories outside Git:
  `~/BugBounty-Workspace/programs/<name>/evidence/<finding_id>/`
* Reference the evidence by path and SHA-256 checksum in finding records.

## 4. Git Isolation Invariant
* **MANDATORY**: Never commit raw HTTP captures, scan logs, target outputs, credentials, or screenshots to Git.
* Verify that `.gitignore` strictly excludes `~/BugBounty-Workspace/` and all evidence artifacts.
