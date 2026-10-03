---
name: evidence-management
description: Evidence capture standards, sensitive token redaction, cryptographic integrity hashing, and reproducible proof preservation.
---

# Evidence Management Methodology

## Core Objective
Ensure that all security findings are substantiated by clear, reproducible, and cryptographically verified evidence while guaranteeing that sensitive credentials and customer secrets are never leaked.

## Evidence Quality Standards
Every verified finding must include:
1. **Raw HTTP Request**: Complete with method, path, headers, and body.
2. **Raw HTTP Response**: Status line, relevant security headers, and response body showing the vulnerability indicator.
3. **Reproducibility**: Clear step-by-step description allowing an application owner or program triage team to reproduce the issue independently.
4. **Integrity Hash**: SHA-256 digest of the captured artifact.

## Sanitization Requirements
Before saving or reporting evidence:
* Redact `Authorization: Bearer <token>` and `Basic <token>` headers.
* Redact sensitive session cookies (`sessionid`, `jwt`, `token`).
* Redact customer personal data (PII) belonging to real individuals.
* Use `bb-evidence` or `EvidenceStore.save_http_capture` to automate redaction.

## Tooling
* `bb-evidence --program <program> --request-file <req> --response-file <res> --note "Proof of BOLA"`
