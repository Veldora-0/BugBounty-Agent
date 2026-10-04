---
name: reporting
description: Professional 17-section vulnerability disclosure report generation conforming to international bug bounty standards.
---

# Vulnerability Reporting Methodology

## Core Objective
Transform validated security findings into executive-ready, technically rigorous vulnerability disclosure reports. Structure reports to enable engineering teams to immediately reproduce, understand, and remediate the defect.

## Strict Prohibition: Zero Automated Submission
* **MANDATORY**: The agent must NEVER automatically submit reports to HackerOne, Bugcrowd, Intigriti, YesWeHack, or any external bug bounty platform.
* Reports are strictly output as local Markdown files in `~/BugBounty-Workspace/programs/<name>/reports/<finding_id>.md`.
* Human review and submission authorization is strictly required.

## 1. Mandatory 17-Section Report Standard
Every disclosure report MUST contain the following 17 sections without omission:

1. **Title**: Direct, descriptive, and actionable. Format: `[Vulnerability Type] in [Endpoint] via [Parameter] leads to [Impact]`.
2. **Summary**: High-level, 2-3 sentence overview of the defect and security impact.
3. **Affected Asset**: Fully qualified domain name (FQDN) or IP address of the target system.
4. **Affected Endpoint**: Specific URL route, API path, or handler.
5. **Vulnerability Type**: Industry classification (e.g. CWE-89, OWASP API1:2023).
6. **Severity**: Realistic CVSS-aligned rating (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`).
7. **Description**: Clear, technical explanation of the vulnerability mechanics.
8. **Root Cause**: The underlying programming, architectural, or configuration flaw.
9. **Prerequisites**: Account tier, authentication tokens, network access, or preconditions required.
10. **Reproduction Steps**: Clear, numbered step-by-step instructions from a clean state.
11. **Expected Result**: Baseline secure system behavior.
12. **Observed Result**: Actual insecure behavior demonstrating the flaw.
13. **Security Impact**: Realistic explanation of what an attacker can achieve (data theft, account takeover, lateral movement).
14. **Evidence**: Sanitized raw HTTP requests and responses, timestamps, and cryptographic hashes.
15. **Remediation**: Concrete, actionable guidance for developers to patch the root cause.
16. **Confidence**: Rating of certainty (`CONFIRMED`, `HIGH`, `MEDIUM`).
17. **Scope Reference**: Matched scope inclusion rule proving target authorization.

## 2. Professional Tone Standards
* Avoid hyperbolic language ("total system destruction", "critical catastrophic flaw" on low-tier bugs).
* Never assume worst-case scenarios without evidence.
* Provide clean, reproducible cURL commands with sanitized headers.
