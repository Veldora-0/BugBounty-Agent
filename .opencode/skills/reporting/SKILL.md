---
name: reporting
description: High-signal, professional vulnerability report generation conforming to bug bounty disclosure standards.
---

# Reporting Methodology

## Core Objective
Produce clear, professional, and actionable vulnerability reports that program triagers and development teams can immediately understand, reproduce, and remediate.

## Mandated Report Sections (17 Standard Sections)
1. **Title**: Concise, descriptive summary (e.g. `BOLA on /api/v1/invoices/{id} Allows Unauthorized Tenant Invoice Access`).
2. **Summary**: Executive overview of the issue.
3. **Affected Asset**: Fully qualified hostname or IP.
4. **Affected Endpoint**: Specific URL, API route, or parameter.
5. **Vulnerability Type**: Industry classification (CWE / OWASP).
6. **Severity**: Calculated severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`).
7. **Description**: Clear technical background.
8. **Root Cause**: Defect in architecture, code, or configuration.
9. **Prerequisites**: Necessary user tier or environment setup.
10. **Reproduction Steps**: Step-by-step numbered instructions.
11. **Expected Result**: Intended secure system behavior.
12. **Observed Result**: Actual insecure behavior demonstrated.
13. **Security Impact**: Realistic business and technical risk.
14. **Evidence**: Sanitized raw HTTP requests and responses.
15. **Remediation**: Concrete, actionable guidance for engineers.
16. **Confidence**: Researcher confidence level (`CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`).
17. **Scope Reference**: Citation of authorized inclusion rule.

## Cardinal Rules
* **Never exaggerate severity**: Do not label a self-XSS or missing header as Critical.
* **Never auto-submit**: Every report must be saved locally and reviewed by the human researcher before external platform submission.
