# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

---

## Reporting a Security Vulnerability

If you discover a security vulnerability within the BugBounty-Agent framework (such as a scope bypass, insecure token deserialization, or unexpected shell execution vector), please report it responsibly:

* **Email**: Contact the repository maintainer directly at the security contact address specified in the repository profile.
* **Do Not File Public Issues**: Please avoid opening public GitHub issues for unpatched vulnerabilities.
* **Response Timeline**: We acknowledge receipt of vulnerability reports within 48 hours and aim to provide a remediation patch within 14 business days.

---

## Safety Guarantees

* **Zero-Telemetry Framework**: BugBounty-Agent does not phone home, report findings to any cloud analytics, or transmit target information to external servers.
* **Offline Verification**: `bb-scope` performs zero target network calls, preventing unintended target disclosures during authorization checks.
* **Redaction by Default**: HTTP headers and payloads stored by `bb-evidence` are automatically scrubbed of authentication tokens, API keys, and session cookies.
