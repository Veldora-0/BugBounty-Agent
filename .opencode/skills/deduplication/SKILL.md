---
name: deduplication
description: Test fingerprinting, candidate finding clustering, root-cause correlation, and duplicate report prevention.
---

# Deduplication Methodology

## Core Objective
Ensure that security research produces high-signal, consolidated findings rather than repetitive duplicates for the same underlying software flaw. Prevent duplicate submissions to bug bounty programs and avoid executing redundant scans.

## 1. Test Fingerprinting (Scan Deduplication)
Before executing any active security probe or tool command against a target endpoint:
1. Compute a deterministic SHA-256 fingerprint from the test tuple:
   $$\text{Fingerprint} = \text{SHA-256}(\text{target\_url} + \text{method} + \text{parameter} + \text{test\_category})$$
2. Check `~/BugBounty-Workspace/programs/<name>/state/tests.json` to verify if this exact probe was already executed.
3. If already executed within the active session, skip the probe to save bandwidth and prevent WAF rate-limiting.

## 2. Finding Correlation Vectors
Group candidate findings across five distinct dimensions:
1. **Endpoint & Parameter Match**: Alerts targeting the same URL route, file, and parameter name.
2. **Root Cause Analysis**: A shared vulnerable middleware, backend library, or database query manifesting across multiple endpoints.
3. **Vulnerability Class & Behavior**: Identical vulnerability patterns occurring across identical resource templates.
4. **Shared Third-Party Component**: Vulnerabilities originating from the same third-party plugin, widget, or library across distinct subdomains.
5. **Evidence Fingerprint Overlap**: Identical stack traces, error strings, or response reflection signatures.

## 3. Consolidation & Lifecycle Decision
* **Novel Finding (`UNIQUE`)**: If the finding represents a newly identified, distinct defect, assign a unique `finding_id` and proceed to reporting.
* **Duplicate Finding (`DUPLICATE`)**:
  * Mark candidate status as `DUPLICATE`.
  * Record reference to the parent `finding_id`.
  * Merge any novel endpoints or evidence captures into the primary finding's evidence log.
  * Do NOT create a separate report document.
