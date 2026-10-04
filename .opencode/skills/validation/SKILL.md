---
name: validation
description: Rigorous adversarial verification, reproducible proof assessment, false-positive elimination, and severity calibration.
---

# Finding Validation Methodology

## Core Objective
Act as an adversarial quality gate before any candidate finding is recorded as a confirmed vulnerability. Treat all alerts, tool outputs, and hypotheses as untrusted and unproven until concrete, reproducible evidence demonstrates a genuine security boundary breach.

## 1. Adversarial Quality Checklist
Every candidate finding must satisfy six rigorous verification gates:

1. **Reproduction Gate**:
   * Can the finding be reliably reproduced using exact step-by-step instructions from a clean state?
   * If an issue occurred once intermittently (e.g. temporary network glitch or load balancer anomaly), it is NOT validated.
2. **Scope Gate**:
   * Is the affected asset definitively confirmed as `IN_SCOPE` via `bb-scope-check`?
   * Does it belong to an authorized domain and environment?
3. **Security Boundary Gate**:
   * Does this represent a violation of an actual security boundary (e.g. cross-user, cross-tenant, unauthorized administrative elevation)?
   * Is this merely expected business functionality or a public API by design?
4. **Attacker Prerequisite Gate**:
   * Are the attack preconditions realistic?
   * Does it require impossible prerequisites (e.g. root access on victim device, physical machine possession, extreme user interaction)?
5. **Demonstrated Impact Gate**:
   * What concrete harm does an attacker achieve?
   * Is unauthorized data exfiltrated? Is application state modified? Is execution achieved?
6. **False-Positive Elimination**:
   * Is a 200 OK response simply a custom 404 page in disguise?
   * Is a WAF returning a block page whose response body echoes the payload?
   * Was the response served from an intermediate cache rather than the origin server?

## 2. Severity & Confidence Calibration
* **Confidence Rating**:
  * `CONFIRMED`: Verified with reproducible multi-step execution.
  * `HIGH`: Strongly evidenced with deterministic differential responses.
  * `MEDIUM`: Partial indication requiring further manual review.
  * `LOW`: Speculative or unverified scanner alert.
* **Severity Calibration (CVSS v3.1 / v4.0 aligned)**:
  * `CRITICAL`: Remote code execution, unauthenticated administrative takeover, mass data exfiltration.
  * `HIGH`: Stored XSS in privileged context, high-impact BOLA/IDOR affecting sensitive data, blind SSRF to internal cloud metadata.
  * `MEDIUM`: Reflected XSS, CSRF on state-changing actions, rate limit absence on sensitive forms.
  * `LOW`: Informational header omissions, open redirects without token leakage.

## 3. Disqualification Rules
* Disqualify findings based purely on missing best-practice headers (e.g. missing `X-Content-Type-Options`) unless exploitable impact is demonstrated.
* Disqualify public token exposures that lack unauthorized write/read capabilities.
* Disqualify scanner alert outputs that lack an explicit validation trace.
