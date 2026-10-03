---
name: validation
description: Rigorous, adversarial validation and false-positive elimination for candidate security findings.
---

# Validation Methodology

## Core Objective
Act as an adversarial internal reviewer. Treat every candidate finding as untrusted until independent, repeatable evidence confirms that a real security boundary has been violated.

## Decision States
* **`VALIDATED`**: The vulnerability is consistently reproducible, clearly violates an authorization or trust boundary, and exhibits demonstrated security impact within program scope.
* **`REJECTED`**: The candidate is an artifact of false-positive scanner heuristics, caching, normal application design, or out-of-scope infrastructure.
* **`NEEDS_MORE_EVIDENCE`**: Potential issue observed, but reproduction is erratic or impact is purely theoretical.

## Critical Validation Checklist
1. **Scope Check**: Is the affected asset definitively IN_SCOPE according to program rules?
2. **False-Positive Analysis**:
   * Could this be a generic 404/custom error page returning 200 OK?
   * Is a WAF or CDN returning a canned block page that mimics a hit?
   * Was response cached from a prior unrelated request?
3. **Attacker Prerequisites**: What role is required? Does this require improbable victim interaction?
4. **Demonstrated Impact**: Does this leak private data or alter server state, or is it merely informational telemetry?
