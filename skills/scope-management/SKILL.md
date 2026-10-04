---
name: scope-management
description: Strict scope validation, recursive subdomain depth controls, and target boundary enforcement for authorized bug bounty research.
---

# Scope Management Methodology

## Core Objective
Ensure that every network interaction, DNS query, HTTP request, or scanner invocation operates strictly within the authorized targets defined by the bug bounty program. Never silently assume authorization.

## Scope Status Definitions
* **`IN_SCOPE`**: Target is explicitly authorized via exact domain/URL/CIDR inclusion, or is an authorized subdomain within configured recursion depth.
* **`OUT_OF_SCOPE`**: Target matches an explicit exclusion, exceeds allowed subdomain recursion depth, or fails to match any inclusion rule.
* **`AMBIGUOUS`**: Target hostname is malformed, cannot be normalized, or the program rules lack explicit clarification. Treat as OUT_OF_SCOPE until clarified by the user.

## Precedence Hierarchy
When evaluating any target, rules must be checked in the following strict order:
1. **Explicit Exclusions (`out_of_scope`)**: Always overrides all inclusions. If `admin.example.com` is excluded, all subdomains (`*.admin.example.com`) are immediately OUT_OF_SCOPE.
2. **Specific Exact Inclusions (`targets.domains`, `targets.urls`)**: Exact matches take second precedence.
3. **Wildcard & Recursive Subdomain Inclusions (`targets.domains`, `recursive_subdomains`)**: Evaluated with DNS-label boundary verification and configured depth restrictions.
4. **Default Safe Fallback**: If no rule matches, the target is rejected as OUT_OF_SCOPE.

## Recursive Subdomain Semantics
Subdomain nesting is measured relative to the parent root domain:
* `example.com` -> Depth 0 (Root)
* `api.example.com` -> Depth 1
* `dev.api.example.com` -> Depth 2
* `v2.dev.api.example.com` -> Depth 3
* `test.v2.dev.api.example.com` -> Depth 4
* When `recursive_subdomains.max_depth` is `0`, recursion is unlimited across arbitrary depth levels.

## DNS Label Boundary Security
Never match hostnames by simple string suffix. The boundary must be anchored at the DNS dot delimiter (`.`):
* `api.example.com` is a valid descendant of `example.com`.
* `example.com.attacker.com` is **NOT** a descendant of `example.com`.
* `attackerexample.com` is **NOT** a descendant of `example.com`.

## Program Rules & Active Testing Restrictions
1. **Rate Limiting**: Adhere to program RPS caps (default 5 req/sec). Never flood target systems.
2. **Authentication Constraints**: Do not test beyond assigned user roles or tiers without authorization.
3. **Restricted Surfaces**: Third-party SaaS providers (Zendesk, Shopify, AWS S3, Salesforce) are out-of-scope unless explicitly owned and authorized.
4. **Denial of Service Prohibition**: Rate exhaustion, volumetric floods, and service disruption are strictly prohibited.

## Usage Guidelines
1. Before invoking any network-facing tool or HTTP request, execute:
   `bb-scope-check --scope <path_to_scope.yaml> <target>`
2. If `bb-scope-check` returns a non-zero exit code, halt execution immediately on that target.
3. Record the scope provenance (matched rule and depth) for every asset entered into the inventory.
