# BugBounty-Agent — Scope Engine Specification

The Scope Engine is the primary authorization boundary of the BugBounty-Agent framework. It guarantees that security research is strictly confined to authorized targets.

---

## 1. Supported Target Types

* **Exact Domains**: e.g., `example.com`, `auth.example.com`.
* **Wildcard Domains**: e.g., `*.example.com`, `*.corp.example.org`.
* **Recursive Subdomains**: Arbitrary depth subdomains under authorized roots when `recursive_subdomains.enabled` is `true`.
* **Exact URLs & URL Prefixes**: e.g., `https://service.example.net/api/v1/`.
* **IP Addresses**: IPv4 and IPv6 addresses.
* **CIDR Blocks**: e.g., `192.168.100.0/24`, `2001:db8::/32`.

---

## 2. Evaluation Precedence

The engine applies strict four-tier precedence when evaluating any target:

```text
1. Explicit Exclusion  (out_of_scope.domains, out_of_scope.urls, out_of_scope.cidrs)
       ↓
2. Specific Inclusion  (targets.domains [exact], targets.urls [exact/prefix], targets.cidrs)
       ↓
3. Recursive / Wildcard Inclusion (targets.domains [wildcard or recursive], max_depth check)
       ↓
4. Ambiguous / Default Fallback (Unmatched hosts or malformed inputs -> OUT_OF_SCOPE / AMBIGUOUS)
```

### Precedence Example
Given the scope configuration:
```yaml
targets:
  domains:
    - "example.com"
  recursive_subdomains:
    enabled: true
    max_depth: 0

out_of_scope:
  domains:
    - "admin.example.com"
```

* `example.com` -> `IN_SCOPE` (Specific Inclusion, Depth 0)
* `api.example.com` -> `IN_SCOPE` (Recursive Inclusion, Depth 1)
* `dev.api.example.com` -> `IN_SCOPE` (Recursive Inclusion, Depth 2)
* `admin.example.com` -> `OUT_OF_SCOPE` (Explicit Exclusion)
* `portal.admin.example.com` -> `OUT_OF_SCOPE` (Descendant of Explicit Exclusion)
* `attacker-example.com` -> `OUT_OF_SCOPE` (Fails DNS label boundary)

---

## 3. Recursive Subdomain Depth Semantics

Depth is computed by counting the difference in DNS labels between the candidate host and the authorized root domain:

$$\text{depth} = \text{len}(\text{candidate\_labels}) - \text{len}(\text{root\_labels})$$

| Candidate Hostname | Authorized Root | Depth | Result (`max_depth: 2`) |
| :--- | :--- | :--- | :--- |
| `example.com` | `example.com` | 0 | `IN_SCOPE` |
| `api.example.com` | `example.com` | 1 | `IN_SCOPE` |
| `dev.api.example.com` | `example.com` | 2 | `IN_SCOPE` |
| `v1.dev.api.example.com` | `example.com` | 3 | `OUT_OF_SCOPE` (exceeds max_depth) |

Setting `max_depth: 0` allows unlimited recursive depth.

---

## 4. DNS-Label Boundary Security

To prevent substring spoofing attacks, hostnames are evaluated strictly along DNS label boundaries (delimited by `.`):

* `dev.api.example.com` ends with `.example.com` -> **Valid Descendant**
* `example.com.attacker.com` ends with `.attacker.com` -> **REJECTED**
* `attackerexample.com` does not contain label dot -> **REJECTED**

---

## 5. Scope Decisions and Provenance

The scope engine outputs structured decisions:
```json
{
  "target": "dev.api.example.com",
  "normalized_target": "dev.api.example.com",
  "scope_status": "IN_SCOPE",
  "reason": "Authorized subdomain (depth 2 within max unlimited)",
  "root_domain": "example.com",
  "parent": "api.example.com",
  "depth": 2,
  "matched_rule": "example.com",
  "rule_category": "RECURSIVE_INCLUSION"
}
```
