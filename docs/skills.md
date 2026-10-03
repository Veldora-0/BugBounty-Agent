# BugBounty-Agent — Skills Catalog

BugBounty-Agent equips subagents with modular OpenCode skills located in `.opencode/skills/`. Each skill provides specialized methodology, decision trees, criteria, and safety constraints.

---

## Skills Index

1. **`scope-management`**
   * Precedence hierarchy (Exclusions > Specific > Wildcards > Ambiguous)
   * Recursive subdomain depth calculation and DNS boundary verification
   * CLI integration via `bb-scope-check`

2. **`asset-discovery`**
   * Passive subdomain discovery (crt.sh, subfinder, assetfinder)
   * Controlled HTTP port probing via `httpx`
   * Rate limiting and passive-first intelligence collection

3. **`asset-correlation`**
   * Canonical URL/hostname normalization
   * Domain hierarchy depth modeling and parent-child linking
   * Infrastructure clustering by IP, CDN edge, and TLS SAN

4. **`web-mapping`**
   * Application routing and form vector enumeration
   * Authentication session lifecycle analysis
   * CORS origin reflection and CSRF posture assessment

5. **`javascript-analysis`**
   * Bundle endpoint extraction and route table mapping
   * Source map recovery (`.map` files)
   * Evaluation of frontend API keys vs privileged credentials

6. **`api-analysis`**
   * REST HTTP verb testing (`OPTIONS`, `PUT`, `DELETE`, `PATCH`)
   * GraphQL introspection and query depth checking
   * Mass assignment and parameter schema discrepancies

7. **`authorization-analysis`**
   * Horizontal and vertical BOLA/IDOR detection
   * Multi-tenant boundary evaluation
   * Dual-account proof methodology

8. **`injection-analysis`**
   * Non-destructive testing for SQLi, SSTI, XSS, and command injection
   * Benign proof markers (`SLEEP`, arithmetic `{{7*7}}`, safe delimiters)

9. **`business-logic-analysis`**
   * Multi-step workflow bypassing and sequence abuse
   * Integer overflow, decimal rounding, and negative values
   * Concurrency race conditions

10. **`cloud-review`**
    * Public S3 / GCS bucket permissions
    * Cloud instance metadata service access via SSRF
    * Subdomain takeover verification on dangling CNAMEs

11. **`evidence-management`**
    * Sanitization of tokens, passwords, and cookies
    * Cryptographic SHA-256 integrity verification
    * Structured file naming and metadata preservation

12. **`validation`**
    * Adversarial verification checklist
    * Elimination of generic 200 OK error pages, CDN blocks, and cached responses
    * Decision states: `VALIDATED`, `REJECTED`, `NEEDS_MORE_EVIDENCE`

13. **`deduplication`**
    * Test fingerprinting using SHA-256 hashes of canonicalized inputs
    * Grouping findings by underlying root cause and vulnerable components

14. **`reporting`**
    * 17-section international disclosure format
    * CVSS-aligned objective severity scoring
    * Human-in-the-loop local disclosure workflow
