---
name: validation
description: Rigorous adversarial verification, reproducible proof assessment, false-positive elimination, and severity calibration.
---

# Finding Validation Methodology & Security Validation Foundation

## Core Objective
Transform recon, webapp, JS, and API intelligence into controlled, hypothesis-driven security validation attempts and structured security findings. Treat all alerts, tool outputs, and scanner hits as untrusted and unproven until concrete, reproducible empirical evidence demonstrates a genuine security boundary breach.

> [!IMPORTANT]
> **Safety Invariant**: Phase 6 establishes a bounded, non-destructive validation foundation and limited proof-of-concept validators. It is **NOT** a general-purpose autonomous exploitation engine. Exploitation logic, weaponized exploits, automated credential attacks, and destructive calls are strictly forbidden.

---

## 1. Formal Finding Lifecycle
All security findings follow an immutable state transition machine:

```
CANDIDATE
    ↓
 TESTING
    ↓
OBSERVED
    ↓
VALIDATED / REJECTED / DUPLICATE / NEEDS_MANUAL_REVIEW
```

* **`CANDIDATE`**: Identified via intelligence intake (API/WebApp/JS discovery) as having parameters, roles, or endpoints warranting controlled testing.
* **`TESTING`**: Actively evaluated against safe test cases with an empirical baseline.
* **`OBSERVED`**: Reproducible differential signal or harmless marker reflection captured.
* **`VALIDATED`**: Meets all adversarial verification criteria with unambiguous proof.
* **`REJECTED`**: Negative signal, neutralized by encoding, or out-of-scope/policy violation.
* **`DUPLICATE`**: Matches existing finding signature (asset, endpoint, vulnerability family, root cause).
* **`NEEDS_MANUAL_REVIEW`**: Ambiguous differential response requiring human researcher intervention.

---

## 2. Security Test Case Model & Safe Request Builder
* **`SecurityTestCase`**: Structured specification capturing target, endpoint, parameter, payload identifier, test strategy, risk level, request budget, and expected signals.
* **`RequestBuilder`**: Constructs controlled HTTP requests and performs deterministic, single-parameter mutations (`mutate_query_param`, `mutate_path_param`, `mutate_header`, `mutate_cookie`, `mutate_json_param`, `mutate_form_param`). Never mutates multiple parameters simultaneously.

---

## 3. Safe Testing Policy (`SecurityTestPolicy`)
Validation adheres to strict, conservative boundaries:
* **Allowed Methods**: `GET`, `HEAD`, `OPTIONS` by default. Arbitrary `POST`, `PUT`, `PATCH`, `DELETE` are blocked.
* **State-Changing GET Protection**: GET requests matching state-changing patterns (`/delete`, `/logout`, `/remove`, `/reset-password`, `/transfer`, `/purge`) are blocked by policy.
* **Budget Ceilings**:
  * Max requests per test: `5`
  * Max requests per endpoint: `20`
  * Max requests per program: `200`
  * Max response bytes: `100KB`
  * Max payload size: `512 bytes`
  * Max evidence size: `4096 bytes`
* **Anti-SSRF Boundaries**: Private IP ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`) and `localhost` are strictly rejected unless explicitly declared in `scope.yaml`.

---

## 4. Empirical Baseline Comparison
Before mutating an endpoint, the engine executes an untouched request to establish an empirical baseline:
1. Record status code, content type, response size, key headers (`Location`, `Content-Security-Policy`, `Server`), title, and body sample.
2. Dispatch single-parameter controlled mutation.
3. Compare responses:
   * Status change (`status_changed`)
   * Size delta (`size_delta`)
   * Content type change (`content_type_changed`)
   * Normalized body similarity ratio (`body_similarity`)
   * Reflected marker detection and reflection context (`SCRIPT_TAG`, `HTML_ATTRIBUTE`, `HTML_BODY_TEXT`, `JSON_VALUE`)
   * Location header redirection to canary destination
   * Error pattern recognition (`error_pattern_detected`)
* **Core Rule**: A single response difference is an empirical signal, **never** an automatic proof of vulnerability.

---

## 5. Payloads & Validator Architecture
* **`PayloadRegistry`**: Manages bounded, deterministic, and benign verification markers. Large payload wordlists or untrusted executable code are strictly forbidden.
* **Proof-of-Concept Validators**:
  1. **`ReflectedXSSValidator` (`reflected-xss`)**:
     * Harmless alphanumeric marker: `XSHIELD_TEST_<token>`
     * Analyzes reflection context in HTML/JSON responses.
     * **NEVER** executes JavaScript or launches a browser to trigger scripts.
     * Neutralized/encoded markers produce `REJECTED`. Unencoded reflections produce `OBSERVED`.
  2. **`OpenRedirectValidator` (`open-redirect`)**:
     * Benign canary destination: `https://canary.bugbounty-agent.local/redirect_<token>`
     * Inspects 3xx status codes and `Location` header.
     * **NEVER** navigates victim browsers. Disregards relative or same-domain redirects.
* **Unavailable Capability Stubs**: `sql-injection`, `ssrf`, `command-injection`, `path-traversal` explicitly declare unavailable capability status.

---

## 6. Dual-Principal Authorization Foundation
Provides data models (`Principal`, `SessionContext`, `ResourceIdentifier`, `ExpectedAccessPolicy`) for comparing access between authorized owners and unauthorized principals without executing destructive attacks or credential harvesting.

---

## 7. Evidence Integration & Deduplication
* **Cryptographic Evidence**: Request/response pairs are sanitized using `sanitize_sensitive_data()`, stripping `Authorization` tokens, `Cookie` session values, and API keys. Stored in `evidence/` with SHA-256 hashes.
* **Deduplication**: `FindingDeduplicator` computes normalized signatures (`affected_asset|affected_endpoint|vulnerability_type|root_cause`) to prevent repetitive alerts and duplicate reports.

---

## 8. State Persistence & CLI
* **State File**: `~/BugBounty-Workspace/programs/<program>/state/security.json`
* **CLI Utility**: `bb-validate`
  ```bash
  # Visual validation tree
  bb-validate --program acme-corp --tree

  # Targeted validator execution
  bb-validate --program acme-corp --endpoint "https://app.example.com/search" --parameter q --validator reflected-xss

  # Offline passive candidate prioritization
  bb-validate --program acme-corp --passive-only --json

  # Dry-run plan without network or disk writes
  bb-validate --program acme-corp --dry-run
  ```
