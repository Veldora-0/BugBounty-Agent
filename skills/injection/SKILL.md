---
name: injection
description: Non-destructive injection intelligence and controlled validation covering SQLi, NoSQLi, SSTI, and Command Injection foundation.
---

# Injection Intelligence & Controlled Validation Methodology

> [!IMPORTANT]
> **Controlled Validation Invariant**: Phase 10 provides **bounded, non-destructive validation**. It does **NOT** perform arbitrary database dumping/extraction, schema enumeration, operating system command execution, template remote code execution (RCE), or destructive exploitation.

---

## 1. Subsystem Architecture

```
Asset / WebApp / API / JS Intelligence (Phases 2-9)
                      ↓
           Parameter Prioritization (0-100)
                      ↓
             Injection Hypothesis
                      ↓
             Validator Selection
                      ↓
               Safe Baseline
                      ↓
             Controlled Test Probe
                      ↓
       Multi-Signal Response Comparator
                      ↓
               Evidence Record
                      ↓
        Finding Lifecycle & Deduplication
```

---

## 2. Test Prioritization Engine (`framework/injection/prioritization.py`)

Parameters are scored from **0 to 100** based on context and relevance:

| Factor | Evaluation Criteria | Adjustment |
| :--- | :--- | :--- |
| **Semantic Role** | `q`, `query`, `search`, `filter` | +22 (SQL/NoSQL filter) |
| **Ordering** | `sort`, `order`, `orderby` | +25 (SQL ORDER BY) |
| **Pagination** | `limit`, `offset`, `page` | +15 (SQL LIMIT) |
| **Entity ID** | `id`, `user_id`, `item_id` | +20 (SQL numeric/string ID) |
| **Template Role** | `template`, `render`, `preview` | +25 (SSTI candidate) |
| **NoSQL Operator** | `where`, `filter`, `query` + JSON body | +24 (NoSQL candidate) |
| **Utility Role** | `file`, `path`, `convert`, `format` | +18 (Command foundation) |
| **Location** | PATH (+12), JSON (+10), QUERY (+8), FORM (+6), HEADER (-10) | Relative location weighting |
| **Tech Signals** | SQL DB / ORM (+10), NoSQL (+12), Template Engine (+15) | Stack intelligence from Phases 2-5 |
| **Demotions** | CSRF tokens, nonces (-40), presentation/locale (-10) | Unlikely injection targets |

### Priority vs. Confidence vs. Severity
* **Priority (0–100)**: How critical and likely it is that this parameter should be tested first.
* **Confidence (`CANDIDATE` $\to$ `OBSERVED` $\to$ `VALIDATED`)**: The mathematical certainty and reproducibility of the differential signal.
* **Severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)**: The potential business/security impact if the vulnerability were exploited.

---

## 3. Vulnerability Families & Bounded Probes

### 3.1 SQL Injection (SQLi)
* **Safe Differential Probes**:
  * Quote syntax fault boundary: `'`
  * String boolean true: `' OR '1'='1`
  * String boolean false: `' OR '1'='2`
  * Numeric boolean true: ` OR 1=1`
  * Numeric boolean false: ` OR 1=2`
  * Numeric identity: `-0`
* **Forbidden Statements**:
  `DROP`, `DELETE`, `UPDATE`, `INSERT`, `ALTER`, `TRUNCATE`, `GRANT`, `SHUTDOWN`.
* **Timing Analysis Foundation**:
  Strictly disabled by default (`--timing` required). Bounded delay (1.0s) with network jitter normalization.

### 3.2 NoSQL Injection (NoSQLi)
* **Safe Operator Probes**:
  * Inequality query operator: `{"$ne": "__bb_nonexistent__"}` or `param[$ne]=__bb_nonexistent__` (Boolean True)
  * Equality to nonexistent: `{"$eq": "__bb_nonexistent__"}` or `param[$eq]=__bb_nonexistent__` (Boolean False)
* **Safety Boundary**: Zero document modification, zero collection dumping, zero credential enumeration.

### 3.3 Server-Side Template Injection (SSTI)
* **Benign Mathematical Probes**:
  * Double curly: `{{7*7}}` $\to$ expects `49`
  * Dollar syntax: `${7*7}` $\to$ expects `49`
  * Tag syntax: `<%= 7*7 %>` $\to$ expects `49`
  * Hash syntax: `#{7*7}` $\to$ expects `49`
* **Safety Boundary**:
  Zero process spawning, zero file reading, zero command execution.

### 3.4 Command Injection Foundation
* **Capability Boundary**:
  Flags candidates with process/utility semantics. Emits `CAPABILITY_REQUIRES_SPECIALIZED_VALIDATION`.
* **Safety Invariant**:
  Strictly **NEVER** executes `curl`, `wget`, `bash`, `sh`, `powershell`, `rm`, or `nc` against target endpoints.

---

## 4. Multi-Signal Comparator & False-Positive Reduction

To prevent false positives from single anomalies, the comparator checks:
1. **WAF & Security Block Filtering**: Identifies Cloudflare, AWS WAF, Akamai, and 403 challenge pages.
2. **Rate-Limiting (429)**: Backs off and rejects false-positive error triggers.
3. **Generic Error Separation**: Distinguishes generic 500 runtime faults from verified database/ORM syntax errors.
4. **Boolean Differential Correlation**: Requires `(TestTrue ≈ Baseline) AND (TestFalse ≠ TestTrue)`.
5. **Mathematical Reflection**: Verifies `49` is present in probe response, absent in baseline, and not rendered literally as `{{7*7}}`.

---

## 5. CLI Tool: `bb-inject`

```bash
# Passive parameter ranking (zero network traffic)
bb-inject --program acme-corp --passive-only --tree

# Dry-run execution plan for an endpoint
bb-inject --program acme-corp -e "https://app.example.com/search?q=test" --param q --dry-run

# Generate human approval dossier
bb-inject --program acme-corp -e "https://app.example.com/search?q=test" --param q --dossier

# Authorized active differential test
bb-inject --program acme-corp -e "https://app.example.com/search?q=test" --param q --approve

# Run local offline security lab simulation
bb-inject --lab --tree
bb-inject --lab -e "http://lab.local/api/items?id=1" --param id --approve
```

---

## 6. State Persistence & Evidence

* Persistent state: `~/BugBounty-Workspace/programs/<program>/state/injection.json`
* Evidence captures: cryptographically signed with SHA-256 evidence hash.
* Sensitive data hygiene: headers and tokens (`Authorization`, `Cookie`, `X-CSRF-Token`) are redacted automatically before persistence.
* Deduplication: identical host/endpoint/param/family/root-cause findings are clustered via `FindingDeduplicator`.
