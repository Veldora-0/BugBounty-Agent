---
name: deduplication
description: Finding and test deduplication methodology to prevent redundant scans and duplicate report submissions.
---

# Deduplication Methodology

## Core Objective
Prevent duplicate submissions to program triagers. Identify when multiple observable symptoms originate from a single underlying root cause or shared vulnerable software component.

## Deduplication Vectors
1. **Endpoint & Parameter Matching**:
   * Same endpoint path and parameter name tested for the same vulnerability class.
2. **Underlying Root Cause**:
   * Multiple endpoints sharing identical vulnerable middleware or authentication filter.
   * If a library is vulnerable to path traversal across multiple endpoints, group into a single consolidated finding.
3. **Test Fingerprinting**:
   * Use `generate_test_fingerprint(target, endpoint, method, parameter, test_category)` to verify whether a test has already executed.
   * Do not repeat expensive or noisy scans against previously validated surfaces unless target code has changed.

## Duplicate Decision Flow
* If candidate matches an existing finding:
  * Transition candidate lifecycle state to `DUPLICATE`.
  * Set `duplicate_of` to the primary finding ID.
  * Consolidate any novel evidence or endpoints into the primary finding record.
