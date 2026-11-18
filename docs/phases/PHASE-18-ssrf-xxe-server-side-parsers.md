# Phase 18 — SSRF, XXE, and Server-Side Parsers

**Status:** XML safety checks and bounded XXE/SSRF candidate validators are implemented; live out-of-band callback confirmation is unavailable without a working provider.
**Implementation:** **framework/xxe/**, **framework/ssrf/**, **framework/common/xml_safe.py**, **framework/validation/validator.py**, **scripts/bb-validate**, and the **injection** and **oob** skills
**State:** XXE validation uses the local security-validation state; SSRF records use **state/ssrf.json**.

## Why this phase exists

Servers often parse structured data such as XML, JSON, archives, or documents. A parser can become a security boundary if it follows references, expands entities, or fetches a resource named by user input. XXE means XML External Entity processing lets a request cause access to external resources. SSRF means the server itself makes an unintended network request. A parser error or internal XML entity expansion is not automatically proof of external access.

Phase 18 has two separate aims: make the project’s own XML parsing safer, and provide controlled validators for an authorized application that accepts XML or URL-like inputs.

## How the phase works

The safe XML helper performs bounded, security-aware parsing and rejects unsafe constructions before ordinary parsing. The XXE validator uses a synthetic internal entity marker; if the application returns that marker, it records an informational observation that internal DTD processing occurred. It does not read local files or claim external entity resolution. Use **bb-validate --validator xxe** for a bounded plan or validation, subject to scope and the validator’s approval requirements.

The SSRF engine reads candidate parameters from existing application and API state and creates bounded canary cases. It blocks internal and metadata address ranges. The provider interface can model supported OOB providers, but live Interactsh or Collaborator polling is not implemented. Therefore a simulated callback is only a test of local code. It cannot confirm a real blind SSRF.

## How to use it

~~~bash
# Review XML-capable endpoints from existing state without requests.
bb-validate --program <program-name> --category xxe --passive-only --json

# Plan a harmless synthetic XML marker for one in-scope endpoint.
bb-validate --program <program-name> --endpoint https://app.example.org/import --validator xxe --dry-run --json

# Review SSRF candidates without sending a canary.
bb-ssrf --program <program-name> --passive-only --tree

# Exercise the SSRF engine against its local lab.
bb-ssrf --program <program-name> --lab --json
~~~

A live blind test requires explicit program permission, an approved case, and a controlled callback service whose end-to-end polling has been verified. Until then, do not report callback-based confirmation.

## What evidence means

For XML, distinguish parser errors, internal-entity expansion, and external resource resolution. The current synthetic check can at most show internal entity expansion. For SSRF, require a unique callback identifier and evidence binding the callback to the exact request. Never infer internal network access from a marker alone.

## Safety and limitations

Never use file URLs, real sensitive files, cloud metadata addresses, or third-party callback infrastructure without permission. Do not download or retain sensitive response content. Provider polling is an open limitation tracked in the [issue register](../PROJECT-AUDIT-ISSUES.md); tests cover local validators and failure behavior, not live external callbacks.

Tests: **tests/test_phase18_xml_security.py**, **tests/test_phase18_xxe_engine.py**, **tests/test_phase18_ssrf_transport.py**, and **tests/test_phase18_ssrf_mutation.py**. See [Phase 9](PHASE-09-ssrf-intelligence.md), [validation guide](PHASE-06-security-validation-foundation.md), and [roadmap](../ROADMAP-24-PHASES.md).