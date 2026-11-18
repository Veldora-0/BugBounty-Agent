# Phase 15 — File Upload, Path Traversal, and Local File Exposure

**Status:** Implemented for controlled validators and local fixtures; live upload or file-state changes require explicit permission and safe canary handling.
**Implementation:** **framework/validation/validator.py**, **framework/validation/**, **scripts/bb-validate**, **scripts/bb-content**
**State:** Validator records are stored in **state/security.json**. Content-discovery output is stored under the program’s local **scans/** directory.

## Why this phase exists

Applications often accept files, retrieve files by a name or path, or expose documents through download endpoints. A path traversal defect may let a user reach a file outside the intended directory. Local file exposure happens when the application returns a file that should not be available. Upload issues can arise when the server stores a file in an unsafe location or treats a harmless file as executable content.

Phase 15 separates these questions. The security validators use synthetic canary markers and controlled test files in local fixtures. The content-discovery command is a separate inventory helper: it searches a bounded list of paths and does not prove a file-handling vulnerability.

## How the validators work

The validation engine discovers file-related candidates from application state, builds test cases, checks scope, and uses a safe request policy. The path traversal and local-file validators look for a unique synthetic marker in the response. A generic error page or status-code change is not enough. The upload validator can inspect an existing upload form and submit a harmless synthetic file only where the engine’s policy allows it. A successful ordinary file upload is not a vulnerability by itself. Some live upload tests are intentionally marked as requiring manual review because a safe server-side rollback cannot be guaranteed.

Use **bb-validate --validator path-traversal**, **--validator local-file-exposure**, or **--validator file-upload** to narrow a plan to one validator. Begin with passive or dry-run mode. Do not use system files, shell scripts, executable payloads, or real user documents.

## Controlled content discovery

**bb-content** is a manually invoked, sequential GET helper. It requires a valid program scope and an in-scope HTTP(S) URL containing one **FUZZ** marker in the path or query, plus a reviewed wordlist. Each expanded URL is checked against scope and fetched through the shared transport, which resolves and pins safe destination IPs and rechecks redirects. It does not launch ffuf or another external scanner. The default request budget is 100 wordlist entries, with a hard maximum of 1,000; the request rate is limited to 1–10 requests per second, the response sample to 64 KiB per request, and the run to 120 seconds by default with a 300-second maximum. Each request also has a five-second timeout, so the final request may finish just after the overall runtime deadline. Output contains only minimal path/status metadata; response bodies and query strings are not written. These are safety ceilings, not a recommendation to send all allowed requests. Review each discovered path before opening it; the path name does not prove that a resource is exposed.

## How to use it

~~~bash
# Review file-related candidates without network traffic.
bb-validate --program <program-name> --category path-traversal --passive-only --tree

# Build a dry-run plan for one specific URL and validator.
bb-validate --program <program-name> --endpoint https://app.example.org/download --parameter path --validator path-traversal --dry-run --json

# Plan upload checks without dispatching requests.
bb-validate --program <program-name> --endpoint https://app.example.org/upload --validator file-upload --dry-run --json

# Search a short approved wordlist at a conservative rate and runtime.
bb-content https://app.example.org/FUZZ --program <program-name> --wordlist ./small-approved-list.txt --rate 2 --max-requests 50 --max-runtime 120
~~~

Use only an endpoint permitted by the program. Keep wordlists small, review what they contain, and do not access discovered files if their content may be sensitive.

## Evidence and limits

A synthetic canary echoed from a path-based response is stronger than a generic 500 error, but it still must be tied to the target behavior and the tested identity. For an upload issue, show how the uploaded canary was handled without trying to execute it or overwrite a real file. For content discovery, report only a path and safe status metadata unless the program expressly authorizes inspection of the content.

The regression suite exercises traversal, upload, exposure, redaction, scope, and lifecycle behavior using a local fixture. It does not make arbitrary live uploads safe, provide rollback for all applications, or prove that the wordlist found every path.

Tests: **tests/test_phase15_file_security.py** and **tests/test_content_discovery_cli.py**. See the [validation guide](PHASE-06-security-validation-foundation.md), [scope guide](../scope.md), and [roadmap](../ROADMAP-24-PHASES.md).
