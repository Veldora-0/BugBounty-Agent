# Project Audit Issues and Known Problems

This register lists only material unresolved project problems. When an issue is fixed and verified, remove it here; its implementation and tests remain traceable in Git history and the test suite. The current audit began from `f8466bd` on `main`; its Kali baseline run is recorded at the end. Findings about implementation are based on repository inspection and tests, not on live bounty targets.

## Open issues

### AUD-03 — Current Windows acceptance evidence is unavailable

- **Severity:** Medium confidence/maintenance risk.
- **Evidence:** The full Kali suite passed at `c1a791f` after the audit fixes. This workspace could not start the Windows Python launcher, so no current Windows full-suite result was obtained; one DACL test is skipped on Kali and Windows ACL subprocess verification for Phase 22 still requires a supported Windows run.
- **Impact:** Historical test numbers can be mistaken for current full regression or live-target coverage.
- **Remediation:** Phase guides now distinguish repository implementation from live effectiveness and call out limits. Add a repeatable Windows/Linux CI matrix and dated acceptance manifests as part of Phase 24.
- **Acceptance gate:** Each maintained acceptance record identifies commit, exact commands, environment/dependencies, pass/skip/fail counts and untested live boundaries.

### AUD-04 — Live OOB integrations for SSRF/XXE are unavailable (Phases 9 and 18)

- **Severity:** Medium; affects confirmation of blind SSRF/XXE only.
- **Evidence:** `framework/ssrf/provider.py` reports configured Interactsh/Burp Collaborator providers as `UNAVAILABLE` because live polling is not implemented; `framework/ssrf/engine.py` and `framework/xxe/engine.py` fail closed and keep simulated callbacks labeled as simulation. The Phase 1–20 baseline records this limitation for Phase 9, and Phase 18 acceptance records it for XXE.
- **Impact:** Blind server-side interaction hypotheses may remain unconfirmed even if local simulations pass.
- **Remediation:** Implement supported provider polling and credential configuration with safe correlation identifiers, timeout/rate limits, scope checks and auditable callback provenance, or keep status unavailable.
- **Acceptance gate:** An isolated owned test endpoint verifies attributable live callback receipt; mock providers remain labeled simulation and cannot create confirmed findings.

### AUD-06 — Phase 1 CLI does not perform the advertised broad asset enrichment

- **Severity:** Medium; asset coverage and confidence can be overstated if the phase guide is read without this limitation.
- **Evidence:** `AssetIntelligenceEngine._discover_child_subdomains()` returns no candidates when its discovery hook is unset, and the normal `scripts/bb-assets` CLI does not configure that hook. The default ASN result is `UNKNOWN`; TLS SAN extraction is also exposed through a hook rather than a provider wired into the normal CLI. The current CLI can model supplied roots/seeds and perform its implemented DNS enrichment, but it does not independently discover arbitrary-depth subdomains as the older roadmap wording implied.
- **Impact:** Researchers may have an incomplete asset inventory and miss hosts that a passive or active discovery provider would have found. `--depth` does not itself provide a discovery source.
- **Remediation:** Wire a reviewed passive provider into the CLI with source attribution, limits, failure reporting and offline fixtures, or keep these features explicitly described as manual/hook-only. Add a CLI-level test proving provider-backed children are persisted and scope-labelled correctly.
- **Acceptance gate:** On owned local fixtures and a controlled provider mock, a CLI run discovers nested children, records provenance, respects limits/exclusions, and remains usable offline without claiming undiscovered coverage.

### AUD-07 — Phase 2 tool catalog is not an execution integration

- **Severity:** Medium; the current built-in reconnaissance is narrower than the tool catalog can suggest.
- **Evidence:** `config/tools.yaml` and the capability graph describe tools such as Subfinder, httpx, and Nmap, but `scripts/bb-recon` does not launch those external binaries. The engine performs its own bounded Python DNS/TLS/HTTP probes and a short default port list.
- **Impact:** Installing a listed binary or configuring an API key does not cause Phase 2 to use that capability. Recon coverage remains limited to the built-in probes and supplied/previously known assets.
- **Remediation:** Decide which external tools should be integrated, then implement explicit invocation contracts with binary validation, offline scope preflight, constrained arguments, output/time/request bounds, and local-fixture tests. Until then, label entries as manual/available tools and avoid implying engine integration.
- **Acceptance gate:** Tests demonstrate the CLI's exact execution behavior, including disabled/manual mode, out-of-scope rejection, timeout, malformed output and tool failure.

### AUD-08 — Phase 21 production acceptance remains platform-limited

- **Severity:** Medium; affects deployment support and confidence in the installed dispatcher path.
- **Evidence:** Linux systemd dispatcher identity, socket permissions, key isolation, live status/ping and invalid-approval rejection have been checked on Kali. A successful operator-approved mutation through that installed service has not been run because provisioning the required operator test key needs privileged setup. Windows production service isolation is not implemented; Windows tests cover state permissions and local development paths, not a dedicated isolated dispatcher service.
- **Impact:** The installed Linux service's successful authorized dispatch path lacks direct live-service acceptance evidence, and the Windows deployment boundary differs from Linux.
- **Remediation:** Document and execute a controlled, reversible Linux integration test using a dedicated test program/action and provisioned test keys. Decide whether Windows production isolation will be implemented or formally unsupported; keep the UI/CLI status explicit.
- **Acceptance gate:** A supported-platform matrix includes successful and rejected dispatch through the actual service boundary, proves receipt/evidence binding and replay rejection, and records platform-specific unsupported behavior without overstating parity.

## Audit boundaries

This register records repository review and current audit-run evidence, not a live-target security assessment. No bounty target was contacted. Review current program rules and scope before use.

## Historical verification (previous audit snapshot)

- Older audit records cite historical commits and platform counts. Those numbers are not a claim about current `main`; use the commit-specific sections below and phase guides for newer evidence.

## Pre-fix baseline at `f8466bd`

- **Kali Linux, Python 3.14.10:** `python3 -m pytest tests/ -ra` — **1,245 passed, 1 skipped** in 576.12 seconds. The skipped test is the Windows-only DACL test (`tests/test_phase21_state.py:370`). This was run before the current working-tree changes; it is not final verification of those changes.
- **Windows:** No full-suite result was obtained for this audit. The prior Phase 22 Windows ACL subprocess issue remains unresolved; do not treat Kali results as Windows evidence.
- **Live-target testing:** None. No bounty target was contacted. Unit and integration results are not proof of live vulnerability-discovery effectiveness.
- This baseline is retained for comparison only. It is superseded by the post-fix verification below.

## Post-fix verification at `c1a791f` (2026-11-18)

- **Kali Linux, Python 3.14.10:** `python3 -m pytest tests/ -ra` — **1,264 passed, 1 skipped** in 147.79 seconds. The single skip is the Windows-only DACL test (`tests/test_phase21_state.py:370`).
- **Focused regressions:** 72 passed in 3.33 seconds across content discovery, Phase 22 CLI scope/reporting, Stage C remediations and the earlier CLI working-directory failure.
- **Windows:** No test result is claimed. The Python launcher could not start in this Windows workspace; Phase 22 Windows ACL subprocess verification remains open.
- **Live-target testing:** None. No bounty target was contacted. Test results validate local code and fixtures only.
