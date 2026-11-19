# Project Audit Issues and Known Problems

This register lists only material unresolved project problems. When an issue is fixed and verified, remove it here; its implementation and tests remain traceable in Git history and the test suite. The earlier audit snapshots below are historical. The latest audit began from `99e2b61` on `main` and its remediation checkpoint is `48d1f7e`; current evidence is recorded at the end. Findings about implementation are based on repository inspection and tests, not on live bounty targets.

## Open issues

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

### AUD-09 — Phase 22 cannot empirically validate attack-path links

- **Severity:** Medium; candidate chains can be correlated and reviewed, but Phase 22 cannot currently demonstrate that a proposed edge or complete chain works against an authorized target.
- **Evidence:** `bb-chain validate` currently executes a deterministic simulation and explicitly makes no target request. The simulation has no evidence reference, digest, or observed impact, and `verify_evidence_and_promote` rejects simulated results and caller-constructed results without a live in-process authorization binding. This is fail-closed behavior after the audit remediation; no trusted Phase 21 dispatch receipt is yet connected to Phase 22 chain promotion.
- **Impact:** Paths stay hypotheses unless every impact-relevant link is proven through another separately trusted workflow. Reports must not describe simulation as empirical validation or use a theoretical chain to raise severity.
- **Remediation:** Integrate Phase 21's authenticated execution receipt and disk-backed EvidenceStore verification into the Phase 22 promotion boundary. Bind the receipt and evidence to the approved plan, current scope, target, execution, and freshness window; preserve single-use/replay protections and require evidence for each promoted edge.
- **Acceptance gate:** Add adversarial tests for missing, stale, altered, forged, cross-plan, and replayed receipts/evidence; prove that simulation never promotes a link, a real receipt can promote only its bound edge, partial chains remain partial, and full chains require proof for every edge. Do not weaken the current simulation or scope fail-closed behavior while integrating this capability.

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

## Phase 24 verification at `9361df3` (2026-11-19)

- **Kali Linux x86-64, Python 3.14.10:** `python3 -m pytest tests/ -ra --durations=10` — **1,272 passed, 2 skipped** in 147.36 seconds. The two skips are the Windows path-canonicalization and Windows DACL tests.
- **Hosted Windows Server 2025, Python 3.14:** The full test suite passed in GitHub Actions; it exercises native Windows DACL and path behavior that Kali skips. Hosted Ubuntu Python 3.10 and 3.14 full-suite jobs also passed. See [workflow run 44381364848](https://github.com/Veldora-0/BugBounty-Agent/actions/runs/44381364848).
- **Deployment and rollback:** Isolated copy and symlink deploy, repeated deploy, status, uninstall, byte-for-byte config restoration, and detached-checkout rollback/forward redeploy passed on Kali. Temporary config/bin paths were used; no program workspace was modified.
- **Diagnostics:** 18 focused doctor/tool-registry tests passed in 17.97 seconds. `test_doctor_full_diagnosis` took 8.64 seconds in the full suite after bounded parallel tool checks were implemented; it previously took 275.75 seconds.
- **Issue status:** AUD-03 is removed because cross-platform full-suite CI evidence is now available. AUD-04, AUD-06, AUD-07, and AUD-08 remain open and continue to limit feature coverage or live-service acceptance.
- **Live-target testing:** None. No bounty target was contacted. These results are fixture, deployment, and hosted-OS evidence only; they are not proof of live vulnerability discovery effectiveness.

## Post-audit regression verification at `48d1f7e` (2026-11-19)

- **Starting point:** Clean `main` at `99e2b61f2dd7bff9d2af1f996b8b339e809bafaa`. Findings were reproduced before changes. The source remediation is commit `48d1f7e1eafe5c51724558188b91ca6a56137524`.
- **Confirmed findings fixed:** Phase 22 simulation previously fabricated evidence-shaped values and could promote simulated graph state; dispatch authorization could also fall back to a prose `IN_SCOPE` marker and did not bind every path target. The fix removes fabricated simulation evidence, prevents simulated or unbound caller-created results from promotion, requires a real `ScopeEngine`, binds all path assets/URLs into the plan hash, and rechecks scope at authorization and immediately before execution.
- **Focused Phase 22 and scope suite, Kali Linux x86-64 / Python 3.14.10:** `python3 -m pytest tests/test_phase22_*.py tests/test_scope_fail_closed_validation.py -ra` — **125 passed** in 36.62 seconds.
- **Neighbor-phase regressions:** `python3 -m pytest tests/test_authz_engine.py tests/test_authentication_engine.py tests/test_ssrf_engine.py tests/test_phase18_*.py tests/test_phase21_*.py tests/test_phase23_research_planning.py tests/test_deploy.py tests/test_installer.py tests/test_installer_security.py -ra` — **423 passed, 2 skipped** in 163.21 seconds. The skipped tests are Windows path-canonicalization and DACL checks, which run on hosted Windows.
- **Complete Kali suite:** `python3 -m pytest tests/ -ra --durations=10` — **1,277 passed, 2 skipped** in 393.52 seconds, across **72 test modules and 1,279 collected tests**. The two skips are Windows path-canonicalization and DACL checks.
- **Hosted platforms:** Ubuntu Python 3.10, Ubuntu Python 3.14, and Windows Server 2025 Python 3.14 full-suite jobs passed for code commit `48d1f7e` in [GitHub Actions run 44494335350](https://github.com/Veldora-0/BugBounty-Agent/actions/runs/44494335350).
- **Issue status:** The two confirmed Phase 22 bypasses were fixed and regression-tested. AUD-04, AUD-06, AUD-07, and AUD-08 remain open. AUD-09 records the intentional current limitation: Phase 22 has no trusted empirical receipt integration, so its validation CLI remains simulation-only and cannot promote a chain.
- **Live-target testing:** None. No bounty target was contacted. Results are local code, fixture, and hosted-OS evidence, not proof of live vulnerability discovery effectiveness.
