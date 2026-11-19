# Project Audit Issues and Known Problems

This register lists only material unresolved project problems. When an issue is fixed and verified, remove it here; its implementation and tests remain traceable in Git history and the test suite. The earlier audit snapshots below are historical. The latest audit began from `99e2b61` on `main`; subsequent code checkpoints include `48d1f7e` and `b6308e8`. Current verification is recorded at the end. Findings about implementation are based on repository inspection and tests, not on live bounty targets.

## Open issues

### AUD-04 — Live OOB acceptance and Burp Collaborator polling remain open (Phases 9 and 18)

- **Severity:** Medium; affects confirmation of blind SSRF/XXE when no live callback provider is available.
- **Evidence:** `framework/ssrf/provider.py` supports the official `interactsh-client` CLI with private token config, bounded registration/polling/output, exact `full-id` matching, and normalized events. Unit coverage uses a fake process. A Kali self-check on 2026-11-19 found the client installed, but it exited before registering a canary. `CollaboratorOobProvider` still has no live polling adapter. SSRF/XXE registration exceptions stop before target dispatch.
- **Impact:** Blind findings remain unconfirmed if the external service is unreachable, not installed, or the target cannot make callbacks. Burp Collaborator remains unavailable.
- **Remediation:** Verify one end-to-end callback using a researcher-owned test endpoint and an explicitly authorized, controlled test; implement Collaborator polling only if the project needs it.
- **Acceptance gate:** The owned test endpoint produces an attributable callback with exact correlation and fresh evidence; mock providers remain simulation-only. Do not claim live acceptance from unit tests.

### AUD-06 — Phase 1 ASN attribution remains unavailable

- **Severity:** Medium; network ownership context remains incomplete, and asset coverage must not be overstated.
- **Evidence:** `scripts/bb-assets --subfinder` invokes a bounded passive provider, rejects out-of-scope results, records provider-source metadata, and persists valid discoveries. TLS SAN enrichment is wired into bounded asset discovery with scope checks, public-IP pinning, SNI, and a discovery-wide handshake budget; tests use mocked sockets and certificates. ASN attribution still defaults to `UNKNOWN`. `--depth` by itself does not discover names.
- **Impact:** Assets absent from passive sources or supplied seeds may be missed; network ownership context remains unknown. Certificate names are discovery leads, not proof of endpoint ownership or service identity.
- **Remediation:** Add an opt-in ASN attribution provider with privacy, rate, output, and failure bounds, or continue to report ASN as unknown. Keep the TLS SAN limits visible and do not use certificate names to bypass scope validation.
- **Acceptance gate:** A controlled ASN provider mock verifies in-scope attribution, nested graph persistence, provenance, exclusions, and fail-closed behavior. TLS SAN local fixtures cover scope, pinning, SAN filtering and budgets; no live target should be contacted for routine acceptance.

### AUD-07 — Phase 2 tool catalog is not an execution integration

- **Severity:** Medium; the current built-in reconnaissance is narrower than the tool catalog can suggest.
- **Evidence:** `scripts/bb-assets --subfinder` now invokes Subfinder explicitly. `config/tools.yaml` also describes httpx, Nmap, and other optional tools, but `scripts/bb-recon` continues to use its built-in bounded Python DNS/TLS/HTTP and port probes and does not launch those binaries.
- **Impact:** Installing a listed external scanner or configuring an API key does not automatically add it to `bb-recon`; integrated recon remains limited to built-in probes and the scoped asset inventory.
- **Remediation:** Decide which external tools should be integrated, then implement explicit invocation contracts with binary validation, offline scope preflight, constrained arguments, output/time/request bounds, and local-fixture tests. Until then, label entries as manual/available tools and avoid implying engine integration.
- **Acceptance gate:** Tests demonstrate the CLI's exact execution behavior, including disabled/manual mode, out-of-scope rejection, timeout, malformed output and tool failure.

### AUD-08 — Phase 21 production acceptance remains platform-limited

- **Severity:** Medium; affects deployment support and confidence in the installed dispatcher path.
- **Evidence:** Earlier Kali checks verified the installed dispatcher identity, socket access, status/ping, and invalid-approval rejection. New code separates the operator HMAC key into a service-only `bbdispatcher-keys` group, but the currently inspected Kali systemd unit has not yet been upgraded to that configuration and no program approval key is provisioned there. A successful operator-approved mutation through the installed service has not been run. Windows production service isolation is unsupported; historical Windows tests covered state permissions and development IPC, not a dedicated production service.
- **Impact:** The installed Linux service's successful authorized dispatch path lacks direct live-service acceptance evidence, and the Windows deployment boundary differs from Linux.
- **Remediation:** Upgrade the Kali unit and run a controlled, reversible Linux integration test using a dedicated test program/action and provisioned test keys. Treat Windows production dispatcher service isolation as unsupported unless a separate design and acceptance effort is approved; keep readiness status explicit.
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

- **Kali Linux, Python 3.14.10:** `python3 -m pytest tests/ -ra` — **1,245 passed, 1 skipped** in 576.12 seconds. The skipped test at that historical revision was a Windows-only DACL case. This was run before the current working-tree changes; it is not final verification of those changes.
- **Windows:** No full-suite result was obtained for this audit. The prior Phase 22 Windows ACL subprocess issue remains unresolved; do not treat Kali results as Windows evidence.
- **Live-target testing:** None. No bounty target was contacted. Unit and integration results are not proof of live vulnerability-discovery effectiveness.
- This baseline is retained for comparison only. It is superseded by the post-fix verification below.

## Post-fix verification at `c1a791f` (2026-11-18)

- **Kali Linux, Python 3.14.10:** `python3 -m pytest tests/ -ra` — **1,264 passed, 1 skipped** in 147.79 seconds. The single skip at that historical revision was a Windows-only DACL case.
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
- **Neighbor-phase regressions:** `python3 -m pytest tests/test_authz_engine.py tests/test_authentication_engine.py tests/test_ssrf_engine.py tests/test_phase18_*.py tests/test_phase21_*.py tests/test_phase23_research_planning.py tests/test_deploy.py tests/test_installer.py tests/test_installer_security.py -ra` — **423 passed, 2 skipped** in 163.21 seconds. The skipped tests at that historical revision were Windows path-canonicalization and DACL checks, which ran on hosted Windows.
- **Complete Kali suite:** `python3 -m pytest tests/ -ra --durations=10` — **1,277 passed, 2 skipped** in 393.52 seconds, across **72 test modules and 1,279 collected tests**. The two skips are Windows path-canonicalization and DACL checks.
- **Hosted platforms:** Ubuntu Python 3.10, Ubuntu Python 3.14, and Windows Server 2025 Python 3.14 full-suite jobs passed for code commit `48d1f7e` in [GitHub Actions run 44494335350](https://github.com/Veldora-0/BugBounty-Agent/actions/runs/44494335350).
- **Issue status:** The two confirmed Phase 22 bypasses were fixed and regression-tested. AUD-04, AUD-06, AUD-07, and AUD-08 remain open. AUD-09 records the intentional current limitation: Phase 22 has no trusted empirical receipt integration, so its validation CLI remains simulation-only and cannot promote a chain.
- **Live-target testing:** None. No bounty target was contacted. Results are local code, fixture, and hosted-OS evidence, not proof of live vulnerability discovery effectiveness.

## Historical checkpoint verification at `b6308e8` (2026-11-20)

The results below predate the current Linux-only test-policy edits. The two native Windows-only cases and Windows CI job have since been removed, along with the Windows service-status test. No tests were rerun for those removals at the user's request.

### Closure classification

| Issue | Classification | What the current evidence says | What closes it |
|---|---|---|---|
| AUD-04 | External dependency and Phase 9/18 live-acceptance gap | The Interactsh adapter is implemented, but the Kali self-check exited before canary registration; no target callback was attempted. Burp Collaborator polling is not implemented. | Verify a callback against a researcher-controlled endpoint using an authorized test, or keep live OOB confirmation explicitly unsupported. |
| AUD-06 | Separate asset-intelligence follow-up | Bounded TLS SAN enrichment is implemented and fixture-tested; ASN attribution remains `UNKNOWN`. | Add and test a bounded ASN provider, or formally keep ASN unknown as a documented Phase 1 limitation. |
| AUD-07 | Accepted product boundary or separate integration follow-up | `bb-recon` uses bounded built-in probes and does not launch most optional catalog tools. Documentation now states this directly. | Either keep the tools clearly manual/optional, or add a specific invocation path with scope, argument, timeout, output and failure tests for each integrated tool. |
| AUD-08 | Phase 24 production-acceptance blocker for Linux; Windows boundary is accepted as unsupported | The latest dispatcher key-group change is in code, but the installed Kali unit remains old and no approved mutation has been verified through the current system service. Windows has no production service isolation. | Privileged Kali upgrade, prove agent/service key separation, then execute one reversible approved test action and a rejection/replay set through the installed service. Keep Windows production dispatch unsupported unless separately designed and accepted. |
| AUD-09 | Phase 22 blocker for empirical vulnerability chaining | Candidate path correlation and reviewable plans work, but `bb-chain validate` is simulation-only and cannot promote empirical links. | Integrate trusted, single-use Phase 21 receipts with disk-backed evidence bound to the approved plan, target, scope and each edge; add adversarial receipt/evidence tests. |

- **Kali focused regressions:** `python3 -m pytest tests/test_dispatcher_config.py tests/test_interactsh_live_adapter.py tests/test_nuclei_integration.py tests/test_subfinder_integration.py tests/test_phase21_security.py -ra` — **46 passed** in 2.45 seconds.
- **Kali full suite at historical checkpoint:** `python3 -m pytest tests/ -ra --durations=10` — **1,329 passed, 2 skipped** in 382.29 seconds at `b6308e8`. The skips were Windows path-canonicalization and Windows DACL checks; hosted Windows CI passed those on this same code commit.
- **Hosted platforms at historical checkpoint:** GitHub Actions run [44584566317](https://github.com/Veldora-0/BugBounty-Agent/actions/runs/44584566317) passed the full Ubuntu Python 3.10/3.14 and Windows Python 3.14 matrix for `b6308e8`.
- **Latest Kali installed-host check (2026-11-20):** The checkout is clean on `main` at documentation commit `6e000ce`, with code unchanged from `b6308e8`. The dispatcher service is active, but `SupplementaryGroups` is empty, the agent is not in `bbdispatcher-keys`, the operator approval key is not readable/provisioned, and `sudo -n` requires a password. The updated service has not been installed.
- **Remaining issues:** AUD-04 is externally dependent on live OOB provider reachability; AUD-06 is limited to ASN attribution; AUD-07 is an explicit product integration boundary; AUD-08 still lacks upgraded-host and successful installed-service acceptance evidence; AUD-09 lacks trusted empirical evidence promotion. None is resolved by this focused test selection.
- **Live-target testing:** None. These tests used fixtures and did not contact a bounty target.
