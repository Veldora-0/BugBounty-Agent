# Project Audit Issues and Known Problems

This register lists material unresolved problems and accepted capability boundaries. When an issue is fixed and verified, remove it here; its implementation and tests remain traceable in Git history and the test suite. Earlier audit snapshots below are historical. The latest audit began from `99e2b61` on `main`; later code checkpoints include `48d1f7e`, `b6308e8`, `6ddbe49`, and `7ac24ee`. Current verification and issue classifications appear before the historical records. The latest target work used CleanShot's published scope for offline scope-engine checks; only public policy/marketing pages were fetched, with no vulnerability probes or authenticated tests.

## Open issues

## Phase 1–24 audit update (2026-11-27)

- **Repository state at review start:** `main` was synchronized with `origin/main` at `eb6d174`; the working tree was clean. This section records the current findings; remediation checkpoints are identified by their commit IDs when completed.
- **Kali Linux, Python 3.14.10:** The latest full-suite result recorded for the coverage/ASN code checkpoint `91792b7` is **1,352 passed** in 270.37 seconds. This is local code/fixture evidence, not live-target effectiveness. No Windows or WSL tests were run.
- **Phase 1 defect found:** IPv6 Team Cymru query names are derived from compressed IPv6 text and are not valid full reverse-nibble query names. Existing provider tests do not exercise IPv6 lookup query construction. AUD-06 is reopened until fixed and regression-tested.
- **Phase 2 boundary:** `bb-recon` uses bounded built-in probes and does not invoke catalog tools such as httpx/Nmap; this remains a disclosed integration limitation (AUD-07). Ubuntu appears only as a hosted Linux CI runner, not as the project's research-platform recommendation.
- **Remaining acceptance limits:** AUD-04 needs a controlled live callback endpoint; AUD-08 needs a disposable local program/key and successful approved action through the installed Kali service; AUD-09 needs trusted, per-edge receipt/evidence binding. Current fail-closed behavior remains in place pending those concrete prerequisites.

### AUD-04 — Live OOB acceptance and Burp Collaborator polling remain open (Phases 9 and 18)

- **Severity:** Medium; affects confirmation of blind SSRF/XXE when no live callback provider is available.
- **Evidence:** `framework/ssrf/provider.py` supports the official `interactsh-client` CLI with private token config, bounded registration/polling/output, exact `full-id` matching, and normalized events. Unit coverage uses a fake process. A Kali self-check on 2026-11-19 found the client installed, but it exited before registering a canary. `CollaboratorOobProvider` still has no live polling adapter. SSRF/XXE registration exceptions stop before target dispatch.
- **Impact:** Blind findings remain unconfirmed if the external service is unreachable, not installed, or the target cannot make callbacks. Burp Collaborator remains unavailable.
- **Remediation:** Verify one end-to-end callback using a researcher-owned test endpoint and an explicitly authorized, controlled test; implement Collaborator polling only if the project needs it.
- **Acceptance gate:** The owned test endpoint produces an attributable callback with exact correlation and fresh evidence; mock providers remain simulation-only. Do not claim live acceptance from unit tests.

### AUD-06 — Phase 1 ASN provider has an IPv6 query defect (open)

- **Severity:** Low; affects IPv6 ASN enrichment, not scope enforcement or active-probe authorization.
- **Evidence:** `framework/assets/asn.py` builds an IPv6 query by removing colons from `str(ip)`, which may be compressed, then reversing the remaining characters. Team Cymru IPv6 origin lookups require the reversed nibbles of the full expanded 128-bit address. Current tests cover IPv4 provider parsing and an IPv6 `UNKNOWN` fallback, but not IPv6 query construction or parsing.
- **Impact:** IPv6 asset ownership metadata can remain unknown even when the optional provider is available. The provider is opt-in, and the code remains fail-closed for target scope decisions.
- **Remediation:** Build the reverse name from `ip.exploded` (all 32 hexadecimal nibbles), validate the exact IPv6 query-name construction, and retain returned-prefix membership validation.
- **Acceptance gate:** Add offline mocked IPv6 query and response tests, including a compressed address, non-global address rejection, budget behavior, malformed response, and returned-prefix mismatch. No live lookup is required for code acceptance; never use ASN metadata as scope authorization.

### AUD-07 — Phase 2 tool catalog is not an execution integration

- **Severity:** Medium; the current built-in reconnaissance is narrower than the tool catalog can suggest.
- **Evidence:** `scripts/bb-assets --subfinder` now invokes Subfinder explicitly. `config/tools.yaml` also describes httpx, Nmap, and other optional tools, but `scripts/bb-recon` continues to use its built-in bounded Python DNS/TLS/HTTP and port probes and does not launch those binaries.
- **Impact:** Installing a listed external scanner or configuring an API key does not automatically add it to `bb-recon`; integrated recon remains limited to built-in probes and the scoped asset inventory.
- **Remediation:** Decide which external tools should be integrated, then implement explicit invocation contracts with binary validation, offline scope preflight, constrained arguments, output/time/request bounds, and local-fixture tests. Until then, label entries as manual/available tools and avoid implying engine integration.
- **Acceptance gate:** Tests demonstrate the CLI's exact execution behavior, including disabled/manual mode, out-of-scope rejection, timeout, malformed output and tool failure.

### AUD-08 — Phase 21 production acceptance remains platform-limited

- **Severity:** Medium; affects deployment support and confidence in the installed dispatcher path.
- **Evidence:** On 2026-11-21, the Kali installer deployed the updated systemd unit. The active service reports `SupplementaryGroups=bbdispatcher-keys`, and the socket and public verification key are present with expected ownership and modes. `sudo bash tests/verify-dispatcher-isolation.sh veldora` passed, checking service identity, service-only group, agent isolation from the private signing key and protected data, IPC access, and cross-process rejection of invalid approval before execution. No program scope or operator approval key is provisioned, so a successful approved mutation through the installed service has not been run. Windows production service isolation is unsupported.
- **Impact:** The installed Linux service's successful authorized dispatch path lacks direct live-service acceptance evidence, and the Windows deployment boundary differs from Linux.
- **Remediation:** The Kali unit upgrade and isolation check are complete. Run a controlled, reversible Linux integration test using a dedicated local acceptance program/action and disposable test keys; do not use a bounty target to test the local dispatcher. Treat Windows production dispatcher service isolation as unsupported unless a separate design and acceptance effort is approved; keep readiness status explicit.
- **Acceptance gate:** A supported-platform matrix includes successful and rejected dispatch through the actual service boundary, proves receipt/evidence binding and replay rejection, and records platform-specific unsupported behavior without overstating parity.

### AUD-09 — Phase 22 cannot empirically validate attack-path links

- **Severity:** Medium; candidate chains can be correlated and reviewed, but Phase 22 cannot currently demonstrate that a proposed edge or complete chain works against an authorized target.
- **Evidence:** `bb-chain validate` currently executes a deterministic simulation and explicitly makes no target request. The simulation has no evidence reference, digest, or observed impact, and `verify_evidence_and_promote` rejects simulated results and caller-constructed results without a live in-process authorization binding. This is fail-closed behavior after the audit remediation; no trusted Phase 21 dispatch receipt is yet connected to Phase 22 chain promotion.
- **Impact:** Paths stay hypotheses unless every impact-relevant link is proven through another separately trusted workflow. Reports must not describe simulation as empirical validation or use a theoretical chain to raise severity.
- **Remediation:** Integrate Phase 21's authenticated execution receipt and disk-backed EvidenceStore verification into the Phase 22 promotion boundary. Bind the receipt and evidence to the approved plan, current scope, target, execution, and freshness window; preserve single-use/replay protections and require evidence for each promoted edge.
- **Acceptance gate:** Add adversarial tests for missing, stale, altered, forged, cross-plan, and replayed receipts/evidence; prove that simulation never promotes a link, a real receipt can promote only its bound edge, partial chains remain partial, and full chains require proof for every edge. Do not weaken the current simulation or scope fail-closed behavior while integrating this capability.

## Audit boundaries

This register records repository review and current audit-run evidence, not a live-target security assessment. No bounty target was contacted. Review current program rules and scope before use.

## Current verification and classifications at `6ddbe49` (2026-11-21)

- **Kali Linux, Python 3.14.10:** `python3 -m pytest tests/ -ra --durations=10` — **1,343 passed** in 163.11 seconds. No Windows-only tests were run or added.
- **Focused security regressions:** `python3 -m pytest -q tests/test_phase21_preflight_and_revocation.py::test_controlled_attestation_security_matrix_d1 tests/test_phase21_dispatcher_state_hardening.py` — **15 passed**. The dispatcher state and security-remediation selection also passed: `python3 -m pytest -q tests/test_phase21_dispatcher_state_hardening.py tests/test_phase21_security_remediation.py` — **37 passed**.
- **GitHub Actions:** [run 44887074727](https://github.com/Veldora-0/BugBounty-Agent/actions/runs/44887074727) for exact code commit `6ddbe49c95e90806575dea59efc4c2877aba8cfe` completed successfully. The Ubuntu Python 3.10 and Python 3.14 jobs both passed.
- **Installed Kali dispatcher:** `sudo bash scripts/install-dispatcher.sh` followed by `sudo bash tests/verify-dispatcher-isolation.sh veldora` completed. The verifier reported the dispatcher alive, invalid approval rejected with `MISSING_APPROVAL_KEY` before execution, and passed service identity, service-only group, signing-key/data isolation, agent IPC, and cross-process invalid-approval checks. The active unit reports `SupplementaryGroups=bbdispatcher-keys`. No operator key, program configuration, or successful approved mutation was provisioned or attempted.
- **Live targets:** None contacted. These are local test, CI, and installed-service results; they do not show that the agent finds vulnerabilities on live bounty targets.

| Issue | Current classification | Remaining acceptance action |
|---|---|---|
| AUD-04 | External provider dependency and separate Phase 9/18 live-acceptance gap | Use a researcher-controlled endpoint for an authorized canary callback; otherwise keep live OOB confirmation unsupported. Burp Collaborator polling is optional follow-up. |
| AUD-06 | Open Phase 1 IPv6 enrichment defect; IPv4 lookup is opt-in | Correct full-nibble IPv6 query construction and add offline regression coverage. Leave ASN `UNKNOWN` when lookup is unavailable or not approved. |
| AUD-07 | Documented product boundary; optional integration follow-up | Add an explicit, tested invocation contract only for tools selected for integration. The current docs must not imply `bb-recon` launches them. |
| AUD-08 | **Phase 24 acceptance blocker** for full installed-service dispatch; Windows production isolation is an accepted unsupported boundary | Verify a successful approved, reversible action using a dedicated local acceptance program and disposable key, plus rejection and replay checks. Do not use an unspecified bounty target. |
| AUD-09 | Separate Phase 22 empirical-chain validation blocker | Integrate authenticated single-use receipts with disk-backed evidence bound to the plan, target, scope, and each edge; retain simulation fail-closed behavior. |

AUD-04, AUD-06, AUD-07, and AUD-09 do not invalidate the passing code tests or Linux dispatcher isolation check, but each limits the corresponding capability. AUD-08 remains open because the production service has only been tested for readiness and rejection; a successful approved dispatch has not been demonstrated.

## Scope-boundary fix at `7ac24ee` (2026-11-21)

- **Finding:** While translating CleanShot's published scope into an offline fixture, `*.cleanshot.cloud` incorrectly authorized the bare `cleanshot.cloud` apex. Wildcard-only authorization should cover descendants; the apex requires a separate exact rule. The asset wildcard-DNS check also checked the apex rather than the exact generated probe names.
- **Fix:** Wildcard rules no longer match their apex. Wildcard DNS detection authorizes each randomized hostname before resolving it, so an exact root may remain out of scope while allowed descendants are checked. Scope docs and the template now state the distinction.
- **Kali verification:** `python3 -m pytest -q tests/test_scope.py tests/test_scope_fail_closed_validation.py` — **23 passed**. The full suite `python3 -m pytest tests/ -ra --durations=10` — **1,344 passed** in 180.71 seconds.
- **Target-specific scope validation:** Offline scope evaluation accepted `cleanshot.com`, listed exact hosts, and wildcard descendants; rejected the wildcard-only apex, unlisted `random.cleanshot.com`, and excluded `docs.cleanshot.com`/`status.cleanshot.com`. No target vulnerability probes or authenticated tests were performed.
- **GitHub Actions:** The exact commit is pushed on `main`; supplementary Ubuntu Python 3.10/3.14 CI jobs passed in [run 44891701876](https://github.com/Veldora-0/BugBounty-Agent/actions/runs/44891701876). Kali remains the primary acceptance platform; these jobs do not represent target testing.

This fix closes a scope over-authorization defect. AUD-04, AUD-06, AUD-07, AUD-08, and AUD-09 remain open under their classifications above; the CleanShot public pages did not provide a researcher account or a safe endpoint for the live OOB and successful-dispatch checks.

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

The results below predate the current Linux-only test-policy edits. At this historical checkpoint, the two native Windows-only cases and Windows CI job had been removed, the service-status test retained its Linux assertions, and those edits had not yet been rerun at the user's request. They were later verified at `6ddbe49` in the current verification section above.

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
