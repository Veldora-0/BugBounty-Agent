# Phase 24 — Final Integration and Production Readiness

**Status:** In progress. Kali is the primary research and local acceptance platform. Code checkpoint `7ac24ee` passed the full Kali suite (**1,344 passed** in 180.71 seconds); the later coverage/ASN checkpoint `91792b7` has a recorded full Kali suite of **1,352 passed** in 270.37 seconds. The IPv6 ASN query construction defect found during this review was fixed at `b212bff`; its focused Kali suite passed (**5 passed**). GitHub Actions uses Ubuntu Linux runners only for supplementary Python 3.10/3.14 CI checks; those jobs do not replace Kali acceptance. The two native Windows-only cases and Windows CI job have been removed; the current automated workflow targets Linux, and Linux-hosted mocked DACL failure cases remain. The updated Kali systemd dispatcher is installed; the root-run isolation verifier passed service identity, key/data isolation, agent IPC, and cross-process invalid-approval checks. A successful approved dispatch is still unverified because no disposable local test program or operator approval key is provisioned. This phase does not authorize a production release or any bounty-target testing.
**Main areas:** `framework/tools/`, `scripts/`, `.github/workflows/`, `docs/`, `tests/`, packaging and release configuration.

## Purpose

Phases 1–23 add capabilities for an authorized researcher: scope validation, asset and endpoint inventory, hypothesis-driven testing, finding validation, evidence handling, reporting, attack-path analysis, and coverage planning. Phase 24 makes the whole repository safer to install, update, diagnose, roll back, remove, and maintain.

Production readiness here is an operational standard, not a promise that the agent finds every vulnerability. A ready release must say which environments have evidence, identify unsupported behavior, preserve the researcher's data, fail closed when configuration is unsafe, and provide repeatable test results tied to a commit. No repository test proves the agent's effectiveness against a bounty target.

The primary environment is Kali Linux. Windows may be used for editing, but it is not a current test target and does not provide the Linux dispatcher service boundary. macOS and other Linux distributions are not assumed supported without test evidence. See [Supported Environments](../supported-environments.md).

## How Phase 24 fits the research workflow

1. Install the Python package into an isolated environment and check required packages with `bb-doctor`.
2. Deploy the canonical global agent, 18 skills, `/Arise` command, and CLI wrappers. The deployer checks destination ownership before it replaces anything.
3. Initialize a local program workspace from the directory opened in OpenCode. Program files are stored under its Git-ignored `programs/<name>/` directory and are not committed. Use a separate OpenCode directory when physical separation from the framework checkout is required.
4. Run diagnostics and inspect authorization and scope before any target-facing command.
5. Upgrade the Git checkout and redeploy. If a problem appears, return to a known commit and redeploy; do not delete program state to recover the framework.
6. Review the release checklist and environment-specific evidence before relying on a new version.

Phase 24 does not add vulnerability probes. It improves the operating envelope around the capabilities already described in Phases 1–23.

## Work areas and implementation

### 1. Supported environment and installation

The project declares Python 3.10 or later, but that declaration is not proof that every operating-system/version combination works. Documentation now separates the declared minimum from tested combinations. Kali Linux is primary; Windows production dispatcher isolation is unsupported; macOS is unverified.

The installation guide identifies PyYAML and `cryptography` as required runtime packages. Playwright belongs to an optional package extra, and its browser binary is a separate runtime requirement. Go, Git, Docker, `jq`, and external security tools are optional host tools rather than required Python dependencies.

The current GitHub Actions workflow runs the repository test suite on Ubuntu with Python 3.10 and 3.14. Earlier Windows jobs are historical and are not part of current platform support. Kali Linux remains a separate required local acceptance environment because GitHub's Ubuntu runner is not Kali.

### 2. Safe global deployment and configuration lifecycle

The global deployer writes the single `Bug-Bounty` agent, skills, `/Arise` command, and CLI wrappers into the OpenCode config and user bin directories. Earlier behavior removed any same-named skill or executable without checking ownership. The hardened deployer now:

- Creates a private deployment manifest in the OpenCode config directory. It records each installed destination, source, deployment mode, asset kind, and SHA-256 content fingerprint.
- Performs a preflight before the normal full deployment. Unmanaged collisions, modified copies, malformed manifest data, invalid JSONC, and invalid permission-rule shapes stop the run before it replaces managed files.
- Stages each asset beside its destination and atomically replaces only an unchanged asset recorded in the manifest. Symlink mode remains the default; copy mode is tracked by content hash.
- Does not remove the lowercase `bug-bounty.md` file. It may be user-owned, so duplicate detection reports it while deployment leaves it untouched.
- Parses JSONC comments and trailing commas without treating comment markers inside strings as comments. It retains user config keys and permission rules instead of deleting `agent` or `agents` entries.
- Saves the exact predeployment `opencode.jsonc` bytes in a private backup before its first edit. The deployer writes the configured file atomically and stops rather than replacing an invalid config.
- On uninstall, removes only unchanged assets attributable to the manifest. It restores the original config only while the deployed config is unchanged; edited, unmanaged, or ambiguous files are preserved and listed in the result.
- Includes CLI wrapper failures in the overall deployment result. Uninstall reports an error or partial removal rather than claiming success when files were preserved.

The ownership manifest is operational state, not a security boundary against a local administrator who deliberately edits it. If a deployment predates the manifest, old copies are ambiguous and are preserved until a person reviews them. The deployer does not remove the repository, Python environment, external tools, program workspaces, evidence, or credentials.

### 3. Program workspace and data lifecycle

Each program's scope, state, evidence, and reports live under `programs/<name>/` in the current OpenCode working directory by default. This path is Git-ignored; a normal Git update or global redeploy does not migrate or delete it. An older `~/BugBounty-Workspace` is not read or deleted automatically. The [runtime guide](../runtime.md) explains the current-directory default and legacy data handling.

This phase does not yet provide a general encrypted workspace backup utility or automatic schema migration system. Researchers must back up local workspaces according to their own storage policy. Any future migration must be versioned, validated before writing, recoverable from interruption, and tested on copies of representative state.

Scope validation remains the prerequisite for target-facing operations. A missing or malformed scope must continue to fail closed; a Phase 24 release review checks this behavior but does not replace the scope engine's phase-specific tests.

### 4. Update and rollback procedure

`bb-update` updates external tools registered in `config/tools.yaml`; it does not update the Git repository. A framework update uses Git, followed by `bb-deploy`. This prevents the word “update” from hiding whether the researcher is changing framework code or a separately installed scanner.

The documented rollback uses a known-good commit in a detached checkout and then reruns `bb-deploy`; it does not require creating a branch. This changes framework files only. It does not roll back program workspace data, tool versions, operating-system packages, or target state. A clean working tree and reviewed commit are required before starting.

Automated release installation, database migrations, and a one-command rollback are not implemented. Until those exist, the tested behavior is limited to code checkout, deployment synchronization, config backup/restore, and preservation checks.

### 5. Diagnostics and normal operation

`bb-doctor` now distinguishes required Python runtime packages from optional host tools. Its optional-tool section reports availability only; it does not claim that an engine invokes an installed executable. Version checks for optional tools run concurrently with a cap of eight workers, avoiding a possible five-second timeout per tool accumulating serially. Browser readiness and OpenCode deployment remain separate diagnostic categories. Provider configuration means that a value is present, not that the service accepted it or is wired into a research engine.

Before running a target-facing workflow, use `bb-doctor`, inspect the active program scope and exclusions, verify the relevant engine's capability, and review its budget. On operational errors, preserve the output without sharing secrets, cookies, target-private data, or raw evidence.

### 6. Security review and release evidence

The versioned [Threat Model](../THREAT-MODEL.md) identifies protected data, trust boundaries, likely failure modes, expected controls, and gaps that remain. The [Release Checklist](../release-checklist.md) defines a stop gate for versioning, dependency review, Linux/Kali test evidence, deployment lifecycle tests, dispatcher verification, and release notes.

The workflow grants only `contents: read` and pins its GitHub-maintained actions to full commit identifiers. This reduces mutable action-reference risk; it does not replace dependency review or a complete software supply-chain audit. No dependency vulnerability scanner or signed release artifact is established by this phase yet.

## Safety requirements

- Never broaden target scope, issue an unbounded scan, or infer authorization from a finding or public report.
- Diagnostics and release logs must not print credentials, cookies, private evidence, or sensitive target data.
- Install, update, rollback, and uninstall must preserve unmanaged files and user modifications.
- A configured API key or installed binary must not be represented as a live integrated capability without an invocation path and tests.
- A hypothetical attack chain must remain a hypothesis until each link has safe, in-scope supporting evidence.
- No automated report submission, destructive testing, denial of service, or credential attack is introduced by this phase.

## Acceptance status

| Acceptance area | Required evidence | Current state |
|---|---|---|
| Environment support | Full-suite evidence for every claimed environment; unsupported hosts clearly named | At `6ddbe49`, the full Kali suite and hosted Ubuntu Python 3.10/3.14 jobs passed. Earlier Windows jobs are historical only. macOS remains unverified and Windows production dispatcher isolation is unsupported. |
| Deployment lifecycle | Install, idempotent update, collision refusal, modified-file preservation, config restore, uninstall, rollback | Isolated Kali runs passed for copy and symlink modes, status, repeat deployment, uninstall, and byte-for-byte restoration of a pre-existing synthetic config. Detached-checkout rollback and forward redeploy passed in both modes without creating a branch or touching user state. Unit tests cover collision and modified-file preservation. |
| Workspace safety | Framework update and removal must preserve program data | Deployment was exercised with isolated temporary config/bin directories, and the implementation does not target program workspace paths. Workspace backup and migration remain separate future work. |
| Diagnostics | Required packages separated from optional tools and integrations; bounded runtime | Doctor and registry focused suite passed. Optional version checks now use a bounded worker pool; `bb-doctor` full diagnosis completed in under nine seconds in the latest full Kali suite. |
| Threat and release review | Versioned threat model, release gate, commit-linked evidence | Threat model, release checklist, and pinned-action CI workflow are present. Dependency advisory scanning, SBOM generation, and signed release artifacts are not implemented; stable release tagging remains subject to the checklist. |
| Installed dispatcher boundary | Updated systemd service identity and groups, key/data isolation, IPC, invalid approval and replay rejection; approved success path | Kali installation and `tests/verify-dispatcher-isolation.sh veldora` passed at code `6ddbe49`. The service uses `bbdispatcher-keys`; invalid approval was rejected before execution. No operator key or local acceptance program is configured, so successful approved dispatch and its receipt/evidence path remain unverified. |
| Scope authorization correction | Wildcard apex exclusion and authorization of each generated wildcard-DNS probe | Fixed at `7ac24ee`; the full Kali suite passed **1,344 tests**. See the scope regression record below. |
| Scope and live boundaries | Scope tests and honest separation of fixture/service evidence from live targets | Phase-specific tests and limits remain authoritative. No bounty target was contacted for Phase 24; repository tests do not establish detection effectiveness or bounty eligibility. |

## Verification record

All implementation evidence below is tied to code commit `9361df3d773c69a36859ad5f1e562a0df21a887b`. The following documentation checkpoint does not change the tested code. Platform jobs ran the repository's full test suite; the linked workflow provides the job records.

| Environment | Commit | Command | Result |
|---|---|---|---|
| Kali Linux x86-64, Linux `7.2.15+kali-amd64`, Python 3.14.10 | `9361df3` | `python3 -m pytest tests/ -ra --durations=10` | **1,272 passed, 2 skipped** in 147.36 seconds. Skips: Windows path-canonicalization and Windows DACL tests. |
| Kali Linux focused diagnostics | `9361df3` | `python3 -m pytest tests/test_doctor.py tests/test_tool_registry.py -ra --durations=5` | **18 passed** in 17.97 seconds; full doctor test took 11.78 seconds in this focused run. |
| GitHub Ubuntu, Python 3.10 | `9361df3` | Workflow `Tests`, `python -m pytest tests/ -ra` | Job passed. |
| GitHub Ubuntu, Python 3.14 | `9361df3` | Workflow `Tests`, `python -m pytest tests/ -ra` | Job passed. |
| GitHub Windows Server 2025, Python 3.14 | `9361df3` | Workflow `Tests`, `python -m pytest tests/ -ra` | Job passed, including native Windows path and DACL test coverage. |

The three hosted jobs are recorded in [GitHub Actions run 44381364848](https://github.com/Veldora-0/BugBounty-Agent/actions/runs/44381364848). On Kali, the diagnostic-only optimization reduced `test_doctor_full_diagnosis` from 275.75 seconds on the prior sequential implementation to 8.64 seconds on the final code commit.

**Deployment lifecycle evidence on Kali, commit `9361df3`:** Using temporary `OPENCODE_CONFIG_DIR` and `BUGBOUNTY_BIN_DIR` paths, copy and symlink modes each passed deploy, status, repeated deploy, and uninstall. The test began with a synthetic user JSONC config and verified uninstall restored its bytes exactly. Separate detached-checkout rollback exercises deployed commit `9361df3`, rolled back to `8434860`, redeployed `9361df3`, checked status at each step, uninstalled, and verified config restoration in both copy and symlink modes. The Kali checkout returned to `main`; no branch was created and the temporary directories were removed.

No live bounty target was contacted. Unit and local integration tests demonstrate code behavior on fixtures only; they do not establish detection rate, bounty eligibility, or authorization.

## Boundaries that remain after Phase 24 acceptance

1. Keep the project beta until open issues `AUD-04`, `AUD-07`, `AUD-08`, and `AUD-09` are resolved or deliberately accepted with the relevant capability limits visible to users. These cover live OOB callback confirmation, external reconnaissance tool execution, successful approved dispatcher acceptance, and empirical Phase 22 chain validation.
2. Treat macOS as unverified and Windows as development only. The current automated test matrix is Linux-only; the Linux systemd dispatcher is the only production service boundary currently implemented.
3. Before a stable tagged release, review dependency provenance and decide on a lockfile, automated advisory scanning, an SBOM, and signed release artifacts. The release checklist remains a stop gate.
4. Run the release checklist again for each release candidate; these results describe commit `9361df3`, not future source changes.

## Post-audit regression verification

This section records the audit of the Phase 22 evidence-promotion and scope-enforcement boundaries, plus regression coverage for neighboring phases. It supplements the Phase 24 implementation record above; the isolated deployment/rollback runs remain specifically tied to commit `9361df3`.

| Environment | Code commit | Command or workflow | Result |
|---|---|---|---|
| Kali Linux x86-64, Linux `7.2.15+kali-amd64`, Python 3.14.10 | `48d1f7e` | `python3 -m pytest tests/test_phase22_*.py tests/test_scope_fail_closed_validation.py -ra` | **125 passed** in 36.62 seconds. |
| Kali Linux neighbor-phase regression | `48d1f7e` | Phase 8, 14, 18, 21, 22, 23, deployment and installer test selection; exact command is recorded in the [issue register](../PROJECT-AUDIT-ISSUES.md#post-audit-regression-verification-at-48d1f7e-2026-11-19). | **423 passed, 2 Windows-only tests skipped** in 163.21 seconds. |
| Kali Linux x86-64, Python 3.14.10 | `48d1f7e` | `python3 -m pytest tests/ -ra --durations=10` | **1,277 passed, 2 skipped** in 393.52 seconds; 1,279 collected tests across 72 modules. |
| GitHub Ubuntu, Python 3.10 and 3.14 | `48d1f7e` | `Tests` workflow, `python -m pytest tests/ -ra` | Both full-suite jobs passed. |
| GitHub Windows Server 2025, Python 3.14 | `48d1f7e` | `Tests` workflow, `python -m pytest tests/ -ra` | Full-suite job passed, including native Windows path and DACL tests. |

The hosted jobs are recorded in [GitHub Actions run 44494335350](https://github.com/Veldora-0/BugBounty-Agent/actions/runs/44494335350). The audit confirmed and fixed two Phase 22 defects: simulation could previously manufacture evidence-shaped data for promotion, and scope authorization could rely on a prose marker while omitting other path assets. The current code emits no simulated evidence, requires a real `ScopeEngine`, binds every path target into the plan hash, and rechecks current scope before authorization and execution. Because no trusted empirical receipt integration exists yet, Phase 22 remains unable to empirically validate or promote links; this is tracked as AUD-09. No bounty target was contacted. These results establish regression behavior on tests and hosted operating systems, not live vulnerability-discovery effectiveness.

## Historical code verification at `b6308e8` (2026-11-20)

The full hosted matrix and Kali full-suite passed for code commit `b6308e8`, before the Windows-only test cases and Windows CI entry were removed. These results are historical. The current Linux-only test-policy edits were later verified at `6ddbe49`, as recorded below.

| Environment | Code commit | Command or workflow | Result |
|---|---|---|---|
| Kali Linux x86-64, Python 3.14.10 | `b6308e8` | `python3 -m pytest tests/ -ra --durations=10`; focused dispatcher/provider regression selection | Full: **1,329 passed, 2 skipped** in 382.29 seconds. Focused selection: **46 passed** in 2.45 seconds. |
| GitHub Ubuntu, Python 3.10 | `b6308e8` | `Tests` workflow, `python -m pytest tests/ -ra` | Passed. |
| GitHub Ubuntu, Python 3.14 | `b6308e8` | `Tests` workflow, `python -m pytest tests/ -ra` | Passed. |
| GitHub Windows Server 2025, Python 3.14 | `b6308e8` | `Tests` workflow, `python -m pytest tests/ -ra` | Passed, including Windows path and DACL checks. |

The hosted jobs are recorded in [GitHub Actions run 44584566317](https://github.com/Veldora-0/BugBounty-Agent/actions/runs/44584566317). The focused Kali selection covered dispatcher configuration, Interactsh adapter behavior, Nuclei and Subfinder integration, and Phase 21 security tests. The full test run did not contact a bounty target or prove live OOB reachability. At that historical checkpoint, the Kali host still ran the older dispatcher unit. The 2026-11-21 installation and verification are recorded in the current section below. Open issue classifications and required next evidence are maintained in the [audit register](../PROJECT-AUDIT-ISSUES.md#current-verification-and-classifications-at-6ddbe49-2026-11-21).

## Current code verification at `6ddbe49` (2026-11-21)

The tested source and test changes are committed at `6ddbe49c95e90806575dea59efc4c2877aba8cfe` on `main`. The exact commit is pushed to `origin/main`; GitHub Actions and Kali both report that commit. Documentation-only updates made after this checkpoint do not change the tested code.

This checkpoint hardens three linked security properties. Dispatcher approval and nonce registries now validate persisted state and fail closed on malformed input. Nonces are durably reserved under a cross-process lock before approval consumption and target transport, preventing concurrent or restart-based replay; state writes use atomic replacement and filesystem flushes. Controlled dispatch now verifies that both receipt-referenced evidence records can be read back from the configured evidence store and that their identifiers and SHA-256 digests match. The asset, reconnaissance, API-reference, and OOB documentation was also corrected to describe implemented limits instead of implying unimplemented sources or broader live acceptance.

| Environment | Commit | Command or workflow | Result |
|---|---|---|---|
| Kali Linux, Python 3.14.10 | `6ddbe49` | `python3 -m pytest tests/ -ra --durations=10` | **1,343 passed** in 163.11 seconds. |
| Kali focused dispatcher/security regressions | `6ddbe49` | `python3 -m pytest -q tests/test_phase21_preflight_and_revocation.py::test_controlled_attestation_security_matrix_d1 tests/test_phase21_dispatcher_state_hardening.py` | **15 passed.** |
| Kali dispatcher state/security remediation | `6ddbe49` | `python3 -m pytest -q tests/test_phase21_dispatcher_state_hardening.py tests/test_phase21_security_remediation.py` | **37 passed.** |
| GitHub Actions, Ubuntu Python 3.10 and 3.14 | `6ddbe49` | `Tests` workflow, `python -m pytest tests/ -ra` | Both jobs passed in [run 44887074727](https://github.com/Veldora-0/BugBounty-Agent/actions/runs/44887074727). |
| Kali installed dispatcher | `6ddbe49` | `sudo bash scripts/install-dispatcher.sh`; `sudo bash tests/verify-dispatcher-isolation.sh veldora` | Installer completed. Verifier passed service identity, service-only group, signing-key/data isolation, agent IPC, and cross-process invalid-approval rejection. |

The installed service is active with `SupplementaryGroups=bbdispatcher-keys`; its socket is owned by `_bbdispatcher:bbgroup` with mode `660`, and the pinned public key is installed as `root:root` mode `644`. The verifier confirmed `MISSING_APPROVAL_KEY` rejection before execution and no state/evidence mutation. No operator approval key or test program was provisioned, so no approved mutation, real service receipt, or successful dispatch evidence was produced. No bounty target was contacted. These checks establish the local isolation and rejection properties only; they do not establish live vulnerability-discovery effectiveness or authorize testing.

The remaining classifications are explicit: AUD-08 is a Phase 24 acceptance blocker for a successful approved local dispatch; AUD-04 depends on an externally reachable OOB provider and controlled callback endpoint; AUD-06 is an ASN coverage limitation; AUD-07 is a documented manual-tool boundary; and AUD-09 is a separate Phase 22 empirical-chain validation gap. Details and acceptance evidence are maintained in the [issue register](../PROJECT-AUDIT-ISSUES.md#current-verification-and-classifications-at-6ddbe49-2026-11-21).

## Scope regression verification at `7ac24ee` (2026-11-21)

The CleanShot program lists `*.cleanshot.cloud` but does not list the bare `cleanshot.cloud` apex. Offline evaluation exposed that the repository had treated the wildcard as authorizing its apex. The scope engine now requires a separate exact rule for that apex. The asset wildcard-DNS check now authorizes the two generated probe hostnames individually before resolving either one. This preserves wildcard reconnaissance when the exact names being queried are in scope, without widening authorization to the apex.

On Kali, `python3 -m pytest -q tests/test_scope.py tests/test_scope_fail_closed_validation.py` passed **23 tests**. The full suite `python3 -m pytest tests/ -ra --durations=10` passed **1,344 tests** in 180.71 seconds. GitHub Actions for exact code commit `7ac24eeff2f61ab88ba62ba7927761bdf3b8b41e` passed both Ubuntu Python 3.10/3.14 jobs in [run 44891701876](https://github.com/Veldora-0/BugBounty-Agent/actions/runs/44891701876). Only CleanShot's public policy and marketing pages were fetched. No vulnerability probes, authenticated tests, user-data access, or state-changing actions were performed.

## Starting points

Read the [installation guide](../installation.md), [supported environments](../supported-environments.md), [runtime guide](../runtime.md), [security policy](../security.md), [threat model](../THREAT-MODEL.md), [release checklist](../release-checklist.md), `framework/tools/deployer.py`, `framework/tools/doctor.py`, `tests/test_deploy.py`, and `tests/test_doctor.py`. The docs explain the intended operation; the test and acceptance records establish what has actually passed.
