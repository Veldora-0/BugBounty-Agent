# Phase 24 — Final Integration and Production Readiness

**Status:** In progress. Operational hardening, documentation and current hosted full-suite CI are in place; updated installed Linux dispatcher acceptance is still pending. The project remains beta, and this phase does not authorize a production release or close the capability limits listed in the audit register.
**Main areas:** `framework/tools/`, `scripts/`, `.github/workflows/`, `docs/`, `tests/`, packaging and release configuration.

## Purpose

Phases 1–23 add capabilities for an authorized researcher: scope validation, asset and endpoint inventory, hypothesis-driven testing, finding validation, evidence handling, reporting, attack-path analysis, and coverage planning. Phase 24 makes the whole repository safer to install, update, diagnose, roll back, remove, and maintain.

Production readiness here is an operational standard, not a promise that the agent finds every vulnerability. A ready release must say which environments have evidence, identify unsupported behavior, preserve the researcher's data, fail closed when configuration is unsafe, and provide repeatable test results tied to a commit. No repository test proves the agent's effectiveness against a bounty target.

The primary environment is Kali Linux. Windows is useful for development and CLI checks but does not provide the Linux dispatcher service boundary. macOS and other Linux distributions are not assumed supported without test evidence. See [Supported Environments](../supported-environments.md).

## How Phase 24 fits the research workflow

1. Install the Python package into an isolated environment and check required packages with `bb-doctor`.
2. Deploy the canonical global agent, 18 skills, `/Arise` command, and CLI wrappers. The deployer checks destination ownership before it replaces anything.
3. Initialize a local program workspace. Scope, credentials, evidence, findings, and reports remain local and are not part of the framework repository.
4. Run diagnostics and inspect authorization and scope before any target-facing command.
5. Upgrade the Git checkout and redeploy. If a problem appears, return to a known commit and redeploy; do not delete program state to recover the framework.
6. Review the release checklist and environment-specific evidence before relying on a new version.

Phase 24 does not add vulnerability probes. It improves the operating envelope around the capabilities already described in Phases 1–23.

## Work areas and implementation

### 1. Supported environment and installation

The project declares Python 3.10 or later, but that declaration is not proof that every operating-system/version combination works. Documentation now separates the declared minimum from tested combinations. Kali Linux is primary; Windows production dispatcher isolation is unsupported; macOS is unverified.

The installation guide identifies PyYAML and `cryptography` as required runtime packages. Playwright belongs to an optional package extra, and its browser binary is a separate runtime requirement. Go, Git, Docker, `jq`, and external security tools are optional host tools rather than required Python dependencies.

The new GitHub Actions workflow runs the repository test suite on Ubuntu with Python 3.10 and 3.14 and on Windows with Python 3.14. These are configured verification jobs, not evidence until they have completed successfully for the commit under review. Kali Linux remains a separate required local acceptance environment because GitHub's Ubuntu runner is not Kali.

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

Each program's scope, state, evidence, and reports live outside the repository under the configured workspace root. A normal Git update or global redeploy does not migrate or delete those directories. The [installation guide](../installation.md) explains the distinction and the no-data-loss behavior of global uninstall.

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

The versioned [Threat Model](../THREAT-MODEL.md) identifies protected data, trust boundaries, likely failure modes, expected controls, and gaps that remain. The [Release Checklist](../release-checklist.md) defines a stop gate for versioning, dependency review, Linux/Kali and Windows test evidence, deployment lifecycle tests, dispatcher verification, and release notes.

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
| Environment support | Full-suite evidence for every claimed environment; unsupported hosts clearly named | The later full-suite run at `48d1f7e` passed on Kali and hosted Ubuntu Python 3.10/3.14 and Windows Server 2025 Python 3.14 (see post-audit record). The deployment/rollback evidence below is from `9361df3`; macOS remains unverified and Windows production dispatcher isolation is unsupported. |
| Deployment lifecycle | Install, idempotent update, collision refusal, modified-file preservation, config restore, uninstall, rollback | Isolated Kali runs passed for copy and symlink modes, status, repeat deployment, uninstall, and byte-for-byte restoration of a pre-existing synthetic config. Detached-checkout rollback and forward redeploy passed in both modes without creating a branch or touching user state. Unit tests cover collision and modified-file preservation. |
| Workspace safety | Framework update and removal must preserve program data | Deployment was exercised with isolated temporary config/bin directories, and the implementation does not target program workspace paths. Workspace backup and migration remain separate future work. |
| Diagnostics | Required packages separated from optional tools and integrations; bounded runtime | Doctor and registry focused suite passed. Optional version checks now use a bounded worker pool; `bb-doctor` full diagnosis completed in under nine seconds in the latest full Kali suite. |
| Threat and release review | Versioned threat model, release gate, commit-linked evidence | Threat model, release checklist, and pinned-action CI workflow are present. Dependency advisory scanning, SBOM generation, and signed release artifacts are not implemented; stable release tagging remains subject to the checklist. |
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

1. Keep the project beta until open issues `AUD-04`, `AUD-06`, `AUD-07`, `AUD-08`, and `AUD-09` are resolved or deliberately accepted with the relevant capability limits visible to users. These cover live OOB callback confirmation, unavailable ASN attribution, external reconnaissance tool execution, live dispatcher mutation evidence, and empirical Phase 22 chain validation.
2. Treat macOS as unverified and Windows as development/CI only. The Linux systemd dispatcher is the only production service boundary currently implemented.
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

## Current code verification at `b6308e8`

The full hosted matrix and Kali full-suite passed for code commit `b6308e8`.

| Environment | Code commit | Command or workflow | Result |
|---|---|---|---|
| Kali Linux x86-64, Python 3.14.10 | `b6308e8` | `python3 -m pytest tests/ -ra --durations=10`; focused dispatcher/provider regression selection | Full: **1,329 passed, 2 skipped** in 382.29 seconds. Focused selection: **46 passed** in 2.45 seconds. |
| GitHub Ubuntu, Python 3.10 | `b6308e8` | `Tests` workflow, `python -m pytest tests/ -ra` | Passed. |
| GitHub Ubuntu, Python 3.14 | `b6308e8` | `Tests` workflow, `python -m pytest tests/ -ra` | Passed. |
| GitHub Windows Server 2025, Python 3.14 | `b6308e8` | `Tests` workflow, `python -m pytest tests/ -ra` | Passed, including Windows path and DACL checks. |

The hosted jobs are recorded in [GitHub Actions run 44584566317](https://github.com/Veldora-0/BugBounty-Agent/actions/runs/44584566317). The focused Kali selection covered dispatcher configuration, Interactsh adapter behavior, Nuclei and Subfinder integration, and Phase 21 security tests. The full test run did not contact a bounty target or prove live OOB reachability. The Kali host is still running the older installed dispatcher unit; its updated service-only approval-key group and a successful approved mutation require privileged installation and verification. Open issue classifications and required next evidence are maintained in the [audit register](../PROJECT-AUDIT-ISSUES.md#current-checkpoint-verification-at-b6308e8-2026-11-19).

## Starting points

Read the [installation guide](../installation.md), [supported environments](../supported-environments.md), [runtime guide](../runtime.md), [security policy](../security.md), [threat model](../THREAT-MODEL.md), [release checklist](../release-checklist.md), `framework/tools/deployer.py`, `framework/tools/doctor.py`, `tests/test_deploy.py`, and `tests/test_doctor.py`. The docs explain the intended operation; the test and acceptance records establish what has actually passed.
