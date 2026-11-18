# Phase 24 — Final Integration and Production Readiness

**Status:** In progress; deployment hardening, operational documentation, and a cross-platform CI gate are implemented. Final acceptance is still open until the new Linux/Kali and Windows results are recorded and remaining platform/service gates are resolved or explicitly accepted.
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

`bb-doctor` now distinguishes required Python runtime packages from optional host tools. Its optional-tool section reports availability only; it does not claim that an engine invokes an installed executable. Browser readiness and OpenCode deployment remain separate diagnostic categories. Provider configuration means that a value is present, not that the service accepted it or is wired into a research engine.

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
| Environment support | Clean install and full test evidence for every claimed environment | Support boundary documented. Kali rerun and newly configured CI results must be attached to the final Phase 24 commit; macOS remains unsupported/unverified. |
| Deployment lifecycle | Install, idempotent update, collision refusal, modified-file preservation, config restore, uninstall | Implementation and regression tests added. Kali test execution is pending for this checkpoint. A release-by-release copy-mode upgrade/rollback run is still required. |
| Workspace safety | Program state, evidence, credentials and reports survive code update/removal | Repository/workspace separation documented. No destructive workspace operation is included in deployment. A separate workspace backup/migration utility is future work. |
| Diagnostics | Required packages separated from optional tools and real integrations | Doctor implementation and regression test added; current Kali verification pending. |
| Threat and release review | Versioned threat model, release gate, commit-linked evidence | Threat model, checklist and CI workflow added. Dependency scanning, signed artifacts and successful CI results remain open. |
| Scope and live boundaries | Scope tests and documented separation of fixture/service evidence from live targets | Existing phase-specific tests and limits remain authoritative. No bounty target was contacted for Phase 24. |

## Verification record

Verification is not complete until this section is updated with the final code commit and the executed results. Record each command, environment, duration, counts, skips, and any remaining limitation. Do not copy historical counts as current evidence.

| Environment | Commit | Command | Result |
|---|---|---|---|
| Kali Linux | Pending | `python3 -m pytest tests/ -ra` | Pending for Phase 24 implementation |
| GitHub Ubuntu, Python 3.10 | Pending | Workflow `Tests` | Configured; run result not yet recorded |
| GitHub Ubuntu, Python 3.14 | Pending | Workflow `Tests` | Configured; run result not yet recorded |
| GitHub Windows, Python 3.14 | Pending | Workflow `Tests` | Configured; run result not yet recorded |

No live bounty target was contacted. Unit and local integration tests demonstrate code behavior on fixtures only; they do not establish detection rate, bounty eligibility, or authorization.

## Remaining work before Phase 24 acceptance

1. Run the focused deployment/doctor regression suite and then the full test suite on Kali from the repository root.
2. Push the workflow and code on `main`, wait for all Linux and Windows jobs, and record their exact results and commit.
3. Exercise deploy, repeated update, and uninstall against an isolated real OpenCode config directory while preserving a copy of the user's existing config.
4. Verify rollback from a known commit in copy and symlink modes without touching program workspaces.
5. Decide whether Windows service isolation and macOS support are out of scope or require implementation. Keep them explicitly unsupported until evidence exists.
6. Review dependency provenance and decide whether a lockfile, automated dependency advisory scan, and signed release artifacts are required for the first production-tagged release.
7. Resolve or explicitly accept the Phase 21, Phase 22, and Windows acceptance limits listed in the [audit register](../PROJECT-AUDIT-ISSUES.md).

## Starting points

Read the [installation guide](../installation.md), [supported environments](../supported-environments.md), [runtime guide](../runtime.md), [security policy](../security.md), [threat model](../THREAT-MODEL.md), [release checklist](../release-checklist.md), `framework/tools/deployer.py`, `framework/tools/doctor.py`, `tests/test_deploy.py`, and `tests/test_doctor.py`. The docs explain the intended operation; the test and acceptance records establish what has actually passed.
