# Phase 24 — Final Integration and Production Readiness

**Status:** Planned
**Main areas:** `scripts/`, `framework/tools/`, `docs/`, `tests/`, packaging and release configuration

## What this phase is for

Phases 1–23 add individual research capabilities and controls. Phase 24 is the work of making those pieces dependable to install, configure, operate, update, recover and maintain. It answers practical questions a researcher or maintainer has before using the project: which operating systems and Python versions are supported, how to confirm dependencies are ready, where sensitive workspace data lives, how an upgrade affects local state, and how to return to a known working version.

“Production ready” does not mean that every tool detects every vulnerability. It means that supported behavior is documented, operational failures are understandable, security boundaries are reviewed, and acceptance evidence is repeatable for the supported environments.

## What the planned work covers

### 1. Supported environment and installation

Choose and document supported Linux distributions, Windows versions, Python versions, shells, optional browser runtimes, and any required service manager. Test a clean installation on each supported platform. The installer should clearly separate required dependencies from optional tools such as browser automation or manually managed OSINT workbenches.

The install and deploy flow must explain which files are copied or linked, how global OpenCode agent/skill files are updated, and how to inspect the result. It should detect missing dependencies and incompatible versions before a researcher begins a run.

### 2. Configuration and local data lifecycle

Document how a program workspace is initialized, where its canonical scope file is stored, which settings are per-user versus per-program, and where credentials, state, findings, evidence, and reports are written. Provide safe backup and recovery instructions. Secret values and target evidence must stay outside Git by default.

The project should validate configuration before network activity. Missing or malformed scope, unavailable trust services, expired approvals, or exhausted budgets must produce a useful error and stop the operation.

### 3. Update, rollback and removal

Define an upgrade path that preserves local program state and explains schema compatibility. Provide a tested rollback to a previous release and a clean uninstall that removes only project-owned installed files. Verify that rollback and uninstall do not delete researcher evidence or user-created configuration.

### 4. Diagnostics and supported operation

Make `bb-doctor` report required and optional capabilities accurately. A configured API key should mean only that a value exists unless an actual provider connectivity check was explicitly requested; it must not imply that an engine integrates or invokes that provider. Diagnostics should identify the missing component, the affected feature, and the next safe repair step without printing secrets.

Document normal commands, expected output, cancellation, logs, permission errors, service health, key rotation, and recovery from interrupted work. Optional tools should be presented as integrated only when an engine really invokes them.

### 5. Security and release evidence

Maintain a threat model covering scope errors, unsafe redirects and DNS, untrusted tool output, credentials, evidence integrity, local permissions, dependency supply chain, and accidental disclosure. Review dependencies and externally downloaded installers. Each release should include version-consistent metadata, a changelog, supported-platform test results, security review notes, and a list of known limitations.

## How this fits the research workflow

Phase 24 does not add a new vulnerability test. It makes the existing workflow more predictable:

1. Install and check the supported runtime.
2. Create a local program workspace and confirm its scope file.
3. Run offline diagnostics before any target-facing operation.
4. Use bounded, scope-checked research capabilities and preserve local, redacted evidence.
5. Upgrade or recover without losing program state, and review release evidence before relying on new behavior.

## Safety requirements

- Installation and upgrade must not silently broaden target scope or enable unbounded scanning.
- Diagnostics must not expose credentials, raw cookies, private target data, or evidence content.
- Backup, rollback, and uninstall must protect user-owned workspaces and evidence.
- A tool's presence in the registry must not be represented as runtime integration unless code actually invokes it.
- Release checks must distinguish unit fixtures from live service or target verification.

## Acceptance criteria

- Supported operating systems and runtime versions are explicit and tested from a clean checkout.
- Install, deploy, upgrade, rollback, and uninstall are exercised on each supported platform, including checks that user data is preserved.
- Scope setup and configuration validation fail closed with clear errors.
- Diagnostics accurately distinguish installed tools, available providers, and capabilities actually wired into engines.
- A versioned threat model, dependency review, release checklist, and commit-linked acceptance record exist.
- Full test and static-check evidence reports commands, environment, commit, pass/skip/fail counts, and untested live boundaries.

## Current status and limits

This phase is planned. The repository already has installers, deployment scripts, `bb-doctor`, platform-specific permissions, and tests, but those pieces do not yet form a complete supported-platform upgrade/recovery/release process. Known cross-platform and external-tool integration issues are listed in the [project audit register](../PROJECT-AUDIT-ISSUES.md). Proposed follow-on work is in [Future Improvements](../FUTURE-IMPROVEMENTS.md).

## Starting points

Review [installation](../installation.md), [runtime](../runtime.md), [security policy](../security.md), [tool recommendations](../TOOLING-RECOMMENDATIONS.md), `tests/test_deploy.py`, `tests/test_installer.py`, and `tests/test_e2e_local_workflow.py`. These are inputs to the phase, not evidence that every Phase 24 acceptance criterion is complete.
