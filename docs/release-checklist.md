# Release Checklist

Use this checklist before tagging or distributing a release. It is a stop gate: mark each item with a commit-linked result, or leave the release unreleased and document the blocker. A passing local unit suite is not proof of live vulnerability discovery.

## 1. Source and version

- [ ] Work on the existing `main` branch; inspect `git status` and the full diff.
- [ ] Update `pyproject.toml`, `CHANGELOG.md`, and release notes consistently.
- [ ] Confirm the repository contains no real targets, credentials, cookies, evidence, reports, or local workspace state.
- [ ] Review dependency changes, installer sources, licenses, and provenance.
- [ ] Review [Threat Model](THREAT-MODEL.md), [Security Policy](security.md), and open issues.

## 2. Automated evidence

- [ ] Run `python3 -m pytest tests/ -ra` on Kali/Linux from the repository root.
- [ ] Record commit, OS/release, architecture, Python version, install extras, command, duration, pass/skip/fail counts, and relevant skip reasons.
- [ ] Run the required GitHub Actions jobs for Linux Python 3.10/3.14 and Windows Python 3.14; link the exact run and commit.
- [ ] Run browser-specific checks only with the optional browser extra and required browser binary installed; identify skips separately.
- [ ] Run `bb-doctor --json`; confirm required Python packages, optional tools, engines, and OpenCode deployment are described accurately.
- [ ] Exercise deployment in isolated temporary config and bin directories, including copy mode, idempotence, collision refusal, modified-file preservation, JSONC errors, config restoration, and uninstall.
- [ ] Verify Linux dispatcher integration separately from unit tests; do not infer successful authorized dispatch from invalid-approval rejection.

## 3. Security and operations

- [ ] Confirm scope fail-closed behavior and test budgets remain enforced.
- [ ] Confirm no automated target scan, destructive action, credential spraying, or report submission was introduced.
- [ ] Inspect diagnostic and error output for secrets and target-private information.
- [ ] Confirm backup, rollback, and uninstall preserve user configuration, evidence, and workspaces.
- [ ] Check known limitations in every affected phase guide and the [audit register](PROJECT-AUDIT-ISSUES.md).
- [ ] If a test fails, a platform job is missing, or required service evidence is unavailable, do not mark the release ready.

## 4. Release evidence record

Create a short record in the release notes with:

```text
Release/version:
Commit:
Kali/Linux result:
Windows result:
Browser result:
Dispatcher live-service result:
Known limitations:
Live-target testing: none / authorized test details
Reviewer:
```

Do not include secrets, target evidence, private program URLs, or exploit details in a public release record.
