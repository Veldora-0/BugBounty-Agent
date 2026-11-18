# BugBounty-Agent Threat Model

**Version:** 1.0  
**Reviewed:** 2026-11-19  
**Applies to:** Local research workspaces, framework CLIs, global OpenCode deployment, and optional external tools.

This threat model describes the security boundaries the project intends to provide. It does not claim that every engine has achieved every control; phase guides and the [audit register](PROJECT-AUDIT-ISSUES.md) record implementation evidence and remaining gaps.

## Assets to protect

- Program scope, authorization notes, account roles, and test budgets.
- API keys, session cookies, test credentials, and provider secrets.
- Raw requests and responses, screenshots, callback identifiers, findings, and report drafts.
- Global OpenCode config and unrelated user agents, skills, commands, scripts, and permission rules.
- Integrity of the source checkout, installed wrappers, dispatcher key material, and approval receipts.

## Trust boundaries and actors

- **Researcher:** supplies authorization, scope, test accounts, and approval for sensitive follow-up actions.
- **Bug-Bounty orchestrator and skills:** treat scope and safety policy as hard boundaries; suggestions alone do not grant authorization.
- **Repository and installed deployment:** source-controlled files are trusted only after review; the global deployer must preserve unmanaged files and user edits.
- **External tools and public research sources:** output is untrusted data. Tool presence or a public report does not prove an in-scope vulnerability.
- **Targets and networks:** target behavior, redirects, DNS, service banners, and responses may be hostile or misleading.
- **Local operating system:** permissions and process isolation are relied on for private state; Windows and Linux service boundaries are not equivalent.

## Main threats and controls

| Threat | Expected control | Residual risk / evidence |
|---|---|---|
| Scope mistake causes unauthorized traffic | Offline scope validation, exclusions-first matching, target normalization, bounded requests, and explicit authorization assumptions | DNS and redirect behavior still require careful review. Each network-capable engine must be checked against its phase guide; no tool should be run on an unapproved target. |
| User data is destroyed during install or removal | Deployment manifest, atomic replacement, preflight collision checks, digest checks, exact config backup, and preservation of modified or unmanaged paths | Older deployments without a manifest may need manual cleanup; ambiguous copies are preserved. Test and review `bb-deploy --uninstall` output. |
| Credentials or target evidence enter Git or logs | Local workspace separation, ignored runtime paths, redaction, private file permissions, no automatic report submission | Redaction is not infallible. Review generated artifacts before sharing. Never place live secrets in fixtures or issues. |
| Tool output injects instructions or false findings | Treat tool output as data, validate candidates independently, require evidence and researcher review | Model interpretation can still be wrong; scanner output alone is never a confirmed finding. |
| Excessive or destructive testing causes harm | Hypothesis-driven tests, rate/time/request limits, non-destructive proofs, approval gates, and no auto-submit | Some optional tools have their own behavior and may not be wired to framework limits. Review scope and exact commands before manual use. |
| Approval or evidence is forged, replayed, or exposed | Separate dispatcher process, signed receipts, expiry/replay checks, least-privilege Linux service identity, local evidence controls | Windows production isolation is unsupported; live successful authorized dispatcher mutation still has an acceptance gap. See Phase 21. |
| Supply-chain compromise through dependencies or installers | Declared Python dependencies, registry allowlist, official source preference, no `curl | shell`, release review | Dependency lockfile and automated vulnerability scanning are not yet a complete release control. Review each dependency and installer change. |
| Public vulnerability research is mistaken for evidence | Attributed public references, sanitized metadata, non-evidence classification, no automatic report fetching | Public writeups may be stale or incomplete. They form hypotheses only and do not authorize testing. |

## Security invariants

1. No target-facing operation may start before scope and authorization checks pass.
2. Exclusions override inclusions; uncertain scope blocks the operation.
3. A tool installed or listed in a registry is not represented as integrated unless runtime code invokes it.
4. Findings require reproducible evidence and validation; hypothetical chains do not increase severity.
5. Secrets and real target evidence remain local and are redacted before output where possible.
6. Deployment and uninstall preserve unrelated or changed user files.
7. The researcher reviews evidence and reports; the software never submits a bounty report automatically.

## Review cadence

Review this model whenever a network-capable engine, credential flow, deployment path, dispatcher boundary, dependency installer, or evidence format changes. Each release review should identify which controls were tested, which were inspected only, and which remain unsupported. Live testing must use explicitly authorized targets; no live bounty target was contacted for this repository review.
