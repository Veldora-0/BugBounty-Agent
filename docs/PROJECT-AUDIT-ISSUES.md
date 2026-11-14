# Project Audit Issues and Known Problems

This is the single consolidated register for material unresolved project problems found during the repository and code audit. Small issues fixed during the audit are recorded below. The audited source is commit `2787f6a` on `main`.

## Open issues

### AUD-01 — Phase 21 trusted execution path is intentionally disabled

- **Severity:** Critical for claiming Phase 21 Mode B completion; does not prevent safe observational research outside that path.
- **Evidence:** `framework/auth_correlation/provenance_boundary.py` sets `PROVENANCE_BOUNDARY_STATUS = "UNAVAILABLE"`; `framework/auth_correlation/ledger.py` disables execution-capability issuance; `framework/auth_correlation/revocation.py` disables controlled-workflow attestation issuance.
- **What works:** Kali systemd service runs as `_bbdispatcher:bbgroup`; the public verification key is installed; IPC works; the isolation script verifies identity, key/data permissions and rejection of a real invalid-approval request before execution. Windows test suite and Linux/Windows repository test results are recorded in the definitive report.
- **What remains unproven:** The negative invalid-approval test does not prove successful approved transport, evidence capture, capability minting, ledger persistence and independent attestation end to end. The gate code still rejects those outputs. Windows production service isolation is also not implemented.
- **Impact:** Phase 21 cannot claim trusted revocation or controlled execution findings through Mode B. Do not treat a dispatcher ping or test pass count as proof of successful authorized execution.
- **Recommended resolution:** Define a threat model and end-to-end protocol where OS-isolated service owns transport and signing authority; pin/rotate its verification key safely; bind approval, scope, exact request and evidence; make persistence atomic/replay resistant; document Linux/Windows support boundaries. Then add adversarial tests and independently review a successful authorized test workflow plus all rejection paths before enabling issuance.
- **Acceptance gate:** A test-only target and explicit approval demonstrate request dispatch, verifiable evidence, single-use receipt, ledger record and attestation, with no agent access to signing secrets or protected storage; altered/replayed/out-of-scope requests fail before dispatch on every claimed supported platform.

### AUD-03 — Verification evidence differs in age and scope across phases

- **Severity:** Medium confidence/maintenance risk.
- **Evidence:** Phase 1–20 matrix and roadmap cite historical commit-specific counts; Phase 21 has recent Windows/Kali results, while some platform runtime tests skip for unavailable browsers or OS-only capabilities. Existing phase counts are not all re-run against current `main` during this documentation audit.
- **Impact:** Historical test numbers can be mistaken for current full regression or live-target coverage.
- **Remediation:** Phase guides now distinguish repository implementation from live effectiveness and call out limits. Add a repeatable CI matrix and dated acceptance manifests as part of Phase 24.
- **Acceptance gate:** Each maintained acceptance record identifies commit, exact commands, environment/dependencies, pass/skip/fail counts and untested live boundaries.

### AUD-04 — Live OOB integrations for SSRF/XXE are unavailable (Phases 9 and 18)

- **Severity:** Medium; affects confirmation of blind SSRF/XXE only.
- **Evidence:** `framework/ssrf/provider.py` reports configured Interactsh/Burp Collaborator providers as `UNAVAILABLE` because live polling is not implemented; `framework/ssrf/engine.py` and `framework/xxe/engine.py` fail closed and keep simulated callbacks labeled as simulation. The Phase 1–20 baseline records this limitation for Phase 9, and Phase 18 acceptance records it for XXE.
- **Impact:** Blind server-side interaction hypotheses may remain unconfirmed even if local simulations pass.
- **Remediation:** Implement supported provider polling and credential configuration with safe correlation identifiers, timeout/rate limits, scope checks and auditable callback provenance, or keep status unavailable.
- **Acceptance gate:** An isolated owned test endpoint verifies attributable live callback receipt; mock providers remain labeled simulation and cannot create confirmed findings.

### AUD-05 — Package version metadata is inconsistent

- **Severity:** Low; release and support tooling may report conflicting versions.
- **Evidence:** `pyproject.toml` declares `1.1.0`, `framework/__init__.py` declares `1.0.0`, while `CHANGELOG.md` contains releases through `1.14.2` and further unreleased changes.
- **Impact:** Installers, diagnostics and bug reports may identify different versions for the same source tree.
- **Recommended resolution:** Decide the next release version, then update package metadata, runtime `__version__`, changelog and any release badges/tags together. No version was guessed during this audit.
- **Acceptance gate:** A single version source or automated consistency check ensures installed package, runtime and release notes agree.

## Small issues fixed in this audit

- Replaced the stale “temporary” roadmap's incorrect Phase 21 accepted/Phase 22-next status with the current canonical 24-phase status index.
- Added an onboarding handbook, 24 phase-specific guides, a consolidated issue register and future-improvements roadmap; pointed the canonical roadmap to these documents.
- Removed generated `.pytest_cache/` and `bugbounty_agent.egg-info/` artifacts from the working tree; they are reproducible and ignored. Kept `.planning/`, `state/`, and `evidence/` because they contain planning history or runtime/user data rather than disposable build output.
- Increased the artificial race window in `LocalConcurrencyLab` after a full Windows run reproduced a scheduling-sensitive false negative in the Phase 20 voting-limit fixture. This changes only the local simulation timing; production target request timing is unaffected. The adjusted test passed 20 consecutive isolated runs, followed by the full Windows suite.
- Disabled ambient `HTTP_PROXY`/`HTTPS_PROXY` inheritance in scope-checked pinned transports used by Phases 2/3/4/5/6/10. Python's default `urllib` opener can otherwise route through an environment proxy and let that proxy resolve the destination independently of the locally vetted/pinned address. Added a regression test for the shared transport. This was a small, cross-cutting fix and is not an open issue.
- Bandit static scan findings were manually triaged: standard XML parsing occurs only after a bounded Expat security-inspection pass; tar extraction has path/symlink/special-file validation plus Python's data filter where available; installer URLs are constrained to fixed GitHub endpoints and archives require a pinned SHA-256; dispatcher socket mode `0660` is intentional for the dedicated service group. The proxy finding was actionable and has been fixed.
- Fixed a real installer error-path defect: malicious TAR symlink rejection interpolated an undefined variable, raising `NameError` instead of the documented `InstallerSecurityError`. Added an adversarial archive regression test.
- Marked contradictory historical Phase 21 acceptance reports as superseded at the top of each document and replaced the stale roadmap path with a pointer to the canonical status. The old acceptance text is retained as historical record, not current status.

## Audit boundaries

This register records repository review and current audit-run evidence, not a live-target security assessment. No bounty target was contacted. Review current program rules and scope before use.

## Verification performed for audited commit `2787f6a`

- **Kali Linux, Python 3.14.8:** `python3 -m pytest tests/ -ra` — **1,109 passed, 1 skipped**. The sole skip is the Windows-only DACL test.
- **Windows, Python 3.14.7:** Full suite before the final TAR error-message fix — **1,103 passed, 6 skipped**. Six skips: two real-browser tests because Chromium/Firefox were unavailable and four POSIX-only permission/socket tests. The final TAR symlink and ambient-proxy regressions both passed in a focused run.
- **Phase 20 fixture stability:** The previously failing voting-limit test passed 20 consecutive Windows repetitions after the local timing adjustment.
- **Static security scan:** Bandit scanned 51,075 lines. Findings were reviewed; proxy inheritance was fixed, while archive extraction, XML parser and permission flags were assessed against the code's explicit guards and documented service group design.
- **Documentation:** `git diff --check` passed; relative Markdown links were checked before the final tooling guide was added.
