# Project Audit Issues and Known Problems

This is the single consolidated register for material unresolved project problems found during the repository and documentation audit. Small documentation fixes made in this audit are not listed as open issues. Status is based on the local tree and matching `origin/main` at audit start (`e79038b`).

## Open issues

### AUD-01 — Phase 21 trusted execution path is intentionally disabled

- **Severity:** Critical for claiming Phase 21 Mode B completion; does not prevent safe observational research outside that path.
- **Evidence:** `framework/auth_correlation/provenance_boundary.py` sets `PROVENANCE_BOUNDARY_STATUS = "UNAVAILABLE"`; `framework/auth_correlation/ledger.py` disables execution-capability issuance; `framework/auth_correlation/revocation.py` disables controlled-workflow attestation issuance.
- **What works:** Kali systemd service runs as `_bbdispatcher:bbgroup`; the public verification key is installed; IPC works; the isolation script verifies identity, key/data permissions and rejection of a real invalid-approval request before execution. Windows test suite and Linux/Windows repository test results are recorded in the definitive report.
- **What remains unproven:** The negative invalid-approval test does not prove successful approved transport, evidence capture, capability minting, ledger persistence and independent attestation end to end. The gate code still rejects those outputs. Windows production service isolation is also not implemented.
- **Impact:** Phase 21 cannot claim trusted revocation or controlled execution findings through Mode B. Do not treat a dispatcher ping or test pass count as proof of successful authorized execution.
- **Recommended resolution:** Define a threat model and end-to-end protocol where OS-isolated service owns transport and signing authority; pin/rotate its verification key safely; bind approval, scope, exact request and evidence; make persistence atomic/replay resistant; document Linux/Windows support boundaries. Then add adversarial tests and independently review a successful authorized test workflow plus all rejection paths before enabling issuance.
- **Acceptance gate:** A test-only target and explicit approval demonstrate request dispatch, verifiable evidence, single-use receipt, ledger record and attestation, with no agent access to signing secrets or protected storage; altered/replayed/out-of-scope requests fail before dispatch on every claimed supported platform.

### AUD-02 — Contradictory Phase 21 verdicts remain in historical source documents

- **Severity:** High documentation correctness risk.
- **Evidence:** `PHASE-21-PLANNING-GATE.md`, `PHASE-21-FINAL-ACCEPTANCE-REPORT.md`, `PHASE-21-FINAL-SECURITY-ACCEPTANCE-REPORT.md`, and older sections of the baseline/roadmap contain accepted/closed verdicts; the definitive report later supersedes them and states Phase 21 is not accepted.
- **Impact:** A new contributor could rely on obsolete acceptance wording and enable unsafe assumptions about provenance.
- **Remediation:** The handbook and canonical roadmap now identify current status and point to this register and definitive report. Historical reports still contain contradictory passages and must be clearly stamped as superseded or archived in a later cleanup.
- **Acceptance gate:** No maintained document presents Phase 21 as accepted without a clear supersession notice and link to the current verdict.

### AUD-03 — Verification evidence differs in age and scope across phases

- **Severity:** Medium confidence/maintenance risk.
- **Evidence:** Phase 1–20 matrix and roadmap cite historical commit-specific counts; Phase 21 has recent Windows/Kali results, while some platform runtime tests skip for unavailable browsers or OS-only capabilities. Existing phase counts are not all re-run against current `main` during this documentation audit.
- **Impact:** Historical test numbers can be mistaken for current full regression or live-target coverage.
- **Remediation:** Phase guides now distinguish repository implementation from live effectiveness and call out limits. Add a repeatable CI matrix and dated acceptance manifests as part of Phase 24.
- **Acceptance gate:** Each maintained acceptance record identifies commit, exact commands, environment/dependencies, pass/skip/fail counts and untested live boundaries.

### AUD-04 — Live OOB integrations are not operationally confirmed

- **Severity:** Medium; affects confirmation of blind SSRF/XXE only.
- **Evidence:** Existing Phase 18 acceptance material reports that configured adapters lack operational live wire polling; simulated callbacks are explicitly not live findings.
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

## Audit boundaries

This register is a code/documentation audit, not a live-target security assessment. No bounty target was contacted. The repository's existing test/acceptance records were reviewed; tests were not rerun solely to create these documents. Review current program rules and scope before use.
