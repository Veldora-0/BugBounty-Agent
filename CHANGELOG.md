# Changelog

All notable changes to the BugBounty-Agent project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Phase 21 — Authentication & Authorization Correlation Engine (Partially Implemented; Not Accepted)

> The entries below include historical implementation and test records. Their older acceptance language is superseded: execution-capability and controlled-attestation issuance remain disabled. See [the current Phase 21 report](docs/PHASE-21-DEFINITIVE-SECURITY-ACCEPTANCE-REPORT.md) and [project issue register](docs/PROJECT-AUDIT-ISSUES.md) for current status.

#### Final Trust-Boundary & Acceptance Remediation (Blockers A–G)
* **Linux Service Isolation & IPC Permissions Hardening (Blocker B)**:
  * Hardened `/run/bugbounty` to mode `0750` owned by `_bbdispatcher:bbgroup` in `scripts/install-dispatcher.sh` and `systemd/bugbounty-dispatcher.service`, allowing group members to connect to the socket while preventing them from deleting or replacing `dispatcher.sock`.
  * Set `/var/lib/bugbounty/keys` and `state` to mode `0700` and `/var/lib/bugbounty/evidence` to `0750`.
  * In `IsolatedExecutionDispatcher.start()`, enforced that parent directories cannot be world-writable or group-writable without the sticky bit, and automatically tightened permissions when owned by the caller. UNIX socket file permissions set to `0660`.
* **Explicit Windows Service Isolation Status (Blocker A)**:
  * Marked Windows production service isolation under a dedicated service account as `NOT IMPLEMENTED` in `scripts/install-dispatcher.ps1` and `STATUS` response in `service.py`, maintaining Named Pipe IPC for local development and testing only.
* **Mandatory Operator Approval & Signature Verification (Blocker C)**:
  * Enforced mandatory operator approval key in `IsolatedExecutionDispatcher`; missing or malformed keys (< 32 bytes) reject dispatch fail-closed with `MISSING_APPROVAL_KEY` or `MALFORMED_APPROVAL_KEY`.
  * Enforced `verify_action_approval` on all incoming dossiers; invalid signatures reject dispatch with `INVALID_APPROVAL_SIGNATURE`.
* **Mandatory ScopeEngine & Safe Transport Routing (Blocker D)**:
  * Enforced mandatory `ScopeEngine` in production dispatch (`SCOPE_OR_DESTINATION_DENIED` if missing or unvetted).
  * Removed `urllib.request` fallback entirely; routed all production mutations through `safe_fetch_url()` with DNS pinning, intermediate redirect validation, and anti-SSRF protections.
* **Mandatory Receipt Verification & Client Nonce Binding (Blocker E)**:
  * Bound client-generated nonce (`client_nonce`) to IPC requests, verified inside signed HMAC receipts (`verify_execution_receipt()`), rejecting receipt tampering or replay across dispatches. Receipt verification key is strictly mandatory in `ControlledDispatchWorkflow`.
* **Evidence Integrity & Terminology Alignment (Blocker F)**:
  * Removed artificial placeholder capture files (`=== ISOLATED DISPATCH...`), enforcing disk-level verification via `EvidenceStore.get_evidence()`.
  * Clarified terminology across docs and comments to distinguish application-level sanitized HTTP request/response captures from raw wire packet captures.
* **Elimination of Security-Error Swallowing (Blocker G)**:
  * Replaced broad exception swallowing with explicit `PermissionError` and `OSError` raises across directory setup, chmod operations, key generation, and socket binding.
* **Focused 20-Test Security Suite (`tests/test_phase21_security_remediation.py`)**:
  * 20 adversarial tests validating all seven acceptance blockers: 17 passed, 3 skipped on Windows 11; 20 passed, 0 skipped on Kali Linux VM.
  * Phase 21 test suites: 162 passed, 4 skipped on Windows 11; 165 passed, 1 skipped on Kali Linux VM.
  * Full regression test suite: 1085 passed, 3 skipped on Windows 11; 1087 passed, 1 skipped on Kali Linux VM.
  * System diagnostics: all 18 diagnostic engines `[HEALTHY]` on both platforms.

#### Isolated Execution Architecture, Mode B Restoration & Final Security Remediation
* **Isolated OS-Enforced Dispatcher Authority (`framework/auth_correlation/ipc/`)**:
  * Implemented an independent execution authority service (`IsolatedExecutionDispatcher`) operating across framed IPC boundaries (Windows Named Pipes `\\.\pipe\bugbounty_dispatcher` and Unix Domain Sockets `/run/bugbounty/dispatcher.sock`).
  * Employs length-prefixed 4-byte big-endian framing with JSON payload validation, monotonic request IDs, and replay-resistant nonce tracking (`protocol.py`).
  * The dispatcher process maintains exclusive custody of private HMAC signing keys and the `authority_token`, completely eliminating caller-controlled provenance forging.
  * Emits cryptographically signed, canonical execution receipts (`receipt.py`) with HMAC-SHA256 (`RCPT-SIG-...`), binding action dossier digests, approval IDs, consumption tokens, and execution timestamps.
* **Controlled Dispatcher CLI & Service Integration (`scripts/bb-dispatcher`, `systemd/`)**:
  * Added `scripts/bb-dispatcher` and `scripts/bb-dispatcher.cmd` providing daemon startup, `--ping`, and `--status` management.
  * Added `systemd/bugbounty-dispatcher.service` and platform installation scripts (`scripts/install-dispatcher.sh`, `scripts/install-dispatcher.ps1`) for unprivileged production deployment under `_bugbounty-dispatcher` service accounts.
* **Private Authority Token Evidence Confinement (`framework/common/evidence.py`)**:
  * `EvidenceStore.save_transport_dispatch_capture()` enforces a private `authority_token` held exclusively in the isolated dispatcher process.
  * Ordinary callers or in-process workflows attempting to invoke transport evidence capture without the authority token fail closed with `EvidencePersistenceError("Trusted transport capture is disabled: caller-supplied request/response objects cannot prove transport dispatch")`.
* **Restoration of Mode B Controlled Invalidation (`framework/auth_correlation/dispatcher.py`, `framework/auth_correlation/revocation.py`)**:
  * Restored genuine Mode B controlled mutation execution in `ControlledDispatchWorkflow.execute` by routing transport execution to the isolated dispatcher over IPC.
  * Enforces fail-fast client preflight validation (action dossier schema, timestamp tolerances, scope verification, approval corruption checks) before delegating to the dispatcher.
  * Restored authentic `CONTROLLED_WORKFLOW` attestation verification in `PostRevocationResourceValidator.verify_invalidation_provenance()`, backed by receipt verification and ledger execution capabilities.
  * Cleaned up 251 lines of unisolated, vulnerable legacy in-process transport code.
* **Fail-Closed Capability Issuance & Ledger Verification (`framework/auth_correlation/ledger.py`)**:
  * `issue_execution_capability()` accepts only genuine `ControlledDispatchResult` objects backed by verified isolated dispatch receipts and signed evidence stores.
  * In-process caller-constructed objects fail closed with `ExecutionProvenanceError`.
* **Adversarial & Cross-Platform Test Verification**:
  * 146 Phase 21 targeted test items collected under pytest: 145 passed, 1 skipped on Windows 11 host (POSIX permissions skipped); 145 passed, 1 skipped on Kali Linux VM (Windows DACL skipped); 0 failures.
  * Full repository regression suite: 1088 tests collected (1085 passed, 3 skipped on Windows 11 host; 1087 passed, 1 skipped on Kali Linux VM; 0 failures).
  * 100% pass rate on browser runtime (103 tests), concurrency engine (128 tests), CLI tools (`bb-auth-correlate`, `bb-dispatcher`), and `bb-doctor` (all 18 engines healthy).
  * Complete resolution of all 20 historical security audit findings (Issues 1–20).

#### Final Execution Provenance Architecture Correction & Acceptance Gate (Commits `0f98435`, `PENDING_DOCS_COMMIT`)
* **Encapsulated Trusted Dispatch Boundary in `ControlledDispatchWorkflow`** (`framework/auth_correlation/dispatcher.py`):
  * Completely eliminated caller-controlled provenance generation by creating `ControlledDispatchWorkflow`, which encapsulates the entire Mode B lifecycle: preflight checks, atomic approval consumption, mutation transport dispatch, independent verification probe dispatch, evidence capture, and result sealing.
  * Emits immutable sealed `ControlledDispatchResult` (`is_genuine_dispatch = True`) binding internal `dispatch_op_id` (`DISP-OP-{token_hex(32).upper()}`).
* **Strict Transport Boundary Capture in `EvidenceStore`** (`framework/common/evidence.py`):
  * Removed public `save_controlled_transport_capture()` to prevent callers from manufacturing provenance strings.
  * Added `save_transport_dispatch_capture()` requiring authentic `ControlledRequest` and `ControlledResponse` instances and calculating deterministic SHA-256 wire digests directly from `request.build_wire_bytes()` and `response.body_bytes`.
  * Enforced fail-closed file security with POSIX mode `0o600` (verified via `os.stat().st_mode & 0o077 == 0`) and Windows DACL `SE_DACL_PROTECTED` via `win32security`, raising `EvidencePersistenceError` on permission failures without swallowing errors.
* **Fail-Closed Execution Capability Issuance** (`framework/auth_correlation/ledger.py`):
  * Bound `issue_execution_capability()` strictly to genuine `ControlledDispatchResult` instances.
  * Re-verifies all transport evidence entries in `EvidenceStore`, recalculates disk capture byte digests, verifies consumed approval receipts under `approval.key`, and validates that `dispatch_op_id` matches across all artifacts.
  * Enforces `mutation_evidence_ref != verification_evidence_ref` and `mutation_request_digest != verification_request_digest`.
* **Cross-Process Single-Use Approval Locking** (`framework/auth_correlation/state.py`):
  * Moved `CrossProcessFileLock` into `state.py` supporting Windows (`msvcrt.locking`) and POSIX (`fcntl.flock`) with timeout handling and private permissions.
* **Full Cross-Platform Verification (Zero Regressions)**:
  * 137 Phase 21 targeted tests collected: 136 passed, 1 skipped on Windows 11 host (POSIX permissions skipped); 136 passed, 1 skipped on Kali Linux VM (Windows DACL skipped); 0 failures.
  * Full regression test suite: 1079 tests collected (1076 passed, 3 skipped on Windows 11 host in 195.20s; 1078 passed, 1 skipped on Kali Linux VM in 213.07s; 0 failures).
  * System Doctor (`bb-doctor`): All 18 engines [HEALTHY] on both Windows 11 and Kali Linux; OpenCode Runtime [INSTALLED] on Kali.
  * Historical commit reference for the resolver test commit: `e76b2468e4d039674f81c76a5916aa366dca9b40`.

#### Definitive Execution Provenance Remediation, Approval Receipts & Adversarial Verification (Commits `756e511`, `e76b246`)
* **Strict Transport Provenance Isolation in `EvidenceStore`** (`framework/common/evidence.py`):
  * Rejects ordinary callers specifying `capture_source="CONTROLLED_TRANSPORT_DISPATCH"` or `evidence_class="CONTROLLED_TRANSPORT_DISPATCH"` via `save_http_capture()` with an immediate `ValueError`.
  * Added dedicated transport boundary method `save_controlled_transport_capture()` restricted to genuine Mode B controlled dispatches.
* **Cryptographically Signed Consumed Approval Receipts** (`framework/auth_correlation/ledger.py`, `framework/auth_correlation/revocation.py`):
  * Consumed approvals in `consumed_approvals.json` require both an operator signature (`SIG-...`) and a cryptographic consumption receipt HMAC (`RCPT-SIG-...`) computed under `approval.key`.
  * Added `sign_consumption_receipt()` and `verify_consumed_approval_entry()`, enforcing canonical JSON serialization and verifying that entries cannot be forged or manipulated without access to `approval.key`.
* **Fail-Closed Execution Capability Verification** (`framework/auth_correlation/ledger.py`):
  * Redesigned `issue_execution_capability()` with strict prerequisite verification: confirms disk transport captures, verifies byte digests, checks consumed approval receipt signatures under `approval.key`, and validates invalidation outcomes.
  * Added `create_test_execution_capability()` marked with `is_testing_primitive = True`.
  * Updated `record_execution()` to verify consumed approval receipts under cross-process file lock and reject testing primitives from producing genuine execution records.
* **Wire Fidelity & Correlation Header Attribution** (`framework/auth_correlation/revocation.py`):
  * Controlled invalidation captures actual wire request and response transactions via `ControlledRequest.get_sanitized_representation()` and `ControlledResponse.get_sanitized_representation()`.
  * Carries genuine HTTP correlation headers (`X-Correlation-Action`, `X-Correlation-Session`, `X-Correlation-Principal`) with distinct mutation and verification SHA-256 digests.
* **Windows File Replacement Resilience** (`framework/state/manager.py`):
  * Added 5-attempt retry loop with exponential delay to `StateManager._atomic_write_json()` to handle transient Windows file handle locks during rapid sequential state persistence.
* **Concurrency Test Harness Resilience** (`tests/test_concurrency_engine.py`):
  * Configured deterministic mock resolver in `test_request_budget_enforcement_blocks_exceeding_15` to ensure offline execution independence from external DNS.
* **Adversarial Security Test Suite** (`tests/test_phase21_execution_ledger.py`):
  * Expanded `tests/test_phase21_execution_ledger.py` to 61 tests: covers all 16 approval failure matrix rows, 30 adversarial tests (AT-01 to AT-30), 10 independent review attack scenarios, and end-to-end Mode B lifecycle.
* **Cross-Platform Verification (Zero Regressions)**:
  * 137 targeted Phase 21 tests collected: 136 passed, 1 skipped on Windows 11 host (POSIX permissions skipped); 136 passed, 1 skipped on Kali Linux VM (Windows DACL skipped); 0 failures.
  * Full regression test suite: 1079 tests collected (1076 passed, 3 skipped on Windows 11 host; 1078 passed, 1 skipped on Kali Linux VM; 0 failures).
  * 100% pass rate on browser runtime (103 tests), concurrency engine (128 tests), CLI tools (`bb-auth-correlate`), and `bb-doctor` (all 18 engines healthy).

#### Definitive Execution Provenance Remediation & Independent Security Acceptance (Commits `293b001`, `6192d5c`)
* **Elimination of Public Capability Minting Interfaces** (`framework/auth_correlation/__init__.py`):
  * Removed `issue_execution_capability`, `get_or_create_capability_key`, and `ExecutionCapability` from public package exports to prevent ordinary callers from constructing trusted execution provenance.
  * Capability issuance is strictly internal to the trusted Mode B controlled execution workflow (`framework/auth_correlation/revocation.py`).
* **Fail-Closed Approval Receipt Verification** (`framework/auth_correlation/ledger.py`):
  * Eliminated fail-open `if os.path.exists(consumed_path):` condition in `ExecutionLedger.record_execution()`.
  * Enforced fail-closed validation across all 16 approval receipt failure conditions: missing registry, unreadable registry, invalid JSON, invalid schema, missing receipt, wrong approval ID, wrong consumption token, wrong program, wrong test account, wrong target endpoint, wrong method, wrong action type, wrong session/principal, already executed, duplicate execution attempt, and replayed receipt.
  * Added atomic registration of `execution_id` in `consumed_approvals.json` under cross-process file lock before ledger persistence, ensuring single-use semantics and concurrency safety.
* **Controlled Transport Dispatch Evidence Tagging** (`framework/auth_correlation/ledger.py`, `framework/auth_correlation/revocation.py`):
  * Required mandatory `"capture_source": "CONTROLLED_TRANSPORT_DISPATCH"` on mutation and verification evidence metadata.
  * Both `ExecutionLedger.record_execution()` and `verify_invalidation_provenance()` fail closed if evidence is missing this tag or if on-disk SHA-256 byte digests do not match.
* **Adversarial Security Test Suite** (`tests/test_phase21_execution_ledger.py`):
  * Expanded `tests/test_phase21_execution_ledger.py` to 41 tests.
  * Added 16 dedicated tests covering all 16 approval receipt failure conditions (`test_approval_failure_row01_...` through `row16_...`).
  * Added 10 dedicated adversarial tests covering Attacks 1 through 10 (`test_attack_01_...` through `attack_10_...`).
* **Cross-Platform Verification (Zero Regressions)**:
  * 117 targeted Phase 21 tests collected: 116 passed, 1 skipped on Windows 11 host (POSIX permissions skipped); 116 passed, 1 skipped on Kali Linux VM (Windows DACL skipped).
  * Full regression test suite: 1059 tests collected (1056 passed, 3 skipped on Windows 11 host; 1058 passed, 1 skipped on Kali Linux VM).
  * 100% pass rate on browser runtime (103 tests), concurrency engine (128 tests), CLI tools, and `bb-doctor` (18 engines healthy).

#### Final Trust-Boundary Remediation & Definitive Acceptance (Commit `f078b093cddc13bb8fc7054d350451a431e4cb16`)
* **Genuine Execution Provenance & Capability Workflow** (`framework/auth_correlation/ledger.py`, `framework/auth_correlation/revocation.py`, `framework/auth_correlation/model.py`):
  * Eliminated arbitrary caller creation of execution records via `record_execution()`. Ordinary callers without a verified `ExecutionCapability` fail closed.
  * Established verifiable `ExecutionCapability` issued strictly upon successful completion of the trusted Mode B execution workflow.
  * Cryptographically signs 26 canonical capability fields under HMAC-SHA256 (`CAP-SIG-...`) using dedicated key `execution_capability.key` stored outside Git (`~/.config/opencode/` on POSIX, `%LOCALAPPDATA%\opencode\` on Windows).
  * Bound consumed approval receipt, session reference, principal, test account, target endpoint, method, action type, mutation and verification evidence references, disk-recomputed request/response digests, status codes, verification method, and single-use consumption token.
  * Added `is_testing_primitive = True` to low-level test helper records (`_record_raw_record_for_testing()`), ensuring Mode A attestation creation and verification strictly rejects test primitives.
* **Exact Evidence-to-Ledger Binding & Disk Byte Recomputation** (`framework/auth_correlation/ledger.py`, `framework/common/evidence.py`):
  * Persistence of execution records retrieves exact persisted capture bytes from `EvidenceStore`.
  * Recomputes SHA-256 byte digests over entire capture files and individual request/response sections from disk.
  * Verifies exact match with capability digests and `.meta.json`.
  * Verifies on-disk metadata (`session_ref`, `principal_id`, `program_id`, `event_type`, `verification_method`).
  * Rejects symbolic links and NTFS reparse points (`FILE_ATTRIBUTE_REPARSE_POINT`).
  * Strictly rejects cross-execution evidence reuse across both mutation and verification capture references.
* **Windows Security & DACL Enforcement** (`framework/auth_correlation/ledger.py`, `framework/auth_correlation/state.py`, `framework/auth_correlation/revocation.py`, `framework/common/evidence.py`):
  * Removed all `except Exception: pass` suppressions around Windows DACL enforcement (`_enforce_windows_directory_dacl`, `_enforce_windows_file_dacl`, `_verify_windows_path_security`).
  * Enforcement and verification failures fail closed immediately with `ExecutionProvenanceError` or `SerializationSecurityError`.
* **Adversarial Regression Test Suite** (`tests/test_phase21_execution_ledger.py`, `tests/test_phase21_preflight_and_revocation.py`):
  * Expanded `tests/test_phase21_execution_ledger.py` from 5 to 15 tests covering all 15 adversarial trust-boundary attack scenarios.
  * Updated test helpers in `test_phase21_preflight_and_revocation.py` to use capability workflow.
  * All 91 Phase 21 tests passed (90 passed, 1 skipped). All 1033 framework tests passed with zero regressions.

#### Final Security Remediation, Execution Ledger Provenance & Acceptance Closure (Commit `ee4fa74312116482f5f7df5cfc84a5c1c2a3b43e`)
* **Tamper-Evident Execution Ledger & Cryptographic Provenance** (`framework/auth_correlation/ledger.py`, `framework/auth_correlation/revocation.py`, `framework/auth_correlation/model.py`):
  * Replaced caller-instantiated dataclasses with a sealed internal `ExecutionLedger` (`state/execution_ledger.json`) backed by cross-process locking (`CrossProcessFileLock`) and atomic descriptor-based updates (`.tmp` + `os.replace`).
  * Bound execution records to an isolated HMAC-SHA256 key (`execution_ledger.key`) stored strictly outside the Git repository (`~/.config/opencode/` on POSIX, `%LOCALAPPDATA%\opencode\` on Windows).
  * Cryptographically signs 25 canonical execution fields under HMAC-SHA256 (`EXEC-SIG-...`) and generates deterministic execution IDs (`EXEC-...`).
  * Enforced single-use attestation claims (`claim_for_attestation`): execution records can only be claimed once, rejecting replay attacks and duplicate attestation issuance.
  * Verified on retrieval: `get_execution()` validates HMAC-SHA256 signature, SHA-256 identifier hash, and schema allowlisting.
* **EvidenceStore Hardening & Multiple Capture Lookup** (`framework/common/evidence.py`):
  * Hardened directory security: `_enforce_directory_security()` enforces private POSIX `0o700` and Windows Win32 protected DACLs (`SE_DACL_PROTECTED`) rejecting symlinks and unapproved principals.
  * Added `is_writable() -> bool` preflight probe.
  * Enforced `SAFE_PREFIX_PATTERN` preventing directory traversal.
  * Converted `save_http_capture()`, `save_invalidation_attestation()`, and metadata writes to atomic `.tmp` + `os.replace`.
  * Enhanced `get_evidence()` with path containment checks and on-disk SHA-256 byte recomputation; fixed multiple-capture scanning to skip missing or corrupted captures and find valid files.
* **Strict Invalidation Verification & Negative Statement Elimination** (`framework/auth_correlation/revocation.py`):
  * Eliminated loose substring matching; introduced `NEGATIVE_REVOCATION_PHRASES` explicitly rejecting negative statements (e.g. `"Your session was not revoked"`).
  * Implemented structured JSON parsing over `status`, `error`, `message`, `detail`, and `error_description` fields for positive revocation/expiration indicators.
  * Mandatory EvidenceStore verification before Mode B mutation dispatch; fails closed with `ApprovalSecurityError` if missing or unwritable.
  * Mandatory attribution checks enforcing `action_dossier["test_account"] == session_ctx.principal_id` and `action_dossier["program_id"] == self._program_id`.
  * Bound `session_ref` and `action_id` into mutation request evidence to prevent cross-session hash collisions.
* **Self-Contained CLI Simulation Lab** (`scripts/bb-auth-correlate`):
  * Set `workspace_root=lab_state_dir` ensuring lab execution is completely self-contained in its isolated temporary directory with zero pollution of the system temp directory.
* **Automated Regression Test Suite** (`tests/test_phase21_execution_ledger.py`, `tests/test_phase21_preflight_and_revocation.py`):
  * Added 5 new tests in `tests/test_phase21_execution_ledger.py` (total 81 tests in Phase 21 test suite).
  * Expanded `test_controlled_attestation_security_matrix_d1` to 32 security scenarios.
  * Full suite: 80 passed, 1 skipped in targeted Phase 21 suite; 1020 passed, 3 skipped on Windows 11 host. Zero regressions.

#### Final Attestation Security Remediation & Acceptance Closure (Commit `ba88a140a905a26de73ea4b50bbbdc9e38185c83`)
* **Genuine Controlled Invalidation Attestation & Verified Execution Binding** (`framework/auth_correlation/model.py`, `framework/auth_correlation/revocation.py`, `framework/common/evidence.py`):
  * Defined `ControlledExecutionResult` dataclass with fail-closed validation of all 17 execution and verification properties (`action_id`, `action_dossier_digest`, `mutation_evidence_ref`, `mutation_timestamp`, `mutation_status_code`, `mutation_response_digest`, `verification_evidence_ref`, `verification_timestamp`, `verification_status_code`, `verification_response_digest`, `verified_invalidation_state`, `verification_method`, `session_ref`, `principal_id`, `program_id`, `target_endpoint`, `executed_by`).
  * Enforced that genuine controlled invalidation attestations can only be generated from a verified `ControlledExecutionResult` via internal factory `_create_controlled_invalidation_attestation_from_result()`.
  * Updated public `create_controlled_invalidation_attestation()` to require `ControlledExecutionResult` and strictly reject caller-asserted action IDs.
  * Expanded canonical signed attestation fields to all 21 security-relevant properties (`CANONICAL_ATTESTATION_FIELDS`), cryptographically binding mutation evidence, verification evidence, action dossiers, and verification methods under HMAC-SHA256 (`ATT-SIG-...`).
* **Uncollidable EvidenceStore Invalidation Attestation Storage** (`framework/common/evidence.py`, `framework/auth_correlation/revocation.py`):
  * Upgraded `EvidenceStore.save_invalidation_attestation()` to store attestations primarily by `attestation_{attestation_id}.att.json` with a secondary lookup alias by `attestation_{original_evidence_ref}.att.json`, eliminating file collisions and accidental overwrites when distinct actions or sessions produce identical HTTP payload digests.
  * In Mode B controlled execution (`execute_controlled_invalidation`), differentiated mutation and verification HTTP evidence captures (`VERIFICATION [{method}]: ...`) to guarantee distinct SHA-256 evidence digests on disk.
* **Operator Attestation Trust Boundary Classification** (`framework/auth_correlation/revocation.py`):
  * Explicitly classified operator assertions as `OPERATOR_REPORTED` in `create_operator_invalidation_attestation()`.
  * Mode A revocation evaluation (`evaluate_revoked_session()`) strictly checks attestation trust level and fails closed to `("INCONCLUSIVE", None)` for any non-controlled attestation source (such as `OPERATOR_ATTESTATION`), preventing unverified human assertions from generating false `SESSION_NOT_INVALIDATED` vulnerability findings.
* **Security Regression Matrix** (`tests/test_phase21_preflight_and_revocation.py`):
  * Implemented 26-case Controlled Attestation Security Matrix D1 (`test_controlled_attestation_security_matrix_d1`): testing invalid action_id regex, missing dossier digest, invalid action_type, missing mutation ref, invalid mutation status, missing verification ref, invalid verification status, unapproved verification state, invalid verification method, session/principal/program attribution mismatches, invalid target endpoint, empty executor, missing attestation fields, tampering with any canonical field, invalid signature, payload tampering, wrong domain, unknown key ID, missing key file, missing mutation capture file, corrupted mutation capture bytes, missing verification capture file, corrupted verification capture bytes, and operator assertion disguised as controlled attestation.
  * Implemented 9-case Operator Attestation Security Matrix D2 (`test_operator_attestation_security_matrix_d2`): testing valid operator attestation creation, all 21 canonical fields present, valid signature verification, `OPERATOR_REPORTED` trust classification, rejection on tampered operator fields, rejection on tampered signature, provenance verification returning `OPERATOR_ATTESTATION`, and Mode A evaluation failing closed to `INCONCLUSIVE` (zero false `SESSION_NOT_INVALIDATED` findings).
* **Final Cross-Platform Verification Results (Commit `ba88a140a905a26de73ea4b50bbbdc9e38185c83`)**:
  * Windows 11: 76 Phase 21 tests (75 passed, 1 skipped in 9.72s), 1018 full suite tests (1015 passed, 3 skipped in 203.88s), bb-doctor all 18 framework engines [HEALTHY].
  * Kali Linux VM: 76 Phase 21 tests (75 passed, 1 skipped in 6.78s), 1018 full suite tests (1017 passed, 1 skipped in 680.77s), Firefox SPA integration test (1 passed in 14.30s), concurrency test (1 passed in 0.75s), bb-doctor all 18 framework engines [HEALTHY].

#### Security Corrections & Acceptance Closure (Commit `6b2fcd9c8afdcd4ac7e8bcb48c0144e6f131d860`)
* **Cryptographic Invalidation-Event Attestation System** (`framework/auth_correlation/revocation.py`, `framework/common/evidence.py`, `framework/auth_correlation/model.py`):
  * Separated ordinary evidence captures from authentic, trusted invalidation events via dedicated HMAC-SHA256 event attestations (`ATT-<SHA256>`).
  * Enforced dedicated attestation key separation: `invalidation_attestation.key` is stored strictly outside Git (`~/.config/opencode/` on POSIX, `%LOCALAPPDATA%\opencode\` on Windows) and is isolated from the Mode B operator action approval key (`auth_approval.key`).
  * Enforced canonical domain-separated payload structure (`BB_INVALIDATION_ATTESTATION_V1`), SHA-256 canonical hashing, and HMAC-SHA256 signatures (`ATT-SIG-<SHA256>`).
  * Enforced inheritance-disabled Windows Win32 protected DACLs (`_enforce_windows_directory_dacl`) and POSIX `0o700`/`0o600` private file permissions.
  * Implemented restricted attestation creation APIs: `create_controlled_invalidation_attestation` for Mode B verified mutations and `create_operator_invalidation_attestation` for auditable operator attestations.
  * Extended `EvidenceStore` with `save_invalidation_attestation()` and `get_invalidation_attestation()` supporting dual lookup by `ATT-...` identifier and `EVID-...` reference.
  * Hardened `verify_invalidation_provenance()` to verify cryptographic signatures, schema, domain, attribution (`session_ref`, `principal_id`, `program_id`), original capture existence, and on-disk SHA-256 byte integrity. Rejects ordinary un-attested captures and caller metadata. Distinguishes operator assertions from controlled workflows.
  * Added exhaustive 17-case provenance verification matrix test in `tests/test_phase21_preflight_and_revocation.py`.
* **Mandatory Fully Authenticated Pre-MFA Comparison Session** (`framework/auth_correlation/pre_mfa.py`, `framework/auth_correlation/engine.py`):
  * Made `full_session_ctx` a mandatory positional parameter in `PreMfaPrivilegeValidator.evaluate_pre_mfa_boundary()` (no default, cannot be None).
  * Enforced independent validator checks: `session_ctx.metadata["mfa_level"] == "PRE_MFA"`, `full_session_ctx.metadata["mfa_level"] == "FULL_MFA"`, distinct session references (`session_ctx.session_ref != full_session_ctx.session_ref`), and baseline 200 OK without landing/login/SPA shell.
  * Enforced fail-closed behavior with zero network dispatch on any invalid, missing, ambiguous, or equivalent session state.
  * Synchronized `AuthCorrelationEngine` to verify both sessions before dispatching preflight or baseline requests.
  * Expanded pre-MFA state enforcement matrix test to 15 cases verifying `engine.last_request is None`.
* **Cross-Platform Verification Results (Commit `6b2fcd9c8afdcd4ac7e8bcb48c0144e6f131d860`)**:
  * Windows 11: 74 Phase 21 tests (73 passed, 1 skipped in 8.72s), 1016 full suite tests (1013 passed, 3 skipped in 155.11s), bb-doctor 26/26 categories healthy.
  * Kali Linux VM: 74 Phase 21 tests (73 passed, 1 skipped in 7.14s), 1016 full suite tests (1015 passed, 1 skipped in 117.89s), Firefox SPA integration test (1 passed in 13.98s), concurrency test (1 passed in 0.69s), bb-doctor 26/26 categories healthy.

#### Added & Hardened
* **Anonymous Differential Preflight Protocol** (`framework/auth_correlation/preflight.py`):
  * Completed full 3-probe sequential verification sequence: Probe 1 (Principal A authenticated) $\rightarrow$ Probe 2 (Principal B authenticated) $\rightarrow$ Probe 3 (Anonymous control) $\rightarrow$ differential classification with anonymous control input.
  * Preserved sequential short-circuiting: authentication/authorization failures on Probe 1 or Probe 2 abort immediately before dispatching subsequent probes.
  * Fail-closed gating on anonymous control failures: anonymous control transport errors or HTTP 5xx responses fail closed to `FAILED`.
  * Equivalent response elimination: authenticated responses equivalent to anonymous control (SequenceMatcher similarity ratio $> 0.70$ or identical body text) fail closed to `UNKNOWN`.
  * Strict false-positive elimination: generic SPA shells, WAF challenges, login challenge forms, and empty bodies are classified as `UNKNOWN` or `AUTHENTICATION_FAILED`.
  * Synchronized `validate_single_session()` with identical differential comparison rules.
* **Evidence Provenance Verification & Capture Integrity** (`framework/auth_correlation/revocation.py`, `framework/common/evidence.py`):
  * Hardened `verify_invalidation_provenance()`: resolves caller-supplied evidence references (`EVID-...`) against `EvidenceStore.get_evidence()`, verifying descriptor structural schema (`evidence_id`, `filename`, `sha256`, `metadata`), 64-hex SHA-256 format, and `EVID-<12-hex>` prefix match.
  * Verifies presence and regular file status of capture files (`*.txt`), enforcing basename validation and preventing directory traversal.
  * Recomputes SHA-256 digest of on-disk capture bytes, ensuring capture content has not been tampered with or corrupted.
  * Rejects Mode A observation artifacts (`mode: "MODE_A"`, `category: "SESSION_NOT_INVALIDATED"`) reused as invalidation evidence.
  * Strictly requires explicit `event_type` from `GENUINE_INVALIDATION_EVENTS` (`SESSION_REVOCATION`, `LOGOUT`, `SESSION_INVALIDATION`, `PASSWORD_CHANGE`, `TOKEN_REVOCATION`, `ADMIN_SESSION_TERMINATION`) without fallback to `hypothesis_category` or `REVOCATION_ENFORCEMENT`.
  * Enforces mandatory, exact attribution matching across `session_ref`, `principal_id`, and `program_id`. Missing or foreign attribution fails closed.
  * Added `EvidenceStore.get_evidence()` returning `meta_copy` with resolved `meta_path` and `capture_path`.
* **Pre-MFA State Enforcement & Zero-Dispatch Boundary** (`framework/auth_correlation/pre_mfa.py`):
  * PreMfaPrivilegeValidator independently requires `session_ctx.metadata["mfa_level"] == "PRE_MFA"`.
  * Validates comparison session `full_session_ctx.metadata["mfa_level"] == "FULL_MFA"`.
  * Preflight verification strictly validates fully authenticated baseline is 200 OK and not a login/landing shell.
  * Rejects candidate sessions with missing, ambiguous, `NONE`, `UNKNOWN`, or malformed MFA metadata prior to probe dispatch, guaranteeing zero network traffic.
  * Exhaustive state enforcement matrix test verifies `engine.last_request is None` across all rejected states.
* **Mode A Scope Authorization at Dispatch** (`framework/auth_correlation/revocation.py`):
  * Enforced read-only `GET`/`HEAD` methods strictly.
  * Immediate `ScopeEngine.is_in_scope()` evaluation at dispatch boundary; live requests fail closed returning `("INCONCLUSIVE", None)` if `scope_engine` is absent or throws during evaluation.
  * Simulation transport validates target URL via `validate_target_url()`.
  * Bound `scope_engine` to `self.engine.scope_engine` to prevent redirect following from escaping program scope.
* **CLI & Production Fail-Closed Hardening** (`scripts/bb-auth-correlate`):
  * Added `--workspace` argument to support targeted workspace roots containing state, scope, and evidence.
  * Corrupted or invalid state files (`state/auth_correlation.json`) fail closed with exit code 1.
  * Active production mode without `--target`, with fewer than 2 registered principals or sessions, or with an out-of-scope target fails closed with exit code 1.
  * Missing or unverified action dossiers for `--approve-action` fail closed with exit code 2 (`ApprovalSecurityError`).
* **Mode A Revocation Orchestration & Gating** (`framework/auth_correlation/engine.py`, `framework/auth_correlation/revocation.py`):
  * Integrated Mode A `evaluate_revoked_session()` directly into `AuthCorrelationEngine.run_correlation()`.
  * Strictly observation-only using read-only requests (`GET` or `HEAD`); never initiates unsafe mutations without approval.
  * Mandatory evidentiary prerequisites: requires both legitimate baseline (`pre_revocation_baseline` with HTTP 200) and attributable invalidation evidence reference (`invalidation_evidence_ref`). Missing either prerequisite fails closed returning `INCONCLUSIVE` without emitting findings.
  * CLI `--revocation` and `--validate` trigger Mode A observation by default unless explicit operator approval (`approved_action_id` and `action_dossier`) triggers Mode B.
* **Conservative Revocation Response Classification** (`framework/auth_correlation/revocation.py`):
  * `classify_revocation_response()` conservatively classifies responses according to defensive security semantics:
    * HTTP 401 with explicit revocation keywords (`"revoked"`, `"token_revoked"`, `"session_invalidated"`, etc.) $\rightarrow$ `REVOKED`.
    * HTTP 401 with explicit expiration keywords $\rightarrow$ `EXPIRED`.
    * Generic HTTP 401 $\rightarrow$ `AUTHENTICATION_FAILED` (does not prove revocation).
    * HTTP 403 $\rightarrow$ `AUTHORIZATION_DENIED` (indicates authorization boundary, not session invalidation; neither 401 nor 403 creates findings).
    * HTTP 3xx redirect to login interface $\rightarrow$ `REDIRECT_LOGIN`.
    * WAF block, bot challenge, public landing page, or empty response $\rightarrow$ `INCONCLUSIVE`.
    * HTTP 200 OK matching protected baseline content ($\ge 0.50$ similarity) $\rightarrow$ `SESSION_NOT_INVALIDATED` finding emitted.
* **Candidate Discovery Contract & Scope Policy** (`framework/auth_correlation/engine.py`):
  * Candidate endpoints derived strictly from registered `resource_targets`, `resource_endpoints`, or explicit `target_asset` path.
  * Empty discovery strictly returns `[]` without inventing fabricated application routes (`/api/v1/tenant/invoices`, `/api/v1/profile` removed).
  * Candidate URLs validated via `_build_and_validate_target_url()` enforcing origin preservation and `ScopeEngine` authorization policy.
* **Truthful Evidence Persistence** (`framework/auth_correlation/revocation.py`, `framework/auth_correlation/tenant.py`, `framework/auth_correlation/pre_mfa.py`):
  * Strictly persists evidence captures via `EvidenceStore.save_http_capture()`, populating `evidence_chain` with valid `EVID-...` identifiers.
  * When `evidence_store is None`, `evidence_chain = []` and notes `[EVIDENCE_NOT_PERSISTED]` in finding descriptions without inventing fictitious evidence IDs.
  * Persistence exceptions are never swallowed, raising `EvidencePersistenceError`.
* **Correlation Context & Data Models** (`framework/auth_correlation/model.py`):
  * `CorrelatedPrincipalContext`: Models authenticated principals with immutable fields, token metadata, tenant bindings, strict allowlists, and credential masking in string/repr.
  * `CorrelatedSessionContext`: Tracks session lifecycles with explicit states (`CREATED`, `UNVERIFIED`, `VERIFIED`, `EXPIRED`, `AUTHENTICATION_FAILED`, `AUTHORIZATION_DENIED`, `REVOKED`, `UNKNOWN`, `FAILED`), expiration, MFA levels (`NONE`, `PRE_MFA`, `FULL_MFA`, `STEP_UP`), and invalidation states.
  * `CorrelationHypothesis`: Encapsulates test hypothesis definitions with safe allowlist representations preventing sensitive `expected_result` leakage.
  * `CorrelationFinding`: Cryptographically hashes evidence, calculates genuine CVSS 3.1 base score, and maintains strict finding state machines.
* **FIRST CVSS 3.1 Metric Calculator** (`framework/auth_correlation/cvss.py`):
  * Implements authentic FIRST CVSS 3.1 base metric equations across AV, AC, PR, UI, S, C, I, and A.
  * Validated against 10 FIRST reference vectors covering scope changes and edge conditions.
  * Finding confidence is preserved as an independent attribute; zero impact evaluates strictly to `0.0` and severity `NONE` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`).
* **Dual-Control Preflight Validation** (`framework/auth_correlation/preflight.py`):
  * `DualControlPreflightValidator`: Verifies session validity against unauthenticated baseline resources to eliminate false-positive access control reports from public endpoints or login redirects.
  * Implements `classify_probe_response()`: explicitly distinguishes `EXPIRED` (401 with expiration indicators), `AUTHENTICATION_FAILED` (generic 401 or login redirect), `AUTHORIZATION_DENIED` (403 Forbidden), `VERIFIED` (200 with authentic protected data), and `UNKNOWN` (soft-404 shell matching anonymous control).
* **Post-Revocation Resource Probing & Approval Tracking** (`framework/auth_correlation/revocation.py`):
  * `PostRevocationResourceValidator`: Mode A (observation-only monitoring against session-bound baseline) and Mode B (dual-account differential probe with mandatory operator approval gate).
  * Mode B approval binding: strictly enforces all 8 mandatory action properties (`action_id`, `target_endpoint`, `method`, `test_account`, `action_type`, `program_id`, `created_at`, `ttl`, `unique_approval_id`).
  * Cryptographic authorization separation: operator approval signature (`SIG-<64-hex>` via HMAC-SHA256 from external approval key) strictly separated from action integrity hash (`ACT-<64-hex>` via SHA256 canonical serialization).
  * Cross-process single-use enforcement: `CrossProcessFileLock` (using Win32 `msvcrt.locking` on Windows and POSIX `fcntl.flock` on Linux) to prevent concurrent replay race conditions.
  * Mandatory ScopeEngine integration: fail-closed scope check immediately before dispatching any mutation probe.
  * Mode A strictly observation-only; Mode B requires explicit operator approval dossier signed with external key.
* **Pre-MFA & Step-Up Boundary Auditing** (`framework/auth_correlation/pre_mfa.py`):
  * `PreMfaPrivilegeValidator`: Audits sensitive endpoint exposure to partially authenticated pre-MFA sessions (`mfa_level == "PRE_MFA"`) against full-auth and unauthenticated baselines.
  * Distinguishes public shells and login challenge forms from authentic profile data. Captures sanitized evidence reference digests (`EVID-<12-hex>`) in `evidence_chain`.
* **Multi-Tenant Dual-Token Cross-Channel Desynchronization** (`framework/auth_correlation/tenant.py`):
  * `MultiTenantDesyncValidator`: Cross-tenant route, query, and header parameter tampering across 3 independent channels (`PATH`, `QUERY`, `HEADER`) in both directions (`A_TO_B`, `B_TO_A`) without token claim modification.
  * Rigorous 3-state cache classification: `CACHE_CONFIRMED`, `CACHE_NOT_INDICATED`, `CACHE_UNKNOWN` with dynamic cache-busting probes (`_bb_cb=<timestamp>`) requiring similarity >= 0.50 to corroborate findings and eliminate reverse-proxy false positives.
* **Correlation Engine Orchestration** (`framework/auth_correlation/engine.py`):
  * `AuthCorrelationEngine`: Orchestrates preflight, revocation Modes A and B, pre-MFA, and tenant workflows dynamically.
  * Target-aware relative endpoint joining against target base URL (`scheme://netloc`), resolving sessions by explicit `principal_id` rather than list indices, and supporting `--preflight-only` and `--dry-run`.
  * Fail-closed persistence: persistence failures return `status = "PERSISTENCE_FAILED"` with explicit error details rather than swallowing exceptions.
* **Native Platform State Directory & Persistence Security** (`framework/auth_correlation/state.py`):
  * `_verify_and_prepare_state_dir`: Confines directory below trusted workspace root, rejects symlinks and reparse points.
  * Windows native security: uses Win32 `advapi32` APIs (`GetSecurityDescriptorControl` to verify `SE_DACL_PROTECTED` 0x1000, `GetSecurityDescriptorDacl`, `GetAce`) to verify non-inherited protected DACL and current user/SYSTEM ownership; explicitly verifies `icacls` return codes.
  * POSIX native security: verifies ownership by current UID, private permissions (`0o700` directories, `0o600` files), and `st_nlink == 1`.
  * Atomic persistence: exclusive creation (`os.O_CREAT | os.O_EXCL`), descriptor-based writing via `os.fdopen()`, descriptor validation via `os.fstat()`, and atomic replace.
* **Deterministic Simulation Lab & Transport** (`framework/auth_correlation/lab.py`):
  * `SimulationTransport`: Strictly confined to numeric `127.0.0.1:<lab_port>` with hop-by-hop redirect isolation (max 3 hops).
  * `LocalAuthCorrelationLab`: Serves 6 deterministic scenarios on ephemeral loopback ports without external egress.
* **CLI Wrapper & Diagnostics Integration**:
  * Added `scripts/bb-auth-correlate` and `scripts/bb-auth-correlate.cmd` with full options: `--lab`, `--tree`, `--preflight`, `--revocation`, `--pre-mfa`, `--tenant`, `--approve-action`, `--dossier`, `--sign-dossier`, `--validate`, `--dry-run`, `--json`, `--output`.
  * Production execution fails closed if invoked without target or initialized principals.
  * Registered Category 26 (`check_auth_correlation_engine`) in `framework/tools/doctor.py` and `scripts/bb-doctor`.
  * Registered `*bb-auth-correlate*` permission rule (`ask`) in `opencode.jsonc`.
* **Automated Regression Test Suites**:
  * Added 72 tests across 9 test modules: `tests/test_phase21_models.py`, `tests/test_phase21_credential_leakage_and_serialization.py`, `tests/test_phase21_cvss.py`, `tests/test_phase21_preflight_and_revocation.py`, `tests/test_phase21_pre_mfa.py`, `tests/test_phase21_tenant_desync.py`, `tests/test_phase21_state.py`, `tests/test_phase21_engine.py`, and `tests/test_phase21_cli.py`.
  * 100% pass rate: 71 passed, 1 skipped in targeted Phase 21 suite; 1011 passed, 3 skipped on Windows 11 host; 1013 passed, 1 skipped on Kali Linux VM; Firefox real browser integration test passed in 18.66s on Kali Linux. Total 1014 items across 55 test modules. Zero regressions.

### Stage C Security Reconciliation & Repository Audit Baseline

#### Original Security Findings Remediation (SEC-01 to SEC-08)
* **SEC-01 (Critical - Fail-Open Scope Gating in Mapping Engines)**:
  * *Original Defect*: When mapping engines (`framework/assets/`, `framework/recon/`, `framework/webapp/`, `framework/javascript/`) were initialized without an explicit `ScopeEngine`, targets defaulted to `IN_SCOPE`, allowing unapproved network egress.
  * *Remediation*: Strict fail-closed scope enforcement across all engines (`_is_in_scope()` returns `False` / raises `ScopeAuthorizationError` when `scope_engine` is absent).
  * *ReconEngine Hook Isolation Remediation*: Enforced method-level hook isolation across `probe_dns`, `probe_tls`, `probe_http`, `probe_ports`, and `probe_endpoints`. Offline simulation hooks execute only when their specific, dedicated hook is configured. Unhooked probes never fall through to unauthenticated live network calls.
* **SEC-02 (High - Unvalidated HTTP Redirects to Private/Metadata IPs & Insecure TLS)**:
  * *Original Defect*: Legacy engines followed HTTP 302 redirects blindly to RFC 1918 or AWS/GCP cloud metadata IP addresses (`169.254.169.254`) and used unverified TLS contexts (`ssl.CERT_NONE`).
  * *Remediation*: Unified HTTP transport onto `framework/common/transport.py` (`safe_fetch_url()`, `PinnedHTTPConnection`, `PinnedHTTPSConnection`, `SafeRedirectHandler`), enforcing destination-IP pinning, preflight anti-SSRF checks, redirect re-validation, and strict TLS certificate verification.
* **SEC-03 (Medium-High - OpenCode Command Permission Wildcard & Chaining Weakness)**:
  * *Original Defect*: Unanchored wildcard patterns (`*bb-doctor*`) in `opencode.jsonc` matched chained commands under the test permission model.
  * *Remediation*: Hardened command permission matching in `opencode.jsonc` against shell chaining operators (`&&`, `||`, `;`, `|`, backticks, `$()`).
* **SEC-04 (High - Silent Ingestion Failure on Malformed Scope Exclusions)**:
  * *Original Defect*: A bare `except Exception: pass` in `ScopeEngine._preprocess_rules()` silently dropped malformed exclusion rules, causing excluded targets to be evaluated as in-scope.
  * *Remediation*: Hardened `framework/scope/engine.py` schema validation: invalid or malformed target/exclusion definitions raise `ScopeConfigurationError` and fail closed instead of being silently ignored.
* **SEC-05 (High - Scope Exclusion Prefix Matching Bypass via Query Strings & Semicolons)**:
  * *Original Defect*: URL-level exclusions matching on prefixes were bypassed when targets contained query strings (`?`) or matrix parameters (`;`).
  * *Remediation*: Hierarchical URL path normalization in `framework/scope/normalizer.py` strips queries, fragments, and matrix parameter semicolons before path-based exclusion matching, preventing scope bypasses like `/api/secret;param=1`.
* **SEC-06 (Medium-High - Evidence Credential-Redaction Gaps in Sensitive Data Sanitizer)**:
  * *Original Defect*: `sanitize_sensitive_data()` failed to redact `X-Auth-Token`, quoted JSON authorization headers, Bearer tokens, and API keys.
  * *Remediation*: Expanded regex patterns in `sanitize_sensitive_data()` (`framework/common/evidence.py`) to scrub Bearer tokens, JWTs, AWS credentials, basic auth headers, and session cookies across state, logs, and evidence artifacts.
* **SEC-07 (Medium - Insecure Tool Installation, Missing Cryptographic Authenticity Verification & Archive Extraction / Zip Slip)**:
  * *Original Defect*: `ToolInstaller` extracted downloaded GitHub release archives without directory traversal protection and lacked independent cryptographic authenticity verification.
  * *Remediation*: Pinned SHA-256 integrity verification is strictly mandatory for all binary archive downloads in `framework/tools/installer.py`. Missing or invalid hashes fail closed with `InstallerSecurityError`. Hardened tarfile and zipfile extraction filters reject directory traversal (Zip Slip) and dangerous file types (device nodes, FIFOs, absolute symlinks).
  * *Documented Limitation*: 24 GitHub-release tools currently lack pinned upstream SHA-256 hashes in `config/tools.yaml` and cannot use automatic archive installation.
* **SEC-08 (Medium - IPv6 URL Normalization Bracket Stripping)**:
  * *Original Defect*: `framework/scope/normalizer.py:normalize_url()` stripped RFC 3986 mandatory brackets from IPv6 URLs with port numbers (`http://[2001:db8::1]:8080/test`), triggering unhandled `ValueError` crashes in downstream consumers accessing `.port`.
  * *Remediation*: Preserves bracketed netloc formatting for IPv6 addresses (`[2001:db8::1]:8080`) during URL reconstruction.

#### Additional Security, Architectural & Packaging Findings (ADD-*)
* **ADD-SEC-01 (CLI Shell Subprocess Command Injection)**:
  * Verified CLI shell wrappers in `scripts/` (`bb-recon`, `bb-assets`, `bb-js`, `bb-webapp`) tokenize argument vectors and invoke utilities without shell interpretation or unescaped string concatenation.
* **ADD-SEC-02 (HTTP Trust Subprocess Insecure Fallback)**:
  * Removed unmediated `curl` subprocess fallback in `HttpTrustEngine` (`framework/http_trust/engine.py`); all transport routed through secure transport layer with fail-closed bounds.
* **ADD-SEC-03 (XXE Entity Expansion DoS / Billion Laughs)**:
  * Hardened XML parser in `framework/common/xml_safe.py` and `framework/injection/engine.py` to enforce entity expansion budgets, protect against quadratic/exponential blowup attacks, and safely handle BOM and malformed XML.
* **ADD-ARCH-01 (Transport Architecture Divergence / Unification)**:
  * Unified divergent HTTP clients across legacy engines onto `framework/common/transport.py` with consistent timeouts, TLS certificate validation, destination-IP pinning, and fail-closed scope gating.
* **ADD-PKG-01 (Missing Python Declarative Packaging Manifest)**:
  * Created standard `pyproject.toml` with build system requirements, package metadata, dependencies, and optional test/dev dependencies.
* **ADD-CFG-01 (Missing Explicit bb-webapp OpenCode Permission)**:
  * Added explicit regex rule for `bb-webapp` CLI wrapper in `opencode.jsonc` to enforce consistent tool execution policy.
* **ADD-DOC-01 (Roadmap Baseline Commit Hash Synchronization)**:
  * Synchronized commit hash and verification metrics in `docs/ROADMAP-24-PHASES-TEMP.md`.
* **ADD-DOC-02 (Changelog Phase 15 Completeness)**:
  * Reconciled Phase 15 deliverables, validation engines, and test counts in `CHANGELOG.md`.
* **Cross-Platform Test Verification**:
  * Windows 11: 939 passed, 2 skipped (Playwright headless browser requirement) out of 941 tests across 46 modules.
  * Kali Linux VM: 941 passed, 0 failures, 0 skipped out of 941 tests across 46 modules.

### Phase 20: Race Conditions & Distributed Workflows Intelligence (Accepted with Documented Limitations)

#### Added & Hardened
* **Concurrency & Race Conditions Subsystem (`framework/concurrency/`)**:
  * Implemented core models (`RaceCategory`, `RaceConfidence`, `SingleProbeExecution`, `ConcurrencyProbePlan`, `RaceConditionHypothesis`, `RaceConditionTestResult`).
  * Defined 6 core categories: `LIMIT_OVERRUN`, `TOCTOU`, `DOUBLE_SPEND`, `IDEMPOTENCY_BYPASS`, `PARTIAL_EXECUTION_DESYNC`, and `CONCURRENT_STATE_MUTATION`.
* **Precision Barrier Synchronization (`BarrierSynchronizer`)**:
  * Employs `threading.Barrier` to pre-arm parallel worker threads and trigger release simultaneously inside the microsecond server execution window.
  * Replaces volumetric flooding, algorithmic stress testing, and DoS attacks with surgical, bounded parallel probes.
* **Resource Identity, Counter Isolation & Candidate Invariant Calibration (Blocker B — `ResourceIdentityTracker`, `ConcurrencyInvariantEngine`)**:
  * Added `ResourceIdentityTracker` with category-prioritized primary key resolution (`order_id`, `redemption_id`, `vote_id`, `tx_id`, `id`).
  * Enforced field-alias deduplication (e.g. `order_id: ORD-1` and `id: ORD-1` in the same response resolve to a single resource entity).
  * Isolated resource identity sets from scalar counters (`items_count: 2`), response status counts, and nonces/timestamps.
  * Distinct provisional response identifiers (e.g. `order_id: ORD-1`, `ORD-2`) alone without authoritative post-state evidence are strictly evaluated as `RaceConfidence.SUSPECTED` (`FindingLifecycle.OBSERVED`, `"INFORMATIONAL"`), never `CONFIRMED`.
  * Invariant validation enforces category-specific counter mapping (`category_counter_map`: `coupon_redemptions` for `DOUBLE_SPEND`, `voting_count` for `LIMIT_OVERRUN`, `order_count` for `IDEMPOTENCY_BYPASS`, `account_balance` for `TOCTOU`) against server post-state.
  * Strictly disallows classifying findings as `CONFIRMED` based solely on HTTP status code counts; requires reliable business-state mutation proof or verified distributed rollback failure.
  * Distinguishes idempotent duplicate representations from duplicate processing (`CONCURRENCY_CONTROLLED` vs `CONFIRMED`).
  * Normal server concurrency defenses (HTTP 409 Conflict, 429 Too Many Requests, 423 Locked) and timeouts strictly evaluate as `CONCURRENCY_CONTROLLED` or `INCONCLUSIVE`.
* **Cryptographic Evidence Provenance Trust Boundary & Full Envelope Attestation (Critical Findings A & B — `EvidenceEnvelope`, `canonical_serialize_envelope()`, `PostStateEvidence`, `LocalConcurrencyLab`)**:
  * Completely eliminated public caller-supplied authoritative evidence factories (`create_authoritative_evidence()`), preventing any caller or test from signing arbitrary untrusted state.
  * Authoritative evidence is strictly issued through genuine observations from an active `LocalConcurrencyLab` instance (`start_observation()`, `complete_observation()`, `capture_evidence()`, `get_authoritative_state()`) bound to its server state and validated port.
  * Implemented `EvidenceEnvelope` (version `concurrency-evidence-v1`) binding all 9 decision-relevant fields (`schema_version`, `observation_id`, `source`, `endpoint`, `verified_at`, `pre_state`, `post_state`, `delta_metrics`, `provenance_details`).
  * Enforced canonical deterministic serialization (`canonical_serialize_envelope()`) with lexicographical key ordering, strict primitive type verification, and deterministic JSON separators.
  * Authenticated with HMAC-SHA256 using the process-private key `_LAB_TRUST_KEY`. Any post-attestation modification of any field or nested dictionary causes immediate verification failure (`is_authoritative() == False`).
  * Deserialized external payloads (`PostStateEvidence.from_dict()`) are strictly forced to `UNTRUSTED_CALLER_CLAIM` and stripped of attestation tokens.
  * Verified endpoint validation ensures evidence originates only from active local lab instances on loopback addresses.
* **Pre-State Baselines, Delta Calculations & Monotonic Progression (Critical Finding C — `ConcurrencyInvariantEngine`, `RaceIntelligenceEngine`)**:
  * Bound observations to unique per-execution identities (`observation_id = obs-{hypothesis.hypothesis_id}-{uuid}`), capturing trusted pre-state baselines prior to burst dispatch and extracting post-state directly upon completion while completely preventing cross-run baseline collisions.
  * Ensured every started observation reaches exactly one safe terminal outcome (Completed, Discarded, or Failed-Closed) via idempotent `LocalConcurrencyLab.discard_observation()` and execution engine `try...finally` guards, preventing state leakage on exceptions, timeouts, or externally supplied caller evidence.
  * Rejected duplicate active observation IDs safely with `ValueError` to prevent silent baseline replacement under concurrent starts.
  * State-based counter invariants (`LIMIT_OVERRUN`, `DOUBLE_SPEND`, `IDEMPOTENCY_BYPASS`) evaluate exact per-test counter deltas ($\Delta = \text{post} - \text{pre}$) rather than raw cumulative counters.
  * Unbaselined post-state counter observations strictly fail safe to `RaceConfidence.SUSPECTED` or `INCONCLUSIVE`, never `CONFIRMED`.
  * Decreasing counters for strictly increasing metrics violate monotonic progression invariants and immediately fail closed to `INCONCLUSIVE`.
  * Contradictory pre/post state fails consistency checks before authority checks, preventing untrusted contradictory state from bypassing validation.
* **Worker Lifecycle, Monotonic Deadlines & Container Sealing (Blocker C — `BurstExecutionContainer`, `WorkerLifecycleState`)**:
  * Modeled explicit lifecycle states: `COMPLETED`, `FAILED`, `TIMED_OUT_UNRESOLVED`, and `CANCELLED`.
  * Replaced cumulative linear worker thread joins with a single monotonic overall deadline (`time.monotonic() + timeout + 1.0`). Workers unresolved at deadline transition to `TIMED_OUT_UNRESOLVED` and propagate to `INCONCLUSIVE`.
  * Formally documented Python thread cancellation limits (lack of preemptive worker cancellation in stdlib threading).
  * `BurstExecutionContainer.seal()` permanently seals test containers upon join completion, preventing late-finishing background threads from mutating finalized test results.
  * Unique thread naming pattern `bb-race-worker-{i}-{burst_id}` eliminates thread tracking collisions across bursts.
* **Per-Hypothesis Request Budget Isolation (Blocker D — `HypothesisBudgetContext`)**:
  * Replaced shared instance counters with thread-safe `HypothesisBudgetContext` instances bound to individual hypotheses.
  * Enforces hard ceiling of 15 requests per test case (`MAX_REQUESTS_PER_TEST = 15`), preventing parallel hypotheses from leaking, starving, or resetting shared request allocations.
* **Fail-Closed DNS Resolution & Prohibited Address Ranges (Blocker E — `resolve_destination`)**:
  * Preflight DNS resolution enforces strict fail-closed safety: resolution errors, empty resolution results, and malformed IP strings raise `PolicyViolationError`.
  * Preflight resolution validates every resolved IP address against RFC 1918 private subnets, loopback (`127.0.0.0/8`), carrier-grade NAT (`100.64.0.0/10`), cloud metadata (`169.254.169.254`), IPv6 equivalents (`::1`, `fc00::/7`, `fe80::/10`), and IPv4-mapped IPv6 ranges (`::ffff:127.0.0.1`, etc.).
  * Added pluggable `resolver` hook to facilitate isolated, deterministic unit testing.
  * Formally documented DNS rebinding limitation: Python standard HTTP transport does not pin socket IPs, recommending validating egress proxies or network namespaces for high-risk targets.
* **Concurrent Observation Attribution, Overlap Guard & Measurement Lock Exception Safety (`LocalConcurrencyLab`, `ConcurrencyInvariantEngine`, `EvidenceEnvelope`, `RaceIntelligenceEngine`)**:
  * Implemented `_measurement_lock` (`threading.RLock`) in `LocalConcurrencyLab` and acquired it in `RaceIntelligenceEngine.execute_hypothesis()` to serialize observation measurement critical sections across executions, ensuring clean sequential observation windows on shared mutable lab state while preserving full barrier-synchronized parallel worker execution within each burst.
  * Hardened measurement lock exception safety: restructured lifecycle with nested `try...finally` blocks protecting observation creation, synchronized burst dispatch, authoritative post-state collection, and invariant evaluation.
  * If lock acquisition fails or times out, execution immediately returns an inconclusive result without dispatching burst probes or producing unauthenticated evidence.
  * Preserved lock-ownership defect reporting: `LocalConcurrencyLab.release_measurement_lock()` releases the lock directly without swallowing `RuntimeError`. Engine cleanup preserves original in-flight exceptions and guarantees lock release across exceptions, early exits, missing post-state, and invariant crashes.
  * Corrected cleanup exception handling: wrapped primary hypothesis execution to explicitly track `primary_exc`. Decoupled observation discard (Stage 1) from primary execution, and guaranteed measurement lock release (Stage 2) is always attempted even if discard fails.
  * Protected observation-state inspection (`is_observation_active()`): enclosed inspection inside Stage 1 exception handlers so inspection failures are treated as cleanup errors and can never bypass Stage 2 lock release. If inspection fails, execution attempts safe discard rather than assuming the observation is inactive.
  * Enforced deterministic exception precedence: when a primary execution exception occurs, cleanup failures do not mask it, and diagnostic information identifying each secondary cleanup failure is attached via exception notes (`add_note` / `__notes__`) and structured diagnostic objects without modifying the primary exception type or message. When no primary exception occurs, cleanup failures are never swallowed and propagate directly; when inspection, discard, and lock-release stages fail, all diagnostic information is preserved through explicit chaining (`__context__` and `__cause__`).
  * Structured Cleanup Diagnostic Safety & Elimination of Raw Exception Retention: Removed raw exception objects, tracebacks, and unsanitized chained exceptions from `primary.__cleanup_failures__`. Replaced them with minimal structured records containing strictly primitive string fields (`stage`, `exception_type`, and length-bounded `diagnostic` sanitized via `sanitize_sensitive_data()`), preventing sensitive-data exposure while keeping cleanup failures individually diagnosable.
  * Diagnostic Generation & Attachment Failure Isolation: Wrapped diagnostic generation and formatting in fail-safe fallback guards. If string conversion (`str(exc)`) or `sanitize_sensitive_data()` raises an exception, diagnostic formatting safely falls back to the exception's type name, never exposing unsanitized error strings or raw secrets. Individual stage diagnostic attachment operations are isolated so that a diagnostic failure in one stage cannot bypass subsequent stage diagnostics or mask/replace the propagating primary exception.
  * Added fail-closed overlap attribution guard: `LocalConcurrencyLab.start_observation()` detects any concurrently active observations (`len(_active_observations) > 0`) and marks all overlapping observations with `has_overlap = True`.
  * Integrated `has_overlap` directly into canonical serialization (`canonical_serialize_envelope()`) and `EvidenceEnvelope`. Any post-attestation modification of `has_overlap` invalidates HMAC verification.
  * `ConcurrencyInvariantEngine.evaluate_burst_results()` logs overlapping measurement windows and immediately fails closed to `RaceConfidence.INCONCLUSIVE` (`is_vulnerable = False`, `FindingLifecycle.OBSERVED`) whenever `post_state_evidence.has_overlap == True`, preventing false positive findings from concurrent observation interference.
* **Deterministic Local Simulation Lab (`LocalConcurrencyLab`)**:
  * Multi-threaded `ThreadingHTTPServer` serving 8 deterministic concurrency scenarios on an ephemeral loopback port (`127.0.0.1:0`).
  * Scenarios: coupon double-spend, balance transfer overdraw, voting limit overrun, idempotency race, mutex serialization (409), rate limit defense (429), gateway timeout (504), and distributed desync (500).
  * Added `get_authoritative_state()` returning HMAC-attested `LAB_FIXTURE_AUTHORITATIVE` post-state evidence.
* **Safe State Management & Secret Scrubbing (`ConcurrencyStateManager`)**:
  * Atomic persistence of program-scoped state in `state/concurrency.json` with schema self-healing and Windows retry handling.
  * Recursive sanitization of credentials, passwords, tokens, and authorization parameters (`[REDACTED_BY_BB_AGENT]`).
  * Exception sanitization via `_classify_request_exception` ensuring zero raw exception strings or secrets leak into state, logs, findings, or reports.
* **CLI Wrapper, System Diagnostics & OpenCode Integration**:
  * Created CLI utility `scripts/bb-race` and `scripts/bb-race.cmd` supporting `--lab`, `--tree`, `--burst`, `--approve`, `--dry-run`, and `--json`.
  * Added Category 25 (`check_concurrency_engine`) to `framework/tools/doctor.py` and `scripts/bb-doctor`.
  * Added `*bb-race*` permission rule to `opencode.jsonc`.
  * Extended `framework/state/manager.py` with `DEFAULT_CONCURRENCY` and synchronized `concurrency.json` into canonical findings.
  * Linked `bb-race` across deployment utilities (total 28 utilities).
* **Automated Test Suite**:
  * Expanded to 128 unit and integration tests in `tests/test_concurrency_engine.py` (and 175 tests across the TestCase unittest discovery subset; 913 tests collected under pytest across all 45 modules at Phase 20 completion; currently 941 tests across 46 modules following Stage C hardening) covering taxonomy, barrier timing, invariant rules, evidence classification hardening, full-envelope HMAC attestation, pre-state baselines, counter deltas, observation lifecycle integrity, execution-bound unique observation IDs, cross-run baseline isolation, measurement window serialization, measurement lock exception-safe release, failed lock acquisition guards, fail-closed `has_overlap` attribution guards on overlapping observations, primary exception preservation during cleanup failures with diagnostic note attachments, observation-state inspection safety, deterministic cleanup exception precedence across inspection/discard/release, structured cleanup diagnostic safety without raw exception retention, fail-safe diagnostic isolation against string conversion and sanitizer crashes, scope fail-closed architecture, request budget bounds, worker lifecycle timeout handling, all 8 lab scenarios, secret scrubbing, and disk report inspection.

### Phase 19: Infrastructure & Configuration Exposure (Accepted with Documented Limitations)

#### Added & Hardened
* **Infrastructure Intelligence Engine (`framework/infrastructure/`)**:
  * Added core models, signatures, differential soft-404 analyzer, safe active evaluator, engine orchestrator, atomic state manager, and local lab simulation harness.
  * Added `INFRASTRUCTURE_EXPOSURE` and `CONFIGURATION_EXPOSURE` to `VulnerabilityFamily`.
  * Implemented support for 8 exposure classes: `VERSION_CONTROL` (`.git/HEAD`, `.svn/entries`), `CONFIG_FILE` (`.env`, `web.config`), `BACKUP_ARCHIVE` (`.zip`, `.tar.gz`), `ADMIN_INTERFACE` (`actuator/health`, `admin`), `DEPLOYMENT_MANIFEST` (`package.json`, `composer.json`), `SOURCE_MAP` (`*.js.map`), `DIRECTORY_LISTING` (`Index of /`), and `DEBUG_INTERFACE` (debug traces).
* **Differential Soft-404 Engine (`DifferentialSoft404Engine`)**:
  * Implemented differential comparison against application-subpath baselines with dynamic token stripping (nonces, timestamps, CSRF tokens, hashes) and token Jaccard similarity.
  * Strictly enforces the non-rejection invariant: candidates are never rejected solely because a baseline probe returned HTTP 200.
  * Handles SPA catch-all, distinct static files, dynamic error pages, and redirect catch-all patterns.
* **Evidence-Sufficiency Stopping Rules**:
  * Capped general HTTP response bodies at 32 KB (`max_response_bytes = 32_768`).
  * Evaluated configuration files within an 8 KB ceiling (`max_config_bytes = 8_192`).
  * Evaluated backup archives using strictly the first 1 KB binary magic bytes (`max_binary_magic_bytes = 1_024`); zero full archive downloads.
* **Fail-Closed Safety Policy & Transport Controls (`InfrastructureExposurePolicy`)**:
  * Restricted HTTP methods strictly to safe, idempotent read-only methods (`{"GET", "HEAD", "OPTIONS"}`).
  * Policy blocks state-changing GET queries and `POST`/`PUT`/`DELETE`/`TRACE` methods.
  * Enforced pre-dispatch ScopeEngine authorization and anti-SSRF loopback/private/metadata protections.
* **Sensitive Data Redaction & Zero Secret Persistence**:
  * Automated sanitization of discovered secret values, API keys, and passwords across state (`state/infrastructure.json`), finding objects, and markdown reports.
  * Authenticated evidence fingerprints over sanitized representation (SHA-256).
* **Deterministic Simulation Lab (`LocalInfrastructureLab`) & Regression Suite**:
  * Implemented 16 deterministic scenarios on ephemeral loopback ports.
  * Added 39 comprehensive tests in `tests/test_infrastructure_engine.py` covering all 16 scenarios, differential classes, stopping rules, secret scrub, and policy enforcement.
* **CLI Wrapper, System Diagnostics & OpenCode Integration**:
  * Created `scripts/bb-infra` (`scripts/bb-infra.cmd`) supporting `--tree`, `--passive-only`, `--dry-run`, `--approve`, `--json`, and `--lab`.
  * Added Category 24 (`check_infrastructure_engine`) to `framework/tools/doctor.py` and `scripts/bb-doctor`.
  * Added `*bb-infra*` permission rule to `opencode.jsonc`.

### Phase 18: SSRF, XXE & Server-Side Parser Expansion (Accepted with Documented Limitations)

#### Added & Hardened
* **Agent-Side XML Hardening (`framework/common/xml_safe.py`)**:
  * Implemented portable stdlib XML security (`safe_parse_xml`, `safe_extract_sitemap_urls`, `XmlBombSecurityError`, `ProhibitedDtdSecurityError`, `ExternalEntitySecurityError`) with strict cumulative expanded-character budgets (`max_expanded_chars`), Expat amplification factor defenses, and Billion Laughs protection.
  * Hardened webapp sitemap parser (`framework/webapp/engine.py`) to fail closed immediately on XML security errors with zero regex fallback.
* **SSRF Transport Hardening (`framework/common/transport.py`, `framework/validation/engine.py`)**:
  * Added `parse_alternate_ip` supporting dotted decimal, decimal scalars, hex scalars, octal scalars, dotted octal/hex, and inet_aton multi-part formats.
  * Hardened destination IP resolution to fail closed if any DNS answer resolves to loopback, private, carrier-grade NAT, or cloud metadata addresses.
  * Implemented continuous streaming byte accounting (`total_bytes_transferred`) across partial reads, redirects, and HTTP errors; added `max_total_bytes` policy control to `SecurityTestPolicy`.
* **SSRF Request Mutation (`framework/ssrf/engine.py`)**:
  * Expanded `_build_mutated_request()` supporting Query parameters, Path template parameters (`{param}`, `:param`), JSON bodies (flat and nested dotted keys), Form-encoded bodies, and XML bodies (DOM text replacement with XML entity escaping).
* **Conservative XXE Intelligence Subsystem (`framework/xxe/`)**:
  * Orchestrates non-destructive synthetic entity reflection, signal classification, deterministic local simulation harness (`LocalXxeLab`), state management (`xxe.json`), and deduplication.
  * Added `XXE = "XXE"` to `VulnerabilityFamily`, safe payloads `PL-XXE-REFL-01` and `PL-SSRF-CANARY-01`, and `XxeValidator` / `SsrfValidator` plugins in `SecurityValidationEngine`.
* **Evidence Semantics & Truthful OOB Availability**:
  * Internal entity reflection alone emits an `OBSERVATION` (`INFORMATIONAL`, `MEDIUM` confidence), never a false `HIGH`-severity `VALIDATED` XXE finding. Parser errors and secure DTD rejections emit zero findings.
  * Out-of-band correlation (`validate_oob_candidate`) differentiates mock test harness interactions (`SIMULATED`, `INFORMATIONAL`, `LOW` confidence) from live external target callbacks (`VALIDATED`, `HIGH`). Mock interactions can never produce live validated findings.
  * Truthful OOB Provider Availability: `InteractshOobProvider` and `CollaboratorOobProvider` report `CONFIG_REQUIRED` when unconfigured and `UNAVAILABLE` when configured (because live wire polling over network protocols is not implemented; storage is local in-memory only).
* **Enforced OOB Destination Trust Boundary & Method Verification**:
  * Prior to canary issuance or probe dispatch, verifies provider availability (`AVAILABLE`), failing closed for `UNAVAILABLE`, `CONFIG_REQUIRED`, or `ERROR` with zero network requests dispatched.
  * Validates generated canary destinations against `validate_oob_destination()` in `SecurityTestPolicy`, verifying that the method exists and is callable; fails closed with `PolicyViolationError`, sets `POLICY_VIOLATION` candidate state, and dispatches zero network requests if missing or non-callable.

### Phase 17: Advanced API Security (Accepted with Documented Limitations)

#### Added & Hardened
* **Bounded OpenAPI & GraphQL Specification Parsing (`framework/api/`)**:
  * Ingests OpenAPI 2.0, 3.0, and 3.1 specifications (JSON/YAML), recursively resolving RFC 6901 local and relative `$ref` pointers up to depth 10 with circular reference protection.
  * GraphQL surface detection and opt-in schema introspection (`allow_graphql_introspection=True`, default disabled), bounded to selection set depth $\le 6$, schema traversal depth $\le 3$, and max 5,000 parameters.
* **Continuous Streaming Byte-Budget Accounting**:
  * Tracks network egress continuously (`total_bytes_transferred`), ensuring malformed, oversized, truncated, or error responses deplete the global network byte budget (`max_bytes`).
* **Loopback Fixture Port Gating**:
  * Local testing against loopback fixtures strictly requires explicit unprivileged port registration (`1024-65535`) and scope authorization; production targets strictly forbid loopback, RFC 1918, and cloud metadata destinations. Dual-export state is maintained in `state/api.json`.

### Phase 16: Browser Runtime & Client-Side Security (Accepted with Documented Limitations)

#### Added & Hardened
* **Local Validating Egress Proxy (`ValidatingEgressProxy`)**:
  * Implemented an ephemeral loopback HTTP/CONNECT forward proxy with direct numeric IP pinning (`_connect_upstream`), closing the DNS TOCTOU rebinding window.
  * Enforced `--proxy-bypass-list=<-loopback>` to prevent Chromium from bypassing loopback proxying.
  * Pre-connection destination, SSRF, literal IP, DNS resolution, and scope checks across all HTTP, HTTPS, WS, and WSS requests before upstream connections can be created.
* **WebSocket Pre-Handshake & Pre-Connection Enforcement**:
  * Integrated Playwright's `BrowserContext.route_web_socket` to intercept `ws://` and `wss://` at the browser engine level; when `allow_websockets=False`, connections are closed with code 1008 without calling `connect_to_server()`, strictly preventing the WebSocket handshake from reaching the server.
  * Intercepted `Upgrade: websocket` and `CONNECT` requests at the transport proxy layer (`ValidatingEgressProxy`), validating destinations and pinning IPs before connection.
  * Configurable `allow_websockets` policy gating across proxy and browser contexts.
  * Retained `context.on("websocket")` as secondary post-handshake defense-in-depth audit/cleanup hook.
* **Execution Budgets & Safe Deadlines**:
  * Bounded browser session initialization with monotonic wall-clock deadlines.
  * Enforced multi-byte Unicode evidence byte limits (`truncate_to_max_bytes`) preserving evidence markers without memory growth.
* **Deterministic Test Suite (`tests/test_phase16_browser_runtime.py`)**:
  * Added 101 comprehensive unit and integration tests across Sections 15–19 verifying proxy fail-closed startup, anti-SSRF IP pinning, pre-handshake WebSocket routing, and Unicode truncation.

### Phase 15: File Handling, Path Traversal & Upload Security (Accepted with Documented Limitations)

#### Added & Hardened
* **File Handling & Path Traversal Validators (`framework/validation/validator.py`)**:
  * Implemented `PathTraversalValidator`, `LocalFileExposureValidator`, and `FileUploadValidator` plugins in `SecurityValidationEngine`.
  * Added `PATH_TRAVERSAL`, `LOCAL_FILE_EXPOSURE`, and `FILE_UPLOAD` to `VulnerabilityFamily` with bounded payload mutations.
  * Strict non-destructive testing: traversal markers use benign target boundaries (benign canonical markers, zero destructive file writing or deletion).
  * Safe file upload testing with synthetic harmless content (benign magic bytes, harmless test markers, strictly zero webshells or executable code execution).
* **State Management & Deduplication**:
  * Integrated finding models into lifecycle state tracking (`state/validation.json`) and SHA-256 evidence captures.

---

## [1.14.2] - 2026-10-10

### Phase 14.2: Authentication Validation Integrity & Executor Safety

#### Added & Improved
* **Request-Executor Safety & TLS Verification (`framework/authentication/executor.py`)**:
  * Restored standard TLS certificate and hostname verification (`ssl.create_default_context()`, `check_hostname=True`, `verify_mode=CERT_REQUIRED`) with fail-closed TLS error handling.
  * Destination-IP pinning at socket connection (`PinnedHTTPConnection`, `PinnedHTTPSConnection`) preserving TLS SNI and HTTP `Host` header, eliminating DNS rebinding / TOCTOU windows.
  * Safe environment proxy bypassing (`ProxyHandler({})`) preventing unauthorized ambient proxy interception.
  * Hardened anti-SSRF defenses including IPv4, IPv6, IPv4-mapped IPv6 (`::ffff:0:0/96`), link-local, and cloud metadata.
  * Per-redirect hop independent anti-SSRF and scope re-verification (`AuthSafeRedirectHandler`) with protocol downgrade prevention and 5-hop cap.
  * Zero-traffic guarantees in `--dry-run`, `--passive-only`, and `--hypotheses` modes.
* **Scope Resolution & Approval Gate Safety (`framework/authentication/policy.py`, `scripts/bb-auth`)**:
  * Eliminated unsafe current-working-directory scope fallbacks (`./scope/scope.yaml`, `./scope.yaml`); fail-closed on missing or ambiguous scope.
  * Tied approval gate to concrete operations (`PASSWORD_RESET_SUBMIT`, `PASSWORD_CHANGE`, `MFA_ENROLLMENT`); enforced strict invariant that operator approval never overrides scope boundaries.
* **Deterministic Fingerprints & State Storage (`framework/authentication/hypotheses.py`, `storage.py`, `models.py`)**:
  * Replaced random UUIDs with deterministic SHA-256 hypothesis IDs (`HYP-<family>-<hash>`) over family, endpoint, principal, and required state.
  * Resilient state loading distinguishing missing files from corrupted JSON, backing up corrupted files to `.corrupt.<timestamp>` and raising `CorruptedStateError`.
  * Recursive dictionary and JSON credential sanitization (`sanitize_dict`) in `AuthenticationEvidenceManager`.
  * Finding lifecycles assign `FindingLifecycle.VALIDATED` only on true operational differential proof; observation-only families remain `INFORMATIONAL`.
  * Surfaced finding persistence errors instead of silently discarding findings.
* **Genuine Validation Pipeline (`framework/authentication/engine.py`, `validators.py`)**:
  * Completely purged hardcoded synthetic mock strings (`sess_fixed_id`, synthetic JSON bodies) from real target evaluation paths.
  * Implemented authentic differential verification sequences for all 11 operational families.
  * Explicitly report `SKIPPED` / `MISSING_PREREQUISITES` or `CANDIDATE` when test credentials or sessions are missing.
  * Updated tree rendering and CLI summaries to visually distinguish verified findings, informational notes, unverified candidates, and skipped hypotheses.
* **Comprehensive Test Suite (`tests/test_authentication_engine.py`)**:
  * Added negative control tests with local HTTP fixture server.
  * Added zero-traffic assertions, proxy isolation, and DNS rebinding pinning tests (total 47 tests passing in suite; 346 passing repo-wide).

---

## [1.14.1] - 2026-10-10

### Phase 14.1: Authentication Engine Hardening & Pipeline Integration

#### Added & Improved
* **Pipeline Execution & Scope Engine Integration (`framework/authentication/executor.py`, `framework/authentication/policy.py`)**:
  * Added `BoundedAuthenticationExecutor` and `AuthSafeRedirectHandler` implementing RFC-compliant HTTP execution capped at 10s timeout, 100KB body limit, and 5 redirect hops with anti-SSRF protections against private/loopback/cloud metadata ranges.
  * Canonical scope path resolution (`resolve_scope_file`) prioritizing `<program_dir>/scope/scope.yaml` and strict fail-closed enforcement using `ScopeEngine.check()` returning `ScopeDecision(status == ScopeStatus.IN_SCOPE)`.
  * Safe approval gating (`AuthenticationApprovalGate`) requiring `--approve` for test account state mutations; enforced invariant that operator approval never overrides scope restrictions.
* **Cross-Phase State Ingestion (`framework/authentication/discovery.py`, `framework/authentication/identity.py`)**:
  * Unified `AuthenticationSurfaceDiscoverer.discover_all()` ingesting 7 real multi-phase state files: `webapps.json`, `api.json`, `javascript.json`, `assets.json`, `recon.json`, `authorization.json`, and `workflows.json`.
  * Graceful degradation handling missing, empty, or partial state files.
  * Identity profile seeding from Phase 8 authorization principals (`seed_from_authorization_state`).
* **Operational Vulnerability Taxonomy & Heuristics (`framework/authentication/hypotheses.py`, `framework/authentication/validators.py`)**:
  * Full coverage of all 14 families from `AuthenticationFindingFamily`: 11 operational testing families and 3 observation-only families.
  * Differential baseline validation (anonymous vs authenticated vs pre-MFA) rejecting generic 200 OK login forms and WAF challenges.
  * Multi-trial differential validation for account enumeration distinguishing real signal variations from baseline noise.
* **Deduplication, Evidence Sanitization & Findings Persistence (`framework/authentication/engine.py`, `framework/authentication/evidence.py`, `framework/authentication/models.py`)**:
  * Test deduplication via `StateManager.record_test` and `StateManager.has_test_run` preventing redundant probes.
  * Support for `--resume` flag to merge existing engine run state.
  * Family-specific credential redaction (`[REDACTED_PASSWORD]`, `[REDACTED_COOKIE]`, `[REDACTED_TOKEN]`, `[REDACTED_SECRET]`) with SHA-256 provenance hashes.
  * Native findings integration persisting confirmed findings into `state/findings.json` using `FindingLifecycle.VALIDATED`.
* **Testing & Diagnostics**:
  * 18 new automated integration and safety test cases in `tests/test_authentication_engine.py` (total 42 tests in suite).
  * Category 23 diagnostic verification reporting `[HEALTHY]` in `bb-doctor`.

---

## [1.14.0] - 2026-10-08

### Phase 14: Authentication, Session & Identity Security Intelligence Engine

#### Added
* **Authentication Security Framework (`framework/authentication/`)**:
  * Structured identity models (`IdentityProfile`) and bi-directional bridge with Phase 8 `PrincipalProfile`. Strict redaction: passwords and live tokens are never stored.
  * Multi-flow surface discovery (`AuthenticationSurfaceDiscoverer`) ingesting login, logout, password change, reset, MFA, and refresh endpoints from previous phases.
  * Session lifecycle and fixation intelligence (`SessionAnalyzer`) tracking hashed/masked fingerprints (`sess_sha256_...`), rotation, logout invalidation, and password-change invalidation.
  * Token & JWT structural parser (`TokenAnalyzer`) locally decoding headers, algorithms, and claims without live signature tampering; detecting transport leaks in URL query parameters.
  * Password reset and differential account enumeration analyzer (`PasswordResetAnalyzer`) detecting token reuse, expiration enforcement, and repeatable differential signals.
  * Multi-factor authentication analyzer (`MFAAnalyzer`) identifying pre-MFA privilege exposure on sensitive account endpoints without OTP brute-forcing.
  * Active false positive rejection (`AuthenticationFalsePositiveClassifier`) eliminating HTTP 200 login pages, non-sensitive missing cookie attributes, and normal access controls.
  * Safety policy & approval gate (`AuthenticationSecurityPolicy`, `AuthenticationApprovalGate`) enforcing scope boundaries, blocking metadata addresses, and requiring `--approve` for sensitive mutations.
  * Atomic state persistence (`AuthenticationStateManager`) storing state at `state/authentication.json` with resume capability.
* **Deterministic Local Authentication Lab (`LocalAuthenticationSecurityLab`)**:
  * 21 deterministic, 100% offline scenarios demonstrating bypasses, pre-MFA exposures, session invalidation, fixation, token reuse, enumeration, and false positive rejections.
* **CLI Wrapper (`scripts/bb-auth`, `scripts/bb-auth.cmd`)**:
  * Commands for `--tree`, `--json`, `--passive-only`, `--dry-run`, `--resume`, `--hypotheses`, `--validate`, `--flow`, `--identity`, `--approve`, and `--lab`.
* **System Diagnostics & Skills Integration**:
  * Updated `framework/tools/doctor.py` and `scripts/bb-doctor` with Category 23: Authentication & Session Security.
  * Added permission rule `*bb-auth*` with `ask` effect to `opencode.jsonc`.
  * Created dedicated methodology skill [`skills/authentication/SKILL.md`](skills/authentication/SKILL.md), expanding modular skills to 18.

---

## [1.13.0] - 2026-10-08

### Phase 13: Cloud Security & Misconfiguration Intelligence Engine

#### Added
* **Cloud Security Framework (`framework/cloud_security/`)**:
  * Multi-signal provider fingerprinting (`ProviderFingerprinter`) supporting AWS, Azure, GCP, Cloudflare, Fastly, DigitalOcean, and Oracle.
  * Cloud service identification (`CloudServiceIdentifier`) recognizing S3, Blob storage, GCS, CloudFront, Azure App Service, Cloud Run, API Gateway, and admin interfaces.
  * Exposure hypothesis engine (`CloudExposureHypothesisEngine`) generating testable assertions for public object read, bucket listing, suspected write capability, cloud takeover, and admin access.
  * Safe non-destructive validator (`SafeCloudValidator`) and false positive classifier (`CloudFalsePositiveClassifier`) rejecting CDN normal endpoints, enforced access controls (HTTP 403 / `AccessDenied`), and HTML static website hosting.
  * Multi-factor exposure scoring (`CloudExposureScorer`) and priority rank engine (`CloudPrioritizationEngine`).
  * Non-destructive policy boundaries (`CloudSecurityPolicy`) enforcing allowed methods (`GET`, `HEAD`, `OPTIONS`), blocking metadata probing (`169.254.169.254`), and flagging write actions without executing uploads.
  * Atomic state persistence (`CloudStateManager`) storing state at `state/cloud.json` with sensitive token redaction.
* **Deterministic Local Cloud Security Lab (`LocalCloudSecurityLab`)**:
  * 15 deterministic, in-memory, 100% offline scenarios demonstrating S3/Blob/GCS read and listing, dangling CNAME takeovers, admin interfaces, and false positive rejections.
* **CLI Wrapper (`scripts/bb-cloud`, `scripts/bb-cloud.cmd`)**:
  * Native commands for `--tree`, `--json`, `--passive-only`, `--dry-run`, `--resume`, `--validate`, and `--lab`.
* **System Diagnostics & OpenCode Integration**:
  * Updated `framework/tools/doctor.py` and `scripts/bb-doctor` with Category 22: Cloud Security Intelligence.
  * Added permission rule `*bb-cloud*` with `ask` effect to `opencode.jsonc`.
  * Comprehensive update of `skills/cloud-security/SKILL.md`.

---

## [1.1.1] - 2026-10-04

### OpenCode V2 Runtime Compatibility & Permission Alignment

#### Changed
* **OpenCode V2 Permission Model (`opencode.jsonc`)**:
  * Migrated from legacy syntax to official OpenCode V2 ordered rules array (`action`, `resource`, `effect`, `description`).
  * Enforced OpenCode V2 "last matching rule wins" precedence logic.
  * Baseline safety: broad shell commands default to human approval (`ask`).
  * Safe local operations (`bb-scope-check`, `bb-target-normalize`, `bb-init`, `bb-doctor`, `bb-evidence`, `git status/diff/log`, `--dry-run`, `--check`) granted automatic execution (`allow`).
  * Active security reconnaissance, HTTP interactions, Nuclei, fuzzing, and host-modifying tool installations (`bb-install`, `bb-update`) strictly approval-gated (`ask`).
  * External report submission (`*submit*report*`, platform APIs for HackerOne, Bugcrowd, Intigriti) and unverified remote curl pipes strictly denied (`deny`).
  * Remote repository modifications (`git push`) strictly approval-gated (`ask`).
* **Agent Frontmatters (`.opencode/agents/`)**:
  * Configured `bb-hunter` with `mode: primary`.
  * Configured all 13 specialist agents with `mode: subagent`.
  * Restricted `bb-scope` to offline-only execution (`*` denied, only scope validation allowed).
  * Restricted `bb-report` to local report generation only (denied external submission and git push).
* **System Diagnostics (`framework/tools/doctor.py`, `scripts/bb-doctor`)**:
  * Added validation of OpenCode V2 configuration, agent modes, subagent depth, and permission rules count.
  * Explicitly reports OpenCode runtime status (`PENDING - requires Kali` when tested on development host).

#### Added
* **Automated OpenCode V2 Test Suite (`tests/test_opencode_runtime.py`)**:
  * 14 tests validating V2 configuration structure, last-matching-rule-wins permission evaluation, safe vs active operation categorization, dangerous command rejection, agent frontmatter compliance, skill discovery, and shell injection prevention (67 tests total, 100% passing).

---

## [1.1.0] - 2026-10-03

### Tool Intelligence, Auto-Install & API Provider Expansion — V1.1

#### Added
* **Central Tool Registry (`config/tools.yaml`)**:
  * 44 curated, actively maintained bug bounty tools indexed by tier (`CORE`, `SPECIALIST`, `PROVIDER-BACKED`, `OPTIONAL`, `LEGACY`).
  * Machine-readable metadata: binary names, categories, capabilities, dependencies, fallbacks, install options, verify commands, and documentation links.
* **Wordlist Registry (`config/wordlists.yaml`)**:
  * Curated wordlists for subdomains, web content, API routes, parameter discovery, and public trusted DNS resolvers.
* **Tool Intelligence & Architecture (`framework/tools/`)**:
  * `ToolRegistry`: Validates and indexes tools and capability tags.
  * `CapabilityGraph`: 23 capability domains, category matching, aliases, and intelligent fallback resolution (e.g. `katana` -> `hakrawler`, `subfinder` -> `amass`, `ffuf` -> `feroxbuster`).
  * `DependencyResolver`: Topological sorting for tool-to-tool prerequisites (`shuffledns` -> `massdns`) and runtime environments (`playwright` -> browser binaries, Go, Python/pipx).
  * `ToolDetector`: Host OS, architecture (`amd64`, `arm64`, `386`), binary path resolution, and semantic version validation.
  * `ProviderManager`: Secure credential discovery strictly outside Git (`~/.config/bugbounty-agent/secrets.env`), status reporting without secret exposure.
  * `ToolInstaller`: Safe, deterministic on-demand installation (`apt`, official releases, `go`, `pipx`, `cargo`) with provenance audit logging.
  * `SystemDoctor`: Complete environment diagnostic engine covering 9 categories.
  * `ToolUpdater`: Outdated version inspection and safe update planning.
* **CLI Additions (`scripts/`)**:
  * `bb-doctor` (+ `.cmd`): System health and diagnostic check across 9 categories.
  * `bb-install` (+ `.cmd`): On-demand tool installer supporting individual tools and capability-driven installs.
  * `bb-update` (+ `.cmd`): Tool version checker and updater.
* **13 Dedicated Provider Setup Guides (`docs/tools/`)**:
  * `subfinder.md`, `chaos.md`, `uncover.md`, `interactsh.md`, `shodan.md`, `censys.md`, `securitytrails.md`, `virustotal.md`, `urlscan.md`, `github.md`, `wpscan.md`, `notify.md`, `projectdiscovery-cloud.md`.
* **Master Documentation & README**:
  * Complete 44-tool catalog table with tiers, API key status, auto-install flags, and documentation links.
  * Tools grouped into 23 functional research domains.
  * Comprehensive documentation of automatic detection, installation, updates, credentials, and fallbacks.
* **Automated Test Suite Expansion**:
  * 27 new tests covering registry parsing, capability graph, dependencies, installer planning, security invariants, providers, and doctor diagnostics (53 tests total, 100% passing).

---

## [1.0.0] - 2026-10-03

### Initial Release — BugBounty-Agent V1

#### Added
* **OpenCode Native Architecture**:
  * 14 specialized agents in `.opencode/agents/` led by `bb-hunter`.
  * 14 modular methodology skills in `.opencode/skills/`.
  * Project configuration in `opencode.jsonc` with granular permission model.
  * Hierarchical documentation in `AGENTS.md`.
* **Scope Engine**:
  * Exact domain, wildcard (`*.example.com`), URL prefix, and CIDR/IP evaluation.
  * Arbitrary-depth recursive subdomain evaluation with configurable `max_depth`.
  * DNS-label boundary verification preventing substring spoofing.
  * Strict precedence: Explicit Exclusion > Specific Inclusion > Recursive/Wildcard Inclusion > Ambiguous.
* **Persistent Research State**:
  * Machine-readable state for assets, endpoints, technologies, hypotheses, and tests.
  * Stable test fingerprinting to eliminate redundant scans.
  * Finding deduplication across root cause, endpoint, and vulnerability class.
* **Controlled CLI Layer**:
  * `bb-init`, `bb-scope-check`, `bb-target-normalize`, `bb-recon`, `bb-http`, `bb-content`, `bb-js`, `bb-api`, `bb-nuclei`, and `bb-evidence`.
  * Windows CMD shims for cross-platform execution.
* **Evidence Management**:
  * Cryptographic SHA-256 integrity hashing of HTTP interactions.
  * Automatic regex redaction of Bearer tokens, API keys, and session cookies.
* **Reporting**:
  * 17-section standard disclosure report generator.
* **Automated Test Suite**:
  * Unit and integration test coverage across scope, recursive depth, normalization, deduplication, finding lifecycle, and runtime isolation.
