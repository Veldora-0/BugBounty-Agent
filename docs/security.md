# BugBounty-Agent — Safety, Ethics & Security Controls

BugBounty-Agent is intended **strictly for authorized security research** under established bug bounty programs or explicit written authorization.

---

## 1. Hard Architectural Safeguards

The framework code enforces the following non-negotiable architectural boundaries:

1. **No Automated Denial of Service**: The framework strictly prohibits stress testing, volumetric HTTP flooding, or algorithmic complexity exhaustion.
2. **No Destructive Exploitation**: No database drops (`DROP TABLE`), record deletions, disk overwrites, or operating system state alterations.
3. **No Credential Attacks**: Password spraying, credential stuffing, and brute-force dictionary attacks against authentication interfaces are forbidden.
4. **No Unauthorized Third-Party Probing**: Discovered dependencies (shared CDNs, SaaS services, analytics endpoints) are strictly filtered out unless explicitly authorized in `scope.yaml`.
5. **No Malware or Persistence**: No shellcode deployment, rootkits, backdoors, or persistence mechanisms are included or permitted.
6. **No Automated Report Submission**: The framework writes disclosure reports to local files (`reports/`) for manual human review and verification. It never interfaces with platform submission APIs without human review.

---

## 2. Sensitive Data & Secret Protection

1. **Automatic Redaction**:
   * Authorization tokens (`Bearer ...`), API keys, and session cookies (`sessionid=...`) are automatically sanitized to `[REDACTED_BY_BB_AGENT]` before persisting to disk or generating reports.
2. **Git Tracking Barrier**:
   * `.gitignore` covers `.env`, `credentials/`, `evidence/`, `scans/`, `targets/`, `*.burp`, `*.key`, and `*.token`.
   * Real target data and secrets must never be added to repository commits.
3. **Pre-Commit Verification**:
   * Before committing, verify git status to confirm no local target data or runtime files are tracked.

---

## 3. Authentication & Identity Testing Safeguards (Phase 14)

1. **Researcher-Controlled Accounts Only**:
   * All authentication, session, password-reset, and MFA testing is performed strictly against explicitly designated, researcher-controlled accounts.
   * Never send password reset requests or verification emails to third-party accounts.
2. **Explicitly Prohibited Operations**:
   * **Zero** password spraying, credential stuffing, password guessing, or dictionary attacks.
   * **Zero** token brute forcing, OTP brute forcing, or OTP flooding.
   * **Zero** CAPTCHA bypass, SIM swap attacks, or attacks against third-party Identity Providers (IdPs).
   * **Zero** mass account enumeration or automated account takeover attempts.
3. **Human Approval Gate (`AuthenticationApprovalGate`)**:
   * State-mutating operations (password reset submission, password changes, MFA enrollments, session revocations) require explicit `--approve` operator confirmation and produce an audit dossier before execution.
4. **Credential Redaction Invariant**:
   * Passwords, live session cookies, refresh tokens, and bearer tokens are never persisted in state files or reports; only cryptographic SHA-256 fingerprint references (`sess_sha256_...`) are tracked.

