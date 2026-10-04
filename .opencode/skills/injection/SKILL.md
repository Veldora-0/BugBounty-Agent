---
name: injection
description: Non-destructive injection flaw analysis covering XSS, SQLi, NoSQLi, command injection, SSTI, path traversal, and SSRF.
---

# Injection Testing Methodology

## Core Objective
Evaluate how target applications sanitize, validate, and parse user-controlled input across interpreters, databases, template engines, and operating system interfaces without causing harm or data loss.

## Strict Non-Destructive Invariant
* **NEVER** use destructive SQL commands (`DROP`, `DELETE`, `UPDATE`, `INSERT`, `TRUNCATE`).
* **NEVER** execute malware, download external binaries, or establish reverse shells.
* **NEVER** overwrite server files or modify system configurations.
* Use benign mathematical expressions, non-destructive delays, and safe reflection markers.

## 1. Vulnerability Classes & Safe Probes

### Cross-Site Scripting (XSS)
* **Reflection Context Detection**: Test unique alphanumeric canary strings (`bbsec73921`) to determine context (HTML body, attribute, JavaScript block).
* **Safe Marker Execution**: Use non-intrusive payloads:
  * `<b/id=bbsec>` or `<svg/onload=console.log(1)>`
  * Never use aggressive or persistent alert loops.
* **Specialized Tooling**: Run `dalfox` for contextual parameter analysis.

### SQL & NoSQL Injection
* **Boolean Differential**: Compare responses for `AND 1=1` vs `AND 1=2`, or `' OR ''='` variations.
* **Time-Based Delays**: Use conservative delays (`SLEEP(2)` or `pg_sleep(2)`) to confirm asynchronous execution.
* **Safe Arithmetic**: Compare `id=10-1` vs `id=9`.
* **NoSQL Probes**: Test JSON object injections (`{"$ne": null}`, `{"$gt": ""}`).
* **Tooling**: Employ `sqlmap --batch --technique=BT --current-user` strictly in read-only diagnostic mode.

### Server-Side Template Injection (SSTI)
* **Arithmetic Expressions**: Inject benign expressions: `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}`.
* **Engine Disambiguation**: Verify engine behavior based on expression evaluation (`49` response confirms execution).

### OS Command Injection
* **Time Delay Markers**: Test non-destructive delays: `; sleep 2;`, `| sleep 2 |`, `& timeout 2 &`.
* **Benign Output**: Verify command substitution with safe arithmetic: `echo $((21+21))`.

### Path Traversal & Arbitrary File Read
* **Standard Paths**: Attempt to read standard non-sensitive system files:
  * Linux: `/etc/hosts`, `/etc/issue`
  * Windows: `C:\Windows\win.ini`
* **Avoid**: Never attempt to exfiltrate private user files or system password hashes.

### Server-Side Request Forgery (SSRF)
* **Loopback & Metadata Checks**: Test loopback addresses (`127.0.0.1`, `[::1]`) and cloud metadata (`169.254.169.254`).
* **DNS Rebinding & Alternative Representations**: Test decimal, octal, and hex IP notations.

## 2. Evidence Standards
* Capture exact HTTP request and response showing the canary reflection, arithmetic computation, or measured response delay.
* Record round-trip timing evidence for time-based confirmations.
