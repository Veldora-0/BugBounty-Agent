---
name: injection-analysis
description: Non-destructive injection flaw analysis covering XSS, SQLi, SSTI, command injection, and path traversal.
---

# Injection Analysis Methodology

## Core Objective
Identify flaws where untrusted user input is passed directly into interpreters, parsers, or execution engines without adequate sanitization, parameterization, or context-aware encoding.

## Critical Safety Principle: Non-Destructive Testing
* **NEVER** perform destructive database updates, drops, or schema modifications (`DROP TABLE`, `UPDATE users SET password=...`).
* **NEVER** execute system command payloads that alter the OS (`rm -rf`, `chmod`, `reboot`).
* Use benign proof-of-concept markers:
  * For SQL Injection: `SLEEP(2)` or Boolean differential queries (`AND 1=1` vs `AND 1=2`).
  * For SSTI: Math evaluation expressions such as `{{7*7}}` -> `49`.
  * For Command Injection: `id` or `whoami` returning current non-root username, or time delays (`sleep 3`).
  * For XSS: Harmless markers like `<test-tag-bb>` or `alert(document.domain)` (in authorized browsers).

## Hypothesis-Driven Pipeline
1. **Observation**: Notice reflection or parameter parsing in server response.
2. **Context Identification**: Determine context (HTML body, attribute, JavaScript literal, SQL query, OS command).
3. **Boundary Probe**: Send minimal syntax characters (e.g. `'`, `"`, `-->`, `}}`, `|`) and inspect response syntax error or change.
4. **Controlled Proof**: Send safe calculation or harmless delimiter.
5. **Evidence Preservation**: Save raw HTTP request and response with `bb-evidence`.
