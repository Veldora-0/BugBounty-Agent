---
name: oob
description: Controlled out-of-band (OOB) interaction testing, blind vulnerability confirmation, and asynchronous callback verification via Interactsh.
---

# Out-of-Band (OOB) Testing Methodology

## Core Objective
Safely confirm blind vulnerabilities that do not return direct output in the HTTP response body. Use dedicated, controlled out-of-band interaction servers to receive asynchronous DNS, HTTP, or SMTP callbacks.

## 1. Vulnerability Classes Requiring OOB
* **Blind Server-Side Request Forgery (SSRF)**: Webhook endpoints, PDF/image converters, URL unfurling services, and proxy forwarders that fetch external URLs asynchronously.
* **Blind Remote Command Injection**: Commands executed in background worker queues or asynchronous job processors.
* **Blind XML External Entity (XXE)**: XML parsers parsing external DTDs or system entities without returning parsed entity values.
* **Blind SQL Injection**: Database functions triggering external network lookups (`xp_dirtree` in MSSQL, `UTL_HTTP` in Oracle).
* **Blind Log4Shell / JNDI**: JNDI lookups triggered via LDAP or RMI callbacks.

## 2. Infrastructure: Interactsh Integration
* Use the ProjectDiscovery `interactsh-client` to generate isolated session domains:
  `subdomain.oob.example.com`
* Track callbacks across three protocols:
  * **DNS**: Resolving the unique session subdomain confirms execution even when egress HTTP traffic is blocked by corporate egress firewalls.
  * **HTTP / HTTPS**: Receiving an HTTP GET/POST request provides source IP, user-agent, and header evidence.
  * **SMTP / LDAP**: Confirms protocol-specific injection vectors.

## 3. Correlation & Provenance Standards
* Every OOB probe MUST include a unique, correlated identifier in the subdomain prefix:
  `<program>-<test_id>-<timestamp>.oob.domain.com`
* When an interaction is observed:
  * Record the exact timestamp of transmission and reception.
  * Record the source IP address that performed the resolution or connection.
  * Record the correlated payload and parameter that triggered the interaction.

## 4. Ethical & Authorization Boundaries
* Only use official, authorized OOB server domains (either self-hosted or trusted ProjectDiscovery Cloud infrastructure).
* Never exfiltrate actual customer data or sensitive configuration values in DNS subdomains. Use random canaries solely to prove callback receipt.
