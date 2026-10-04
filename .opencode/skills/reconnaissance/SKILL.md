---
name: reconnaissance
description: Controlled passive and active surface reconnaissance, DNS resolution, HTTP probing, technology detection, and content discovery.
---

# Reconnaissance Methodology

## Core Objective
Systematically map an organization's authorized external attack surface using passive intelligence feeds, controlled DNS resolution, HTTP service probing, and content discovery without exceeding rate limits or generating disruptive traffic.

## 1. Passive Reconnaissance (Zero Target Traffic)
* **Certificate Transparency (CT)**: Interrogate public CT logs using `subfinder` and `assetfinder`.
* **Passive DNS Feeds**: Aggregate historical records from VirusTotal, SecurityTrails, Censys, and ProjectDiscovery Chaos where API keys are configured.
* **Search Engine Intelligence**: Query Google, Bing, Shodan, and Uncover for public indexing anomalies.
* **Repository & Code Dorks**: Review public GitHub commits and developer documentation for referenced staging endpoints.

## 2. Controlled Active Reconnaissance
* **DNS Resolution & Permutations**:
  * Resolve candidate hostnames with `dnsx` using trusted resolvers.
  * Generate algorithmic permutations using `alterx` or `dnsgen` for high-value targets.
  * Employ `shuffledns` with `massdns` for large-scale wordlist brute-forcing only when explicitly authorized.
* **HTTP Service Probing**:
  * Probe live HTTP and HTTPS endpoints using `httpx`.
  * Capture HTTP response status codes, redirects, web server headers, TLS certificate details, and JARM/favicon hashes.
  * Enforce strict concurrency and rate limits (`--rate-limit 5`).
* **Service & Port Discovery**:
  * Execute lightweight port scanning using `naabu` across top standard web and administrative ports.
  * For specialized network audits, invoke `nmap` with controlled flags.
* **Technology & Stack Fingerprinting**:
  * Identify CMS platforms (WordPress, Drupal), frameworks (React, Vue, Next.js, Django, Spring), and servers (Nginx, Apache, IIS, Caddy).
  * Check for exposed management interfaces (`/swagger`, `/actuator`, `/debug`, `/_health`).
* **Directory & Content Discovery**:
  * Perform controlled fuzzing using `ffuf`, `feroxbuster`, or `dirsearch` with calibrated wordlists from `config/wordlists.yaml`.
  * Filter out wildcard 404 responses and soft-redirect pages.

## 3. Tool Orchestration & Graceful Fallbacks
Orchestrate tools dynamically via the Tool Registry rather than hardcoding executions:
* Subdomain Discovery: `subfinder` → fallback `amass` → fallback `assetfinder`.
* Crawling & URL Extraction: `katana` → fallback `hakrawler` → fallback `gospider`.
* Web Fuzzing: `ffuf` → fallback `feroxbuster` → fallback `dirsearch`.

## 4. Normalization & Deduplication
* Filter all discovered hostnames through `bb-scope-check` before network probing.
* Pipe raw outputs through `anew` and `uro` to ensure only unique, normalized records are passed to analysis modules.
* Record discovery provenance (timestamp, tool, raw banner) for all active services.
