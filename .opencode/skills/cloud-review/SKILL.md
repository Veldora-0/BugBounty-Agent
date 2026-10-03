---
name: cloud-review
description: Cloud asset review, misconfiguration analysis, storage bucket permissions, and metadata exposure assessment.
---

# Cloud Review Methodology

## Core Objective
Examine cloud-hosted interfaces (AWS, GCP, Azure, Cloudflare) for common exposure vectors, publicly writable object storage, dangling DNS pointers, and server-side metadata access.

## Focus Areas
1. **Public Storage Buckets**:
   * S3, GCS, or Azure Blob URLs discovered in HTML or JS bundles.
   * Check permissions: Test if listing (`ListBucket`) or writing (`PutObject`) is anonymously enabled on authorized target buckets.
2. **SSRF & Cloud Metadata Access**:
   * Where an endpoint fetches remote URLs or webhooks, test for SSRF targeting internal metadata endpoints (e.g. `http://169.254.169.254/latest/meta-data/`).
3. **Subdomain Takeovers (Dangling CNAMEs)**:
   * Identify CNAME records pointing to unclaimed cloud services (unclaimed S3 buckets, GitHub Pages, Heroku, Azure Traffic Manager).
   * Verify claimability safely without deploying disruptive assets.

## Safety & Scope Boundaries
* **DO NOT** access unrelated third-party infrastructure merely because an application references it.
* If a storage bucket is discovered that clearly belongs to an unlisted third party (e.g. a shared CDN dependency), do not attempt destructive actions or data exfiltration.
