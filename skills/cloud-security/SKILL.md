---
name: cloud-security
description: Cloud infrastructure security review, public storage bucket auditing, metadata SSRF exposure, and dangling DNS takeover assessment.
---

# Cloud Security Methodology

## Core Objective
Evaluate cloud-hosted components, storage repositories, serverless functions, and infrastructure configurations associated with target applications across AWS, GCP, Azure, and Cloudflare.

## 1. Investigation Vectors

### Public Cloud Storage Repositories
* **Bucket Discovery**: Extract cloud storage names (Amazon S3, Google Cloud Storage, Azure Blob Storage) from web responses, JavaScript files, and CNAME records.
* **Anonymous Access Testing**:
  * Check for unauthenticated listing permissions: `aws s3 ls s3://<bucket> --no-sign-request`.
  * Check for anonymous read and write permissions on target-owned buckets.
* **Boundary Invariant**: NEVER write, delete, or overwrite data in third-party or shared cloud storage. If a bucket is public, stop at read-only proof of listing.

### Cloud Instance Metadata & SSRF
* **Metadata Endpoints**:
  * AWS / OpenStack / GCP: `http://169.254.169.254/latest/meta-data/`
  * Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
  * DigitalOcean: `http://169.254.169.254/metadata/v1/`
* **IMDSv2 Awareness**: Test whether token retrieval (`PUT /latest/api/token`) is enforced.
* **Header Exploitation**: Test whether SSRF vectors can forward custom headers required by cloud providers (`Metadata: true`).

### Dangling DNS & Subdomain Takeovers
* **Cloud Service Pointers**: Inspect CNAME records pointing to decommissioned or unclaimed cloud resources:
  * GitHub Pages, Heroku, AWS S3, CloudFront, Azure Traffic Manager, Fastly.
* **Takeover Verification**: Verify if the underlying provider returns a service-not-found registration prompt rather than executing an unauthorized claim.

### Cloud Configuration & Deployment Exposures
* **Exposed Environment Files**: Probe for publicly accessible `.env`, `.aws/credentials`, `docker-compose.yml`, or CI/CD deployment configurations.
* **Serverless Endpoints**: Identify unauthenticated AWS Lambda function URLs or API Gateway direct invokes.

## 2. Operating Boundaries
* Only test cloud assets directly owned by the authorized target program.
* Never launch attacks against multi-tenant cloud control planes or third-party infrastructure.
