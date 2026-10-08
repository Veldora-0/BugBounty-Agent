"""
Deterministic Local Cloud Security Lab (Phase 13).

Provides 15 deterministic, offline, in-memory fixtures and simulation scenarios:
1.  AWS S3 public object (HEAD 200, public read verified)
2.  AWS S3 private bucket (AccessDenied, 403 rejected)
3.  AWS S3 listing exposure (ListBucketResult XML returned)
4.  Azure Blob public container (Blob listing verified)
5.  Azure Blob private container (AuthenticationFailed, 403 rejected)
6.  GCP Cloud Storage public object (Public read verified)
7.  CloudFront-only exposure (Informational CDN, no storage leak)
8.  Azure App Service fingerprint only (Informational hosting, no takeover)
9.  GCP Cloud Run fingerprint only (Informational serverless container)
10. Dangling cloud CNAME (Unclaimed AWS S3 NoSuchBucket takeover prompt)
11. Dangling Azure CNAME (Unclaimed 404 Web Site not found)
12. Unauthenticated admin hypothesis (Dashboard 200 with no login barrier)
13. Admin interface with login barrier (Admin 200 with SSO login form rejected)
14. False positive CDN HTML (HTTP 200 normal HTML instead of XML listing)
15. Suspected write capability (Write hypothesis flagged for human review, no mutation)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from framework.cloud_security.models import (
    CloudAsset,
    CloudExposureHypothesis,
    CloudHypothesisType,
    CloudProvider,
    CloudServiceType,
)
from framework.validation.request import ControlledRequest, ControlledResponse


class LocalCloudSecurityLab:
    """Deterministic, 100% offline cloud security evaluation laboratory."""

    SCENARIOS: Dict[str, Dict[str, Any]] = {
        # 1. AWS S3 Public Object
        "aws_s3_public_object": {
            "name": "AWS S3 Public Object Read",
            "asset": "assets.acme.com.s3.amazonaws.com",
            "provider": CloudProvider.AWS,
            "service": CloudServiceType.OBJECT_STORAGE,
            "hypothesis_type": CloudHypothesisType.PUBLIC_OBJECT_READ,
            "endpoint": "https://assets.acme.com.s3.amazonaws.com/logo.png",
            "mock_response": ControlledResponse(
                status_code=200,
                headers={"server": "AmazonS3", "content-type": "image/png"},
                body_text="PNG_DATA_STREAM",
            ),
            "expected_verdict": "ACCEPTED",
        },
        # 2. AWS S3 Private Bucket
        "aws_s3_private_bucket": {
            "name": "AWS S3 Private Bucket AccessDenied",
            "asset": "internal-data.s3.amazonaws.com",
            "provider": CloudProvider.AWS,
            "service": CloudServiceType.OBJECT_STORAGE,
            "hypothesis_type": CloudHypothesisType.PUBLIC_OBJECT_READ,
            "endpoint": "https://internal-data.s3.amazonaws.com",
            "mock_response": ControlledResponse(
                status_code=403,
                headers={"server": "AmazonS3"},
                body_text="<?xml version='1.0'?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>",
            ),
            "expected_verdict": "REJECTED",
        },
        # 3. AWS S3 Listing Exposure
        "aws_s3_listing_exposure": {
            "name": "AWS S3 Public Bucket Listing",
            "asset": "public-backups.s3.amazonaws.com",
            "provider": CloudProvider.AWS,
            "service": CloudServiceType.OBJECT_STORAGE,
            "hypothesis_type": CloudHypothesisType.PUBLIC_OBJECT_LISTING,
            "endpoint": "https://public-backups.s3.amazonaws.com",
            "mock_response": ControlledResponse(
                status_code=200,
                headers={"server": "AmazonS3", "content-type": "application/xml"},
                body_text="""<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>public-backups</Name>
    <Contents>
        <Key>database_backup_2026.sql.gz</Key>
        <Size>10485760</Size>
    </Contents>
</ListBucketResult>""",
            ),
            "expected_verdict": "ACCEPTED",
        },
        # 4. Azure Blob Public Container
        "azure_blob_public_container": {
            "name": "Azure Blob Public Container Enumeration",
            "asset": "acmestorage.blob.core.windows.net",
            "provider": CloudProvider.AZURE,
            "service": CloudServiceType.OBJECT_STORAGE,
            "hypothesis_type": CloudHypothesisType.PUBLIC_OBJECT_LISTING,
            "endpoint": "https://acmestorage.blob.core.windows.net/public?restype=container&comp=list",
            "mock_response": ControlledResponse(
                status_code=200,
                headers={"server": "Windows-Azure-Blob/1.0", "content-type": "application/xml"},
                body_text="""<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ContainerName="https://acmestorage.blob.core.windows.net/public">
    <Blobs>
        <Blob><Name>user_export.csv</Name></Blob>
    </Blobs>
</EnumerationResults>""",
            ),
            "expected_verdict": "ACCEPTED",
        },
        # 5. Azure Blob Private Container
        "azure_blob_private_container": {
            "name": "Azure Blob Private Container AuthenticationFailed",
            "asset": "privatestorage.blob.core.windows.net",
            "provider": CloudProvider.AZURE,
            "service": CloudServiceType.OBJECT_STORAGE,
            "hypothesis_type": CloudHypothesisType.PUBLIC_OBJECT_LISTING,
            "endpoint": "https://privatestorage.blob.core.windows.net/secure?restype=container&comp=list",
            "mock_response": ControlledResponse(
                status_code=403,
                headers={"server": "Windows-Azure-Blob/1.0"},
                body_text="<?xml version='1.0'?><Error><Code>AuthenticationFailed</Code></Error>",
            ),
            "expected_verdict": "REJECTED",
        },
        # 6. GCP Cloud Storage Public Object
        "gcp_storage_public_object": {
            "name": "GCP Cloud Storage Public Read",
            "asset": "static-assets.storage.googleapis.com",
            "provider": CloudProvider.GCP,
            "service": CloudServiceType.OBJECT_STORAGE,
            "hypothesis_type": CloudHypothesisType.PUBLIC_OBJECT_READ,
            "endpoint": "https://static-assets.storage.googleapis.com/report.pdf",
            "mock_response": ControlledResponse(
                status_code=200,
                headers={"server": "UploadServer", "content-type": "application/pdf"},
                body_text="%PDF-1.5...",
            ),
            "expected_verdict": "ACCEPTED",
        },
        # 7. CloudFront-Only Exposure
        "cloudfront_cdn_only": {
            "name": "CloudFront CDN Normal Behavior",
            "asset": "d111111abcdef8.cloudfront.net",
            "provider": CloudProvider.AWS,
            "service": CloudServiceType.CDN,
            "hypothesis_type": CloudHypothesisType.INFORMATIONAL_FINGERPRINT,
            "endpoint": "https://d111111abcdef8.cloudfront.net",
            "mock_response": ControlledResponse(
                status_code=200,
                headers={"server": "CloudFront", "x-amz-cf-id": "XYZ123=="},
                body_text="<html>CDN Front</html>",
            ),
            "expected_verdict": "INFORMATIONAL",
        },
        # 8. Azure App Service Fingerprint Only
        "azure_app_service_fingerprint": {
            "name": "Azure App Service Normal Endpoint",
            "asset": "acme-portal.azurewebsites.net",
            "provider": CloudProvider.AZURE,
            "service": CloudServiceType.APP_HOSTING,
            "hypothesis_type": CloudHypothesisType.INFORMATIONAL_FINGERPRINT,
            "endpoint": "https://acme-portal.azurewebsites.net",
            "mock_response": ControlledResponse(
                status_code=200,
                headers={"server": "Microsoft-IIS/10.0"},
                body_text="<html>Welcome to Acme Portal</html>",
            ),
            "expected_verdict": "INFORMATIONAL",
        },
        # 9. GCP Cloud Run Fingerprint Only
        "gcp_cloud_run_fingerprint": {
            "name": "GCP Cloud Run Normal Microservice",
            "asset": "api-service-xyz-uc.a.run.app",
            "provider": CloudProvider.GCP,
            "service": CloudServiceType.CONTAINER_ENDPOINT,
            "hypothesis_type": CloudHypothesisType.INFORMATIONAL_FINGERPRINT,
            "endpoint": "https://api-service-xyz-uc.a.run.app",
            "mock_response": ControlledResponse(
                status_code=200,
                headers={"server": "Google Frontend"},
                body_text='{"status": "ok"}',
            ),
            "expected_verdict": "INFORMATIONAL",
        },
        # 10. Dangling Cloud CNAME Takeover (AWS)
        "dangling_cname_aws_takeover": {
            "name": "Dangling CNAME AWS NoSuchBucket Takeover",
            "asset": "downloads.acme.com",
            "provider": CloudProvider.AWS,
            "service": CloudServiceType.DNS_ROUTING,
            "hypothesis_type": CloudHypothesisType.POTENTIAL_CLOUD_TAKEOVER,
            "endpoint": "https://downloads.acme.com",
            "mock_response": ControlledResponse(
                status_code=404,
                headers={"server": "AmazonS3"},
                body_text="<?xml version='1.0'?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>",
            ),
            "expected_verdict": "ACCEPTED",
        },
        # 11. Dangling Azure CNAME Takeover
        "dangling_cname_azure_takeover": {
            "name": "Dangling CNAME Azure Web Site Not Found",
            "asset": "staging.acme.com",
            "provider": CloudProvider.AZURE,
            "service": CloudServiceType.DNS_ROUTING,
            "hypothesis_type": CloudHypothesisType.POTENTIAL_CLOUD_TAKEOVER,
            "endpoint": "https://staging.acme.com",
            "mock_response": ControlledResponse(
                status_code=404,
                headers={"server": "Microsoft-Azure-AppService"},
                body_text="<html>404 Web Site not found. The app is stopped or does not exist.</html>",
            ),
            "expected_verdict": "ACCEPTED",
        },
        # 12. Unauthenticated Admin Interface
        "unauthenticated_admin_interface": {
            "name": "Unauthenticated Cloud Admin Interface",
            "asset": "admin.cloud.acme.com",
            "provider": CloudProvider.AWS,
            "service": CloudServiceType.ADMIN_INTERFACE,
            "hypothesis_type": CloudHypothesisType.UNAUTHENTICATED_ADMIN_ACCESS,
            "endpoint": "https://admin.cloud.acme.com/admin/dashboard",
            "mock_response": ControlledResponse(
                status_code=200,
                headers={"content-type": "text/html", "server": "AmazonS3", "x-amz-request-id": "adm123"},
                body_text="<html><h1>Cloud Administration Console</h1><button>Manage Clusters</button></html>",
            ),
            "expected_verdict": "ACCEPTED",
        },
        # 13. Admin Interface Enforcing Login Barrier
        "admin_interface_login_protected": {
            "name": "Admin Interface Enforcing SSO / Login",
            "asset": "secure-admin.acme.com",
            "provider": CloudProvider.GCP,
            "service": CloudServiceType.ADMIN_INTERFACE,
            "hypothesis_type": CloudHypothesisType.UNAUTHENTICATED_ADMIN_ACCESS,
            "endpoint": "https://secure-admin.acme.com/admin",
            "mock_response": ControlledResponse(
                status_code=200,
                headers={"content-type": "text/html", "server": "Google Frontend", "x-cloud-trace-context": "gcp123"},
                body_text="<html><h2>Please Log In</h2><form action='/sso/auth'><input type='password' name='pass'></form></html>",
            ),
            "expected_verdict": "REJECTED",
        },
        # 14. False Positive CDN HTML
        "false_positive_cdn_html": {
            "name": "CDN HTML 200 Rejected as Bucket Listing",
            "asset": "cdn-cache.acme.com",
            "provider": CloudProvider.CLOUDFLARE,
            "service": CloudServiceType.OBJECT_STORAGE,
            "hypothesis_type": CloudHypothesisType.PUBLIC_OBJECT_LISTING,
            "endpoint": "https://cdn-cache.acme.com",
            "mock_response": ControlledResponse(
                status_code=200,
                headers={"content-type": "text/html", "server": "cloudflare"},
                body_text="<!DOCTYPE html><html><body><h1>Acme Marketing Page</h1></body></html>",
            ),
            "expected_verdict": "REJECTED",
        },
        # 15. Suspected Write Capability
        "suspected_write_capability": {
            "name": "Suspected Write Capability Flagged (No Mutation)",
            "asset": "uploads.acme.com.s3.amazonaws.com",
            "provider": CloudProvider.AWS,
            "service": CloudServiceType.OBJECT_STORAGE,
            "hypothesis_type": CloudHypothesisType.WRITE_CAPABILITY_SUSPECTED,
            "endpoint": "https://uploads.acme.com.s3.amazonaws.com",
            "mock_response": ControlledResponse(
                status_code=200,
                headers={"server": "AmazonS3"},
                body_text="Bucket root",
            ),
            "expected_verdict": "NEEDS_VALIDATION",
        },
    }

    @classmethod
    def list_scenarios(cls) -> List[str]:
        return list(cls.SCENARIOS.keys())

    @classmethod
    def get_scenario(cls, scenario_key: str) -> Optional[Dict[str, Any]]:
        return cls.SCENARIOS.get(scenario_key)

    @classmethod
    def make_mock_requester(cls):
        """Creates a mock HTTP request handler matching the lab scenario endpoints."""
        def mock_request(req: ControlledRequest) -> ControlledResponse:
            for sdata in cls.SCENARIOS.values():
                if req.url.startswith(sdata["endpoint"]) or sdata["endpoint"].startswith(req.url):
                    return sdata["mock_response"]
            return ControlledResponse(status_code=404, body_text="Not Found")
        return mock_request
