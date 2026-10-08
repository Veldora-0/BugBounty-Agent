"""
Cloud Service Identification and Resource Extractor (Phase 13).

Detects specific cloud services and extracts structured resource identifiers:
- AWS: S3, CloudFront, API Gateway, ELB/ALB, Elastic Beanstalk
- Azure: Blob Storage, App Service, Front Door / CDN, Traffic Manager, API Management
- GCP: Cloud Storage, Cloud Run, App Engine, Cloud Functions
- Generic: Object Storage, Exposed Admin Interfaces, Cloud-hosted APIs
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from framework.cloud_security.models import (
    CloudProvider,
    CloudResource,
    CloudServiceType,
    CloudExposureState,
)


class CloudServiceIdentifier:
    """Classifies specific cloud services and extracts resource identifiers from endpoints/hostnames."""

    @classmethod
    def identify_service(
        cls,
        provider: CloudProvider,
        hostname: str,
        path: str = "",
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[CloudServiceType, Optional[str], Optional[str]]:
        """
        Returns:
            (CloudServiceType, resource_identifier, region)
        """
        host = (hostname or "").lower()
        headers_str = " ".join([f"{k}:{v}" for k, v in (headers or {}).items()]).lower()

        # ----------------------------------------------------------------------
        # 1. AWS Services
        # ----------------------------------------------------------------------
        if provider == CloudProvider.AWS or "amazonaws.com" in host or "cloudfront.net" in host:
            # S3: bucket.s3.amazonaws.com or bucket.s3.region.amazonaws.com or s3.amazonaws.com/bucket
            s3_match1 = re.match(r"^([a-z0-9.\-_]+)\.s3(?:-([a-z0-9\-]+))?\.amazonaws\.com$", host)
            if s3_match1:
                bucket = s3_match1.group(1)
                region = s3_match1.group(2)
                return CloudServiceType.OBJECT_STORAGE, bucket, region

            s3_match2 = re.match(r"^s3(?:-([a-z0-9\-]+))?\.amazonaws\.com$", host)
            if s3_match2:
                region = s3_match2.group(1)
                # Bucket may be first path component
                clean_path = path.strip("/")
                bucket = clean_path.split("/")[0] if clean_path else "unknown_s3_bucket"
                return CloudServiceType.OBJECT_STORAGE, bucket, region

            # API Gateway: *.execute-api.<region>.amazonaws.com
            apigw_match = re.match(r"^([a-z0-9]+)\.execute-api\.([a-z0-9\-]+)\.amazonaws\.com$", host)
            if apigw_match:
                return CloudServiceType.API_GATEWAY, apigw_match.group(1), apigw_match.group(2)

            # CloudFront: *.cloudfront.net
            cf_match = re.match(r"^([a-z0-9]+)\.cloudfront\.net$", host)
            if cf_match:
                return CloudServiceType.CDN, cf_match.group(1), None

            # ELB / ALB: *.elb.amazonaws.com
            if ".elb.amazonaws.com" in host or "awselb" in headers_str:
                return CloudServiceType.LOAD_BALANCER, host.split(".")[0], None

            # Elastic Beanstalk: *.elasticbeanstalk.com
            eb_match = re.match(r"^([a-z0-9\-]+)\.([a-z0-9\-]+)\.elasticbeanstalk\.com$", host)
            if eb_match:
                return CloudServiceType.APP_HOSTING, eb_match.group(1), eb_match.group(2)

        # ----------------------------------------------------------------------
        # 2. Azure Services
        # ----------------------------------------------------------------------
        if provider == CloudProvider.AZURE or "windows.net" in host or "azurewebsites.net" in host:
            # Azure Blob: *.blob.core.windows.net
            blob_match = re.match(r"^([a-z0-9\-]+)\.blob\.core\.windows\.net$", host)
            if blob_match:
                account = blob_match.group(1)
                clean_path = path.strip("/")
                container = clean_path.split("/")[0] if clean_path else None
                identifier = f"{account}/{container}" if container else account
                return CloudServiceType.OBJECT_STORAGE, identifier, None

            # Azure App Service: *.azurewebsites.net
            app_match = re.match(r"^([a-z0-9\-]+)\.azurewebsites\.net$", host)
            if app_match:
                return CloudServiceType.APP_HOSTING, app_match.group(1), None

            # Azure Front Door: *.azurefd.net
            fd_match = re.match(r"^([a-z0-9\-]+)\.azurefd\.net$", host)
            if fd_match:
                return CloudServiceType.CDN, fd_match.group(1), None

            # Traffic Manager: *.trafficmanager.net
            tm_match = re.match(r"^([a-z0-9\-]+)\.trafficmanager\.net$", host)
            if tm_match:
                return CloudServiceType.DNS_ROUTING, tm_match.group(1), None

            # Azure API Management: *.azure-api.net
            apim_match = re.match(r"^([a-z0-9\-]+)\.azure-api\.net$", host)
            if apim_match:
                return CloudServiceType.API_GATEWAY, apim_match.group(1), None

        # ----------------------------------------------------------------------
        # 3. GCP Services
        # ----------------------------------------------------------------------
        if provider == CloudProvider.GCP or "googleapis.com" in host or "appspot.com" in host or "run.app" in host:
            # Google Cloud Storage: *.storage.googleapis.com or storage.googleapis.com/bucket
            if host == "storage.googleapis.com":
                clean_path = path.strip("/")
                bucket = clean_path.split("/")[0] if clean_path else "unknown_gcs_bucket"
                return CloudServiceType.OBJECT_STORAGE, bucket, None

            gcs_match = re.match(r"^([a-z0-9.\-_]+)\.storage\.googleapis\.com$", host)
            if gcs_match:
                return CloudServiceType.OBJECT_STORAGE, gcs_match.group(1), None

            # Cloud Run: *.run.app
            run_match = re.match(r"^([a-z0-9\-]+)-[a-z0-9]+\.([a-z0-9\-]+)\.run\.app$", host)
            if run_match:
                return CloudServiceType.CONTAINER_ENDPOINT, run_match.group(1), run_match.group(2)
            if host.endswith(".run.app"):
                return CloudServiceType.CONTAINER_ENDPOINT, host.split(".")[0], None

            # App Engine: *.appspot.com
            appspot_match = re.match(r"^([a-z0-9\-]+)\.appspot\.com$", host)
            if appspot_match:
                return CloudServiceType.APP_HOSTING, appspot_match.group(1), None

            # Cloud Functions: *.<region>-<project>.cloudfunctions.net
            cfn_match = re.match(r"^([a-z0-9\-]+)\.cloudfunctions\.net$", host)
            if cfn_match:
                return CloudServiceType.SERVERLESS_ENDPOINT, cfn_match.group(1), None

        # ----------------------------------------------------------------------
        # 4. Cloudflare / Fastly CDN / DigitalOcean Spaces
        # ----------------------------------------------------------------------
        if provider == CloudProvider.CLOUDFLARE:
            if host.endswith(".workers.dev"):
                return CloudServiceType.SERVERLESS_ENDPOINT, host.split(".")[0], None
            if host.endswith(".pages.dev"):
                return CloudServiceType.APP_HOSTING, host.split(".")[0], None
            return CloudServiceType.CDN, host, None

        if provider == CloudProvider.FASTLY:
            return CloudServiceType.CDN, host, None

        if provider == CloudProvider.DIGITALOCEAN:
            if "digitaloceanspaces.com" in host:
                return CloudServiceType.OBJECT_STORAGE, host.split(".")[0], None
            if "ondigitalocean.app" in host:
                return CloudServiceType.APP_HOSTING, host.split(".")[0], None

        # Fallback / Admin Interface detection
        if any(term in path.lower() for term in ["/admin", "/dashboard", "/console", "/portal", "/management"]):
            return CloudServiceType.ADMIN_INTERFACE, f"{host}{path}", None

        return CloudServiceType.UNKNOWN_CLOUD_SERVICE, host or None, None
