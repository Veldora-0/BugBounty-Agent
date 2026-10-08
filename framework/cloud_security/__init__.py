"""
Cloud Security & Misconfiguration Intelligence Engine (Phase 13).

Provides structured modeling, provider fingerprinting, exposure hypothesis generation,
safe non-destructive validation, false-positive classification, and prioritized findings
for cloud-hosted assets across AWS, Azure, GCP, Cloudflare, Fastly, DigitalOcean, and Oracle.
"""

from framework.cloud_security.models import (
    CloudAsset,
    CloudExposureHypothesis,
    CloudExposureState,
    CloudFindingCandidate,
    CloudProvider,
    CloudResource,
    CloudServiceType,
    HypothesisValidationStatus,
)
from framework.cloud_security.engine import CloudSecurityEngine
from framework.cloud_security.policy import CloudSecurityPolicy
from framework.cloud_security.lab import LocalCloudSecurityLab

__all__ = [
    "CloudProvider",
    "CloudServiceType",
    "CloudExposureState",
    "CloudAsset",
    "CloudResource",
    "CloudExposureHypothesis",
    "CloudFindingCandidate",
    "HypothesisValidationStatus",
    "CloudSecurityEngine",
    "CloudSecurityPolicy",
    "LocalCloudSecurityLab",
]
