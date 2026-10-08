"""
Safe Cloud Validators and False Positive Elimination (Phase 13).

Provides deterministic verification for:
- S3 Bucket anonymous read / listing
- Azure Blob anonymous container read / listing
- GCP Cloud Storage anonymous read / listing
- Cloud Takeover signature detection (unclaimed tenant/bucket prompts)
- Admin Interface authentication presence check
- CloudFalsePositiveClassifier: Prevents mistaking normal CDN endpoints,
  HTTP 200 responses, or expected static public assets for vulnerabilities.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from framework.cloud_security.models import (
    CloudExposureHypothesis,
    CloudExposureState,
    CloudFindingCandidate,
    CloudHypothesisType,
    CloudProvider,
    CloudServiceType,
    HypothesisValidationStatus,
)
from framework.cloud_security.policy import CloudSecurityPolicy
from framework.findings.lifecycle import FindingLifecycle
from framework.validation.request import ControlledRequest, ControlledResponse


# Cloud takeover error messages per provider
TAKEOVER_PATTERNS: Dict[CloudProvider, List[re.Pattern]] = {
    CloudProvider.AWS: [
        re.compile(r"The specified bucket does not exist", re.IGNORECASE),
        re.compile(r"NoSuchBucket", re.IGNORECASE),
        re.compile(r"404 Not Found.*Code: NoSuchBucket", re.IGNORECASE),
        re.compile(r"Bad Request.*Bucket does not exist", re.IGNORECASE),
    ],
    CloudProvider.AZURE: [
        re.compile(r"The specified resource does not exist", re.IGNORECASE),
        re.compile(r"ResourceNotFound", re.IGNORECASE),
        re.compile(r"404 Web Site not found", re.IGNORECASE),
        re.compile(r"azurewebsites\.net.*not found", re.IGNORECASE),
    ],
    CloudProvider.GCP: [
        re.compile(r"The specified bucket does not exist", re.IGNORECASE),
        re.compile(r"NoSuchBucket", re.IGNORECASE),
        re.compile(r"BucketNotFound", re.IGNORECASE),
    ],
    CloudProvider.FASTLY: [
        re.compile(r"Fastly error: unknown domain", re.IGNORECASE),
    ],
}


class CloudFalsePositiveClassifier:
    """Eliminates non-vulnerable cloud hosting behaviors and scanner false positives."""

    @classmethod
    def evaluate(
        cls,
        hypothesis: CloudExposureHypothesis,
        response: Optional[ControlledResponse],
    ) -> Tuple[HypothesisValidationStatus, str]:
        """
        Validates if an observation represents a legitimate vulnerability or an expected false positive.
        """
        # Rule 1: CDN endpoints are designed to be public; returning 200 is expected and informational
        if hypothesis.service == CloudServiceType.CDN and hypothesis.hypothesis_type == CloudHypothesisType.INFORMATIONAL_FINGERPRINT:
            return HypothesisValidationStatus.INFORMATIONAL, "Cloud CDN endpoint is inherently public by design; not a vulnerability."

        if response is None:
            return HypothesisValidationStatus.NEEDS_VALIDATION, "No response data available to evaluate."

        status_code = response.status_code
        body = response.body_text or ""
        headers = {k.lower(): v for k, v in response.headers.items()}

        # Rule 2: AccessDenied or 403 Forbidden means private bucket / access controls are WORKING
        if status_code in (401, 403) or "AccessDenied" in body or "AuthenticationFailed" in body:
            return HypothesisValidationStatus.REJECTED, "Access control enforced by cloud provider (HTTP 403 / AccessDenied)."

        # Rule 3: HTTP 200 on administrative interface with active login form / SSO redirect is SECURE
        if hypothesis.hypothesis_type == CloudHypothesisType.UNAUTHENTICATED_ADMIN_ACCESS:
            login_indicators = ["login", "signin", "sso", "authenticate", "password", "oauth"]
            if any(term in body.lower() for term in login_indicators) or status_code in (301, 302, 307, 308):
                return HypothesisValidationStatus.REJECTED, "Admin portal enforces authentication / login prompt; no unauthenticated bypass observed."

        # Rule 4: Ordinary HTML/web page returning 200 on S3/Azure is website hosting, not raw bucket leak
        content_type = headers.get("content-type", "").lower()
        if hypothesis.hypothesis_type == CloudHypothesisType.PUBLIC_OBJECT_LISTING:
            if "text/html" in content_type and not ("<ListBucketResult>" in body or "<EnumerationResults" in body):
                return HypothesisValidationStatus.REJECTED, "HTTP 200 returned normal HTML content, not XML/JSON bucket listing."

        # Rule 5: Generic 404 without provider-specific unclaimed signature is not takeover
        if hypothesis.hypothesis_type == CloudHypothesisType.POTENTIAL_CLOUD_TAKEOVER:
            patterns = TAKEOVER_PATTERNS.get(hypothesis.provider, [])
            matched = any(p.search(body) for p in patterns)
            if not matched:
                return HypothesisValidationStatus.REJECTED, "Standard 404 response without unclaimed cloud resource signatures."

        return HypothesisValidationStatus.ACCEPTED, "Empirical evidence supports hypothesis."


class SafeCloudValidator:
    """Executes safe, non-destructive validation probes against cloud exposure hypotheses."""

    def __init__(
        self,
        request_hook: Callable[[ControlledRequest], ControlledResponse],
        policy: Optional[CloudSecurityPolicy] = None,
    ):
        self.request_hook = request_hook
        self.policy = policy or CloudSecurityPolicy()

    def validate_hypothesis(
        self,
        hypothesis: CloudExposureHypothesis,
    ) -> Tuple[HypothesisValidationStatus, CloudExposureState, Optional[CloudFindingCandidate], str]:
        """
        Executes bounded, safe probe based on hypothesis type.
        """
        target_url = hypothesis.endpoint or f"https://{hypothesis.asset}"

        # ----------------------------------------------------------------------
        # 1. Suspicion-only hypotheses: Write Capability Suspicion
        # ----------------------------------------------------------------------
        if hypothesis.hypothesis_type == CloudHypothesisType.WRITE_CAPABILITY_SUSPECTED:
            # Policy explicitly forbids automatic write/upload attempts
            return (
                HypothesisValidationStatus.NEEDS_VALIDATION,
                CloudExposureState.PUBLIC_WRITE_LIKELY,
                None,
                "Suspected public write capability flagged for human review. Automatic upload probe strictly disabled by safety policy.",
            )

        # ----------------------------------------------------------------------
        # 2. Informational Fingerprints
        # ----------------------------------------------------------------------
        if hypothesis.hypothesis_type == CloudHypothesisType.INFORMATIONAL_FINGERPRINT:
            return (
                HypothesisValidationStatus.INFORMATIONAL,
                CloudExposureState.INFORMATIONAL,
                None,
                "Informational cloud provider fingerprint.",
            )

        # ----------------------------------------------------------------------
        # 3. Object Storage Listing Probe
        # ----------------------------------------------------------------------
        if hypothesis.hypothesis_type == CloudHypothesisType.PUBLIC_OBJECT_LISTING:
            req = ControlledRequest(
                method="GET",
                url=target_url,
                headers={"Accept": "application/xml,application/json,*/*"},
            )
            resp = self.request_hook(req)
            fp_status, reason = CloudFalsePositiveClassifier.evaluate(hypothesis, resp)

            if fp_status == HypothesisValidationStatus.REJECTED:
                return HypothesisValidationStatus.REJECTED, CloudExposureState.PRIVATE_LIKELY, None, reason

            body = resp.body_text or ""
            # S3 / GCS ListBucketResult XML, Azure EnumerationResults
            if ("<ListBucketResult" in body and "<Contents>" in body) or ("<EnumerationResults" in body and "<Blobs>" in body):
                candidate = CloudFindingCandidate(
                    candidate_id=f"cfind-{hypothesis.id}",
                    vulnerability_family="cloud-misconfiguration",
                    title=f"Public Cloud Storage Listing ({hypothesis.provider.value})",
                    asset=hypothesis.asset,
                    endpoint=target_url,
                    evidence=[{
                        "type": "bucket_listing",
                        "status_code": resp.status_code,
                        "snippet": body[:500],
                    }],
                    confidence=0.95,
                    impact_hint="HIGH",
                    validation_state=FindingLifecycle.VALIDATED,
                    provider=hypothesis.provider,
                    service=CloudServiceType.OBJECT_STORAGE,
                    hypothesis_id=hypothesis.id,
                    remediation=f"Disable anonymous ListBucket / blob enumeration permissions on {hypothesis.asset}.",
                )
                return HypothesisValidationStatus.ACCEPTED, CloudExposureState.PUBLIC_LISTING_LIKELY, candidate, "Anonymous bucket listing confirmed via valid XML enumeration results."

            return HypothesisValidationStatus.REJECTED, CloudExposureState.PRIVATE_LIKELY, None, "Bucket listing prohibited or not exposed."

        # ----------------------------------------------------------------------
        # 4. Object Storage Read Probe
        # ----------------------------------------------------------------------
        if hypothesis.hypothesis_type == CloudHypothesisType.PUBLIC_OBJECT_READ:
            # Safe HEAD request
            req = ControlledRequest(method="HEAD", url=target_url)
            resp = self.request_hook(req)
            fp_status, reason = CloudFalsePositiveClassifier.evaluate(hypothesis, resp)

            if fp_status == HypothesisValidationStatus.REJECTED:
                return HypothesisValidationStatus.REJECTED, CloudExposureState.PRIVATE_LIKELY, None, reason

            if resp.status_code == 200:
                candidate = CloudFindingCandidate(
                    candidate_id=f"cfind-{hypothesis.id}",
                    vulnerability_family="cloud-misconfiguration",
                    title=f"Publicly Accessible Cloud Object Storage ({hypothesis.provider.value})",
                    asset=hypothesis.asset,
                    endpoint=target_url,
                    evidence=[{
                        "type": "object_read_head",
                        "status_code": resp.status_code,
                        "headers": dict(resp.headers),
                    }],
                    confidence=0.85,
                    impact_hint="MEDIUM",
                    validation_state=FindingLifecycle.VALIDATED,
                    provider=hypothesis.provider,
                    service=CloudServiceType.OBJECT_STORAGE,
                    hypothesis_id=hypothesis.id,
                    remediation="Restrict anonymous read access if objects contain confidential or internal data.",
                )
                return HypothesisValidationStatus.ACCEPTED, CloudExposureState.PUBLIC_READ_LIKELY, candidate, "Anonymous object access verified via HEAD 200."

            return HypothesisValidationStatus.REJECTED, CloudExposureState.PRIVATE_LIKELY, None, f"HTTP {resp.status_code} returned; public read not verified."

        # ----------------------------------------------------------------------
        # 5. Cloud Subdomain Takeover Probe
        # ----------------------------------------------------------------------
        if hypothesis.hypothesis_type == CloudHypothesisType.POTENTIAL_CLOUD_TAKEOVER:
            req = ControlledRequest(method="GET", url=target_url)
            resp = self.request_hook(req)
            fp_status, reason = CloudFalsePositiveClassifier.evaluate(hypothesis, resp)

            if fp_status == HypothesisValidationStatus.REJECTED:
                return HypothesisValidationStatus.REJECTED, CloudExposureState.NOT_REPRODUCIBLE, None, reason

            patterns = TAKEOVER_PATTERNS.get(hypothesis.provider, [])
            for pat in patterns:
                if pat.search(resp.body_text or ""):
                    candidate = CloudFindingCandidate(
                        candidate_id=f"cfind-{hypothesis.id}",
                        vulnerability_family="dns-takeover",
                        title=f"Potential Cloud Subdomain Takeover ({hypothesis.provider.value})",
                        asset=hypothesis.asset,
                        endpoint=target_url,
                        evidence=[{
                            "type": "takeover_pattern_match",
                            "status_code": resp.status_code,
                            "matched_pattern": pat.pattern,
                            "snippet": (resp.body_text or "")[:400],
                        }],
                        confidence=0.90,
                        impact_hint="HIGH",
                        validation_state=FindingLifecycle.VALIDATED,
                        provider=hypothesis.provider,
                        service=CloudServiceType.DNS_ROUTING,
                        hypothesis_id=hypothesis.id,
                        remediation="Remove dangling CNAME record or reclaim the orphaned cloud resource.",
                    )
                    return HypothesisValidationStatus.ACCEPTED, CloudExposureState.MISCONFIGURED, candidate, f"Unclaimed cloud resource signature confirmed: {pat.pattern}"

            return HypothesisValidationStatus.REJECTED, CloudExposureState.NOT_REPRODUCIBLE, None, "No unclaimed cloud signatures detected."

        # ----------------------------------------------------------------------
        # 6. Admin Interface Probe
        # ----------------------------------------------------------------------
        if hypothesis.hypothesis_type == CloudHypothesisType.UNAUTHENTICATED_ADMIN_ACCESS:
            req = ControlledRequest(method="GET", url=target_url)
            resp = self.request_hook(req)
            fp_status, reason = CloudFalsePositiveClassifier.evaluate(hypothesis, resp)

            if fp_status == HypothesisValidationStatus.REJECTED:
                return HypothesisValidationStatus.REJECTED, CloudExposureState.PUBLIC_ACCESSIBLE, None, reason

            body = (resp.body_text or "").lower()
            if resp.status_code == 200 and not any(term in body for term in ["login", "sign in", "sso", "auth"]):
                candidate = CloudFindingCandidate(
                    candidate_id=f"cfind-{hypothesis.id}",
                    vulnerability_family="broken-access-control",
                    title=f"Unauthenticated Cloud Administrative Interface ({hypothesis.provider.value})",
                    asset=hypothesis.asset,
                    endpoint=target_url,
                    evidence=[{
                        "type": "admin_no_auth",
                        "status_code": resp.status_code,
                        "snippet": (resp.body_text or "")[:400],
                    }],
                    confidence=0.80,
                    impact_hint="HIGH",
                    validation_state=FindingLifecycle.VALIDATED,
                    provider=hypothesis.provider,
                    service=CloudServiceType.ADMIN_INTERFACE,
                    hypothesis_id=hypothesis.id,
                    remediation="Enforce mandatory authentication on cloud administration dashboard.",
                )
                return HypothesisValidationStatus.ACCEPTED, CloudExposureState.MISCONFIGURED, candidate, "Unauthenticated administrative functionality observed without login barrier."

            return HypothesisValidationStatus.REJECTED, CloudExposureState.PUBLIC_ACCESSIBLE, None, "Administrative interface enforces login or redirection."

        return HypothesisValidationStatus.NEEDS_VALIDATION, CloudExposureState.UNKNOWN, None, "Hypothesis requires manual operator review."
