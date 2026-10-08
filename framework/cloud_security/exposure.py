"""
Exposure Hypothesis Generator and Rule Evaluator (Phase 13).

Formulates structured hypotheses based on:
1. Object storage discovery (S3, Azure Blob, GCS)
2. Suspected public write capability (flagged as WRITE_CAPABILITY_SUSPECTED, never executed)
3. Dangling cloud pointers / potential takeover (CNAMEs, orphaned cloud hostnames)
4. Unauthenticated administrative interfaces
5. Secret/credential references found in client-side code
6. Informational cloud service fingerprints
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
import uuid

from framework.cloud_security.models import (
    CloudAsset,
    CloudExposureHypothesis,
    CloudHypothesisType,
    CloudProvider,
    CloudResource,
    CloudServiceType,
    HypothesisValidationStatus,
)


class CloudExposureHypothesisEngine:
    """Generates structured testable assertions from observed assets and resources."""

    @classmethod
    def generate_hypotheses(
        cls,
        asset: CloudAsset,
        resource: Optional[CloudResource] = None,
        cname_record: Optional[str] = None,
        js_secrets: Optional[List[Dict[str, Any]]] = None,
        is_orphaned_dns: bool = False,
    ) -> List[CloudExposureHypothesis]:
        """Formulates actionable cloud exposure hypotheses."""
        hypotheses: List[CloudExposureHypothesis] = []
        target_host = asset.hostname or asset.asset
        target_url = f"https://{target_host}"

        # ----------------------------------------------------------------------
        # 1. Object Storage Hypotheses
        # ----------------------------------------------------------------------
        if asset.service == CloudServiceType.OBJECT_STORAGE or (resource and resource.resource_type == "object_storage"):
            # Public Object Read
            h_read = CloudExposureHypothesis(
                id=f"hyp-cloud-{uuid.uuid4().hex[:8]}",
                asset=asset.asset,
                provider=asset.provider,
                service=CloudServiceType.OBJECT_STORAGE,
                hypothesis_type=CloudHypothesisType.PUBLIC_OBJECT_READ,
                confidence=0.60,
                severity_hint="MEDIUM",
                rationale=f"Identified object storage endpoint '{target_host}'. Verify whether stored objects are publicly accessible anonymously.",
                endpoint=target_url,
                evidence_refs=asset.evidence_refs[:],
            )
            h_read.compute_fingerprint()
            hypotheses.append(h_read)

            # Public Object Listing
            h_list = CloudExposureHypothesis(
                id=f"hyp-cloud-{uuid.uuid4().hex[:8]}",
                asset=asset.asset,
                provider=asset.provider,
                service=CloudServiceType.OBJECT_STORAGE,
                hypothesis_type=CloudHypothesisType.PUBLIC_OBJECT_LISTING,
                confidence=0.55,
                severity_hint="HIGH",
                rationale=f"Object storage endpoint '{target_host}' may allow anonymous XML/JSON bucket enumeration (ListBucket).",
                endpoint=target_url,
                evidence_refs=asset.evidence_refs[:],
            )
            h_list.compute_fingerprint()
            hypotheses.append(h_list)

            # Public Write Capability Suspicion (Requires Manual Approval, never executed automatically)
            h_write = CloudExposureHypothesis(
                id=f"hyp-cloud-{uuid.uuid4().hex[:8]}",
                asset=asset.asset,
                provider=asset.provider,
                service=CloudServiceType.OBJECT_STORAGE,
                hypothesis_type=CloudHypothesisType.WRITE_CAPABILITY_SUSPECTED,
                confidence=0.40,
                severity_hint="CRITICAL",
                rationale=f"Bucket '{target_host}' could have loose write/upload ACLs. Flagged as suspicion for operator review; automatic write probing is strictly disabled.",
                endpoint=target_url,
                evidence_refs=asset.evidence_refs[:],
                validation_status=HypothesisValidationStatus.NEEDS_VALIDATION,
            )
            h_write.compute_fingerprint()
            hypotheses.append(h_write)

        # ----------------------------------------------------------------------
        # 2. Dangling Cloud CNAME / Takeover Hypotheses
        # ----------------------------------------------------------------------
        if is_orphaned_dns or (cname_record and any(cp in cname_record.lower() for cp in [
            "s3.amazonaws.com", "azurewebsites.net", "blob.core.windows.net", "trafficmanager.net",
            "cloudapp.net", "elasticbeanstalk.com", "storage.googleapis.com", "run.app"
        ])):
            h_takeover = CloudExposureHypothesis(
                id=f"hyp-cloud-{uuid.uuid4().hex[:8]}",
                asset=asset.asset,
                provider=asset.provider,
                service=CloudServiceType.DNS_ROUTING,
                hypothesis_type=CloudHypothesisType.POTENTIAL_CLOUD_TAKEOVER,
                confidence=0.70,
                severity_hint="HIGH",
                rationale=f"Domain '{asset.asset}' points via CNAME '{cname_record or 'orphaned'}' to a cloud service. If the target resource is decommissioned or unclaimed, it may be vulnerable to cloud subdomain takeover.",
                endpoint=target_url,
                evidence_refs=asset.evidence_refs[:],
            )
            h_takeover.compute_fingerprint()
            hypotheses.append(h_takeover)

        # ----------------------------------------------------------------------
        # 3. Administrative Interface Hypotheses
        # ----------------------------------------------------------------------
        if asset.service == CloudServiceType.ADMIN_INTERFACE or any(term in target_host.lower() for term in ["admin", "dashboard", "console"]):
            h_admin = CloudExposureHypothesis(
                id=f"hyp-cloud-{uuid.uuid4().hex[:8]}",
                asset=asset.asset,
                provider=asset.provider,
                service=CloudServiceType.ADMIN_INTERFACE,
                hypothesis_type=CloudHypothesisType.UNAUTHENTICATED_ADMIN_ACCESS,
                confidence=0.50,
                severity_hint="HIGH",
                rationale=f"Exposed cloud endpoint '{target_host}' indicates administrative or dashboard functionality. Verify if access controls or authentication mechanisms are enforced.",
                endpoint=target_url,
                evidence_refs=asset.evidence_refs[:],
            )
            h_admin.compute_fingerprint()
            hypotheses.append(h_admin)

        # ----------------------------------------------------------------------
        # 4. Cloud Secret / Credential Reference Hypotheses
        # ----------------------------------------------------------------------
        if js_secrets:
            for sec in js_secrets:
                stype = sec.get("type", "cloud_secret")
                h_sec = CloudExposureHypothesis(
                    id=f"hyp-cloud-{uuid.uuid4().hex[:8]}",
                    asset=asset.asset,
                    provider=asset.provider,
                    service=CloudServiceType.IDENTITY_ENDPOINT,
                    hypothesis_type=CloudHypothesisType.HIGH_CONFIDENCE_CREDENTIAL if "key" in stype.lower() else CloudHypothesisType.SECRET_REFERENCE_FOUND,
                    confidence=0.75,
                    severity_hint="HIGH",
                    rationale=f"Identified reference to cloud credential/token ({stype}) associated with {asset.asset}. Masked value logged; direct credential execution is forbidden.",
                    endpoint=sec.get("file_url", target_url),
                    evidence_refs=[sec.get("masked_value", "REDACTED")],
                )
                h_sec.compute_fingerprint()
                hypotheses.append(h_sec)

        # ----------------------------------------------------------------------
        # 5. Informational Cloud Fingerprint
        # ----------------------------------------------------------------------
        if not hypotheses:
            h_info = CloudExposureHypothesis(
                id=f"hyp-cloud-{uuid.uuid4().hex[:8]}",
                asset=asset.asset,
                provider=asset.provider,
                service=asset.service,
                hypothesis_type=CloudHypothesisType.INFORMATIONAL_FINGERPRINT,
                confidence=asset.confidence,
                severity_hint="INFO",
                rationale=f"Asset '{asset.asset}' is attributed to {asset.provider.value} ({asset.service.value}) based on infrastructure signals. No active misconfiguration indicated.",
                endpoint=target_url,
                evidence_refs=asset.evidence_refs[:],
                validation_status=HypothesisValidationStatus.INFORMATIONAL,
            )
            h_info.compute_fingerprint()
            hypotheses.append(h_info)

        return hypotheses
