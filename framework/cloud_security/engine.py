"""
Primary Cloud Security & Misconfiguration Intelligence Engine (Phase 13).

Consumes attack surface intelligence from previous phases (Assets, Recon, WebApp, JS, API),
classifies cloud providers and services, generates exposure hypotheses, applies safe
non-destructive validation, scores and prioritizes findings, and atomically persists state.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import uuid

from framework.cloud_security.discovery import CloudServiceIdentifier
from framework.cloud_security.exposure import CloudExposureHypothesisEngine
from framework.cloud_security.fingerprints import ProviderFingerprinter
from framework.cloud_security.models import (
    CloudAsset,
    CloudExposureHypothesis,
    CloudExposureState,
    CloudFindingCandidate,
    CloudHypothesisType,
    CloudProvider,
    CloudResource,
    CloudServiceType,
    HypothesisValidationStatus,
)
from framework.cloud_security.policy import CloudSecurityPolicy
from framework.cloud_security.prioritization import CloudExposureScorer, CloudPrioritizationEngine
from framework.cloud_security.storage import CloudStateManager
from framework.cloud_security.validators import SafeCloudValidator
from framework.common.evidence import EvidenceStore
from framework.scope.engine import ScopeEngine
from framework.validation.request import ControlledRequest, ControlledResponse


class CloudSecurityEngine:
    """Primary orchestrator for Cloud Security & Misconfiguration Intelligence."""

    def __init__(
        self,
        program_dir: str,
        scope_engine: Optional[ScopeEngine] = None,
        policy: Optional[CloudSecurityPolicy] = None,
        request_hook: Optional[Callable[[ControlledRequest], ControlledResponse]] = None,
        evidence_store: Optional[EvidenceStore] = None,
    ):
        self.program_dir = os.path.abspath(program_dir)
        self.program_name = os.path.basename(self.program_dir)
        self.scope_engine = scope_engine
        self.policy = policy or CloudSecurityPolicy()
        self.state_mgr = CloudStateManager(self.program_dir)
        self.request_hook = request_hook or (lambda req: ControlledResponse(200, body_text="OK"))
        self.validator = SafeCloudValidator(self.request_hook, self.policy)
        self.evidence_store = evidence_store or EvidenceStore(os.path.join(self.program_dir, "evidence"))

    def analyze_asset(
        self,
        asset_identifier: str,
        hostname: Optional[str] = None,
        cnames: Optional[List[str]] = None,
        dns_records: Optional[List[str]] = None,
        headers: Optional[Dict[str, str]] = None,
        server: Optional[str] = None,
        tls_san: Optional[List[str]] = None,
        asn: Optional[str] = None,
        is_orphaned_dns: bool = False,
        js_secrets: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[Optional[CloudAsset], List[CloudExposureHypothesis]]:
        """
        Classifies an asset, discovers its cloud services, and generates exposure hypotheses.
        """
        host = hostname or asset_identifier

        # 1. Fingerprint cloud provider
        provider, confidence, signals = ProviderFingerprinter.fingerprint(
            hostname=host,
            cnames=cnames,
            dns_records=dns_records,
            headers=headers,
            server=server,
            tls_san=tls_san,
            asn=asn,
        )

        if provider == CloudProvider.UNKNOWN and not is_orphaned_dns:
            return None, []

        # 2. Identify cloud service
        parsed = urlparse(f"https://{host}" if "://" not in host else host)
        path = parsed.path
        service, resource_id, region = CloudServiceIdentifier.identify_service(
            provider=provider,
            hostname=parsed.netloc or host,
            path=path,
            headers=headers,
        )

        # 3. Create CloudAsset
        cloud_asset = CloudAsset(
            id=f"ca-{uuid.uuid4().hex[:8]}",
            asset=asset_identifier,
            provider=provider,
            service=service,
            region=region,
            hostname=parsed.netloc or host,
            confidence=confidence,
            signals=signals,
        )
        self.state_mgr.record_asset(cloud_asset)

        # 4. Formulate hypotheses
        cname_str = cnames[0] if cnames else None
        hypotheses = CloudExposureHypothesisEngine.generate_hypotheses(
            asset=cloud_asset,
            cname_record=cname_str,
            js_secrets=js_secrets,
            is_orphaned_dns=is_orphaned_dns,
        )

        # Prioritize hypotheses
        prioritized = CloudPrioritizationEngine.prioritize(hypotheses)
        for h in prioritized:
            self.state_mgr.record_hypothesis(h)

        return cloud_asset, prioritized

    def validate_hypotheses(
        self,
        hypotheses: List[CloudExposureHypothesis],
        dry_run: bool = False,
        resume: bool = False,
    ) -> List[Tuple[CloudExposureHypothesis, HypothesisValidationStatus, Optional[CloudFindingCandidate], str]]:
        """
        Executes safe validation against hypotheses under ScopeEngine and Policy constraints.
        """
        results = []

        for hyp in hypotheses:
            fingerprint = hyp.compute_fingerprint()

            # Resume check
            if resume and self.state_mgr.is_fingerprint_tested(fingerprint):
                continue

            target_url = hyp.endpoint or f"https://{hyp.asset}"

            # 1. Scope Engine Verification
            in_scope, scope_reason = CloudSecurityPolicy.check_scope(self.scope_engine, target_url)
            if not in_scope:
                hyp.validation_status = HypothesisValidationStatus.REJECTED
                hyp.rejection_reason = scope_reason
                self.state_mgr.record_hypothesis(hyp)
                results.append((hyp, HypothesisValidationStatus.REJECTED, None, scope_reason))
                continue

            # 2. Dry-Run Check
            if dry_run:
                results.append((hyp, HypothesisValidationStatus.NEEDS_VALIDATION, None, f"[DRY-RUN] Planned probe for {hyp.hypothesis_type.value} against {target_url}"))
                continue

            # 3. Policy Action Safety Check
            method = "HEAD" if hyp.hypothesis_type == CloudHypothesisType.PUBLIC_OBJECT_READ else "GET"
            safe, policy_reason = CloudSecurityPolicy.evaluate_action_safety(method, target_url)
            if not safe:
                hyp.validation_status = HypothesisValidationStatus.REJECTED
                hyp.rejection_reason = policy_reason
                self.state_mgr.record_hypothesis(hyp)
                results.append((hyp, HypothesisValidationStatus.REJECTED, None, policy_reason))
                continue

            # 4. Execute Validation Probe
            status, exposure_state, candidate, detail = self.validator.validate_hypothesis(hyp)
            hyp.validation_status = status
            if status == HypothesisValidationStatus.REJECTED:
                hyp.rejection_reason = detail

            self.state_mgr.record_hypothesis(hyp)
            self.state_mgr.mark_fingerprint_tested(fingerprint)

            if candidate:
                self.state_mgr.record_finding(candidate)

            results.append((hyp, status, candidate, detail))

        return results
