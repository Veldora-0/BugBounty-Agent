"""
Cloud Security Data Models for BugBounty-Agent (Phase 13).

Defines structured representations for:
- CloudProvider: AWS, AZURE, GCP, CLOUDFLARE, FASTLY, DIGITALOCEAN, ORACLE, UNKNOWN
- CloudServiceType: Object Storage, CDN, Load Balancer, App Hosting, Container Endpoint, etc.
- CloudExposureState: Exposure categorization with evidence-based distinctions
- CloudAsset: Core mapped cloud asset entity
- CloudResource: Inferred or observed specific cloud resource instance
- CloudExposureHypothesis: Testable assertion regarding cloud configuration/exposure
- CloudFindingCandidate: Finding candidate integrated with FindingLifecycle
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from framework.findings.lifecycle import FindingLifecycle


class CloudProvider(str, Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"
    CLOUDFLARE = "CLOUDFLARE"
    FASTLY = "FASTLY"
    DIGITALOCEAN = "DIGITALOCEAN"
    ORACLE = "ORACLE"
    UNKNOWN = "UNKNOWN"


class CloudServiceType(str, Enum):
    OBJECT_STORAGE = "Object Storage"
    CDN = "CDN"
    LOAD_BALANCER = "Load Balancer"
    APP_HOSTING = "App Hosting"
    CONTAINER_ENDPOINT = "Container Endpoint"
    API_GATEWAY = "API Gateway"
    DATABASE_ENDPOINT = "Database Endpoint"
    IDENTITY_ENDPOINT = "Identity Endpoint"
    SERVERLESS_ENDPOINT = "Serverless Endpoint"
    ADMIN_INTERFACE = "Admin Interface"
    DNS_ROUTING = "DNS Routing"
    UNKNOWN_CLOUD_SERVICE = "Unknown Cloud Service"


class CloudExposureState(str, Enum):
    UNKNOWN = "UNKNOWN"
    PRIVATE_LIKELY = "PRIVATE_LIKELY"
    PUBLIC_ACCESSIBLE = "PUBLIC_ACCESSIBLE"
    PUBLIC_READ_LIKELY = "PUBLIC_READ_LIKELY"
    PUBLIC_WRITE_LIKELY = "PUBLIC_WRITE_LIKELY"
    PUBLIC_LISTING_LIKELY = "PUBLIC_LISTING_LIKELY"
    MISCONFIGURED = "MISCONFIGURED"
    NOT_REPRODUCIBLE = "NOT_REPRODUCIBLE"
    INFORMATIONAL = "INFORMATIONAL"


class HypothesisValidationStatus(str, Enum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    NEEDS_VALIDATION = "NEEDS_VALIDATION"
    INFORMATIONAL = "INFORMATIONAL"


class CloudHypothesisType(str, Enum):
    PUBLIC_OBJECT_READ = "PUBLIC_OBJECT_READ"
    PUBLIC_OBJECT_LISTING = "PUBLIC_OBJECT_LISTING"
    WRITE_CAPABILITY_SUSPECTED = "WRITE_CAPABILITY_SUSPECTED"
    BUCKET_EXISTENCE_DISCLOSURE = "BUCKET_EXISTENCE_DISCLOSURE"
    ANONYMOUS_METADATA_EXPOSURE = "ANONYMOUS_METADATA_EXPOSURE"
    POTENTIAL_CLOUD_TAKEOVER = "POTENTIAL_CLOUD_TAKEOVER"
    UNAUTHENTICATED_ADMIN_ACCESS = "UNAUTHENTICATED_ADMIN_ACCESS"
    PUBLIC_INTERFACE = "PUBLIC_INTERFACE"
    SECRET_REFERENCE_FOUND = "SECRET_REFERENCE_FOUND"
    POSSIBLE_CREDENTIAL = "POSSIBLE_CREDENTIAL"
    HIGH_CONFIDENCE_CREDENTIAL = "HIGH_CONFIDENCE_CREDENTIAL"
    INFORMATIONAL_FINGERPRINT = "INFORMATIONAL_FINGERPRINT"


@dataclass
class CloudAsset:
    """Represents an asset mapped to a cloud provider."""
    id: str
    asset: str
    provider: CloudProvider
    service: CloudServiceType
    region: Optional[str] = None
    hostname: Optional[str] = None
    ip: Optional[str] = None
    source: str = "asset_intelligence"
    confidence: float = 0.5  # 0.0 - 1.0
    evidence_refs: List[str] = field(default_factory=list)
    signals: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "asset": self.asset,
            "provider": self.provider.value if isinstance(self.provider, CloudProvider) else self.provider,
            "service": self.service.value if isinstance(self.service, CloudServiceType) else self.service,
            "region": self.region,
            "hostname": self.hostname,
            "ip": self.ip,
            "source": self.source,
            "confidence": self.confidence,
            "evidence_refs": self.evidence_refs,
            "signals": self.signals,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CloudAsset:
        provider = CloudProvider(data.get("provider", "UNKNOWN")) if data.get("provider") in CloudProvider._value2member_map_ else CloudProvider.UNKNOWN
        service = CloudServiceType(data.get("service", "Unknown Cloud Service")) if data.get("service") in CloudServiceType._value2member_map_ else CloudServiceType.UNKNOWN_CLOUD_SERVICE
        return cls(
            id=data["id"],
            asset=data["asset"],
            provider=provider,
            service=service,
            region=data.get("region"),
            hostname=data.get("hostname"),
            ip=data.get("ip"),
            source=data.get("source", "asset_intelligence"),
            confidence=float(data.get("confidence", 0.5)),
            evidence_refs=data.get("evidence_refs", []),
            signals=data.get("signals", []),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            updated_at=data.get("updated_at", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class CloudResource:
    """Represents a specific cloud resource instance (e.g. S3 bucket, Blob container, Cloud Run service)."""
    resource_type: str
    provider: CloudProvider
    identifier: str
    hostname: Optional[str] = None
    url: Optional[str] = None
    exposure_state: CloudExposureState = CloudExposureState.UNKNOWN
    evidence: List[str] = field(default_factory=list)
    confidence: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_type": self.resource_type,
            "provider": self.provider.value if isinstance(self.provider, CloudProvider) else self.provider,
            "identifier": self.identifier,
            "hostname": self.hostname,
            "url": self.url,
            "exposure_state": self.exposure_state.value if isinstance(self.exposure_state, CloudExposureState) else self.exposure_state,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CloudResource:
        provider = CloudProvider(data.get("provider", "UNKNOWN")) if data.get("provider") in CloudProvider._value2member_map_ else CloudProvider.UNKNOWN
        state = CloudExposureState(data.get("exposure_state", "UNKNOWN")) if data.get("exposure_state") in CloudExposureState._value2member_map_ else CloudExposureState.UNKNOWN
        return cls(
            resource_type=data.get("resource_type", "cloud_resource"),
            provider=provider,
            identifier=data["identifier"],
            hostname=data.get("hostname"),
            url=data.get("url"),
            exposure_state=state,
            evidence=data.get("evidence", []),
            confidence=float(data.get("confidence", 0.5)),
            metadata=data.get("metadata", {}),
        )


@dataclass
class CloudExposureHypothesis:
    """A structured, testable assertion regarding cloud configuration, access, or exposure."""
    id: str
    asset: str
    provider: CloudProvider
    service: CloudServiceType
    hypothesis_type: CloudHypothesisType
    confidence: float
    severity_hint: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    rationale: str
    evidence_refs: List[str] = field(default_factory=list)
    validation_status: HypothesisValidationStatus = HypothesisValidationStatus.NEEDS_VALIDATION
    endpoint: Optional[str] = None
    rejection_reason: Optional[str] = None
    fingerprint: Optional[str] = None

    def compute_fingerprint(self) -> str:
        """Computes a deterministic fingerprint to prevent redundant tests."""
        raw = f"{self.asset}:{self.provider.value}:{self.service.value}:{self.hypothesis_type.value}:{self.endpoint or ''}"
        self.fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return self.fingerprint

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "asset": self.asset,
            "provider": self.provider.value if isinstance(self.provider, CloudProvider) else self.provider,
            "service": self.service.value if isinstance(self.service, CloudServiceType) else self.service,
            "hypothesis_type": self.hypothesis_type.value if isinstance(self.hypothesis_type, CloudHypothesisType) else self.hypothesis_type,
            "confidence": self.confidence,
            "severity_hint": self.severity_hint,
            "rationale": self.rationale,
            "evidence_refs": self.evidence_refs,
            "validation_status": self.validation_status.value if isinstance(self.validation_status, HypothesisValidationStatus) else self.validation_status,
            "endpoint": self.endpoint,
            "rejection_reason": self.rejection_reason,
            "fingerprint": self.fingerprint or self.compute_fingerprint(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CloudExposureHypothesis:
        provider = CloudProvider(data.get("provider", "UNKNOWN")) if data.get("provider") in CloudProvider._value2member_map_ else CloudProvider.UNKNOWN
        service = CloudServiceType(data.get("service", "Unknown Cloud Service")) if data.get("service") in CloudServiceType._value2member_map_ else CloudServiceType.UNKNOWN_CLOUD_SERVICE
        htype = CloudHypothesisType(data.get("hypothesis_type", "INFORMATIONAL_FINGERPRINT")) if data.get("hypothesis_type") in CloudHypothesisType._value2member_map_ else CloudHypothesisType.INFORMATIONAL_FINGERPRINT
        status = HypothesisValidationStatus(data.get("validation_status", "NEEDS_VALIDATION")) if data.get("validation_status") in HypothesisValidationStatus._value2member_map_ else HypothesisValidationStatus.NEEDS_VALIDATION
        hyp = cls(
            id=data["id"],
            asset=data["asset"],
            provider=provider,
            service=service,
            hypothesis_type=htype,
            confidence=float(data.get("confidence", 0.5)),
            severity_hint=data.get("severity_hint", "INFO"),
            rationale=data.get("rationale", ""),
            evidence_refs=data.get("evidence_refs", []),
            validation_status=status,
            endpoint=data.get("endpoint"),
            rejection_reason=data.get("rejection_reason"),
            fingerprint=data.get("fingerprint"),
        )
        if not hyp.fingerprint:
            hyp.compute_fingerprint()
        return hyp


@dataclass
class CloudFindingCandidate:
    """A finding candidate generated from a validated or high-confidence cloud hypothesis."""
    candidate_id: str
    vulnerability_family: str  # e.g. "cloud-misconfiguration", "broken-access-control"
    title: str
    asset: str
    endpoint: str
    evidence: List[Dict[str, Any]]
    confidence: float
    impact_hint: str
    validation_state: FindingLifecycle = FindingLifecycle.CANDIDATE
    provider: CloudProvider = CloudProvider.UNKNOWN
    service: CloudServiceType = CloudServiceType.UNKNOWN_CLOUD_SERVICE
    hypothesis_id: Optional[str] = None
    remediation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "vulnerability_family": self.vulnerability_family,
            "title": self.title,
            "asset": self.asset,
            "endpoint": self.endpoint,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "impact_hint": self.impact_hint,
            "validation_state": self.validation_state.value if isinstance(self.validation_state, FindingLifecycle) else self.validation_state,
            "provider": self.provider.value if isinstance(self.provider, CloudProvider) else self.provider,
            "service": self.service.value if isinstance(self.service, CloudServiceType) else self.service,
            "hypothesis_id": self.hypothesis_id,
            "remediation": self.remediation,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CloudFindingCandidate:
        vstate = FindingLifecycle(data.get("validation_state", "CANDIDATE")) if data.get("validation_state") in FindingLifecycle._value2member_map_ else FindingLifecycle.CANDIDATE
        provider = CloudProvider(data.get("provider", "UNKNOWN")) if data.get("provider") in CloudProvider._value2member_map_ else CloudProvider.UNKNOWN
        service = CloudServiceType(data.get("service", "Unknown Cloud Service")) if data.get("service") in CloudServiceType._value2member_map_ else CloudServiceType.UNKNOWN_CLOUD_SERVICE
        return cls(
            candidate_id=data["candidate_id"],
            vulnerability_family=data.get("vulnerability_family", "cloud-misconfiguration"),
            title=data.get("title", "Cloud Finding Candidate"),
            asset=data["asset"],
            endpoint=data.get("endpoint", ""),
            evidence=data.get("evidence", []),
            confidence=float(data.get("confidence", 0.7)),
            impact_hint=data.get("impact_hint", "LOW"),
            validation_state=vstate,
            provider=provider,
            service=service,
            hypothesis_id=data.get("hypothesis_id"),
            remediation=data.get("remediation"),
        )
