"""
JavaScript Intelligence Data Models for BugBounty-Agent.

Defines structured, normalized, deterministic, and serializable observation models for:
- JavaScriptResource: Acquired JS files, content hashes, minification status
- DiscoveredEndpoint: API paths, endpoints, and websocket URLs extracted from JS
- DiscoveredRoute: Frontend SPA client routes (React Router, Vue, Angular, Next.js)
- ParameterReference: Client-side parameter names and locations (query, path, body)
- InterestingString: Classified strings, public API keys, environment variables, masked secrets
- DependencyObservation: Client libraries, frameworks, and versions detected in bundles
- SourceMapObservation: Source map references, URLs, and source counts
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlsplit

from framework.assets.provenance import ObservationProvenance
from framework.webapp.model import canonicalize_url


class StringSensitivity(str, Enum):
    """Sensitivity classification for extracted interesting strings."""
    INFORMATIONAL = "informational"
    INTERESTING = "interesting"
    SENSITIVE_LOOKING = "sensitive-looking"
    HIGH_CONFIDENCE_SECRET = "high-confidence-secret-candidate"


def mask_sensitive_value(val: str, max_visible: int = 4) -> str:
    """
    Masks sensitive values (tokens, credentials, API keys) to prevent secret leakage.
    Shows only the first few and last few characters, replacing the middle with asterisks.
    Example: 'AKIAIOSFODNN7EXAMPLE' -> 'AKIA...MPLE'
    """
    clean = val.strip()
    if len(clean) <= max_visible * 2:
        return "****"
    prefix = clean[:max_visible]
    suffix = clean[-max_visible:]
    return f"{prefix}...{suffix}"


# ==============================================================================
# 1. JAVASCRIPT RESOURCE
# ==============================================================================

@dataclass
class JavaScriptResource:
    """Represents an acquired and indexed JavaScript file/bundle."""
    url: str
    host: str
    path: str
    scheme: str = "https"
    status_code: int = 200
    content_type: str = "application/javascript"
    content_length: int = 0
    sha256_hash: str = ""
    is_minified: bool = False
    has_source_map: bool = False
    source_map_url: Optional[str] = None
    source_page: Optional[str] = None
    application: Optional[str] = None
    retrieval_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)
    confidence: str = "CONFIRMED"

    @property
    def key(self) -> str:
        return canonicalize_url(self.url)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "scheme": self.scheme,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "sha256_hash": self.sha256_hash,
            "is_minified": self.is_minified,
            "has_source_map": self.has_source_map,
            "source_map_url": self.source_map_url,
            "source_page": self.source_page,
            "application": self.application,
            "retrieval_timestamp": self.retrieval_timestamp,
            "confidence": self.confidence,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> JavaScriptResource:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            url=data.get("url", ""),
            host=data.get("host", ""),
            path=data.get("path", ""),
            scheme=data.get("scheme", "https"),
            status_code=int(data.get("status_code", 200)),
            content_type=data.get("content_type", "application/javascript"),
            content_length=int(data.get("content_length", 0)),
            sha256_hash=data.get("sha256_hash", ""),
            is_minified=bool(data.get("is_minified", False)),
            has_source_map=bool(data.get("has_source_map", False)),
            source_map_url=data.get("source_map_url"),
            source_page=data.get("source_page"),
            application=data.get("application"),
            retrieval_timestamp=data.get("retrieval_timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
            confidence=data.get("confidence", "CONFIRMED"),
        )


# ==============================================================================
# 2. DISCOVERED ENDPOINT
# ==============================================================================

@dataclass
class DiscoveredEndpoint:
    """Represents an API endpoint or network route extracted from JavaScript."""
    raw_endpoint: str
    normalized_endpoint: str
    method: str = "UNKNOWN"  # GET, POST, PUT, DELETE, GRAPHQL, UNKNOWN
    source_resource_url: str = ""
    evidence_snippet: str = ""
    confidence: str = "OBSERVED"
    extraction_method: str = "regex_pattern"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.normalized_endpoint}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_endpoint": self.raw_endpoint,
            "normalized_endpoint": self.normalized_endpoint,
            "method": self.method.upper(),
            "source_resource_url": self.source_resource_url,
            "evidence_snippet": self.evidence_snippet,
            "confidence": self.confidence,
            "extraction_method": self.extraction_method,
            "timestamp": self.timestamp,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DiscoveredEndpoint:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            raw_endpoint=data.get("raw_endpoint", ""),
            normalized_endpoint=data.get("normalized_endpoint", ""),
            method=data.get("method", "UNKNOWN").upper(),
            source_resource_url=data.get("source_resource_url", ""),
            evidence_snippet=data.get("evidence_snippet", ""),
            confidence=data.get("confidence", "OBSERVED"),
            extraction_method=data.get("extraction_method", "regex_pattern"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
        )


# ==============================================================================
# 3. DISCOVERED CLIENT ROUTE
# ==============================================================================

@dataclass
class DiscoveredRoute:
    """Represents a frontend SPA client route template discovered in JavaScript."""
    route_pattern: str
    framework_hint: Optional[str] = None  # react-router, vue-router, next.js, angular
    source_resource_url: str = ""
    confidence: str = "OBSERVED"
    evidence_snippet: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)

    @property
    def key(self) -> str:
        return self.route_pattern.strip()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "route_pattern": self.route_pattern,
            "framework_hint": self.framework_hint,
            "source_resource_url": self.source_resource_url,
            "confidence": self.confidence,
            "evidence_snippet": self.evidence_snippet,
            "timestamp": self.timestamp,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DiscoveredRoute:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            route_pattern=data.get("route_pattern", ""),
            framework_hint=data.get("framework_hint"),
            source_resource_url=data.get("source_resource_url", ""),
            confidence=data.get("confidence", "OBSERVED"),
            evidence_snippet=data.get("evidence_snippet", ""),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
        )


# ==============================================================================
# 4. PARAMETER REFERENCE
# ==============================================================================

@dataclass
class ParameterReference:
    """Represents a parameter name referenced in JavaScript logic."""
    name: str
    location_hint: str = "query"  # query, path, body, header, unknown
    associated_endpoint: Optional[str] = None
    source_resource_url: str = ""
    confidence: str = "OBSERVED"
    evidence_snippet: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)

    @property
    def key(self) -> str:
        ep = self.associated_endpoint or "global"
        return f"{ep}:{self.location_hint}:{self.name.lower()}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "location_hint": self.location_hint,
            "associated_endpoint": self.associated_endpoint,
            "source_resource_url": self.source_resource_url,
            "confidence": self.confidence,
            "evidence_snippet": self.evidence_snippet,
            "timestamp": self.timestamp,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ParameterReference:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            name=data.get("name", ""),
            location_hint=data.get("location_hint", "query"),
            associated_endpoint=data.get("associated_endpoint"),
            source_resource_url=data.get("source_resource_url", ""),
            confidence=data.get("confidence", "OBSERVED"),
            evidence_snippet=data.get("evidence_snippet", ""),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
        )


# ==============================================================================
# 5. INTERESTING STRING
# ==============================================================================

@dataclass
class InterestingString:
    """Represents an interesting or sensitive string identified in JavaScript."""
    category: str  # api_key, token, internal_host, env_var, cloud_service, debug
    matched_value: str
    masked_value: str
    sensitivity: str = StringSensitivity.INTERESTING.value
    source_resource_url: str = ""
    evidence_snippet: str = ""
    confidence: str = "PROBABLE"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)

    @property
    def key(self) -> str:
        # Use a hash of category + matched_value for deterministic deduplication
        sig = hashlib.sha256(f"{self.category}:{self.matched_value}".encode("utf-8")).hexdigest()[:16]
        return f"{self.category}:{sig}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "masked_value": self.masked_value,
            "sensitivity": self.sensitivity,
            "source_resource_url": self.source_resource_url,
            "evidence_snippet": self.evidence_snippet,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> InterestingString:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        masked = data.get("masked_value", "****")
        return cls(
            category=data.get("category", "informational"),
            matched_value=masked,  # Do not store raw sensitive values in rehydrated state
            masked_value=masked,
            sensitivity=data.get("sensitivity", StringSensitivity.INTERESTING.value),
            source_resource_url=data.get("source_resource_url", ""),
            evidence_snippet=data.get("evidence_snippet", ""),
            confidence=data.get("confidence", "PROBABLE"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
        )


# ==============================================================================
# 6. DEPENDENCY OBSERVATION
# ==============================================================================

@dataclass
class DependencyObservation:
    """Represents a third-party JavaScript library or framework identified in bundles."""
    name: str
    version: Optional[str] = None
    detection_method: str = "banner_comment"  # banner_comment, global_signature, source_map
    source_resource_url: str = ""
    confidence: str = "CONFIRMED"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)

    @property
    def key(self) -> str:
        return self.name.strip().lower()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "detection_method": self.detection_method,
            "source_resource_url": self.source_resource_url,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DependencyObservation:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            name=data.get("name", ""),
            version=data.get("version"),
            detection_method=data.get("detection_method", "banner_comment"),
            source_resource_url=data.get("source_resource_url", ""),
            confidence=data.get("confidence", "CONFIRMED"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
        )


# ==============================================================================
# 7. SOURCE MAP OBSERVATION
# ==============================================================================

@dataclass
class SourceMapObservation:
    """Represents an observed source map reference (//# sourceMappingURL=...)."""
    source_js_url: str
    source_map_url: str
    is_reachable: bool = False
    source_file_count: int = 0
    bounded_sources: List[str] = field(default_factory=list)
    confidence: str = "CONFIRMED"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)

    @property
    def key(self) -> str:
        return canonicalize_url(self.source_map_url, self.source_js_url)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_js_url": self.source_js_url,
            "source_map_url": self.source_map_url,
            "is_reachable": self.is_reachable,
            "source_file_count": self.source_file_count,
            "bounded_sources": list(self.bounded_sources[:50]),
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SourceMapObservation:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            source_js_url=data.get("source_js_url", ""),
            source_map_url=data.get("source_map_url", ""),
            is_reachable=bool(data.get("is_reachable", False)),
            source_file_count=int(data.get("source_file_count", 0)),
            bounded_sources=data.get("bounded_sources", []) or [],
            confidence=data.get("confidence", "CONFIRMED"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
        )
