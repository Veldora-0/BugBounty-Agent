"""
Reconnaissance Data Models for BugBounty-Agent.

Defines structured, normalized, deterministic, and serializable observation models
for HTTP services, ports/network services, DNS records, TLS certificates,
technologies, and endpoints, all retaining multi-source observation provenance.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import urlparse

from framework.assets.provenance import ObservationProvenance


class ObservationConfidence(str, Enum):
    """Calibrated confidence ratings for reconnaissance observations."""
    OBSERVED = "OBSERVED"
    PROBABLE = "PROBABLE"
    CONFIRMED = "CONFIRMED"


class ReachabilityStatus(str, Enum):
    """Reachability status of a network or web service."""
    REACHABLE = "REACHABLE"
    UNREACHABLE = "UNREACHABLE"
    FILTERED = "FILTERED"
    UNKNOWN = "UNKNOWN"


def normalize_url(raw_url: str) -> str:
    """
    Normalizes a URL to a canonical format:
    lowercase scheme and host, default ports removed, trailing slash stripped if root path.
    """
    raw = raw_url.strip()
    if not raw.startswith(("http://", "https://")):
        raw = f"http://{raw}"
    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # Strip default ports
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]

    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path[:-1]

    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{netloc}{path}{query}"


# ==============================================================================
# 1. HTTP SERVICE OBSERVATION
# ==============================================================================

@dataclass
class HttpObservation:
    """Represents an observed HTTP/HTTPS web service on an asset."""
    url: str
    scheme: str
    host: str
    port: int
    status_code: int
    title: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    redirect_chain: List[str] = field(default_factory=list)
    final_url: Optional[str] = None
    server_header: Optional[str] = None
    security_headers: Dict[str, str] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    response_time_ms: Optional[float] = None
    reachability: str = ReachabilityStatus.REACHABLE.value
    provenance: List[ObservationProvenance] = field(default_factory=list)
    raw_reference: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def key(self) -> str:
        """Deterministic canonical key for deduplication."""
        return normalize_url(self.url)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "status_code": self.status_code,
            "title": self.title,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "redirect_chain": list(self.redirect_chain),
            "final_url": self.final_url,
            "server_header": self.server_header,
            "security_headers": dict(self.security_headers),
            "technologies": list(self.technologies),
            "response_time_ms": self.response_time_ms,
            "reachability": self.reachability,
            "provenance": [p.to_dict() for p in self.provenance],
            "raw_reference": self.raw_reference,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> HttpObservation:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            url=data.get("url", ""),
            scheme=data.get("scheme", "http"),
            host=data.get("host", ""),
            port=int(data.get("port", 80)),
            status_code=int(data.get("status_code", 0)),
            title=data.get("title"),
            content_type=data.get("content_type"),
            content_length=data.get("content_length"),
            redirect_chain=data.get("redirect_chain", []) or [],
            final_url=data.get("final_url"),
            server_header=data.get("server_header"),
            security_headers=data.get("security_headers", {}) or {},
            technologies=data.get("technologies", []) or [],
            response_time_ms=data.get("response_time_ms"),
            reachability=data.get("reachability", ReachabilityStatus.REACHABLE.value),
            provenance=prov,
            raw_reference=data.get("raw_reference"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )


# ==============================================================================
# 2. PORT & SERVICE OBSERVATION
# ==============================================================================

@dataclass
class PortServiceObservation:
    """Represents a discovered network port and associated protocol/service."""
    host: str
    port: int
    protocol: str = "tcp"  # tcp or udp
    service: str = "unknown"
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    reachability: str = ReachabilityStatus.REACHABLE.value
    confidence: str = ObservationConfidence.CONFIRMED.value
    provenance: List[ObservationProvenance] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def key(self) -> str:
        """Deterministic canonical key for port observation."""
        return f"{self.host.strip().lower()}:{self.protocol.lower()}:{self.port}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "banner": self.banner,
            "reachability": self.reachability,
            "confidence": self.confidence,
            "provenance": [p.to_dict() for p in self.provenance],
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PortServiceObservation:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            host=data.get("host", ""),
            port=int(data.get("port", 0)),
            protocol=data.get("protocol", "tcp"),
            service=data.get("service", "unknown"),
            product=data.get("product"),
            version=data.get("version"),
            banner=data.get("banner"),
            reachability=data.get("reachability", ReachabilityStatus.REACHABLE.value),
            confidence=data.get("confidence", ObservationConfidence.CONFIRMED.value),
            provenance=prov,
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )


# ==============================================================================
# 3. DNS RECORD OBSERVATION
# ==============================================================================

@dataclass
class DnsRecordObservation:
    """Represents an observed DNS record (A, AAAA, CNAME, MX, NS, TXT)."""
    host: str
    record_type: str  # A, AAAA, CNAME, MX, NS, TXT
    values: List[str] = field(default_factory=list)
    ttl: Optional[int] = None
    provenance: List[ObservationProvenance] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def key(self) -> str:
        return f"{self.host.strip().lower()}:{self.record_type.upper()}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "record_type": self.record_type.upper(),
            "values": sorted(list(self.values)),
            "ttl": self.ttl,
            "provenance": [p.to_dict() for p in self.provenance],
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DnsRecordObservation:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            host=data.get("host", ""),
            record_type=data.get("record_type", "").upper(),
            values=data.get("values", []) or [],
            ttl=data.get("ttl"),
            provenance=prov,
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )


# ==============================================================================
# 4. TLS CERTIFICATE OBSERVATION
# ==============================================================================

@dataclass
class TlsObservation:
    """Represents TLS certificate and handshake observations."""
    host: str
    port: int = 443
    san_names: List[str] = field(default_factory=list)
    issuer: Optional[str] = None
    subject: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    expired: bool = False
    provenance: List[ObservationProvenance] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def key(self) -> str:
        return f"{self.host.strip().lower()}:{self.port}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "san_names": sorted(list(set(self.san_names))),
            "issuer": self.issuer,
            "subject": self.subject,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "tls_version": self.tls_version,
            "cipher": self.cipher,
            "expired": self.expired,
            "provenance": [p.to_dict() for p in self.provenance],
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TlsObservation:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            host=data.get("host", ""),
            port=int(data.get("port", 443)),
            san_names=data.get("san_names", []) or [],
            issuer=data.get("issuer"),
            subject=data.get("subject"),
            valid_from=data.get("valid_from"),
            valid_to=data.get("valid_to"),
            tls_version=data.get("tls_version"),
            cipher=data.get("cipher"),
            expired=bool(data.get("expired", False)),
            provenance=prov,
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )


# ==============================================================================
# 5. TECHNOLOGY OBSERVATION
# ==============================================================================

@dataclass
class TechnologyObservation:
    """Represents an observed framework, server, CMS, or library fingerprint."""
    host: str
    name: str
    category: str = "general"  # web-server, framework, cms, cdn, analytics, frontend
    version: Optional[str] = None
    confidence: str = ObservationConfidence.OBSERVED.value
    evidence_source: str = "header"  # header, body, cookie, url, script, favicon
    provenance: List[ObservationProvenance] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def key(self) -> str:
        return f"{self.host.strip().lower()}:{self.name.strip().lower()}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "confidence": self.confidence,
            "evidence_source": self.evidence_source,
            "provenance": [p.to_dict() for p in self.provenance],
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TechnologyObservation:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            host=data.get("host", ""),
            name=data.get("name", ""),
            category=data.get("category", "general"),
            version=data.get("version"),
            confidence=data.get("confidence", ObservationConfidence.OBSERVED.value),
            evidence_source=data.get("evidence_source", "header"),
            provenance=prov,
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )


# ==============================================================================
# 6. ENDPOINT OBSERVATION
# ==============================================================================

@dataclass
class EndpointObservation:
    """Represents an observed web route, API path, or URL endpoint."""
    scheme: str
    host: str
    port: int
    path: str
    method: str = "GET"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    source_tool: str = "crawling"
    confidence: str = ObservationConfidence.OBSERVED.value
    provenance: List[ObservationProvenance] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def url(self) -> str:
        clean_path = self.path if self.path.startswith("/") else f"/{self.path}"
        default_port = (self.scheme == "http" and self.port == 80) or (self.scheme == "https" and self.port == 443)
        port_str = "" if default_port else f":{self.port}"
        return f"{self.scheme}://{self.host.lower()}{port_str}{clean_path}"

    @property
    def key(self) -> str:
        """Deterministic fingerprint: METHOD + canonical URL."""
        return f"{self.method.upper()} {normalize_url(self.url)}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "method": self.method.upper(),
            "status_code": self.status_code,
            "content_type": self.content_type,
            "source_tool": self.source_tool,
            "confidence": self.confidence,
            "url": self.url,
            "provenance": [p.to_dict() for p in self.provenance],
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EndpointObservation:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            scheme=data.get("scheme", "https"),
            host=data.get("host", ""),
            port=int(data.get("port", 443 if data.get("scheme") == "https" else 80)),
            path=data.get("path", "/"),
            method=data.get("method", "GET").upper(),
            status_code=data.get("status_code"),
            content_type=data.get("content_type"),
            source_tool=data.get("source_tool", "crawling"),
            confidence=data.get("confidence", ObservationConfidence.OBSERVED.value),
            provenance=prov,
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )
