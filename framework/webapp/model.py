"""
Web Application Intelligence Data Models for BugBounty-Agent.

Defines structured, normalized, deterministic, and serializable observation models for
WebApplications, WebPages, WebEndpoints/Routes, Parameters, Forms, Cookies,
Resources, and Links, retaining multi-source provenance.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import posixpath
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlparse, urlsplit, urlunsplit

from framework.assets.provenance import ObservationProvenance


class ParameterLocation(str, Enum):
    """Location of an observable web parameter."""
    QUERY = "query"
    PATH = "path"
    BODY = "body"
    COOKIE = "cookie"
    HEADER = "header"


class ResourceType(str, Enum):
    """Classification of web application static and dynamic resources."""
    JS = "js"
    CSS = "css"
    IMAGE = "image"
    FONT = "font"
    JSON = "json"
    WASM = "wasm"
    MEDIA = "media"
    OTHER = "other"


def canonicalize_url(raw_url: str, base_url: Optional[str] = None) -> str:
    """
    Produces a canonical, normalized, deterministic URL:
    - Resolves relative URLs against base_url
    - Converts scheme and hostname to lowercase
    - Strips default ports (:80 for http, :443 for https)
    - Normalizes path (/foo/../bar -> /bar)
    - Strips fragments (#section)
    - Sorts query parameters deterministically without discarding duplicate keys
    - Removes trailing slash for non-root paths
    - Handles encoded characters safely
    """
    raw = raw_url.strip()
    if not raw:
        return ""

    if base_url:
        raw = urljoin(base_url, raw)

    split = urlsplit(raw)
    scheme = split.scheme.lower()
    if not scheme:
        scheme = "http"

    netloc = split.netloc.lower()
    # Strip userinfo if any for safety
    if "@" in netloc:
        netloc = netloc.split("@", 1)[1]

    # Handle default port stripping
    if ":" in netloc:
        host, port = netloc.rsplit(":", 1)
        if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
            netloc = host

    # Normalize path segments
    path = split.path or "/"
    # Clean up relative segments safely
    path_segments = posixpath.normpath(path)
    if path.endswith("/") and not path_segments.endswith("/"):
        path_segments += "/"
    if not path_segments.startswith("/"):
        path_segments = "/" + path_segments

    # Strip trailing slash on non-root paths for deduplication
    if len(path_segments) > 1 and path_segments.endswith("/"):
        path_segments = path_segments[:-1]

    # Deterministically sort query parameters
    query = ""
    if split.query:
        query_pairs = sorted(parse_qsl(split.query, keep_blank_values=True))
        query = urlencode(query_pairs)

    # Reassemble without fragment
    return urlunsplit((scheme, netloc, path_segments, query, ""))


def is_same_origin(url1: str, url2: str) -> bool:
    """Checks if two URLs share the identical scheme, host, and port."""
    s1 = urlsplit(canonicalize_url(url1))
    s2 = urlsplit(canonicalize_url(url2))
    return (s1.scheme, s1.netloc) == (s2.scheme, s2.netloc)


# ==============================================================================
# 1. WEB APPLICATION
# ==============================================================================

@dataclass
class WebApplication:
    """Represents a discovered web application rooted at a canonical base URL."""
    base_url: str
    host: str
    scheme: str
    port: int
    title: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    server: Optional[str] = None
    application_type: str = "web-service"  # spa, api, traditional, cms, portal
    status: str = "DISCOVERED"
    confidence: str = "CONFIRMED"
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)

    @property
    def key(self) -> str:
        return canonicalize_url(self.base_url)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_url": self.base_url,
            "host": self.host,
            "scheme": self.scheme,
            "port": self.port,
            "title": self.title,
            "technologies": sorted(list(set(self.technologies))),
            "server": self.server,
            "application_type": self.application_type,
            "status": self.status,
            "confidence": self.confidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WebApplication:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            base_url=data.get("base_url", ""),
            host=data.get("host", ""),
            scheme=data.get("scheme", "http"),
            port=int(data.get("port", 80)),
            title=data.get("title"),
            technologies=data.get("technologies", []) or [],
            server=data.get("server"),
            application_type=data.get("application_type", "web-service"),
            status=data.get("status", "DISCOVERED"),
            confidence=data.get("confidence", "CONFIRMED"),
            first_seen=data.get("first_seen", datetime.now(timezone.utc).isoformat()),
            last_seen=data.get("last_seen", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
        )


# ==============================================================================
# 2. WEB PAGE
# ==============================================================================

@dataclass
class WebPage:
    """Represents an observed HTML document or web page."""
    url: str
    path: str
    method: str = "GET"
    status_code: int = 200
    content_type: Optional[str] = "text/html"
    title: Optional[str] = None
    parent_url: Optional[str] = None
    depth: int = 0
    links_count: int = 0
    forms_count: int = 0
    scripts_count: int = 0
    resources_count: int = 0
    confidence: str = "CONFIRMED"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)

    @property
    def key(self) -> str:
        return canonicalize_url(self.url)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "path": self.path,
            "method": self.method.upper(),
            "status_code": self.status_code,
            "content_type": self.content_type,
            "title": self.title,
            "parent_url": self.parent_url,
            "depth": self.depth,
            "links_count": self.links_count,
            "forms_count": self.forms_count,
            "scripts_count": self.scripts_count,
            "resources_count": self.resources_count,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WebPage:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            url=data.get("url", ""),
            path=data.get("path", "/"),
            method=data.get("method", "GET").upper(),
            status_code=int(data.get("status_code", 200)),
            content_type=data.get("content_type", "text/html"),
            title=data.get("title"),
            parent_url=data.get("parent_url"),
            depth=int(data.get("depth", 0)),
            links_count=int(data.get("links_count", 0)),
            forms_count=int(data.get("forms_count", 0)),
            scripts_count=int(data.get("scripts_count", 0)),
            resources_count=int(data.get("resources_count", 0)),
            confidence=data.get("confidence", "CONFIRMED"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
        )


# ==============================================================================
# 3. WEB ENDPOINT / ROUTE
# ==============================================================================

@dataclass
class WebEndpoint:
    """Represents a discovered route, API path, or URL endpoint."""
    url: str
    path: str
    method: str = "GET"
    parameter_names: List[str] = field(default_factory=list)
    parameter_locations: List[str] = field(default_factory=list)
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    source: str = "html-crawl"
    confidence: str = "OBSERVED"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {canonicalize_url(self.url)}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "path": self.path,
            "method": self.method.upper(),
            "parameter_names": sorted(list(set(self.parameter_names))),
            "parameter_locations": sorted(list(set(self.parameter_locations))),
            "status_code": self.status_code,
            "content_type": self.content_type,
            "source": self.source,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WebEndpoint:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            url=data.get("url", ""),
            path=data.get("path", "/"),
            method=data.get("method", "GET").upper(),
            parameter_names=data.get("parameter_names", []) or [],
            parameter_locations=data.get("parameter_locations", []) or [],
            status_code=data.get("status_code"),
            content_type=data.get("content_type"),
            source=data.get("source", "html-crawl"),
            confidence=data.get("confidence", "OBSERVED"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
        )


# ==============================================================================
# 4. PARAMETER OBSERVATION
# ==============================================================================

@dataclass
class ParameterObservation:
    """Represents an observed parameter (query, path, body, cookie, header)."""
    name: str
    location: str  # query, path, body, cookie, header
    method: str = "GET"
    endpoint_url: str = ""
    datatype: str = "string"  # string, int, boolean, json, array
    required: bool = False
    source: str = "query"
    confidence: str = "OBSERVED"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{canonicalize_url(self.endpoint_url)}:{self.location.lower()}:{self.name.lower()}:{self.method.upper()}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "method": self.method.upper(),
            "endpoint_url": self.endpoint_url,
            "datatype": self.datatype,
            "required": self.required,
            "source": self.source,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ParameterObservation:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            name=data.get("name", ""),
            location=data.get("location", "query"),
            method=data.get("method", "GET").upper(),
            endpoint_url=data.get("endpoint_url", ""),
            datatype=data.get("datatype", "string"),
            required=bool(data.get("required", False)),
            source=data.get("source", "query"),
            confidence=data.get("confidence", "OBSERVED"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
        )


# ==============================================================================
# 5. FORM OBSERVATION
# ==============================================================================

@dataclass
class FormObservation:
    """Represents an HTML form extracted from a page."""
    page_url: str
    action: str
    method: str = "GET"
    input_names: List[str] = field(default_factory=list)
    input_types: Dict[str, str] = field(default_factory=dict)
    enctype: str = "application/x-www-form-urlencoded"
    has_password: bool = False
    has_file_upload: bool = False
    source: str = "html-parser"
    confidence: str = "OBSERVED"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)

    @property
    def key(self) -> str:
        act = canonicalize_url(self.action, self.page_url)
        inputs_sig = ",".join(sorted(self.input_names))
        return f"{self.method.upper()} {act} [fields:{inputs_sig}]"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "page_url": self.page_url,
            "action": self.action,
            "method": self.method.upper(),
            "input_names": list(self.input_names),
            "input_types": dict(self.input_types),
            "enctype": self.enctype,
            "has_password": self.has_password,
            "has_file_upload": self.has_file_upload,
            "source": self.source,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FormObservation:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            page_url=data.get("page_url", ""),
            action=data.get("action", ""),
            method=data.get("method", "GET").upper(),
            input_names=data.get("input_names", []) or [],
            input_types=data.get("input_types", {}) or {},
            enctype=data.get("enctype", "application/x-www-form-urlencoded"),
            has_password=bool(data.get("has_password", False)),
            has_file_upload=bool(data.get("has_file_upload", False)),
            source=data.get("source", "html-parser"),
            confidence=data.get("confidence", "OBSERVED"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
        )


# ==============================================================================
# 6. COOKIE OBSERVATION
# ==============================================================================

@dataclass
class CookieObservation:
    """Represents an observed HTTP response cookie."""
    name: str
    domain: str
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    same_site: Optional[str] = None  # Strict, Lax, None
    source_url: str = ""
    confidence: str = "CONFIRMED"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.domain.lower()}:{self.name}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "domain": self.domain,
            "path": self.path,
            "secure": self.secure,
            "http_only": self.http_only,
            "same_site": self.same_site,
            "source_url": self.source_url,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CookieObservation:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            name=data.get("name", ""),
            domain=data.get("domain", ""),
            path=data.get("path", "/"),
            secure=bool(data.get("secure", False)),
            http_only=bool(data.get("http_only", False)),
            same_site=data.get("same_site"),
            source_url=data.get("source_url", ""),
            confidence=data.get("confidence", "CONFIRMED"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
        )


# ==============================================================================
# 7. RESOURCE OBSERVATION
# ==============================================================================

@dataclass
class ResourceObservation:
    """Represents an observed static or dynamic web asset (script, CSS, image, etc.)."""
    url: str
    resource_type: str  # js, css, image, font, json, wasm, media, other
    source_page: str
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    size: Optional[int] = None
    confidence: str = "OBSERVED"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)

    @property
    def key(self) -> str:
        return canonicalize_url(self.url)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "resource_type": self.resource_type,
            "source_page": self.source_page,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "size": self.size,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ResourceObservation:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            url=data.get("url", ""),
            resource_type=data.get("resource_type", ResourceType.OTHER.value),
            source_page=data.get("source_page", ""),
            status_code=data.get("status_code"),
            content_type=data.get("content_type"),
            size=data.get("size"),
            confidence=data.get("confidence", "OBSERVED"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
        )


# ==============================================================================
# 8. LINK OBSERVATION
# ==============================================================================

@dataclass
class LinkObservation:
    """Represents a discovered directional navigation hyperlink between two URLs."""
    source_url: str
    destination_url: str
    canonical_destination: str
    is_same_origin: bool = True
    is_in_scope: bool = True
    source: str = "a-href"
    confidence: str = "OBSERVED"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{canonicalize_url(self.source_url)} -> {canonicalize_url(self.destination_url)}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_url": self.source_url,
            "destination_url": self.destination_url,
            "canonical_destination": self.canonical_destination,
            "is_same_origin": self.is_same_origin,
            "is_in_scope": self.is_in_scope,
            "source": self.source,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> LinkObservation:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            source_url=data.get("source_url", ""),
            destination_url=data.get("destination_url", ""),
            canonical_destination=data.get("canonical_destination", ""),
            is_same_origin=bool(data.get("is_same_origin", True)),
            is_in_scope=bool(data.get("is_in_scope", True)),
            source=data.get("source", "a-href"),
            confidence=data.get("confidence", "OBSERVED"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
        )
