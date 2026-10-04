"""
API Security and Parameter Intelligence Data Models for BugBounty-Agent.

Defines structured, normalized, and serializable observation models for:
- ApiApplication: Base API host and style (REST, GraphQL, RPC)
- ApiEndpoint: Normalized endpoint route templates, methods, and auth requirements
- ApiParameter: Merged parameters across query, path, headers, cookies, and bodies
- ApiRequestSchema & ApiResponseSchema: Bounded schema models
- ApiAuthenticationObservation: Observed auth mechanisms (bearer, basic, api-key, etc.)
- ApiSpecification: Discovered API documentation/specifications (OpenAPI, Swagger, etc.)
- ParameterUsageObservation: Contextual usage observations across JS, HTML, and specs
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


class ApiStyle(str, Enum):
    """API Architecture / Style."""
    REST = "REST"
    GRAPHQL = "GraphQL"
    RPC = "RPC"
    UNKNOWN = "unknown"


class ParameterLocation(str, Enum):
    """Location of an API parameter."""
    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    COOKIE = "cookie"
    BODY = "body"
    FORM = "form"


class ParameterRole(str, Enum):
    """Semantic role classification of an API parameter."""
    IDENTIFIER = "identifier"
    USER_ID = "user_id"
    ACCOUNT_ID = "account_id"
    RESOURCE_ID = "resource_id"
    REDIRECT = "redirect"
    CALLBACK = "callback"
    RETURN_URL = "return_url"
    SEARCH = "search"
    FILTER = "filter"
    SORT = "sort"
    PAGINATION = "pagination"
    PAGE = "page"
    LIMIT = "limit"
    OFFSET = "offset"
    TOKEN = "token"
    SESSION = "session"
    LOCALE = "locale"
    FILE = "file"
    PATH = "path"
    GENERIC = "generic"


class AuthScheme(str, Enum):
    """Authentication scheme classification."""
    NONE = "none"
    BEARER = "bearer"
    BASIC = "basic"
    API_KEY = "api-key"
    COOKIE = "cookie"
    OAUTH2 = "oauth2"
    OPENID_CONNECT = "openid-connect"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class SpecFormat(str, Enum):
    """API Specification format."""
    OPENAPI = "OpenAPI"
    SWAGGER = "Swagger"
    GRAPHQL_SCHEMA = "GraphQL schema"
    POSTMAN = "Postman collection"
    HAR = "HAR"
    UNKNOWN = "unknown"


# ==============================================================================
# 1. API APPLICATION
# ==============================================================================

@dataclass
class ApiApplication:
    """Represents an API service base application (e.g. https://api.example.com/v1)."""
    base_url: str
    host: str
    scheme: str = "https"
    port: int = 443
    api_style: str = ApiStyle.REST.value
    application_association: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    confidence: str = "PROBABLE"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
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
            "api_style": self.api_style,
            "application_association": self.application_association,
            "technologies": list(self.technologies),
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ApiApplication:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            base_url=data.get("base_url", ""),
            host=data.get("host", ""),
            scheme=data.get("scheme", "https"),
            port=int(data.get("port", 443)),
            api_style=data.get("api_style", ApiStyle.REST.value),
            application_association=data.get("application_association"),
            technologies=data.get("technologies", []) or [],
            confidence=data.get("confidence", "PROBABLE"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
        )


# ==============================================================================
# 2. API ENDPOINT
# ==============================================================================

@dataclass
class ApiEndpoint:
    """Represents an API operation / endpoint with path template and method."""
    canonical_url: str
    path_template: str
    method: str = "GET"
    operation_id: Optional[str] = None
    api_style: str = ApiStyle.REST.value
    content_types: List[str] = field(default_factory=list)
    response_content_types: List[str] = field(default_factory=list)
    auth_required: bool = False
    auth_scheme: Optional[str] = None
    source: str = "observation"
    observed_urls: List[str] = field(default_factory=list)
    confidence: str = "OBSERVED"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)

    @property
    def key(self) -> str:
        m = self.method.upper()
        return f"{m} {canonicalize_url(self.canonical_url)}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "canonical_url": self.canonical_url,
            "path_template": self.path_template,
            "method": self.method.upper(),
            "operation_id": self.operation_id,
            "api_style": self.api_style,
            "content_types": list(self.content_types),
            "response_content_types": list(self.response_content_types),
            "auth_required": self.auth_required,
            "auth_scheme": self.auth_scheme,
            "source": self.source,
            "observed_urls": list(self.observed_urls),
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ApiEndpoint:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            canonical_url=data.get("canonical_url", ""),
            path_template=data.get("path_template", "/"),
            method=data.get("method", "GET").upper(),
            operation_id=data.get("operation_id"),
            api_style=data.get("api_style", ApiStyle.REST.value),
            content_types=data.get("content_types", []) or [],
            response_content_types=data.get("response_content_types", []) or [],
            auth_required=bool(data.get("auth_required", False)),
            auth_scheme=data.get("auth_scheme"),
            source=data.get("source", "observation"),
            observed_urls=data.get("observed_urls", []) or [],
            confidence=data.get("confidence", "OBSERVED"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
        )


# ==============================================================================
# 3. API PARAMETER
# ==============================================================================

@dataclass
class ApiParameter:
    """Represents a parameter associated with an API endpoint or request."""
    name: str
    location: str = ParameterLocation.QUERY.value
    datatype: str = "string"
    required: bool = False
    default_value: Optional[str] = None
    enum_values: List[str] = field(default_factory=list)
    endpoint_key: Optional[str] = None
    semantic_role: str = ParameterRole.GENERIC.value
    source: str = "observation"
    confidence: str = "OBSERVED"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)

    @property
    def key(self) -> str:
        ep = self.endpoint_key or "global"
        return f"{ep}:{self.location}:{self.name.lower()}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "datatype": self.datatype,
            "required": self.required,
            "default_value": self.default_value,
            "enum_values": list(self.enum_values),
            "endpoint_key": self.endpoint_key,
            "semantic_role": self.semantic_role,
            "source": self.source,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ApiParameter:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            name=data.get("name", ""),
            location=data.get("location", ParameterLocation.QUERY.value),
            datatype=data.get("datatype", "string"),
            required=bool(data.get("required", False)),
            default_value=data.get("default_value"),
            enum_values=data.get("enum_values", []) or [],
            endpoint_key=data.get("endpoint_key"),
            semantic_role=data.get("semantic_role", ParameterRole.GENERIC.value),
            source=data.get("source", "observation"),
            confidence=data.get("confidence", "OBSERVED"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
        )


# ==============================================================================
# 4. API REQUEST SCHEMA & RESPONSE SCHEMA
# ==============================================================================

@dataclass
class ApiRequestSchema:
    """Bounded representation of an API request payload schema."""
    endpoint_key: str
    content_type: str = "application/json"
    fields: Dict[str, Any] = field(default_factory=dict)
    required_fields: List[str] = field(default_factory=list)
    nested_structure: bool = False
    datatype: str = "object"
    enums: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.endpoint_key}:{self.content_type}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint_key": self.endpoint_key,
            "content_type": self.content_type,
            "fields": dict(self.fields),
            "required_fields": list(self.required_fields),
            "nested_structure": self.nested_structure,
            "datatype": self.datatype,
            "enums": dict(self.enums),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ApiRequestSchema:
        return cls(
            endpoint_key=data.get("endpoint_key", ""),
            content_type=data.get("content_type", "application/json"),
            fields=data.get("fields", {}) or {},
            required_fields=data.get("required_fields", []) or [],
            nested_structure=bool(data.get("nested_structure", False)),
            datatype=data.get("datatype", "object"),
            enums=data.get("enums", {}) or {},
        )


@dataclass
class ApiResponseSchema:
    """Bounded representation of an API response payload schema."""
    endpoint_key: str
    status_code: int = 200
    content_type: str = "application/json"
    fields: Dict[str, Any] = field(default_factory=dict)
    datatype: str = "object"

    @property
    def key(self) -> str:
        return f"{self.endpoint_key}:{self.status_code}:{self.content_type}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint_key": self.endpoint_key,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "fields": dict(self.fields),
            "datatype": self.datatype,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ApiResponseSchema:
        return cls(
            endpoint_key=data.get("endpoint_key", ""),
            status_code=int(data.get("status_code", 200)),
            content_type=data.get("content_type", "application/json"),
            fields=data.get("fields", {}) or {},
            datatype=data.get("datatype", "object"),
        )


# ==============================================================================
# 5. API AUTHENTICATION OBSERVATION
# ==============================================================================

@dataclass
class ApiAuthenticationObservation:
    """Represents an observed authentication mechanism or requirement."""
    scheme: str = AuthScheme.UNKNOWN.value
    location: str = "header"  # header, query, cookie
    name: str = "Authorization"
    confidence: str = "PROBABLE"
    source: str = "observation"
    endpoint_key: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)

    @property
    def key(self) -> str:
        ep = self.endpoint_key or "global"
        return f"{ep}:{self.scheme}:{self.location}:{self.name.lower()}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scheme": self.scheme,
            "location": self.location,
            "name": self.name,
            "confidence": self.confidence,
            "source": self.source,
            "endpoint_key": self.endpoint_key,
            "details": dict(self.details),
            "timestamp": self.timestamp,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ApiAuthenticationObservation:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            scheme=data.get("scheme", AuthScheme.UNKNOWN.value),
            location=data.get("location", "header"),
            name=data.get("name", "Authorization"),
            confidence=data.get("confidence", "PROBABLE"),
            source=data.get("source", "observation"),
            endpoint_key=data.get("endpoint_key"),
            details=data.get("details", {}) or {},
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
        )


# ==============================================================================
# 6. API SPECIFICATION
# ==============================================================================

@dataclass
class ApiSpecification:
    """Represents a discovered or ingested API specification document."""
    url_or_path: str
    format: str = SpecFormat.OPENAPI.value
    version: Optional[str] = None
    endpoint_count: int = 0
    source: str = "discovery"
    confidence: str = "CONFIRMED"
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)

    @property
    def key(self) -> str:
        return canonicalize_url(self.url_or_path)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url_or_path": self.url_or_path,
            "format": self.format,
            "version": self.version,
            "endpoint_count": self.endpoint_count,
            "source": self.source,
            "confidence": self.confidence,
            "details": dict(self.details),
            "timestamp": self.timestamp,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ApiSpecification:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            url_or_path=data.get("url_or_path", ""),
            format=data.get("format", SpecFormat.OPENAPI.value),
            version=data.get("version"),
            endpoint_count=int(data.get("endpoint_count", 0)),
            source=data.get("source", "discovery"),
            confidence=data.get("confidence", "CONFIRMED"),
            details=data.get("details", {}) or {},
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
        )


# ==============================================================================
# 7. PARAMETER USAGE OBSERVATION
# ==============================================================================

@dataclass
class ParameterUsageObservation:
    """Tracks contextual parameter usage across pages, scripts, forms, and specs."""
    parameter_name: str
    source_resource: str
    endpoint_key: str
    usage_context: str = "query_parameter"  # query_parameter, urlsearchparams, form_input, body_key
    confidence: str = "OBSERVED"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: List[ObservationProvenance] = field(default_factory=list)

    @property
    def key(self) -> str:
        sig = hashlib.sha256(f"{self.parameter_name}:{self.source_resource}:{self.endpoint_key}:{self.usage_context}".encode("utf-8")).hexdigest()[:16]
        return f"usage:{sig}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "parameter_name": self.parameter_name,
            "source_resource": self.source_resource,
            "endpoint_key": self.endpoint_key,
            "usage_context": self.usage_context,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "provenance": [p.to_dict() for p in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ParameterUsageObservation:
        prov = [ObservationProvenance.from_dict(p) for p in data.get("provenance", [])]
        return cls(
            parameter_name=data.get("parameter_name", ""),
            source_resource=data.get("source_resource", ""),
            endpoint_key=data.get("endpoint_key", ""),
            usage_context=data.get("usage_context", "query_parameter"),
            confidence=data.get("confidence", "OBSERVED"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            provenance=prov,
        )
