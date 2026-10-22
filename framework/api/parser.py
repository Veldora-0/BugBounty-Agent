"""
API Parser and Intelligence Analyzers for BugBounty-Agent.

Provides:
- Path parameter inference and REST route normalization
- Semantic parameter role classification
- Safe, bounded OpenAPI 2.0 (Swagger) and OpenAPI 3.x schema parsing
- GraphQL endpoint detection and metadata extraction
- Safe, bounded schema structure generation preventing infinite recursion
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlsplit, urlunsplit
import yaml

from framework.assets.provenance import ObservationProvenance
from framework.api.model import (
    ApiApplication,
    ApiAuthenticationObservation,
    ApiEndpoint,
    ApiParameter,
    ApiRequestSchema,
    ApiResponseSchema,
    ApiSpecification,
    ApiStyle,
    AuthScheme,
    ParameterLocation,
    ParameterRole,
    SpecFormat,
)
from framework.webapp.model import canonicalize_url


# ==============================================================================
# 1. PARAMETER ROLE CLASSIFIER
# ==============================================================================

ROLE_PATTERNS: List[Tuple[ParameterRole, List[str]]] = [
    (ParameterRole.USER_ID, ["user_id", "userid", "uid", "account_id", "member_id", "profile_id"]),
    (ParameterRole.ACCOUNT_ID, ["acc_id", "account", "org_id", "organization_id", "tenant_id", "team_id"]),
    (ParameterRole.RESOURCE_ID, ["item_id", "order_id", "product_id", "doc_id", "record_id", "entity_id"]),
    (ParameterRole.IDENTIFIER, ["id", "uuid", "guid", "slug", "key"]),
    (ParameterRole.REDIRECT, ["redirect", "redirect_url", "redirect_uri", "return", "return_url", "return_to", "next", "dest", "target", "r_url"]),
    (ParameterRole.CALLBACK, ["callback", "callback_url", "cb", "webhook", "webhook_url", "notify_url"]),
    (ParameterRole.SEARCH, ["search", "query", "q", "keyword", "term", "find"]),
    (ParameterRole.FILTER, ["filter", "filter_by", "status", "category", "type", "state", "group", "tag"]),
    (ParameterRole.SORT, ["sort", "sort_by", "order", "order_by", "direction", "dir"]),
    (ParameterRole.PAGE, ["page", "p", "page_number", "page_no"]),
    (ParameterRole.LIMIT, ["limit", "size", "per_page", "page_size", "count", "max"]),
    (ParameterRole.OFFSET, ["offset", "skip", "start", "from"]),
    (ParameterRole.TOKEN, ["token", "access_token", "api_key", "secret", "auth_token", "jwt", "bearer"]),
    (ParameterRole.SESSION, ["session", "session_id", "sid", "sess", "jsessionid", "phpsessid"]),
    (ParameterRole.FILE, ["file", "filename", "filepath", "document", "upload", "path", "attachment"]),
    (ParameterRole.LOCALE, ["lang", "language", "locale", "country", "region"]),
]


def classify_parameter_role(name: str) -> str:
    """Classifies parameter semantic role based on normalized name patterns."""
    clean = name.strip().lower()
    # 1. Exact matches first
    for role, patterns in ROLE_PATTERNS:
        if clean in patterns:
            return role.value

    # 2. Suffix/prefix matches (specific roles before generic identifier)
    for role, patterns in ROLE_PATTERNS:
        if role == ParameterRole.IDENTIFIER:
            continue
        for pat in patterns:
            if clean.endswith(f"_{pat}") or clean.endswith(f"-{pat}") or clean.startswith(f"{pat}_"):
                return role.value

    # 3. Generic identifier fallback
    for pat in ["id", "uuid", "guid", "slug", "key"]:
        if clean.endswith(f"_{pat}") or clean.endswith(f"-{pat}"):
            return ParameterRole.IDENTIFIER.value

    return ParameterRole.GENERIC.value


# ==============================================================================
# 2. REST PATH PARAMETER INFERENCE
# ==============================================================================

UUID_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
HEX_HASH_REGEX = re.compile(r"^[0-9a-f]{24,64}$", re.IGNORECASE)
INTEGER_ID_REGEX = re.compile(r"^\d{1,12}$")


def infer_path_parameters(url_or_path: str) -> Tuple[str, List[ApiParameter]]:
    """
    Infers REST path parameter templates from concrete paths.
    Example:
      /api/v1/users/123 -> (/api/v1/users/{id}, [ApiParameter(name='id', location='path', ...)])
      /api/orders/550e8400-e29b-41d4-a716-446655440000 -> (/api/orders/{id}, ...)
    Preserves non-dynamic segments (e.g. /users/me, /api/v1/status).
    """
    parts = urlsplit(url_or_path)
    path = parts.path or "/"

    segments = path.split("/")
    new_segments = []
    inferred_params: List[ApiParameter] = []

    for i, seg in enumerate(segments):
        if not seg:
            new_segments.append("")
            continue

        prev_seg = segments[i - 1].lower() if i > 0 else ""

        is_dynamic = False
        param_name = "id"
        datatype = "string"
        role = ParameterRole.IDENTIFIER.value

        if INTEGER_ID_REGEX.match(seg):
            is_dynamic = True
            datatype = "integer"
            if prev_seg.endswith("s") and len(prev_seg) > 2:
                param_name = f"{prev_seg[:-1]}_id"
            elif prev_seg:
                param_name = f"{prev_seg}_id"
            role = ParameterRole.USER_ID.value if "user" in prev_seg else ParameterRole.RESOURCE_ID.value

        elif UUID_REGEX.match(seg):
            is_dynamic = True
            datatype = "string"
            if prev_seg.endswith("s") and len(prev_seg) > 2:
                param_name = f"{prev_seg[:-1]}_id"
            elif prev_seg:
                param_name = f"{prev_seg}_id"
            role = ParameterRole.RESOURCE_ID.value

        elif HEX_HASH_REGEX.match(seg) and prev_seg in ("users", "orders", "tokens", "items", "documents"):
            is_dynamic = True
            datatype = "string"
            param_name = "id"
            role = ParameterRole.RESOURCE_ID.value

        if is_dynamic:
            new_segments.append(f"{{{param_name}}}")
            inferred_params.append(
                ApiParameter(
                    name=param_name,
                    location=ParameterLocation.PATH.value,
                    datatype=datatype,
                    required=True,
                    semantic_role=role,
                    source="path_inference",
                    confidence="PROBABLE",
                    provenance=[
                        ObservationProvenance(
                            source="api_parser",
                            method="rest_path_inference",
                            confidence="PROBABLE",
                        )
                    ],
                )
            )
        else:
            new_segments.append(seg)

    template_path = "/".join(new_segments)

    # Reconstruct with scheme/host if provided
    if parts.scheme and parts.netloc:
        canon_template = urlunsplit((parts.scheme, parts.netloc, template_path, "", ""))
    else:
        canon_template = template_path

    return canon_template, inferred_params


# ==============================================================================
# 3. BOUNDED SCHEMA BUILDER
# ==============================================================================

MAX_SCHEMA_DEPTH = 5
MAX_SCHEMA_FIELDS = 100


def build_bounded_schema(
    schema_data: Any,
    current_depth: int = 0,
    resolver: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None,
    visited_refs: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """
    Safely extracts normalized, bounded schema representations without unbounded
    recursion or memory bloat. Resolves local $ref schemas up to maximum depth.
    """
    if current_depth > MAX_SCHEMA_DEPTH or not isinstance(schema_data, dict):
        return {"type": "unknown"}

    if visited_refs is None:
        visited_refs = set()

    # Expand $ref pointer if present
    if "$ref" in schema_data and isinstance(schema_data["$ref"], str):
        ref_ptr = schema_data["$ref"]
        if ref_ptr in visited_refs:
            return {"type": "object", "_cyclic_ref": ref_ptr}
        visited_refs.add(ref_ptr)
        if resolver:
            resolved = resolver(ref_ptr)
            if resolved and isinstance(resolved, dict):
                schema_data = resolved
            else:
                return {"type": "object", "_unresolved_ref": ref_ptr}
        else:
            return {"type": "object", "_ref": ref_ptr}

    stype = schema_data.get("type", "object")
    if isinstance(stype, list):
        stype = stype[0] if stype else "unknown"

    result: Dict[str, Any] = {"type": str(stype)}

    if "description" in schema_data:
        result["description"] = str(schema_data["description"])[:200]

    if "enum" in schema_data and isinstance(schema_data["enum"], list):
        result["enum"] = [str(e)[:50] for e in schema_data["enum"][:20]]

    if "format" in schema_data:
        result["format"] = str(schema_data["format"])[:50]

    # Object properties
    if stype == "object" or "properties" in schema_data:
        props = schema_data.get("properties", {})
        if isinstance(props, dict):
            bounded_props: Dict[str, Any] = {}
            for i, (k, v) in enumerate(props.items()):
                if i >= MAX_SCHEMA_FIELDS:
                    bounded_props["_truncated"] = True
                    break
                bounded_props[str(k)[:50]] = build_bounded_schema(v, current_depth + 1, resolver, set(visited_refs))
            result["properties"] = bounded_props

        if "required" in schema_data and isinstance(schema_data["required"], list):
            result["required"] = [str(r)[:50] for r in schema_data["required"][:MAX_SCHEMA_FIELDS]]

    # Array items
    elif stype == "array" and "items" in schema_data:
        items = schema_data.get("items", {})
        result["items"] = build_bounded_schema(items, current_depth + 1, resolver, set(visited_refs))

    return result


# ==============================================================================
# 4. OPENAPI / SWAGGER PARSER
# ==============================================================================

class OpenApiParser:
    """
    Parses OpenAPI 2.0 (Swagger) and OpenAPI 3.x specifications into normalized
    ApiApplication, ApiEndpoint, ApiParameter, ApiRequestSchema, and ApiResponseSchema.
    """

    def __init__(self, raw_content: str, spec_url: str):
        self.raw_content = raw_content
        self.spec_url = spec_url
        self.spec_data: Dict[str, Any] = {}
        self.format = SpecFormat.UNKNOWN
        self.version: Optional[str] = None
        self._scheme_type_by_key: Dict[str, str] = {}
        self._parse_raw()

    def _parse_raw(self) -> None:
        """Parses JSON or YAML deterministically."""
        import textwrap
        clean = textwrap.dedent(self.raw_content).strip()
        if not clean:
            return

        try:
            if clean.startswith("{"):
                self.spec_data = json.loads(clean)
            else:
                self.spec_data = yaml.safe_load(clean) or {}
        except Exception:
            return

        if not isinstance(self.spec_data, dict):
            self.spec_data = {}
            return

        # Determine specification format and version
        if "swagger" in self.spec_data:
            self.format = SpecFormat.SWAGGER
            self.version = str(self.spec_data.get("swagger", "2.0"))
        elif "openapi" in self.spec_data:
            self.format = SpecFormat.OPENAPI
            self.version = str(self.spec_data.get("openapi", "3.0.0"))

    def is_valid_spec(self) -> bool:
        return self.format in (SpecFormat.OPENAPI, SpecFormat.SWAGGER) and "paths" in self.spec_data

    def _resolve_local_ref(
        self,
        ref_str: str,
        visited: Optional[Set[str]] = None,
        current_depth: int = 0,
    ) -> Optional[Dict[str, Any]]:
        """
        Safely resolves a local RFC 6901 JSON pointer ($ref) within this specification.
        Forbids external URLs or file paths to prevent SSRF and arbitrary file access.
        Enforces maximum recursion depth and cycle detection.
        """
        if not isinstance(ref_str, str) or not ref_str.startswith("#"):
            return None

        if visited is None:
            visited = set()

        if ref_str in visited or current_depth > MAX_SCHEMA_DEPTH:
            return None

        visited.add(ref_str)

        # Remove leading "#" and split into path tokens
        path = ref_str[1:]
        if path.startswith("/"):
            path = path[1:]

        tokens = path.split("/") if path else []
        curr: Any = self.spec_data

        for raw_token in tokens:
            # RFC 6901 unescaping: ~1 -> /, ~0 -> ~
            token = raw_token.replace("~1", "/").replace("~0", "~")
            if isinstance(curr, dict) and token in curr:
                curr = curr[token]
            elif isinstance(curr, list):
                try:
                    idx = int(token)
                    if 0 <= idx < len(curr):
                        curr = curr[idx]
                    else:
                        return None
                except ValueError:
                    return None
            else:
                return None

        if not isinstance(curr, dict):
            return None

        # Transitive $ref resolution if the target is itself a reference
        if "$ref" in curr and isinstance(curr["$ref"], str):
            transitive = self._resolve_local_ref(curr["$ref"], visited, current_depth + 1)
            if isinstance(transitive, dict):
                return transitive

        return curr

    def _resolve_param(self, p_item: Any) -> Optional[Dict[str, Any]]:
        """Resolves local $ref on parameter if present."""
        if not isinstance(p_item, dict):
            return None
        if "$ref" in p_item and isinstance(p_item["$ref"], str):
            resolved = self._resolve_local_ref(p_item["$ref"])
            if isinstance(resolved, dict):
                return dict(resolved)
            return None
        return dict(p_item)

    @staticmethod
    def _normalize_param_location(raw_loc: str) -> str:
        """Normalizes OpenAPI parameter location string."""
        raw_loc = str(raw_loc).strip().lower()
        if raw_loc == "formdata":
            return ParameterLocation.FORM.value
        for loc in ParameterLocation:
            if loc.value == raw_loc:
                return loc.value
        return ParameterLocation.QUERY.value

    def extract_base_url(self) -> str:
        """Extracts canonical API base URL from specification servers or host/basePath."""
        spec_parts = urlsplit(self.spec_url)
        default_base = f"{spec_parts.scheme or 'https'}://{spec_parts.netloc}"

        if self.format == SpecFormat.OPENAPI:
            servers = self.spec_data.get("servers", [])
            if isinstance(servers, list) and servers and isinstance(servers[0], dict):
                server_url = servers[0].get("url", "/")
                return urljoin(default_base, server_url)
            return default_base

        elif self.format == SpecFormat.SWAGGER:
            host = self.spec_data.get("host")
            base_path = self.spec_data.get("basePath", "/")
            schemes = self.spec_data.get("schemes", ["https"])
            scheme = schemes[0] if schemes else "https"
            if host:
                return f"{scheme}://{host}{base_path}".rstrip("/")
            return urljoin(default_base, base_path).rstrip("/")

        return default_base

    def extract_auth_schemes(self) -> List[ApiAuthenticationObservation]:
        """Extracts security definitions / schemes from specification."""
        observations: List[ApiAuthenticationObservation] = []
        sec_defs: Dict[str, Any] = {}

        if self.format == SpecFormat.SWAGGER:
            sec_defs = self.spec_data.get("securityDefinitions", {}) or {}
        elif self.format == SpecFormat.OPENAPI:
            components = self.spec_data.get("components", {}) or {}
            sec_defs = components.get("securitySchemes", {}) or {}

        if not isinstance(sec_defs, dict):
            return observations

        for name, item in sec_defs.items():
            if not isinstance(item, dict):
                continue
            if "$ref" in item and isinstance(item["$ref"], str):
                resolved_sec = self._resolve_local_ref(item["$ref"])
                if isinstance(resolved_sec, dict):
                    item = resolved_sec

            stype = str(item.get("type", "")).lower()
            scheme = AuthScheme.UNKNOWN.value

            if stype == "basic":
                scheme = AuthScheme.BASIC.value
            elif stype in ("bearer", "http") and str(item.get("scheme", "")).lower() == "bearer":
                scheme = AuthScheme.BEARER.value
            elif stype == "http":
                subscheme = str(item.get("scheme", "")).lower()
                if subscheme == "basic":
                    scheme = AuthScheme.BASIC.value
                elif subscheme == "bearer":
                    scheme = AuthScheme.BEARER.value
                else:
                    scheme = AuthScheme.CUSTOM.value
            elif stype == "apikey":
                scheme = AuthScheme.API_KEY.value
            elif stype in ("oauth2", "openidconnect"):
                scheme = AuthScheme.OAUTH2.value if stype == "oauth2" else AuthScheme.OPENID_CONNECT.value

            self._scheme_type_by_key[name] = scheme

            loc = item.get("in", "header")
            param_name = item.get("name", "Authorization")

            observations.append(
                ApiAuthenticationObservation(
                    scheme=scheme,
                    location=loc,
                    name=param_name,
                    confidence="CONFIRMED",
                    source=f"spec:{self.format.value}",
                    details={"spec_key": name, "type": stype},
                    provenance=[
                        ObservationProvenance(
                            source="api_spec_parser",
                            method=f"{self.format.value}_security_definitions",
                            confidence="CONFIRMED",
                        )
                    ],
                )
            )

        return observations

    def parse(self) -> Dict[str, Any]:
        """Parses complete API specification into structured models."""
        if not self.is_valid_spec():
            return {
                "specification": None,
                "application": None,
                "endpoints": [],
                "parameters": [],
                "request_schemas": [],
                "response_schemas": [],
                "auth_observations": [],
            }

        base_url = self.extract_base_url()
        base_parts = urlsplit(base_url)

        # 1. API Application
        api_app = ApiApplication(
            base_url=base_url,
            host=base_parts.hostname or "",
            scheme=base_parts.scheme or "https",
            port=base_parts.port or (443 if base_parts.scheme == "https" else 80),
            api_style=ApiStyle.REST.value,
            confidence="CONFIRMED",
            provenance=[
                ObservationProvenance(
                    source="api_spec_parser",
                    method=f"{self.format.value}_document",
                    confidence="CONFIRMED",
                )
            ],
        )

        # 2. Authentication Observations
        auth_obs = self.extract_auth_schemes()

        endpoints: List[ApiEndpoint] = []
        parameters: List[ApiParameter] = []
        request_schemas: List[ApiRequestSchema] = []
        response_schemas: List[ApiResponseSchema] = []

        paths = self.spec_data.get("paths", {})
        if not isinstance(paths, dict):
            paths = {}

        http_methods = ("get", "post", "put", "delete", "patch", "options", "head")

        for path_key, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            # Resolve full canonical path
            full_url = urljoin(base_url.rstrip("/") + "/", path_key.lstrip("/"))
            canon_url = canonicalize_url(full_url)

            # Global path parameters
            common_params = path_item.get("parameters", []) if isinstance(path_item.get("parameters"), list) else []

            for method_name in http_methods:
                if method_name not in path_item:
                    continue
                op = path_item[method_name]
                if not isinstance(op, dict):
                    continue

                op_id = op.get("operationId")

                # Security requirements:
                # - If op has "security": [] -> explicitly public (auth_required = False)
                # - If op has "security": [...] -> requires auth specified
                # - If op does not have "security" -> fallback to top-level spec_data.get("security", [])
                if "security" in op:
                    security_reqs = op.get("security")
                else:
                    security_reqs = self.spec_data.get("security")

                if security_reqs is None:
                    security_reqs = []

                has_auth = bool(isinstance(security_reqs, list) and len(security_reqs) > 0)
                matched_scheme: Optional[str] = None
                if has_auth and isinstance(security_reqs, list):
                    for sec_req in security_reqs:
                        if isinstance(sec_req, dict):
                            for s_name in sec_req.keys():
                                if s_name in self._scheme_type_by_key:
                                    matched_scheme = self._scheme_type_by_key[s_name]
                                    break
                        if matched_scheme:
                            break

                ep = ApiEndpoint(
                    canonical_url=canon_url,
                    path_template=path_key,
                    method=method_name.upper(),
                    operation_id=str(op_id) if op_id else None,
                    api_style=ApiStyle.REST.value,
                    auth_required=has_auth,
                    auth_scheme=matched_scheme,
                    source=f"spec:{self.format.value}",
                    confidence="CONFIRMED",
                    provenance=[
                        ObservationProvenance(
                            source="api_spec_parser",
                            method=f"{self.format.value}_path_operation",
                            confidence="CONFIRMED",
                        )
                    ],
                )
                endpoints.append(ep)

                # Merge parameters with operation-level overriding path-level:
                # OpenAPI identity: (name.lower(), location)
                merged_params: Dict[Tuple[str, str], Dict[str, Any]] = {}

                # Path-level parameters
                for raw_p in common_params:
                    resolved_p = self._resolve_param(raw_p)
                    if not resolved_p or not isinstance(resolved_p, dict):
                        continue
                    p_name = resolved_p.get("name", "")
                    if not p_name:
                        continue
                    p_loc = self._normalize_param_location(resolved_p.get("in", ParameterLocation.QUERY.value))
                    merged_params[(p_name.strip().lower(), p_loc)] = resolved_p

                # Operation-level parameters (overrides matching (name.lower(), location))
                op_params = op.get("parameters", []) if isinstance(op.get("parameters"), list) else []
                for raw_p in op_params:
                    resolved_p = self._resolve_param(raw_p)
                    if not resolved_p or not isinstance(resolved_p, dict):
                        continue
                    p_name = resolved_p.get("name", "")
                    if not p_name:
                        continue
                    p_loc = self._normalize_param_location(resolved_p.get("in", ParameterLocation.QUERY.value))
                    merged_params[(p_name.strip().lower(), p_loc)] = resolved_p

                for p_item in merged_params.values():
                    p_name = p_item.get("name", "")
                    p_loc = self._normalize_param_location(p_item.get("in", ParameterLocation.QUERY.value))

                    p_schema = p_item.get("schema", p_item)
                    if isinstance(p_schema, dict) and "$ref" in p_schema:
                        resolved_schema = self._resolve_local_ref(p_schema["$ref"])
                        if isinstance(resolved_schema, dict):
                            p_schema = resolved_schema

                    p_type = p_schema.get("type", "string") if isinstance(p_schema, dict) else "string"
                    p_req = bool(p_item.get("required", p_loc == ParameterLocation.PATH.value))
                    p_default = str(p_schema.get("default", "")) if isinstance(p_schema, dict) and "default" in p_schema else None
                    enums = [str(e) for e in p_schema.get("enum", [])] if isinstance(p_schema, dict) and "enum" in p_schema else []

                    role = classify_parameter_role(p_name)
                    parameters.append(
                        ApiParameter(
                            name=p_name,
                            location=p_loc,
                            datatype=str(p_type),
                            required=p_req,
                            default_value=p_default,
                            enum_values=enums,
                            endpoint_key=ep.key,
                            semantic_role=role,
                            source=f"spec:{self.format.value}",
                            confidence="CONFIRMED",
                            provenance=[
                                ObservationProvenance(
                                    source="api_spec_parser",
                                    method=f"{self.format.value}_parameter",
                                    confidence="CONFIRMED",
                                )
                            ],
                        )
                    )

                    # Swagger 2 body parameter -> ApiRequestSchema
                    if (p_loc == ParameterLocation.BODY.value or p_item.get("in") == "body") and isinstance(p_schema, dict):
                        bounded = build_bounded_schema(p_schema, resolver=self._resolve_local_ref)
                        request_schemas.append(
                            ApiRequestSchema(
                                endpoint_key=ep.key,
                                content_type="application/json",
                                fields=bounded.get("properties", {}),
                                required_fields=bounded.get("required", []),
                                datatype=bounded.get("type", "object"),
                            )
                        )

                # Request Schemas (OpenAPI 3)
                if self.format == SpecFormat.OPENAPI:
                    req_body = op.get("requestBody", {})
                    if isinstance(req_body, dict):
                        if "$ref" in req_body and isinstance(req_body["$ref"], str):
                            resolved_rb = self._resolve_local_ref(req_body["$ref"])
                            if isinstance(resolved_rb, dict):
                                req_body = resolved_rb

                        content = req_body.get("content", {})
                        if isinstance(content, dict):
                            for ctype, cobj in content.items():
                                if isinstance(cobj, dict) and "schema" in cobj:
                                    bounded = build_bounded_schema(
                                        cobj["schema"],
                                        resolver=self._resolve_local_ref,
                                    )
                                    request_schemas.append(
                                        ApiRequestSchema(
                                            endpoint_key=ep.key,
                                            content_type=ctype,
                                            fields=bounded.get("properties", {}),
                                            required_fields=bounded.get("required", []),
                                            datatype=bounded.get("type", "object"),
                                        )
                                    )

                # Response Schemas (OpenAPI 3 vs Swagger 2)
                responses = op.get("responses", {})
                if isinstance(responses, dict):
                    for status_code_str, resp_obj in responses.items():
                        if not isinstance(resp_obj, dict):
                            continue
                        if "$ref" in resp_obj and isinstance(resp_obj["$ref"], str):
                            resolved_resp = self._resolve_local_ref(resp_obj["$ref"])
                            if isinstance(resolved_resp, dict):
                                resp_obj = resolved_resp

                        try:
                            st_code = int(status_code_str)
                        except ValueError:
                            st_code = 200

                        if self.format == SpecFormat.OPENAPI:
                            rcontent = resp_obj.get("content", {})
                            if isinstance(rcontent, dict):
                                for ctype, cobj in rcontent.items():
                                    if isinstance(cobj, dict) and "schema" in cobj:
                                        bounded_resp = build_bounded_schema(
                                            cobj["schema"],
                                            resolver=self._resolve_local_ref,
                                        )
                                        response_schemas.append(
                                            ApiResponseSchema(
                                                endpoint_key=ep.key,
                                                status_code=st_code,
                                                content_type=ctype,
                                                fields=bounded_resp.get("properties", {}),
                                                datatype=bounded_resp.get("type", "object"),
                                            )
                                        )
                        elif self.format == SpecFormat.SWAGGER:
                            if "schema" in resp_obj:
                                bounded_resp = build_bounded_schema(
                                    resp_obj["schema"],
                                    resolver=self._resolve_local_ref,
                                )
                                response_schemas.append(
                                    ApiResponseSchema(
                                        endpoint_key=ep.key,
                                        status_code=st_code,
                                        content_type="application/json",
                                        fields=bounded_resp.get("properties", {}),
                                        datatype=bounded_resp.get("type", "object"),
                                    )
                                )

        spec_obs = ApiSpecification(
            url_or_path=self.spec_url,
            format=self.format.value,
            version=self.version,
            endpoint_count=len(endpoints),
            source="specification_parser",
            confidence="CONFIRMED",
            details={
                "title": self.spec_data.get("info", {}).get("title", ""),
                "description": str(self.spec_data.get("info", {}).get("description", ""))[:300],
            },
            provenance=[
                ObservationProvenance(
                    source="api_spec_parser",
                    method="document_analysis",
                    confidence="CONFIRMED",
                )
            ],
        )

        return {
            "specification": spec_obs,
            "application": api_app,
            "endpoints": endpoints,
            "parameters": parameters,
            "request_schemas": request_schemas,
            "response_schemas": response_schemas,
            "auth_observations": auth_obs,
        }


def calculate_graphql_query_depth(query_str: str) -> int:
    """
    Deterministically computes the maximum selection set nesting depth of a GraphQL query.
    Depth is defined as the maximum nested level of selection sets enclosed in braces '{ ... }',
    ignoring braces inside comments or string literals.
    """
    if query_str.strip().startswith("{") and '"query"' in query_str:
        try:
            parsed = json.loads(query_str)
            if isinstance(parsed, dict) and "query" in parsed:
                query_str = str(parsed["query"])
        except Exception:
            pass

    max_depth = 0
    current_depth = 0
    in_string = False
    in_comment = False
    escape = False

    for ch in query_str:
        if in_comment:
            if ch in ("\n", "\r"):
                in_comment = False
            continue

        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == "#":
            in_comment = True
            continue
        elif ch == '"':
            in_string = True
            continue
        elif ch == "{":
            current_depth += 1
            if current_depth > max_depth:
                max_depth = current_depth
        elif ch == "}":
            if current_depth > 0:
                current_depth -= 1

    return max_depth


# ==============================================================================
# 5. GRAPHQL ANALYZER
# ==============================================================================

class GraphQLAnalyzer:
    """Detects and analyzes GraphQL surfaces without intrusive or destructive probes."""

    MAX_INTROSPECTION_SELECTION_DEPTH: int = 6
    MAX_INTROSPECTION_SCHEMA_DEPTH: int = 3

    @staticmethod
    def calculate_query_depth(query_str: str) -> int:
        """
        Calculates the maximum selection set nesting depth ({ ... }) of a GraphQL query,
        ignoring comments and string literals.
        """
        return calculate_graphql_query_depth(query_str)

    @staticmethod
    def is_likely_graphql_endpoint(url: str, content_type: str = "", body_sample: str = "") -> bool:
        """Determines if an endpoint is likely GraphQL based on URL, headers, and body."""
        path = urlsplit(url).path.lower()
        if path.endswith(("/graphql", "/gql", "/api/graphql", "/api/v1/graphql", "/v1/graphql")):
            return True
        if "application/graphql" in content_type:
            return True
        if '"__schema"' in body_sample or ('"query"' in body_sample and '"mutation"' in body_sample):
            return True
        return False

    @staticmethod
    def create_graphql_endpoint(url: str, source: str = "detection") -> ApiEndpoint:
        """Constructs an ApiEndpoint representation for a GraphQL service."""
        canon = canonicalize_url(url)
        path = urlsplit(canon).path or "/graphql"
        return ApiEndpoint(
            canonical_url=canon,
            path_template=path,
            method="POST",
            api_style=ApiStyle.GRAPHQL.value,
            content_types=["application/json", "application/graphql"],
            response_content_types=["application/json"],
            source=source,
            confidence="PROBABLE",
            provenance=[
                ObservationProvenance(
                    source="graphql_analyzer",
                    method="endpoint_detection",
                    confidence="PROBABLE",
                )
            ],
        )

    @staticmethod
    def build_bounded_introspection_query() -> str:
        """
        Builds a safe, non-destructive, read-only GraphQL introspection query.

        Depth Metrics:
        - Selection Set Nesting Depth = 6 (query -> __schema -> types -> fields -> args -> type)
        - Schema Traversal Depth = 3 (__schema -> types -> fields, with bounded leaf args)

        Strictly read-only; queries metadata types without executing any state mutations
        or unbounded recursive fragment expansions.
        """
        return json.dumps({
            "query": """query SafeIntrospection {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args {
          name
          type { name kind }
        }
      }
    }
  }
}"""
        })

    @staticmethod
    def parse_introspection_result(
        service_url: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Parses GraphQL introspection JSON into ApiEndpoint, ApiParameter, and schema definitions.
        """
        endpoints: List[ApiEndpoint] = []
        parameters: List[ApiParameter] = []

        if not isinstance(data, dict):
            return {"endpoints": [], "parameters": []}

        schema_data = data.get("data", {}).get("__schema") if isinstance(data.get("data"), dict) else data.get("__schema")
        if not isinstance(schema_data, dict):
            return {"endpoints": [], "parameters": []}

        query_type_name = (schema_data.get("queryType") or {}).get("name", "Query") if isinstance(schema_data.get("queryType"), dict) else "Query"
        mutation_type_name = (schema_data.get("mutationType") or {}).get("name", "Mutation") if isinstance(schema_data.get("mutationType"), dict) else "Mutation"

        types_list = schema_data.get("types", [])
        if not isinstance(types_list, list):
            types_list = []

        types_by_name: Dict[str, Dict[str, Any]] = {}
        for t in types_list:
            if isinstance(t, dict) and "name" in t:
                types_by_name[t["name"]] = t

        canon_base = canonicalize_url(service_url)
        path = urlsplit(canon_base).path or "/graphql"

        for op_type, op_kind in [(query_type_name, "query"), (mutation_type_name, "mutation")]:
            type_obj = types_by_name.get(op_type)
            if not type_obj or not isinstance(type_obj.get("fields"), list):
                continue

            for field in type_obj["fields"]:
                if not isinstance(field, dict):
                    continue
                field_name = field.get("name", "")
                if not field_name or field_name.startswith("__"):
                    continue

                op_url = f"{canon_base}#{op_kind}:{field_name}"
                ep = ApiEndpoint(
                    canonical_url=op_url,
                    path_template=f"{path}#{op_kind}:{field_name}",
                    method="POST",
                    operation_id=f"{op_kind}_{field_name}",
                    api_style=ApiStyle.GRAPHQL.value,
                    source="graphql_introspection",
                    confidence="CONFIRMED",
                    provenance=[
                        ObservationProvenance(
                            source="graphql_analyzer",
                            method="introspection_schema",
                            confidence="CONFIRMED",
                        )
                    ],
                )
                endpoints.append(ep)

                args = field.get("args", [])
                if isinstance(args, list):
                    for arg in args:
                        if not isinstance(arg, dict):
                            continue
                        arg_name = arg.get("name", "")
                        if not arg_name:
                            continue
                        arg_type_info = arg.get("type", {})
                        arg_type_name = arg_type_info.get("name") or arg_type_info.get("kind") or "string"
                        parameters.append(
                            ApiParameter(
                                name=arg_name,
                                location=ParameterLocation.BODY.value,
                                datatype=str(arg_type_name).lower(),
                                endpoint_key=ep.key,
                                semantic_role=classify_parameter_role(arg_name),
                                source="graphql_introspection",
                                confidence="CONFIRMED",
                                provenance=[
                                    ObservationProvenance(
                                        source="graphql_analyzer",
                                        method="introspection_args",
                                        confidence="CONFIRMED",
                                    )
                                ],
                            )
                        )

        return {"endpoints": endpoints, "parameters": parameters}
