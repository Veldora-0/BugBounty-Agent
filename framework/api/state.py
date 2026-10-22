"""
API Intelligence State Management for BugBounty-Agent.

Provides atomic, resumable, and deduplicated storage of API observations in:
~/BugBounty-Workspace/programs/<program>/state/api.json.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import tempfile
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlsplit

from framework.api.graph import ApiGraph, ApiRelationship, ApiRelationType
from framework.api.model import (
    ApiApplication,
    ApiAuthenticationObservation,
    ApiEndpoint,
    ApiParameter,
    ApiRequestSchema,
    ApiResponseSchema,
    ApiSpecification,
    ParameterUsageObservation,
)
from framework.webapp.model import canonicalize_url


class ApiStateManager:
    """
    Manages persistent local state for API security intelligence.
    Stores applications, endpoints, parameters, schemas, auth observations,
    specifications, parameter usages, and relationship graph atomically.
    """

    def __init__(self, program_dir: str):
        self.program_dir = os.path.abspath(program_dir)
        self.state_dir = os.path.join(self.program_dir, "state")
        os.makedirs(self.state_dir, exist_ok=True)
        self.api_file = os.path.join(self.state_dir, "api.json")

        self.applications: Dict[str, ApiApplication] = {}
        self.endpoints: Dict[str, ApiEndpoint] = {}
        self.parameters: Dict[str, ApiParameter] = {}
        self.request_schemas: Dict[str, ApiRequestSchema] = {}
        self.response_schemas: Dict[str, ApiResponseSchema] = {}
        self.auth_observations: Dict[str, ApiAuthenticationObservation] = {}
        self.specifications: Dict[str, ApiSpecification] = {}
        self.parameter_usages: Dict[str, ParameterUsageObservation] = {}
        self.graph = ApiGraph()

        self.processed_urls: Set[str] = set()
        self.failed_urls: Set[str] = set()

        self.metadata: Dict[str, Any] = {
            "first_run": datetime.now(timezone.utc).isoformat(),
            "last_run": datetime.now(timezone.utc).isoformat(),
            "total_applications": 0,
            "total_endpoints": 0,
            "total_parameters": 0,
            "total_specifications": 0,
            "total_auth_observations": 0,
        }

        self.load()

    def _atomic_write_json(self, filepath: str, data: Any) -> None:
        """Writes JSON data atomically using a temporary file replacement."""
        dir_name = os.path.dirname(filepath)
        with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
            json.dump(data, tf, indent=2)
            temp_path = tf.name
        os.replace(temp_path, filepath)

    def load(self) -> None:
        """Loads existing state from api.json if present."""
        if not os.path.isfile(self.api_file):
            return

        try:
            with open(self.api_file, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
        except (json.JSONDecodeError, OSError):
            return

        self.metadata = data.get("metadata", self.metadata)
        self.processed_urls = set(data.get("processed_urls", []))
        self.failed_urls = set(data.get("failed_urls", []))

        # Rehydrate Applications
        for item in data.get("applications", []):
            app = ApiApplication.from_dict(item)
            self.applications[app.key] = app

        # Rehydrate Endpoints
        raw_eps = data.get("endpoints", [])
        eps_list = raw_eps.values() if isinstance(raw_eps, dict) else (raw_eps if isinstance(raw_eps, list) else [])
        for item in eps_list:
            if isinstance(item, dict):
                ep = ApiEndpoint.from_dict(item)
                self.endpoints[ep.key] = ep
            elif isinstance(item, str):
                ep = ApiEndpoint(canonical_url=item, path_template=urlsplit(item).path)
                self.endpoints[ep.key] = ep

        # Rehydrate Parameters
        for item in data.get("parameters", []):
            if isinstance(item, dict):
                p = ApiParameter.from_dict(item)
                self.parameters[p.key] = p

        # Legacy catalog support: if endpoints empty, rehydrate from catalog dictionary
        if not self.endpoints and "catalog" in data and isinstance(data["catalog"], dict):
            for path_k, ep_info in data["catalog"].items():
                if not isinstance(ep_info, dict):
                    continue
                base_u = ep_info.get("url") or path_k
                for op in ep_info.get("operations", []):
                    if not isinstance(op, dict):
                        continue
                    m = op.get("method", "GET").upper()
                    ep_obj = ApiEndpoint(
                        canonical_url=op.get("url") or base_u,
                        path_template=path_k,
                        method=m,
                        operation_id=op.get("operation_id"),
                        auth_required=bool(op.get("auth_required", False)),
                        auth_scheme=op.get("auth_scheme"),
                    )
                    self.endpoints[ep_obj.key] = ep_obj
                    for p_data in op.get("parameters", []):
                        if isinstance(p_data, dict):
                            param_obj = ApiParameter.from_dict(p_data)
                            param_obj.endpoint_key = ep_obj.key
                            self.parameters[param_obj.key] = param_obj

        # Rehydrate Schemas
        for item in data.get("request_schemas", []):
            rs = ApiRequestSchema.from_dict(item)
            self.request_schemas[rs.key] = rs

        for item in data.get("response_schemas", []):
            rps = ApiResponseSchema.from_dict(item)
            self.response_schemas[rps.key] = rps

        # Rehydrate Auth Observations
        for item in data.get("auth_observations", []):
            ao = ApiAuthenticationObservation.from_dict(item)
            self.auth_observations[ao.key] = ao

        # Rehydrate Specifications
        for item in data.get("specifications", []):
            sp = ApiSpecification.from_dict(item)
            self.specifications[sp.key] = sp

        # Rehydrate Parameter Usages
        for item in data.get("parameter_usages", []):
            pu = ParameterUsageObservation.from_dict(item)
            self.parameter_usages[pu.key] = pu

        # Rehydrate Graph
        self.graph = ApiGraph.from_dict(data.get("graph", []))

    def save(self) -> None:
        """Saves current state atomically to api.json with full backward compatibility."""
        self.metadata["last_run"] = datetime.now(timezone.utc).isoformat()
        self.metadata["total_applications"] = len(self.applications)
        self.metadata["total_endpoints"] = len(self.endpoints)
        self.metadata["total_parameters"] = len(self.parameters)
        self.metadata["total_specifications"] = len(self.specifications)
        self.metadata["total_auth_observations"] = len(self.auth_observations)

        # Build backward-compatible catalog dictionary for authz and ssrf consumers
        catalog: Dict[str, Dict[str, Any]] = {}
        endpoints_export: List[Dict[str, Any]] = []

        for ep in sorted(self.endpoints.values(), key=lambda x: x.key):
            ep_params = [p.to_dict() for p in self.get_parameters_for_endpoint(ep.key)]
            d = ep.to_dict()
            d["parameters"] = ep_params
            endpoints_export.append(d)

            path_key = ep.path_template
            if path_key not in catalog:
                catalog[path_key] = {
                    "url": ep.canonical_url,
                    "path": ep.path_template,
                    "operations": [],
                }
            catalog[path_key]["operations"].append({
                "method": ep.method.upper(),
                "url": ep.canonical_url,
                "path": ep.path_template,
                "operation_id": ep.operation_id,
                "auth_required": ep.auth_required,
                "auth_scheme": ep.auth_scheme,
                "parameters": ep_params,
            })

        export_data = {
            "metadata": self.metadata,
            "processed_urls": sorted(list(self.processed_urls)),
            "failed_urls": sorted(list(self.failed_urls)),
            "catalog": catalog,
            "applications": [a.to_dict() for a in sorted(self.applications.values(), key=lambda x: x.key)],
            "endpoints": endpoints_export,
            "parameters": [p.to_dict() for p in sorted(self.parameters.values(), key=lambda x: x.key)],
            "request_schemas": [s.to_dict() for s in sorted(self.request_schemas.values(), key=lambda x: x.key)],
            "response_schemas": [s.to_dict() for s in sorted(self.response_schemas.values(), key=lambda x: x.key)],
            "auth_observations": [ao.to_dict() for ao in sorted(self.auth_observations.values(), key=lambda x: x.key)],
            "specifications": [sp.to_dict() for sp in sorted(self.specifications.values(), key=lambda x: x.key)],
            "parameter_usages": [pu.to_dict() for pu in sorted(self.parameter_usages.values(), key=lambda x: x.key)],
            "graph": self.graph.to_dict(),
        }
        self._atomic_write_json(self.api_file, export_data)

    def is_processed(self, url: str) -> bool:
        """Checks if a URL has already been processed."""
        return canonicalize_url(url) in self.processed_urls

    def mark_processed(self, url: str) -> None:
        self.processed_urls.add(canonicalize_url(url))

    def mark_failed(self, url: str) -> None:
        self.failed_urls.add(canonicalize_url(url))

    # ---------------- Add & Merge Observations ----------------

    def add_application(self, app: ApiApplication) -> bool:
        key = app.key
        if key in self.applications:
            existing = self.applications[key]
            for tech in app.technologies:
                if tech not in existing.technologies:
                    existing.technologies.append(tech)
            for p in app.provenance:
                existing.provenance.append(p)
            return False
        self.applications[key] = app
        return True

    def add_endpoint(self, ep: ApiEndpoint) -> bool:
        """Inserts or merges an endpoint with multi-source correlation."""
        key = ep.key
        if key in self.endpoints:
            existing = self.endpoints[key]
            # Merge observed URLs
            for u in ep.observed_urls:
                if u not in existing.observed_urls:
                    existing.observed_urls.append(u)
            # Merge content types
            for ct in ep.content_types:
                if ct not in existing.content_types:
                    existing.content_types.append(ct)
            for rct in ep.response_content_types:
                if rct not in existing.response_content_types:
                    existing.response_content_types.append(rct)
            # Upgrade confidence if new observation is higher
            if ep.confidence == "CONFIRMED":
                existing.confidence = "CONFIRMED"
            elif ep.confidence == "PROBABLE" and existing.confidence == "OBSERVED":
                existing.confidence = "PROBABLE"
            # Update operation ID or auth requirement if newly discovered
            if not existing.operation_id and ep.operation_id:
                existing.operation_id = ep.operation_id
            if ep.auth_required:
                existing.auth_required = True
            if not existing.auth_scheme and ep.auth_scheme:
                existing.auth_scheme = ep.auth_scheme
            # Append provenance
            for p in ep.provenance:
                existing.provenance.append(p)
            return False
        else:
            self.endpoints[key] = ep
            return True

    def add_parameter(self, param: ApiParameter) -> bool:
        """Inserts or merges parameter intelligence."""
        key = param.key
        if key in self.parameters:
            existing = self.parameters[key]
            if not existing.default_value and param.default_value:
                existing.default_value = param.default_value
            for ev in param.enum_values:
                if ev not in existing.enum_values:
                    existing.enum_values.append(ev)
            if existing.datatype == "string" and param.datatype != "string":
                existing.datatype = param.datatype
            if existing.semantic_role == "generic" and param.semantic_role != "generic":
                existing.semantic_role = param.semantic_role
            if param.confidence == "CONFIRMED":
                existing.confidence = "CONFIRMED"
            for p in param.provenance:
                existing.provenance.append(p)
            return False
        else:
            self.parameters[key] = param
            return True

    def add_request_schema(self, rs: ApiRequestSchema) -> bool:
        key = rs.key
        if key in self.request_schemas:
            existing = self.request_schemas[key]
            existing.fields.update(rs.fields)
            for rf in rs.required_fields:
                if rf not in existing.required_fields:
                    existing.required_fields.append(rf)
            return False
        self.request_schemas[key] = rs
        return True

    def add_response_schema(self, rps: ApiResponseSchema) -> bool:
        key = rps.key
        if key in self.response_schemas:
            self.response_schemas[key].fields.update(rps.fields)
            return False
        self.response_schemas[key] = rps
        return True

    def add_auth_observation(self, ao: ApiAuthenticationObservation) -> bool:
        key = ao.key
        if key in self.auth_observations:
            for p in ao.provenance:
                self.auth_observations[key].provenance.append(p)
            return False
        self.auth_observations[key] = ao
        return True

    def add_specification(self, spec: ApiSpecification) -> bool:
        key = spec.key
        if key in self.specifications:
            existing = self.specifications[key]
            existing.endpoint_count = max(existing.endpoint_count, spec.endpoint_count)
            for p in spec.provenance:
                existing.provenance.append(p)
            return False
        self.specifications[key] = spec
        return True

    def add_parameter_usage(self, pu: ParameterUsageObservation) -> bool:
        key = pu.key
        if key in self.parameter_usages:
            return False
        self.parameter_usages[key] = pu
        return True

    # ---------------- Query Methods ----------------

    def get_endpoints(self) -> List[ApiEndpoint]:
        """
        Returns list of all ApiEndpoint models with associated parameters attached.
        Provides seamless backward compatibility for validation and authorization consumers.
        """
        result: List[ApiEndpoint] = []
        for ep in self.endpoints.values():
            ep.parameters = self.get_parameters_for_endpoint(ep.key)
            result.append(ep)
        return result

    def get_endpoints_for_domain(self, domain: str) -> List[ApiEndpoint]:
        """Filters endpoints whose host matches or ends with domain."""
        results = []
        clean_d = domain.lower()
        for ep in self.endpoints.values():
            host = urlsplit(ep.canonical_url).hostname or ""
            if host == clean_d or host.endswith(f".{clean_d}"):
                results.append(ep)
        return results

    def get_parameters_for_endpoint(self, endpoint_key: str) -> List[ApiParameter]:
        """Returns all parameters associated with a specific endpoint key."""
        return [p for p in self.parameters.values() if p.endpoint_key == endpoint_key]
