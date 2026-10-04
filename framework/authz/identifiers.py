"""
Object Identifier Intelligence for BugBounty-Agent Authorization Subsystem.

Discovers, classifies, and models candidate resource object identifiers across
API templates, web application endpoints, and JavaScript routes.
Assigns confidence without falsely declaring every identifier an IDOR vulnerability.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlparse

from framework.authz.model import ResourceAccessTarget


# Common parameter names that reference identifiable domain objects
DOMAIN_OBJECT_PARAM_NAMES: Set[str] = {
    "id", "user_id", "userid", "account_id", "accountid", "customer_id", "customerid",
    "order_id", "orderid", "document_id", "documentid", "invoice_id", "invoiceid",
    "file_id", "fileid", "project_id", "projectid", "tenant_id", "tenantid",
    "org_id", "organization_id", "resource_id", "resourceid", "item_id", "itemid",
    "member_id", "memberid", "profile_id", "profileid", "ticket_id", "ticketid",
    "report_id", "reportid", "message_id", "messageid", "transaction_id", "cart_id",
}

# Regex patterns for matching UUIDs and numeric IDs in path segments
UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
NUMERIC_ID_PATTERN = re.compile(r"^[1-9][0-9]{0,18}$")
SLUG_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]+$")

# Resource entity keyword inference from path
RESOURCE_PATH_KEYWORDS = re.compile(
    r"/(?:api/v[0-9]+/)?([a-zA-Z0-9_-]+)/(?:\{[^}]+\}|:[a-zA-Z0-9_-]+|<[^>]+>|[0-9]+|[0-9a-f-]{36})",
    re.IGNORECASE,
)


class ObjectIdentifierAnalyzer:
    """
    Analyzes API endpoints, URLs, and parameter schemas to identify
    potential authorization candidate resources.
    """

    @classmethod
    def classify_identifier_type(cls, val: str) -> str:
        """Determines syntactic format of identifier value."""
        s = str(val).strip()
        if UUID_PATTERN.match(s):
            return "UUID"
        if NUMERIC_ID_PATTERN.match(s):
            return "NUMERIC"
        if len(s) in (32, 40, 64) and re.match(r"^[0-9a-fA-F]+$", s):
            return "OPAQUE"
        if SLUG_PATTERN.match(s):
            return "SLUG"
        return "UNKNOWN"

    @classmethod
    def infer_resource_type(cls, endpoint_or_url: str, param_name: Optional[str] = None) -> str:
        """Infers domain entity type from endpoint route or parameter name."""
        if param_name:
            clean_p = param_name.lower().replace("_id", "").replace("id", "")
            if clean_p and clean_p not in ("param", "query"):
                return clean_p

        match = RESOURCE_PATH_KEYWORDS.search(endpoint_or_url)
        if match:
            entity = match.group(1).lower()
            if entity.endswith("s") and len(entity) > 3:
                return entity[:-1]  # Singularize e.g. users -> user
            return entity

        # Default fallback to last path segment
        parts = [p for p in urlparse(endpoint_or_url).path.split("/") if p and not p.startswith("v")]
        if parts:
            return parts[-1].lower()

        return "resource"

    @classmethod
    def extract_from_endpoint(
        cls,
        endpoint_url: str,
        method: str = "GET",
        parameters: Optional[List[Dict[str, Any] | str]] = None,
        tenant_id: Optional[str] = None,
        owner_principal_id: Optional[str] = None,
    ) -> List[ResourceAccessTarget]:
        """
        Analyzes a single endpoint URL and parameters to produce candidate targets.
        """
        targets: List[ResourceAccessTarget] = []
        parsed = urlparse(endpoint_url)
        path = parsed.path

        # 1. Path-based identification: check path segments for templates or IDs
        path_segments = [s for s in path.split("/") if s]
        for idx, seg in enumerate(path_segments):
            # Check template: {id}, :id, <id>
            is_template = (seg.startswith("{") and seg.endswith("}")) or seg.startswith(":") or (seg.startswith("<") and seg.endswith(">"))
            id_type = cls.classify_identifier_type(seg)

            if is_template or id_type in ("NUMERIC", "UUID"):
                # Infer entity name from preceding segment if available
                res_type = path_segments[idx - 1] if idx > 0 else "resource"
                if res_type.endswith("s") and len(res_type) > 3:
                    res_type = res_type[:-1]

                clean_val = seg.strip("{}<>:").strip()
                targets.append(
                    ResourceAccessTarget(
                        resource_id=clean_val,
                        resource_type=res_type.lower(),
                        endpoint=endpoint_url,
                        method=method,
                        tenant_id=tenant_id,
                        owner_principal_id=owner_principal_id,
                        param_location="PATH",
                        identifier_type=id_type if not is_template else "TEMPLATE",
                        confidence="HIGH" if is_template or id_type in ("NUMERIC", "UUID") else "MEDIUM",
                        provenance={"path_index": idx, "segment": seg},
                    )
                )

        # 2. Query parameter identification
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        for p_name, p_val in query_pairs:
            p_lower = p_name.lower()
            if p_lower in DOMAIN_OBJECT_PARAM_NAMES or p_lower.endswith("_id"):
                id_type = cls.classify_identifier_type(p_val) if p_val else "QUERY_ID"
                res_type = cls.infer_resource_type(endpoint_url, p_name)
                targets.append(
                    ResourceAccessTarget(
                        resource_id=p_val or "1",
                        resource_type=res_type,
                        endpoint=endpoint_url,
                        method=method,
                        tenant_id=tenant_id,
                        owner_principal_id=owner_principal_id,
                        param_location="QUERY",
                        identifier_type=id_type,
                        confidence="HIGH" if p_lower in DOMAIN_OBJECT_PARAM_NAMES else "MEDIUM",
                        provenance={"param_name": p_name},
                    )
                )

        # 3. Explicit parameters list (e.g. from API intelligence schema)
        if parameters:
            for p in parameters:
                p_dict = p if isinstance(p, dict) else {"name": str(p)}
                name = p_dict.get("name", "")
                name_lower = name.lower()
                loc = p_dict.get("location", "QUERY").upper()
                if name_lower in DOMAIN_OBJECT_PARAM_NAMES or name_lower.endswith("_id"):
                    # Check if already added
                    if not any(t.param_location == loc and t.resource_type == cls.infer_resource_type(endpoint_url, name) for t in targets):
                        targets.append(
                            ResourceAccessTarget(
                                resource_id="1",
                                resource_type=cls.infer_resource_type(endpoint_url, name),
                                endpoint=endpoint_url,
                                method=method,
                                tenant_id=tenant_id,
                                owner_principal_id=owner_principal_id,
                                param_location=loc,
                                identifier_type="PARAM_SCHEMA",
                                confidence="HIGH",
                                provenance={"schema_param": name},
                            )
                        )

        return targets

    @classmethod
    def scan_api_state(cls, api_endpoints: List[Dict[str, Any]]) -> List[ResourceAccessTarget]:
        """
        Scans a list of endpoint dictionaries from Phase 5 API intelligence.
        """
        all_targets: List[ResourceAccessTarget] = []
        for ep in api_endpoints:
            url = ep.get("canonical_url") or ep.get("url") or ep.get("path") or ""
            method = ep.get("method", "GET")
            params = ep.get("parameters", [])
            extracted = cls.extract_from_endpoint(url, method=method, parameters=params)
            all_targets.extend(extracted)
        return all_targets
