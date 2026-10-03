"""
Deduplication Engine for BugBounty-Agent.

Provides stable fingerprint generation for security tests and duplicate finding detection
to prevent repetitive scans and duplicate vulnerability reports.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse


def canonicalize_url_path(url_or_path: str) -> str:
    """Canonicalizes a URL or path for consistent fingerprinting."""
    if not url_or_path:
        return "/"
    clean = url_or_path.strip()
    if "://" in clean:
        parsed = urlparse(clean)
        clean = parsed.path or "/"
    # Collapse multiple slashes
    clean = re.sub(r"/{2,}", "/", clean)
    if not clean.startswith("/"):
        clean = "/" + clean
    # Strip trailing slash unless root
    if len(clean) > 1 and clean.endswith("/"):
        clean = clean[:-1]
    return clean.lower()


def canonicalize_parameter(param: str) -> str:
    """Normalizes parameter name for consistent fingerprinting."""
    if not param:
        return ""
    return param.strip().lower()


def generate_test_fingerprint(
    target: str,
    endpoint: str,
    method: str,
    parameter: Optional[str] = None,
    test_category: str = "general",
) -> str:
    """
    Generates a stable, reproducible test fingerprint.

    Fields considered:
    - Target (normalized hostname or IP)
    - Endpoint path (canonicalized)
    - HTTP method (uppercase)
    - Parameter (canonicalized, or empty string if None)
    - Test category (lowercase e.g., 'idor', 'sqli', 'cors')
    """
    norm_target = target.strip().lower() if target else ""
    norm_endpoint = canonicalize_url_path(endpoint)
    norm_method = method.strip().upper() if method else "GET"
    norm_param = canonicalize_parameter(parameter or "")
    norm_cat = test_category.strip().lower() if test_category else "general"

    components = [norm_target, norm_endpoint, norm_method, norm_param, norm_cat]
    raw_key = "|".join(components)
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


class FindingDeduplicator:
    """
    Evaluates candidate findings against previously recorded findings
    to detect duplicates across endpoints, root causes, and vulnerability classes.
    """

    @staticmethod
    def compute_finding_signature(
        affected_asset: str,
        affected_endpoint: str,
        vulnerability_type: str,
        root_cause: str,
    ) -> str:
        """
        Creates a normalized signature for finding deduplication.
        """
        asset = affected_asset.strip().lower()
        endpoint = canonicalize_url_path(affected_endpoint)
        vuln = vulnerability_type.strip().lower()
        # Normalize whitespace in root cause
        rc = re.sub(r"\s+", " ", root_cause.strip().lower())

        raw = f"{asset}|{endpoint}|{vuln}|{rc}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @classmethod
    def check_duplicate(
        cls,
        candidate_asset: str,
        candidate_endpoint: str,
        candidate_vuln: str,
        candidate_root_cause: str,
        existing_findings: List[Dict[str, Any]],
    ) -> Tuple[bool, Optional[str]]:
        """
        Determines whether candidate finding matches any existing finding.
        Returns (is_duplicate, duplicate_of_finding_id).
        """
        cand_sig = cls.compute_finding_signature(
            candidate_asset, candidate_endpoint, candidate_vuln, candidate_root_cause
        )

        cand_asset_norm = candidate_asset.strip().lower()
        cand_endpoint_norm = canonicalize_url_path(candidate_endpoint)
        cand_vuln_norm = candidate_vuln.strip().lower()

        for item in existing_findings:
            exist_id = item.get("finding_id", "unknown")
            exist_asset = item.get("affected_asset", "").strip().lower()
            exist_endpoint = canonicalize_url_path(item.get("affected_endpoint", ""))
            exist_vuln = item.get("vulnerability_type", "").strip().lower()
            exist_rc = item.get("root_cause", "")

            # Exact signature match
            exist_sig = cls.compute_finding_signature(exist_asset, exist_endpoint, exist_vuln, exist_rc)
            if cand_sig == exist_sig:
                return True, exist_id

            # Same asset, endpoint, and vulnerability class
            if (
                cand_asset_norm == exist_asset
                and cand_endpoint_norm == exist_endpoint
                and cand_vuln_norm == exist_vuln
            ):
                return True, exist_id

        return False, None
