"""
Scope management package for BugBounty-Agent.
"""

from framework.scope.engine import ScopeDecision, ScopeEngine, ScopeStatus
from framework.scope.normalizer import (
    NormalizationError,
    calculate_subdomain_depth,
    is_dns_label_descendant,
    is_valid_cidr,
    is_valid_ip,
    normalize_hostname,
    normalize_url,
    parse_and_normalize_target,
)

__all__ = [
    "ScopeEngine",
    "ScopeDecision",
    "ScopeStatus",
    "NormalizationError",
    "calculate_subdomain_depth",
    "is_dns_label_descendant",
    "is_valid_cidr",
    "is_valid_ip",
    "normalize_hostname",
    "normalize_url",
    "parse_and_normalize_target",
]
