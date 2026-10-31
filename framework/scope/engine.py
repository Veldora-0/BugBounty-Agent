"""
Scope Engine for BugBounty-Agent.

Enforces strict authorization boundaries, recursion controls, exclusion precedence,
and provenance tracking. Never silently assumes authorization.
"""

from __future__ import annotations

from enum import Enum
import ipaddress
import os
import posixpath
from typing import Any, Dict, List, Optional, Union
from urllib.parse import parse_qsl, unquote, urlparse
import yaml

from framework.scope.normalizer import (
    calculate_subdomain_depth,
    is_dns_label_descendant,
    is_valid_cidr,
    is_valid_ip,
    normalize_hostname,
    normalize_url,
    parse_and_normalize_target,
    NormalizationError,
)


class ScopeConfigurationError(ValueError):
    """Raised when scope configuration contains invalid syntax, schema, or values."""
    pass


class ScopeStatus(str, Enum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    AMBIGUOUS = "AMBIGUOUS"


class ScopeDecision:
    """Represents a definitive scope evaluation decision with provenance."""

    def __init__(
        self,
        status: ScopeStatus,
        reason: str,
        target: str,
        normalized_target: str,
        root_domain: Optional[str] = None,
        parent: Optional[str] = None,
        depth: Optional[int] = None,
        matched_rule: Optional[str] = None,
        rule_category: Optional[str] = None,
    ):
        self.status = status
        self.reason = reason
        self.target = target
        self.normalized_target = normalized_target
        self.root_domain = root_domain
        self.parent = parent
        self.depth = depth
        self.matched_rule = matched_rule
        self.rule_category = rule_category

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "target": self.target,
            "normalized_target": self.normalized_target,
            "scope_status": self.status.value,
            "reason": self.reason,
            "matched_rule": self.matched_rule,
            "rule_category": self.rule_category,
        }
        if self.root_domain is not None:
            result["root_domain"] = self.root_domain
        if self.parent is not None:
            result["parent"] = self.parent
        if self.depth is not None:
            result["depth"] = self.depth
        return result

    def __repr__(self) -> str:
        return f"<ScopeDecision status={self.status.value} target='{self.target}' reason='{self.reason}'>"


class ScopeEngine:
    """
    Evaluates targets against program scope definition.
    Precedence:
      1. Explicit Exclusion (domains, subdomains, URLs, CIDRs)
      2. Specific Exact Inclusion (exact domains, exact URLs, specific IPs)
      3. Wildcard / Recursive Inclusion (subject to max_depth)
      4. Ambiguous / Unmatched -> OUT_OF_SCOPE or AMBIGUOUS
    """

    def __init__(self, scope_config: Dict[str, Any]):
        if not isinstance(scope_config, dict):
            raise ScopeConfigurationError(f"Scope configuration must be a dictionary, got {type(scope_config).__name__}")
        self.config = scope_config

        prog = self.config.get("program")
        if prog is not None and not isinstance(prog, dict):
            raise ScopeConfigurationError(f"'program' section must be a dictionary, got {type(prog).__name__}")
        self.program_name = self.config.get("program", {}).get("name", "unnamed-program")

        # Inclusions
        targets = self.config.get("targets") or {}
        if not isinstance(targets, dict):
            raise ScopeConfigurationError(f"'targets' section must be a dictionary, got {type(targets).__name__}")

        for key in ("domains", "urls", "cidrs"):
            val = targets.get(key)
            if val is not None and not isinstance(val, list):
                raise ScopeConfigurationError(f"targets.{key} must be a list, got {type(val).__name__}")

        self.included_domains: List[str] = [str(d) for d in targets.get("domains", [])]
        self.included_urls: List[str] = [str(u) for u in targets.get("urls", [])]
        self.included_cidrs: List[str] = [str(c) for c in targets.get("cidrs", [])]

        # Recursive subdomain configuration
        rec_conf = targets.get("recursive_subdomains") or {}
        if not isinstance(rec_conf, dict):
            raise ScopeConfigurationError(f"targets.recursive_subdomains must be a dictionary, got {type(rec_conf).__name__}")
        self.recursive_enabled: bool = bool(rec_conf.get("enabled", False))
        # max_depth: 0 means unlimited
        self.max_depth: int = int(rec_conf.get("max_depth", 0))

        # Exclusions (Explicit Out-of-Scope)
        oos = self.config.get("out_of_scope") or {}
        if not isinstance(oos, dict):
            raise ScopeConfigurationError(f"'out_of_scope' section must be a dictionary, got {type(oos).__name__}")

        for key in ("domains", "urls", "cidrs"):
            val = oos.get(key)
            if val is not None and not isinstance(val, list):
                raise ScopeConfigurationError(f"out_of_scope.{key} must be a list, got {type(val).__name__}")

        self.excluded_domains: List[str] = [str(d) for d in oos.get("domains", [])]
        self.excluded_urls: List[str] = [str(u) for u in oos.get("urls", [])]
        self.excluded_cidrs: List[str] = [str(c) for c in oos.get("cidrs", [])]

        self._preprocess_rules()

    @classmethod
    def from_file(cls, filepath: str) -> ScopeEngine:
        """Loads scope configuration from a YAML or JSON file."""
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Scope configuration file not found: {filepath}")

        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        return cls(data or {})

    def _preprocess_rules(self) -> None:
        """Normalizes and indexes inclusion and exclusion rules."""
        # Process exclusions
        self._parsed_excluded_domains = []
        for d in self.excluded_domains:
            if not isinstance(d, str) or not d.strip():
                raise ScopeConfigurationError(f"Malformed domain in out_of_scope.domains: {d!r}")
            try:
                norm = normalize_hostname(d)
                clean = norm[2:] if norm.startswith("*.") else norm
                self._parsed_excluded_domains.append((norm, clean, norm.startswith("*.")))
            except Exception as e:
                raise ScopeConfigurationError(f"Invalid domain in out_of_scope.domains: {d!r} ({e})") from e

        self._parsed_excluded_urls = []
        for u in self.excluded_urls:
            if not isinstance(u, str) or not u.strip():
                raise ScopeConfigurationError(f"Malformed URL in out_of_scope.urls: {u!r}")
            try:
                self._parsed_excluded_urls.append(normalize_url(u))
            except Exception as e:
                raise ScopeConfigurationError(f"Invalid URL in out_of_scope.urls: {u!r} ({e})") from e

        self._parsed_excluded_networks = []
        for c in self.excluded_cidrs:
            if not isinstance(c, str) or not c.strip():
                raise ScopeConfigurationError(f"Malformed CIDR in out_of_scope.cidrs: {c!r}")
            try:
                self._parsed_excluded_networks.append(ipaddress.ip_network(c.strip(), strict=False))
            except Exception as e:
                raise ScopeConfigurationError(f"Invalid CIDR in out_of_scope.cidrs: {c!r} ({e})") from e

        # Process inclusions
        self._parsed_included_domains = []
        for d in self.included_domains:
            if not isinstance(d, str) or not d.strip():
                raise ScopeConfigurationError(f"Malformed domain in targets.domains: {d!r}")
            try:
                norm = normalize_hostname(d)
                clean = norm[2:] if norm.startswith("*.") else norm
                is_wildcard = norm.startswith("*.")
                self._parsed_included_domains.append((norm, clean, is_wildcard))
            except Exception as e:
                raise ScopeConfigurationError(f"Invalid domain in targets.domains: {d!r} ({e})") from e

        self._parsed_included_urls = []
        for u in self.included_urls:
            if not isinstance(u, str) or not u.strip():
                raise ScopeConfigurationError(f"Malformed URL in targets.urls: {u!r}")
            try:
                self._parsed_included_urls.append(normalize_url(u))
            except Exception as e:
                raise ScopeConfigurationError(f"Invalid URL in targets.urls: {u!r} ({e})") from e

        self._parsed_included_networks = []
        for c in self.included_cidrs:
            if not isinstance(c, str) or not c.strip():
                raise ScopeConfigurationError(f"Malformed CIDR in targets.cidrs: {c!r}")
            try:
                self._parsed_included_networks.append(ipaddress.ip_network(c.strip(), strict=False))
            except Exception as e:
                raise ScopeConfigurationError(f"Invalid CIDR in targets.cidrs: {c!r} ({e})") from e

    def is_in_scope(self, target: str) -> bool:
        """Returns True if the target evaluates strictly to IN_SCOPE."""
        decision = self.check(target)
        return decision.status == ScopeStatus.IN_SCOPE

    def check(self, target: str) -> ScopeDecision:
        """
        Main scope evaluation entrypoint.
        Checks target against the configured scope rules.
        """
        if not target or not isinstance(target, str):
            return ScopeDecision(
                status=ScopeStatus.AMBIGUOUS,
                reason="Target must be a non-empty string.",
                target=str(target),
                normalized_target="",
            )

        try:
            parsed = parse_and_normalize_target(target)
        except NormalizationError as e:
            return ScopeDecision(
                status=ScopeStatus.AMBIGUOUS,
                reason=f"Target normalization failed: {str(e)}",
                target=target,
                normalized_target="",
            )

        target_type = parsed["type"]

        if target_type == "URL":
            return self._check_url(parsed)
        elif target_type in ("IP", "CIDR"):
            return self._check_ip_or_cidr(parsed)
        elif target_type == "DOMAIN":
            return self._check_domain(parsed)
        else:
            return ScopeDecision(
                status=ScopeStatus.AMBIGUOUS,
                reason=f"Unrecognized target type: {target_type}",
                target=target,
                normalized_target=parsed.get("normalized", ""),
            )

    @staticmethod
    def _is_url_path_contained(target_url: str, rule_url: str) -> bool:
        """
        Determines if target_url matches or is contained under rule_url.
        Enforces strict scheme, host, port, canonical path containment, and query constraints:
        - Path decomposition with posixpath.normpath(unquote(...))
        - Strict directory hierarchy (/api matches /api, /api/, /api/users, but NOT /api-v2 or /api2)
        - Matrix parameter (;) and traversal (..) normalization
        - Query parameters ignored unless rule explicitly specifies them
        """
        t_parsed = urlparse(target_url)
        r_parsed = urlparse(rule_url)

        if t_parsed.scheme.lower() != r_parsed.scheme.lower():
            return False
        if t_parsed.netloc.lower() != r_parsed.netloc.lower():
            return False

        t_raw_path = t_parsed.path.split(";")[0] if t_parsed.path else "/"
        r_raw_path = r_parsed.path.split(";")[0] if r_parsed.path else "/"

        t_path = posixpath.normpath(unquote(t_raw_path))
        r_path = posixpath.normpath(unquote(r_raw_path))

        if not t_path.startswith("/"):
            t_path = "/" + t_path.lstrip("/")
        if not r_path.startswith("/"):
            r_path = "/" + r_path.lstrip("/")

        if r_path == "/":
            path_matches = True
        elif t_path == r_path or t_path.startswith(r_path.rstrip("/") + "/"):
            path_matches = True
        else:
            path_matches = False

        if not path_matches:
            return False

        if r_parsed.query:
            r_params = set(parse_qsl(r_parsed.query, keep_blank_values=True))
            t_params = set(parse_qsl(t_parsed.query, keep_blank_values=True))
            if not r_params.issubset(t_params):
                return False

        return True

    def _check_url(self, parsed: Dict[str, Any]) -> ScopeDecision:
        """Evaluates a URL target."""
        norm_url = parsed["normalized"]
        hostname = parsed["hostname"]

        # 1. Check explicit URL exclusions
        for ex_url in self._parsed_excluded_urls:
            if self._is_url_path_contained(norm_url, ex_url):
                return ScopeDecision(
                    status=ScopeStatus.OUT_OF_SCOPE,
                    reason=f"Matches explicit excluded URL: {ex_url}",
                    target=parsed["raw"],
                    normalized_target=norm_url,
                    matched_rule=ex_url,
                    rule_category="EXPLICIT_EXCLUSION_URL",
                )

        # 2. Check if the URL's host is explicitly excluded
        if hostname:
            for ex_norm, ex_clean, _ in self._parsed_excluded_domains:
                if is_dns_label_descendant(hostname, ex_clean):
                    return ScopeDecision(
                        status=ScopeStatus.OUT_OF_SCOPE,
                        reason=f"URL host '{hostname}' matches explicit exclusion: {ex_norm}",
                        target=parsed["raw"],
                        normalized_target=norm_url,
                        matched_rule=ex_norm,
                        rule_category="EXPLICIT_EXCLUSION_HOST",
                    )
            # If hostname is an IP, check excluded networks
            if is_valid_ip(hostname):
                ip_obj = ipaddress.ip_address(hostname)
                for net in self._parsed_excluded_networks:
                    if ip_obj in net:
                        return ScopeDecision(
                            status=ScopeStatus.OUT_OF_SCOPE,
                            reason=f"URL host IP '{hostname}' falls within excluded CIDR: {net}",
                            target=parsed["raw"],
                            normalized_target=norm_url,
                            matched_rule=str(net),
                            rule_category="EXPLICIT_EXCLUSION_CIDR",
                        )

        # 3. Check explicit URL inclusions
        for inc_url in self._parsed_included_urls:
            if self._is_url_path_contained(norm_url, inc_url):
                return ScopeDecision(
                    status=ScopeStatus.IN_SCOPE,
                    reason=f"Matches included URL: {inc_url}",
                    target=parsed["raw"],
                    normalized_target=norm_url,
                    matched_rule=inc_url,
                    rule_category="SPECIFIC_INCLUSION_URL",
                )

        # 4. If URL host is in scope via domain/IP rules, URL inherits host scope
        if hostname:
            host_decision = self.check(hostname)
            if host_decision.status == ScopeStatus.IN_SCOPE:
                return ScopeDecision(
                    status=ScopeStatus.IN_SCOPE,
                    reason=f"URL host '{hostname}' is in scope ({host_decision.reason})",
                    target=parsed["raw"],
                    normalized_target=norm_url,
                    root_domain=host_decision.root_domain,
                    parent=host_decision.parent,
                    depth=host_decision.depth,
                    matched_rule=host_decision.matched_rule,
                    rule_category=host_decision.rule_category,
                )
            elif host_decision.status == ScopeStatus.AMBIGUOUS:
                return ScopeDecision(
                    status=ScopeStatus.AMBIGUOUS,
                    reason=f"URL host '{hostname}' scope is ambiguous: {host_decision.reason}",
                    target=parsed["raw"],
                    normalized_target=norm_url,
                )

        return ScopeDecision(
            status=ScopeStatus.OUT_OF_SCOPE,
            reason="URL does not match any authorized scope inclusion.",
            target=parsed["raw"],
            normalized_target=norm_url,
        )

    def _check_ip_or_cidr(self, parsed: Dict[str, Any]) -> ScopeDecision:
        """Evaluates an IP address or CIDR network target."""
        raw = parsed["raw"]
        norm = parsed["normalized"]

        if parsed["type"] == "IP":
            ip_obj = parsed["ip"]

            # Check excluded CIDRs
            for net in self._parsed_excluded_networks:
                if ip_obj in net:
                    return ScopeDecision(
                        status=ScopeStatus.OUT_OF_SCOPE,
                        reason=f"IP {ip_obj} falls within excluded CIDR: {net}",
                        target=raw,
                        normalized_target=norm,
                        matched_rule=str(net),
                        rule_category="EXPLICIT_EXCLUSION_CIDR",
                    )

            # Check included CIDRs
            for net in self._parsed_included_networks:
                if ip_obj in net:
                    return ScopeDecision(
                        status=ScopeStatus.IN_SCOPE,
                        reason=f"IP {ip_obj} falls within authorized CIDR: {net}",
                        target=raw,
                        normalized_target=norm,
                        matched_rule=str(net),
                        rule_category="SPECIFIC_INCLUSION_CIDR",
                    )

        elif parsed["type"] == "CIDR":
            net_obj = parsed["network"]

            # Check if any excluded CIDR overlaps or encloses this CIDR
            for ex_net in self._parsed_excluded_networks:
                if net_obj.overlaps(ex_net):
                    return ScopeDecision(
                        status=ScopeStatus.OUT_OF_SCOPE,
                        reason=f"CIDR {net_obj} overlaps with excluded CIDR: {ex_net}",
                        target=raw,
                        normalized_target=norm,
                        matched_rule=str(ex_net),
                        rule_category="EXPLICIT_EXCLUSION_CIDR",
                    )

            # Check if included CIDR encloses this CIDR
            for inc_net in self._parsed_included_networks:
                if net_obj.subnet_of(inc_net):
                    return ScopeDecision(
                        status=ScopeStatus.IN_SCOPE,
                        reason=f"CIDR {net_obj} is contained within authorized CIDR: {inc_net}",
                        target=raw,
                        normalized_target=norm,
                        matched_rule=str(inc_net),
                        rule_category="SPECIFIC_INCLUSION_CIDR",
                    )

        return ScopeDecision(
            status=ScopeStatus.OUT_OF_SCOPE,
            reason="IP/CIDR does not match any authorized scope inclusion.",
            target=raw,
            normalized_target=norm,
        )

    def _check_domain(self, parsed: Dict[str, Any]) -> ScopeDecision:
        """
        Evaluates a domain or hostname against scope.
        Applies strict DNS-label boundary verification, recursive depth evaluation,
        and exclusion precedence.
        """
        raw = parsed["raw"]
        norm_host = parsed["normalized"]
        clean_target = parsed["clean_host"]

        # STEP 1: PRECEDENCE 1 - EXPLICIT EXCLUSIONS
        # Any exact match or subdomain descendant of an excluded domain is OUT_OF_SCOPE.
        for ex_norm, ex_clean, ex_wildcard in self._parsed_excluded_domains:
            if is_dns_label_descendant(clean_target, ex_clean):
                return ScopeDecision(
                    status=ScopeStatus.OUT_OF_SCOPE,
                    reason=f"Host matches or is descendant of explicit exclusion: {ex_norm}",
                    target=raw,
                    normalized_target=norm_host,
                    matched_rule=ex_norm,
                    rule_category="EXPLICIT_EXCLUSION_DOMAIN",
                )

        # STEP 2: PRECEDENCE 2 - SPECIFIC / EXACT INCLUSIONS
        for inc_norm, inc_clean, is_wildcard in self._parsed_included_domains:
            if not is_wildcard and clean_target == inc_clean:
                return ScopeDecision(
                    status=ScopeStatus.IN_SCOPE,
                    reason=f"Exact match on authorized target domain: {inc_norm}",
                    target=raw,
                    normalized_target=norm_host,
                    root_domain=inc_clean,
                    parent=None,
                    depth=0,
                    matched_rule=inc_norm,
                    rule_category="EXACT_INCLUSION",
                )

        # STEP 3: PRECEDENCE 3 - WILDCARD & RECURSIVE SUBDOMAIN INCLUSIONS
        # Check every authorized root domain
        matched_candidates = []
        for inc_norm, inc_clean, is_wildcard in self._parsed_included_domains:
            # Does the target qualify as a valid DNS descendant?
            if is_dns_label_descendant(clean_target, inc_clean):
                depth, parent = calculate_subdomain_depth(clean_target, inc_clean)

                if depth == 0:
                    # Matches the root domain itself
                    matched_candidates.append({
                        "root_domain": inc_clean,
                        "depth": 0,
                        "parent": None,
                        "rule": inc_norm,
                        "is_wildcard": is_wildcard,
                        "allowed": True,
                        "reason": "Root domain match"
                    })
                    continue

                # It is a descendant (depth >= 1)
                # Check whether recursion or wildcard allows this descendant
                can_recurse = self.recursive_enabled or is_wildcard

                if not can_recurse:
                    # Recursive subdomains disabled and not a wildcard root
                    matched_candidates.append({
                        "root_domain": inc_clean,
                        "depth": depth,
                        "parent": parent,
                        "rule": inc_norm,
                        "is_wildcard": is_wildcard,
                        "allowed": False,
                        "reason": f"Subdomains under '{inc_clean}' not authorized (recursion disabled)"
                    })
                    continue

                # Check max depth
                # max_depth: 0 means unlimited
                if self.max_depth == 0 or depth <= self.max_depth:
                    matched_candidates.append({
                        "root_domain": inc_clean,
                        "depth": depth,
                        "parent": parent,
                        "rule": inc_norm,
                        "is_wildcard": is_wildcard,
                        "allowed": True,
                        "reason": f"Authorized subdomain (depth {depth} within max {self.max_depth if self.max_depth > 0 else 'unlimited'})"
                    })
                else:
                    matched_candidates.append({
                        "root_domain": inc_clean,
                        "depth": depth,
                        "parent": parent,
                        "rule": inc_norm,
                        "is_wildcard": is_wildcard,
                        "allowed": False,
                        "reason": f"Subdomain depth {depth} exceeds allowed max_depth {self.max_depth}"
                    })

        # Evaluate candidate matches
        if matched_candidates:
            # Pick the most specific match (deepest root_domain or first allowed)
            allowed_matches = [m for m in matched_candidates if m["allowed"]]
            if allowed_matches:
                best = allowed_matches[0]
                return ScopeDecision(
                    status=ScopeStatus.IN_SCOPE,
                    reason=best["reason"],
                    target=raw,
                    normalized_target=norm_host,
                    root_domain=best["root_domain"],
                    parent=best["parent"],
                    depth=best["depth"],
                    matched_rule=best["rule"],
                    rule_category="RECURSIVE_INCLUSION" if best["depth"] > 0 else "EXACT_INCLUSION",
                )
            else:
                # Matches structurally but disallowed due to depth or recursion rules
                best_disallowed = matched_candidates[0]
                return ScopeDecision(
                    status=ScopeStatus.OUT_OF_SCOPE,
                    reason=best_disallowed["reason"],
                    target=raw,
                    normalized_target=norm_host,
                    root_domain=best_disallowed["root_domain"],
                    parent=best_disallowed["parent"],
                    depth=best_disallowed["depth"],
                    matched_rule=best_disallowed["rule"],
                    rule_category="DEPTH_EXCEEDED_OR_RECURSION_RESTRICTED",
                )

        # STEP 4: PRECEDENCE 4 - UNMATCHED
        return ScopeDecision(
            status=ScopeStatus.OUT_OF_SCOPE,
            reason="Domain does not match any authorized scope inclusion.",
            target=raw,
            normalized_target=norm_host,
        )
