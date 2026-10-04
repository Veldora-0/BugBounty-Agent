"""
Differential Comparator & Multi-Signal Analysis Engine for HTTP Trust (Phase 11).

Compares baseline responses with controlled mutated-header responses.
Inspects Location redirects, canonical links, OpenGraph metadata, JSON URLs,
action URLs (password reset, invitations), CORS origins, and cache behaviors.
Eliminates false positives (harmless reflections, debug pages, public wildcard CORS).
"""

from __future__ import annotations

import difflib
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from framework.http_trust.model import (
    HttpTrustCategory,
    HttpTrustConfidence,
    TrustClassification,
    TrustSource,
)
from framework.validation.request import ControlledResponse


class HttpTrustComparisonResult:
    """Detailed differential evaluation result between baseline and test response."""

    def __init__(
        self,
        category: HttpTrustCategory,
        header_name: str,
        supplied_value: str,
        trust_classification: TrustClassification,
        trust_source: TrustSource,
        is_validated: bool,
        confidence: HttpTrustConfidence,
        signals: List[str],
        security_effect_summary: str,
        is_false_positive: bool = False,
        false_positive_reason: str = "",
        location_diff: Optional[Dict[str, str]] = None,
        url_poisoning_findings: Optional[List[Dict[str, str]]] = None,
        cors_details: Optional[Dict[str, Any]] = None,
        hpp_details: Optional[Dict[str, Any]] = None,
        cache_details: Optional[Dict[str, Any]] = None,
    ):
        self.category = category
        self.header_name = header_name
        self.supplied_value = supplied_value
        self.trust_classification = trust_classification
        self.trust_source = trust_source
        self.is_validated = is_validated
        self.confidence = confidence
        self.signals = list(signals)
        self.security_effect_summary = security_effect_summary
        self.is_false_positive = is_false_positive
        self.false_positive_reason = false_positive_reason
        self.location_diff = dict(location_diff or {})
        self.url_poisoning_findings = list(url_poisoning_findings or [])
        self.cors_details = dict(cors_details or {})
        self.hpp_details = dict(hpp_details or {})
        self.cache_details = dict(cache_details or {})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "header_name": self.header_name,
            "supplied_value": self.supplied_value,
            "trust_classification": self.trust_classification.value,
            "trust_source": self.trust_source.value,
            "is_validated": self.is_validated,
            "confidence": self.confidence.value,
            "signals": self.signals,
            "security_effect_summary": self.security_effect_summary,
            "is_false_positive": self.is_false_positive,
            "false_positive_reason": self.false_positive_reason,
            "location_diff": self.location_diff,
            "url_poisoning_findings": self.url_poisoning_findings,
            "cors_details": self.cors_details,
            "hpp_details": self.hpp_details,
            "cache_details": self.cache_details,
        }


class HttpTrustComparator:
    """
    Differential analysis engine for HTTP header manipulation.
    """

    DEBUG_PAGE_PATTERNS = [
        re.compile(r"traceback\s+\(most\s+recent\s+call\s+last\)", re.IGNORECASE),
        re.compile(r"django\.core\.exceptions|werkzeug\.debug|laravel.*whoops", re.IGNORECASE),
        re.compile(r"environ\[.*REQUEST_METHOD.*\]", re.IGNORECASE),
        re.compile(r"phpinfo\(\)|php\s+version", re.IGNORECASE),
        re.compile(r"stack\s+trace:\s+at\s+", re.IGNORECASE),
    ]

    CDN_REJECTION_PATTERNS = [
        re.compile(r"<title>403\s+Forbidden.*Cloudflare</title>", re.IGNORECASE),
        re.compile(r"The\s+request\s+could\s+not\s+be\s+satisfied.*CloudFront", re.IGNORECASE),
        re.compile(r"Akamai\s+GHost.*Access\s+Denied", re.IGNORECASE),
        re.compile(r"Direct\s+IP\s+access\s+not\s+allowed", re.IGNORECASE),
    ]

    CANONICAL_LINK_REGEX = re.compile(r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)
    CANONICAL_LINK_REV_REGEX = re.compile(r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\']canonical["\']', re.IGNORECASE)
    OPENGRAPH_URL_REGEX = re.compile(r'<meta[^>]+property=["\']og:url["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
    ACTION_LINK_REGEX = re.compile(r'href=["\'](https?://[^"\']*(?:reset|token|verify|activate|invite|enroll)[^"\']*)["\']', re.IGNORECASE)
    ABSOLUTE_URL_REGEX = re.compile(r'https?://[a-zA-Z0-9.\-_:]+(?:/[^\s"\'<>]*)?')

    @classmethod
    def compare(
        cls,
        category: HttpTrustCategory,
        header_name: str,
        supplied_value: str,
        baseline: ControlledResponse,
        test_resp: ControlledResponse,
        workflow_type: str = "GENERAL",
    ) -> HttpTrustComparisonResult:
        """
        Executes multi-signal comparison between baseline and mutated response.
        """
        base_body = baseline.body_text or ""
        test_body = test_resp.body_text or ""
        base_headers = {k.lower(): v for k, v in baseline.headers.items()}
        test_headers = {k.lower(): v for k, v in test_resp.headers.items()}

        signals: List[str] = []
        is_validated = False
        confidence = HttpTrustConfidence.CANDIDATE
        trust_class = TrustClassification.UNUSED
        trust_source = TrustSource.UNKNOWN_TRUST_SOURCE
        sec_summary = ""
        is_fp = False
        fp_reason = ""
        url_findings: List[Dict[str, str]] = []
        loc_diff: Dict[str, str] = {}
        cors_details: Dict[str, Any] = {}
        hpp_details: Dict[str, Any] = {}
        cache_details: Dict[str, Any] = {}

        # 1. CDN or WAF rejection check
        for pattern in cls.CDN_REJECTION_PATTERNS:
            if pattern.search(test_body):
                return HttpTrustComparisonResult(
                    category=category,
                    header_name=header_name,
                    supplied_value=supplied_value,
                    trust_classification=TrustClassification.UNUSED,
                    trust_source=TrustSource.PROXY_TRUST,
                    is_validated=False,
                    confidence=HttpTrustConfidence.CANDIDATE,
                    signals=["EDGE_WAF_HOST_REJECTED"],
                    security_effect_summary="Fronting CDN/WAF rejected mutated Host/proxy header",
                    is_false_positive=True,
                    false_positive_reason="Edge CDN rejected header without passing to backend",
                )

        # 2. Debug / Exception page reflection check
        for pattern in cls.DEBUG_PAGE_PATTERNS:
            if pattern.search(test_body):
                signals.append("DEBUG_PAGE_ECHO")
                return HttpTrustComparisonResult(
                    category=category,
                    header_name=header_name,
                    supplied_value=supplied_value,
                    trust_classification=TrustClassification.REFLECTED,
                    trust_source=TrustSource.FRAMEWORK_TRUST,
                    is_validated=False,
                    confidence=HttpTrustConfidence.OBSERVED,
                    signals=["DEBUG_PAGE_ECHO"],
                    security_effect_summary="Header echoed inside development debug stack trace (non-exploitable Host injection)",
                    is_false_positive=True,
                    false_positive_reason="Echoed inside debug exception screen, not active URL generation",
                )

        # ====================================================================
        # Category A: Host / Forwarded / Scheme Injection
        # ====================================================================
        if category in (
            HttpTrustCategory.HOST_INJECTION,
            HttpTrustCategory.FORWARDED_TRUST,
            HttpTrustCategory.SCHEME_TRUST,
            HttpTrustCategory.REDIRECT_POISONING,
            HttpTrustCategory.URL_POISONING,
        ):
            canary = supplied_value.strip().lower()
            base_loc = base_headers.get("location", "")
            test_loc = test_headers.get("location", "")

            # Check 1: Redirect Host Poisoning
            if test_loc and canary in test_loc.lower():
                signals.append("REDIRECT_HOST_POISONING")
                loc_diff = {"baseline_location": base_loc, "test_location": test_loc}
                trust_class = TrustClassification.USED_FOR_REDIRECT
                trust_source = (
                    TrustSource.PROXY_TRUST
                    if "forwarded" in header_name.lower()
                    else TrustSource.DIRECT_APPLICATION_TRUST
                )
                confidence = HttpTrustConfidence.VALIDATED
                is_validated = True
                sec_summary = f"Manipulated {header_name} successfully poisoned redirect Location target to '{test_loc}'"

            # Check 2: Absolute Action Link Poisoning (Password reset, Invite, Activation)
            action_matches = cls.ACTION_LINK_REGEX.findall(test_body)
            for act_url in action_matches:
                if canary in act_url.lower():
                    signals.append("ACTION_LINK_POISONING")
                    url_findings.append({"type": "ACTION_LINK", "url": act_url})
                    trust_class = TrustClassification.USED_FOR_URL_GENERATION
                    trust_source = TrustSource.DIRECT_APPLICATION_TRUST
                    confidence = HttpTrustConfidence.VALIDATED
                    is_validated = True
                    sec_summary = f"High-impact: {header_name} poisoned account action URL ({act_url})"

            # Check 3: Canonical Link Poisoning
            canon_match = cls.CANONICAL_LINK_REGEX.search(test_body) or cls.CANONICAL_LINK_REV_REGEX.search(test_body)
            if canon_match:
                canon_url = canon_match.group(1)
                if canary in canon_url.lower():
                    signals.append("CANONICAL_URL_POISONING")
                    url_findings.append({"type": "CANONICAL_URL", "url": canon_url})
                    trust_class = TrustClassification.USED_FOR_URL_GENERATION
                    trust_source = TrustSource.DIRECT_APPLICATION_TRUST
                    if not is_validated:
                        confidence = HttpTrustConfidence.VALIDATED
                        is_validated = True
                        sec_summary = f"{header_name} poisoned HTML canonical link ({canon_url})"

            # Check 4: OpenGraph URL Poisoning
            og_match = cls.OPENGRAPH_URL_REGEX.search(test_body)
            if og_match:
                og_url = og_match.group(1)
                if canary in og_url.lower():
                    signals.append("OPENGRAPH_URL_POISONING")
                    url_findings.append({"type": "OPENGRAPH_URL", "url": og_url})
                    trust_class = TrustClassification.USED_FOR_URL_GENERATION
                    if not is_validated:
                        confidence = HttpTrustConfidence.OBSERVED
                        sec_summary = f"{header_name} poisoned OpenGraph metadata URL ({og_url})"

            # Check 5: JSON Absolute URLs
            if "application/json" in test_headers.get("content-type", "").lower():
                try:
                    parsed_json = json.loads(test_body)
                    json_str = json.dumps(parsed_json)
                    if canary in json_str.lower():
                        signals.append("JSON_URL_POISONING")
                        url_findings.append({"type": "JSON_URL", "snippet": json_str[:200]})
                        trust_class = TrustClassification.USED_FOR_URL_GENERATION
                        if not is_validated:
                            confidence = HttpTrustConfidence.OBSERVED
                            sec_summary = f"{header_name} poisoned server-generated URLs in JSON response"
                except Exception:
                    pass

            # Check 6: Scheme Downgrade / Trust (X-Forwarded-Proto)
            if header_name.lower() in ("x-forwarded-proto", "x-forwarded-port"):
                if "http" in supplied_value.lower():
                    # Check if canonical or redirect switched from https to http
                    if test_loc.startswith("http://") and not base_loc.startswith("http://"):
                        signals.append("SCHEME_DOWNGRADE_REDIRECT")
                        trust_class = TrustClassification.USED_FOR_REDIRECT
                        confidence = HttpTrustConfidence.VALIDATED
                        is_validated = True
                        sec_summary = f"{header_name} forced insecure HTTP redirect downgrade"
                    elif canon_match and canon_match.group(1).startswith("http://"):
                        signals.append("SCHEME_DOWNGRADE_CANONICAL")
                        trust_class = TrustClassification.USED_FOR_URL_GENERATION
                        confidence = HttpTrustConfidence.OBSERVED
                        sec_summary = f"{header_name} influenced generated URL scheme to insecure http"

            # Check 7: Plain Body Reflection without Security-Sensitive URL generation -> HARMLESS
            if canary in test_body.lower() and not is_validated and not url_findings:
                signals.append("HARMLESS_HOST_REFLECTION")
                trust_class = TrustClassification.REFLECTED
                trust_source = TrustSource.FRAMEWORK_TRUST
                confidence = HttpTrustConfidence.OBSERVED
                is_fp = True
                fp_reason = "Canary reflected in HTML body text without generating actionable links or redirects"
                sec_summary = "Host value reflected harmlessly in text content (not a security finding)"

            # Check 8: If no reflection and no redirect change
            if not signals:
                if test_resp.status_code == baseline.status_code:
                    trust_class = TrustClassification.ACCEPTED
                    signals.append("HEADER_ACCEPTED_NO_CHANGE")
                    sec_summary = f"Header {header_name} was accepted with status {test_resp.status_code} but produced no observable changes"
                else:
                    trust_class = TrustClassification.UNUSED
                    signals.append("STATUS_CODE_DIFFERENTIAL")
                    sec_summary = f"Header {header_name} altered status code from {baseline.status_code} to {test_resp.status_code}"

        # ====================================================================
        # Category B: CORS Trust Intelligence
        # ====================================================================
        elif category == HttpTrustCategory.CORS_TRUST:
            acao = test_headers.get("access-control-allow-origin", "").strip()
            acac = test_headers.get("access-control-allow-credentials", "").strip().lower()
            vary = test_headers.get("vary", "")

            cors_details = {
                "acao": acao,
                "acac": acac,
                "vary": vary,
                "origin_sent": supplied_value,
            }

            if not acao:
                trust_class = TrustClassification.UNUSED
                signals.append("NO_CORS_HEADERS")
                sec_summary = "No Access-Control-Allow-Origin header returned by server"
            elif acao == "*":
                if acac == "true":
                    signals.append("CORS_WILDCARD_CREDENTIALS_INVALID")
                    is_fp = True
                    fp_reason = "Browsers strictly reject wildcard ACAO when credentials are true"
                    sec_summary = "Invalid browser CORS configuration (wildcard with credentials)"
                else:
                    signals.append("CORS_WILDCARD_PUBLIC")
                    trust_class = TrustClassification.ACCEPTED
                    is_fp = True
                    fp_reason = "Standard public API wildcard CORS without credentials"
                    sec_summary = "Standard public wildcard CORS (not a finding on non-sensitive APIs)"
            elif acao.lower() == supplied_value.strip().lower():
                # Reflected origin!
                trust_class = TrustClassification.REFLECTED
                if acac == "true":
                    signals.append("CORS_CREDENTIALED_REFLECTION")
                    confidence = HttpTrustConfidence.VALIDATED
                    is_validated = True
                    sec_summary = f"Critical CORS trust boundary failure: Origin '{supplied_value}' reflected with credentials allowed"
                else:
                    signals.append("CORS_REFLECTED_NO_CREDENTIALS")
                    confidence = HttpTrustConfidence.OBSERVED
                    sec_summary = f"Origin '{supplied_value}' reflected in ACAO but without credentials"
            else:
                # Origin was NOT reflected; checked against allowlist
                trust_class = TrustClassification.USED_FOR_SECURITY_DECISION
                signals.append("CORS_ALLOWLIST_ENFORCED")
                sec_summary = f"Origin allowlist enforced; server replied with configured origin '{acao}' instead of supplied canary"

        # ====================================================================
        # Category C: HTTP Parameter Pollution (HPP)
        # ====================================================================
        elif category == HttpTrustCategory.HPP:
            # Analyze parser behavior when duplicate parameters are supplied
            # supplied_value format: "param=val1&param=val2"
            test_body_lower = test_body.lower()
            val1_present = "bbval1" in test_body_lower
            val2_present = "bbval2" in test_body_lower

            if val1_present and val2_present:
                parser_mode = "COMBINED_OR_ARRAY"
                signals.append("HPP_PARSER_ARRAY")
            elif val2_present:
                parser_mode = "LAST_VALUE"
                signals.append("HPP_PARSER_LAST_VALUE")
            elif val1_present:
                parser_mode = "FIRST_VALUE"
                signals.append("HPP_PARSER_FIRST_VALUE")
            else:
                parser_mode = "UNKNOWN"
                signals.append("HPP_PARSER_IDENTICAL")

            hpp_details = {
                "parser_mode": parser_mode,
                "val1_present": val1_present,
                "val2_present": val2_present,
                "status_code": test_resp.status_code,
            }

            trust_class = TrustClassification.ACCEPTED
            confidence = HttpTrustConfidence.OBSERVED
            sec_summary = f"HPP behavior characterized: framework parser adopts {parser_mode}"

        # ====================================================================
        # Category D: Cache Poisoning Foundation
        # ====================================================================
        elif category == HttpTrustCategory.CACHE_POISONING:
            cache_ctrl = test_headers.get("cache-control", "")
            age = test_headers.get("age", "")
            x_cache = test_headers.get("x-cache", "")
            cf_cache = test_headers.get("cf-cache-status", "")

            cache_details = {
                "cache_control": cache_ctrl,
                "age": age,
                "x_cache": x_cache,
                "cf_cache_status": cf_cache,
            }

            has_cache_headers = bool(cache_ctrl or age or x_cache or cf_cache)
            if has_cache_headers:
                signals.append("CACHE_HEADERS_PRESENT")
                # Look for unkeyed reflection or variation
                if supplied_value.lower() in test_body.lower():
                    signals.append("CACHE_UNKEYED_INPUT_REFLECTED")
                    trust_class = TrustClassification.USED_FOR_CACHE_KEY
                    confidence = HttpTrustConfidence.OBSERVED
                    sec_summary = "Unkeyed header candidate reflected on endpoint exhibiting cache headers (MANUAL_REVIEW_REQUIRED for production safety)"
                else:
                    signals.append("CACHE_VARIATION_WITHOUT_POISONING")
                    is_fp = True
                    fp_reason = "Response exhibited cache headers but no unkeyed contamination observed"
                    sec_summary = "Standard caching headers without observable unkeyed reflection"
            else:
                signals.append("NO_CACHE_HEADERS")
                sec_summary = "Endpoint does not exhibit caching headers"

        return HttpTrustComparisonResult(
            category=category,
            header_name=header_name,
            supplied_value=supplied_value,
            trust_classification=trust_class,
            trust_source=trust_source,
            is_validated=is_validated,
            confidence=confidence,
            signals=signals,
            security_effect_summary=sec_summary,
            is_false_positive=is_fp,
            false_positive_reason=fp_reason,
            location_diff=loc_diff,
            url_poisoning_findings=url_findings,
            cors_details=cors_details,
            hpp_details=hpp_details,
            cache_details=cache_details,
        )
