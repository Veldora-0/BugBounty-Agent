"""
Controlled HTTP / Header Trust Validators (Phase 11).

Provides specialized validators for:
1. Host Header Injection
2. Forwarded Header Trust (X-Forwarded-Host, X-Original-Host, Forwarded)
3. Scheme Trust (X-Forwarded-Proto, X-Forwarded-Port)
4. CORS Trust Boundaries
5. HTTP Parameter Pollution (HPP)
6. Cache Poisoning Foundation (Bounded safety gate)

Enforces strict request bounds and non-destructive methodology.
"""

from __future__ import annotations

import copy
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import uuid

from framework.findings.lifecycle import FindingLifecycle
from framework.http_trust.comparator import (
    HttpTrustComparator,
    HttpTrustComparisonResult,
)
from framework.http_trust.model import (
    HeaderTrustCandidate,
    HeaderTrustEvidence,
    HttpTrustCategory,
    HttpTrustConfidence,
    HttpTrustTestCase,
    generate_canary_host,
)
from framework.validation.policy import SecurityTestPolicy
from framework.validation.request import ControlledRequest, ControlledResponse


class BaseHttpTrustValidator:
    """Base class for HTTP header trust validators."""

    def __init__(
        self,
        send_request_hook: Callable[[ControlledRequest], ControlledResponse],
        policy: Optional[SecurityTestPolicy] = None,
        program_name: str = "lab",
        lab_mode: bool = False,
    ):
        self.send_request = send_request_hook
        self.policy = policy or SecurityTestPolicy()
        self.program_name = program_name
        self.lab_mode = lab_mode

    def _get_baseline(self, candidate: HeaderTrustCandidate) -> ControlledResponse:
        """Sends baseline request using legitimate hostname."""
        parsed = urlparse(candidate.endpoint)
        legit_host = parsed.netloc

        headers = {
            "Host": legit_host,
            "User-Agent": "BugBounty-Agent/1.0 (+https://github.com/Veldora-0/BugBounty-Agent)",
            "Accept": "*/*",
        }
        req = ControlledRequest(
            url=candidate.endpoint,
            method=candidate.method or "GET",
            headers=headers,
        )
        return self.send_request(req)


class HostInjectionValidator(BaseHttpTrustValidator):
    """Validates direct Host header injection and URL/redirect poisoning."""

    def validate(self, candidate: HeaderTrustCandidate) -> Tuple[HttpTrustComparisonResult, HttpTrustTestCase]:
        baseline = self._get_baseline(candidate)

        canary = generate_canary_host(self.program_name, test_id=candidate.candidate_id, lab_mode=self.lab_mode)
        mutated_headers = {
            "Host": canary,
            "User-Agent": "BugBounty-Agent/1.0",
            "Accept": "*/*",
        }

        test_req = ControlledRequest(
            url=candidate.endpoint,
            method=candidate.method or "GET",
            headers=mutated_headers,
        )
        test_resp = self.send_request(test_req)

        comp = HttpTrustComparator.compare(
            category=HttpTrustCategory.HOST_INJECTION,
            header_name="Host",
            supplied_value=canary,
            baseline=baseline,
            test_resp=test_resp,
        )

        ev = HeaderTrustEvidence(
            evidence_id=f"ev-host-{uuid.uuid4().hex[:8]}",
            candidate_id=candidate.candidate_id,
            category=HttpTrustCategory.HOST_INJECTION,
            header_name="Host",
            supplied_value=canary,
            baseline_status=baseline.status_code,
            test_status=test_resp.status_code,
            baseline_headers=baseline.headers,
            test_headers=test_resp.headers,
            match_signals=comp.signals,
            body_snippet=test_resp.body_text or "",
            security_effect_summary=comp.security_effect_summary,
        )

        test_case = HttpTrustTestCase(
            test_id=f"test-host-{uuid.uuid4().hex[:8]}",
            candidate_id=candidate.candidate_id,
            endpoint=candidate.endpoint,
            mutated_header="Host",
            mutation_value=canary,
            expected_effect="Test if server trusts Host header for redirect or URL generation",
            security_sensitive_purpose="Host Header Injection",
            category=HttpTrustCategory.HOST_INJECTION,
            method=candidate.method,
            baseline_summary={"status": baseline.status_code},
            test_summary={"status": test_resp.status_code},
            result="VALIDATED" if comp.is_validated else "OBSERVED" if comp.confidence == HttpTrustConfidence.OBSERVED else "REJECTED",
            evidence=ev,
            confidence=comp.confidence,
            severity=candidate.severity,
            priority=candidate.priority,
            lifecycle=FindingLifecycle.VALIDATED if comp.is_validated else FindingLifecycle.OBSERVED,
        )

        return comp, test_case


class ForwardedValidator(BaseHttpTrustValidator):
    """Validates reverse-proxy trust headers (X-Forwarded-Host, Forwarded, X-Original-Host)."""

    def validate(self, candidate: HeaderTrustCandidate) -> Tuple[HttpTrustComparisonResult, HttpTrustTestCase]:
        baseline = self._get_baseline(candidate)

        parsed = urlparse(candidate.endpoint)
        legit_host = parsed.netloc
        canary = generate_canary_host(self.program_name, test_id=candidate.candidate_id, lab_mode=self.lab_mode)

        hdr_name = candidate.header_name or "X-Forwarded-Host"
        hdr_val = canary if "forwarded" != hdr_name.lower() else f"host={canary}"

        mutated_headers = {
            "Host": legit_host,  # Keep legitimate Host header
            hdr_name: hdr_val,
            "User-Agent": "BugBounty-Agent/1.0",
            "Accept": "*/*",
        }

        test_req = ControlledRequest(
            url=candidate.endpoint,
            method=candidate.method or "GET",
            headers=mutated_headers,
        )
        test_resp = self.send_request(test_req)

        comp = HttpTrustComparator.compare(
            category=HttpTrustCategory.FORWARDED_TRUST,
            header_name=hdr_name,
            supplied_value=canary,
            baseline=baseline,
            test_resp=test_resp,
        )

        ev = HeaderTrustEvidence(
            evidence_id=f"ev-fwd-{uuid.uuid4().hex[:8]}",
            candidate_id=candidate.candidate_id,
            category=HttpTrustCategory.FORWARDED_TRUST,
            header_name=hdr_name,
            supplied_value=canary,
            baseline_status=baseline.status_code,
            test_status=test_resp.status_code,
            baseline_headers=baseline.headers,
            test_headers=test_resp.headers,
            match_signals=comp.signals,
            body_snippet=test_resp.body_text or "",
            security_effect_summary=comp.security_effect_summary,
        )

        test_case = HttpTrustTestCase(
            test_id=f"test-fwd-{uuid.uuid4().hex[:8]}",
            candidate_id=candidate.candidate_id,
            endpoint=candidate.endpoint,
            mutated_header=hdr_name,
            mutation_value=canary,
            expected_effect=f"Test if server prioritizes {hdr_name} over Host header",
            security_sensitive_purpose="Proxy Forwarded Trust Analysis",
            category=HttpTrustCategory.FORWARDED_TRUST,
            method=candidate.method,
            baseline_summary={"status": baseline.status_code},
            test_summary={"status": test_resp.status_code},
            result="VALIDATED" if comp.is_validated else "OBSERVED",
            evidence=ev,
            confidence=comp.confidence,
            severity=candidate.severity,
            priority=candidate.priority,
            lifecycle=FindingLifecycle.VALIDATED if comp.is_validated else FindingLifecycle.OBSERVED,
        )

        return comp, test_case


class SchemeValidator(BaseHttpTrustValidator):
    """Validates X-Forwarded-Proto / scheme trust (http vs https downgrade)."""

    def validate(self, candidate: HeaderTrustCandidate) -> Tuple[HttpTrustComparisonResult, HttpTrustTestCase]:
        baseline = self._get_baseline(candidate)

        parsed = urlparse(candidate.endpoint)
        legit_host = parsed.netloc

        mutated_headers = {
            "Host": legit_host,
            "X-Forwarded-Proto": "http",
            "User-Agent": "BugBounty-Agent/1.0",
            "Accept": "*/*",
        }

        test_req = ControlledRequest(
            url=candidate.endpoint,
            method=candidate.method or "GET",
            headers=mutated_headers,
        )
        test_resp = self.send_request(test_req)

        comp = HttpTrustComparator.compare(
            category=HttpTrustCategory.SCHEME_TRUST,
            header_name="X-Forwarded-Proto",
            supplied_value="http",
            baseline=baseline,
            test_resp=test_resp,
        )

        ev = HeaderTrustEvidence(
            evidence_id=f"ev-scheme-{uuid.uuid4().hex[:8]}",
            candidate_id=candidate.candidate_id,
            category=HttpTrustCategory.SCHEME_TRUST,
            header_name="X-Forwarded-Proto",
            supplied_value="http",
            baseline_status=baseline.status_code,
            test_status=test_resp.status_code,
            baseline_headers=baseline.headers,
            test_headers=test_resp.headers,
            match_signals=comp.signals,
            body_snippet=test_resp.body_text or "",
            security_effect_summary=comp.security_effect_summary,
        )

        test_case = HttpTrustTestCase(
            test_id=f"test-scheme-{uuid.uuid4().hex[:8]}",
            candidate_id=candidate.candidate_id,
            endpoint=candidate.endpoint,
            mutated_header="X-Forwarded-Proto",
            mutation_value="http",
            expected_effect="Test if X-Forwarded-Proto forces scheme downgrade or insecure link generation",
            security_sensitive_purpose="Scheme Downgrade Analysis",
            category=HttpTrustCategory.SCHEME_TRUST,
            method=candidate.method,
            baseline_summary={"status": baseline.status_code},
            test_summary={"status": test_resp.status_code},
            result="VALIDATED" if comp.is_validated else "OBSERVED",
            evidence=ev,
            confidence=comp.confidence,
            severity=candidate.severity,
            priority=candidate.priority,
            lifecycle=FindingLifecycle.VALIDATED if comp.is_validated else FindingLifecycle.OBSERVED,
        )

        return comp, test_case


class CorsValidator(BaseHttpTrustValidator):
    """Validates CORS trust boundaries (Origin reflection and credentials)."""

    def validate(self, candidate: HeaderTrustCandidate) -> Tuple[HttpTrustComparisonResult, HttpTrustTestCase]:
        baseline = self._get_baseline(candidate)

        test_origin = candidate.supplied_value or "https://attacker.example.com"
        parsed = urlparse(candidate.endpoint)
        legit_host = parsed.netloc

        mutated_headers = {
            "Host": legit_host,
            "Origin": test_origin,
            "User-Agent": "BugBounty-Agent/1.0",
            "Accept": "*/*",
        }

        test_req = ControlledRequest(
            url=candidate.endpoint,
            method=candidate.method or "GET",
            headers=mutated_headers,
        )
        test_resp = self.send_request(test_req)

        comp = HttpTrustComparator.compare(
            category=HttpTrustCategory.CORS_TRUST,
            header_name="Origin",
            supplied_value=test_origin,
            baseline=baseline,
            test_resp=test_resp,
        )

        ev = HeaderTrustEvidence(
            evidence_id=f"ev-cors-{uuid.uuid4().hex[:8]}",
            candidate_id=candidate.candidate_id,
            category=HttpTrustCategory.CORS_TRUST,
            header_name="Origin",
            supplied_value=test_origin,
            baseline_status=baseline.status_code,
            test_status=test_resp.status_code,
            baseline_headers=baseline.headers,
            test_headers=test_resp.headers,
            match_signals=comp.signals,
            body_snippet=test_resp.body_text or "",
            security_effect_summary=comp.security_effect_summary,
        )

        test_case = HttpTrustTestCase(
            test_id=f"test-cors-{uuid.uuid4().hex[:8]}",
            candidate_id=candidate.candidate_id,
            endpoint=candidate.endpoint,
            mutated_header="Origin",
            mutation_value=test_origin,
            expected_effect="Test if arbitrary Origin is reflected with credentials allowed",
            security_sensitive_purpose="CORS Trust Boundary Analysis",
            category=HttpTrustCategory.CORS_TRUST,
            method=candidate.method,
            baseline_summary={"status": baseline.status_code},
            test_summary={"status": test_resp.status_code},
            result="VALIDATED" if comp.is_validated else "OBSERVED",
            evidence=ev,
            confidence=comp.confidence,
            severity="HIGH" if comp.is_validated else "LOW",
            priority=candidate.priority,
            lifecycle=FindingLifecycle.VALIDATED if comp.is_validated else FindingLifecycle.OBSERVED,
        )

        return comp, test_case


class HppValidator(BaseHttpTrustValidator):
    """Validates HTTP Parameter Pollution parser behavior (first/last/array)."""

    def validate(self, candidate: HeaderTrustCandidate) -> Tuple[HttpTrustComparisonResult, HttpTrustTestCase]:
        baseline = self._get_baseline(candidate)

        parsed = urlparse(candidate.endpoint)
        param_name = candidate.header_name or "id"

        # Build polluted query: param=bbval1&param=bbval2
        q_parts = parse_qsl(parsed.query, keep_blank_values=True)
        # Filter out existing param
        remaining = [(k, v) for k, v in q_parts if k != param_name]
        remaining.append((param_name, "bbval1"))
        remaining.append((param_name, "bbval2"))

        polluted_query = urlencode(remaining)
        polluted_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, polluted_query, parsed.fragment))

        test_req = ControlledRequest(
            url=polluted_url,
            method=candidate.method or "GET",
            headers={
                "Host": parsed.netloc,
                "User-Agent": "BugBounty-Agent/1.0",
            },
        )
        test_resp = self.send_request(test_req)

        comp = HttpTrustComparator.compare(
            category=HttpTrustCategory.HPP,
            header_name=param_name,
            supplied_value=f"{param_name}=bbval1&{param_name}=bbval2",
            baseline=baseline,
            test_resp=test_resp,
        )

        ev = HeaderTrustEvidence(
            evidence_id=f"ev-hpp-{uuid.uuid4().hex[:8]}",
            candidate_id=candidate.candidate_id,
            category=HttpTrustCategory.HPP,
            header_name=param_name,
            supplied_value=f"{param_name}=bbval1&{param_name}=bbval2",
            baseline_status=baseline.status_code,
            test_status=test_resp.status_code,
            baseline_headers=baseline.headers,
            test_headers=test_resp.headers,
            match_signals=comp.signals,
            body_snippet=test_resp.body_text or "",
            security_effect_summary=comp.security_effect_summary,
        )

        test_case = HttpTrustTestCase(
            test_id=f"test-hpp-{uuid.uuid4().hex[:8]}",
            candidate_id=candidate.candidate_id,
            endpoint=polluted_url,
            mutated_header=param_name,
            mutation_value=f"{param_name}=bbval1&{param_name}=bbval2",
            expected_effect="Determine parameter precedence in HTTP Parameter Pollution",
            security_sensitive_purpose="HTTP Parameter Pollution Characterization",
            category=HttpTrustCategory.HPP,
            method=candidate.method,
            baseline_summary={"status": baseline.status_code},
            test_summary={"status": test_resp.status_code},
            result="OBSERVED",
            evidence=ev,
            confidence=comp.confidence,
            severity=candidate.severity,
            priority=candidate.priority,
            lifecycle=FindingLifecycle.OBSERVED,
        )

        return comp, test_case


class CacheValidator(BaseHttpTrustValidator):
    """Foundation validator for unkeyed header / cache behavior."""

    def validate(self, candidate: HeaderTrustCandidate) -> Tuple[HttpTrustComparisonResult, HttpTrustTestCase]:
        baseline = self._get_baseline(candidate)

        parsed = urlparse(candidate.endpoint)
        canary = generate_canary_host(self.program_name, test_id=candidate.candidate_id, lab_mode=self.lab_mode)

        hdr_name = candidate.header_name or "X-Forwarded-Host"
        mutated_headers = {
            "Host": parsed.netloc,
            hdr_name: canary,
            "User-Agent": "BugBounty-Agent/1.0",
            "Accept": "*/*",
        }

        test_req = ControlledRequest(
            url=candidate.endpoint,
            method=candidate.method or "GET",
            headers=mutated_headers,
        )
        test_resp = self.send_request(test_req)

        comp = HttpTrustComparator.compare(
            category=HttpTrustCategory.CACHE_POISONING,
            header_name=hdr_name,
            supplied_value=canary,
            baseline=baseline,
            test_resp=test_resp,
        )

        ev = HeaderTrustEvidence(
            evidence_id=f"ev-cache-{uuid.uuid4().hex[:8]}",
            candidate_id=candidate.candidate_id,
            category=HttpTrustCategory.CACHE_POISONING,
            header_name=hdr_name,
            supplied_value=canary,
            baseline_status=baseline.status_code,
            test_status=test_resp.status_code,
            baseline_headers=baseline.headers,
            test_headers=test_resp.headers,
            match_signals=comp.signals,
            body_snippet=test_resp.body_text or "",
            security_effect_summary=comp.security_effect_summary,
        )

        test_case = HttpTrustTestCase(
            test_id=f"test-cache-{uuid.uuid4().hex[:8]}",
            candidate_id=candidate.candidate_id,
            endpoint=candidate.endpoint,
            mutated_header=hdr_name,
            mutation_value=canary,
            expected_effect="Analyze cache key behavior for unkeyed header candidate",
            security_sensitive_purpose="Cache Poisoning Foundation Analysis",
            category=HttpTrustCategory.CACHE_POISONING,
            method=candidate.method,
            baseline_summary={"status": baseline.status_code},
            test_summary={"status": test_resp.status_code},
            result="OBSERVED" if comp.confidence == HttpTrustConfidence.OBSERVED else "REJECTED",
            evidence=ev,
            confidence=comp.confidence,
            severity="LOW",
            priority=candidate.priority,
            lifecycle=FindingLifecycle.OBSERVED if comp.confidence == HttpTrustConfidence.OBSERVED else FindingLifecycle.REJECTED,
        )

        return comp, test_case


class HttpTrustValidatorFactory:
    """Factory creating the appropriate validator for a test category."""

    @classmethod
    def get_validator(
        cls,
        category: HttpTrustCategory | str,
        send_request_hook: Callable[[ControlledRequest], ControlledResponse],
        policy: Optional[SecurityTestPolicy] = None,
        program_name: str = "lab",
        lab_mode: bool = False,
    ) -> BaseHttpTrustValidator:
        cat = (
            category
            if isinstance(category, HttpTrustCategory)
            else HttpTrustCategory.from_string(category)
        )
        if cat in (HttpTrustCategory.HOST_INJECTION, HttpTrustCategory.REDIRECT_POISONING, HttpTrustCategory.URL_POISONING):
            return HostInjectionValidator(send_request_hook, policy, program_name, lab_mode)
        elif cat == HttpTrustCategory.FORWARDED_TRUST:
            return ForwardedValidator(send_request_hook, policy, program_name, lab_mode)
        elif cat == HttpTrustCategory.SCHEME_TRUST:
            return SchemeValidator(send_request_hook, policy, program_name, lab_mode)
        elif cat == HttpTrustCategory.CORS_TRUST:
            return CorsValidator(send_request_hook, policy, program_name, lab_mode)
        elif cat == HttpTrustCategory.HPP:
            return HppValidator(send_request_hook, policy, program_name, lab_mode)
        elif cat == HttpTrustCategory.CACHE_POISONING:
            return CacheValidator(send_request_hook, policy, program_name, lab_mode)
        else:
            return HostInjectionValidator(send_request_hook, policy, program_name, lab_mode)
