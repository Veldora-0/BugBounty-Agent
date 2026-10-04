"""
Validator Plugin Architecture and Proof-of-Concept Validators for BugBounty-Agent.

Provides the BaseValidator plugin contract and bounded implementations:
- ReflectedXSSValidator (benign marker reflection detection; zero JS execution)
- OpenRedirectValidator (benign canary redirect verification; zero victim navigation)
- Explicit unavailable capability stubs for future validator implementations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import html
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from framework.findings.lifecycle import FindingLifecycle
from framework.findings.schema import Finding
from framework.validation.baseline import BaselineComparison, BaselineObservation
from framework.validation.model import RiskLevel, SecurityTestCase, ValidationResult, VulnerabilityFamily
from framework.validation.payload import PayloadRegistry
from framework.validation.request import ControlledResponse


class BaseValidator(ABC):
    """
    Abstract base validator contract.
    Validators consume prior reconnaissance/intelligence to prepare controlled test cases,
    and analyze differential baseline signals to produce structured observations/findings.
    """

    def __init__(self, validator_id: str, vulnerability_family: VulnerabilityFamily, is_available: bool = True):
        self.validator_id = validator_id
        self.vulnerability_family = vulnerability_family
        self.is_available = is_available

    @abstractmethod
    def can_test(self, endpoint: str, parameter: Optional[str] = None) -> bool:
        """Determines if this validator is applicable to the endpoint/parameter."""
        pass

    @abstractmethod
    def prepare_test_cases(
        self,
        target: str,
        endpoint: str,
        parameter: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> List[SecurityTestCase]:
        """Generates bounded, hypothesis-driven test cases for evaluation."""
        pass

    @abstractmethod
    def analyze(
        self,
        comparison: BaselineComparison,
        baseline: BaselineObservation,
        response: ControlledResponse,
        test_case: SecurityTestCase,
    ) -> Tuple[ValidationResult, Optional[Finding]]:
        """Analyzes differential response behavior and determines lifecycle outcome."""
        pass


class ReflectedXSSValidator(BaseValidator):
    """
    Non-destructive Reflected XSS Candidate Validator.
    Uses harmless alphanumeric marker (XSHIELD_TEST_<token>).
    Strict boundaries:
    - NEVER executes JavaScript.
    - NEVER launches a browser just to execute scripts.
    - Classifies findings according to reflection context.
    """

    def __init__(self):
        super().__init__(
            validator_id="reflected-xss",
            vulnerability_family=VulnerabilityFamily.XSS,
            is_available=True,
        )

    def can_test(self, endpoint: str, parameter: Optional[str] = None) -> bool:
        # Requires at least one parameter to mutate
        return bool(parameter) or "?" in endpoint

    def prepare_test_cases(
        self,
        target: str,
        endpoint: str,
        parameter: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> List[SecurityTestCase]:
        payload = PayloadRegistry.get_payload("PL-XSS-REFL-01")
        if not payload:
            return []

        return [
            SecurityTestCase(
                vulnerability_family=self.vulnerability_family,
                target=target,
                endpoint=endpoint,
                method="GET",
                parameter=parameter,
                payload_identifier=payload.payload_id,
                test_strategy="reflected_marker",
                risk_level=RiskLevel.SAFE,
                request_budget=2,
                expected_signals=["MARKER_REFLECTED_IN_BODY"],
                provenance=provenance,
            )
        ]

    def analyze(
        self,
        comparison: BaselineComparison,
        baseline: BaselineObservation,
        response: ControlledResponse,
        test_case: SecurityTestCase,
    ) -> Tuple[ValidationResult, Optional[Finding]]:
        if not comparison.marker_reflected:
            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=FindingLifecycle.REJECTED,
                signals_observed=["NO_REFLECTION"],
                evidence_summary="Test marker was not reflected in post-mutation HTTP response.",
                confidence="LOW",
                severity="INFORMATIONAL",
            )
            return result, None

        # Marker was reflected! Assess reflection context
        ctx = comparison.reflection_context or "UNKNOWN"
        signals = list(comparison.signals)

        # Determine severity and confidence based on context
        if ctx == "SCRIPT_TAG":
            severity = "HIGH"
            confidence = "HIGH"
            finding_state = FindingLifecycle.OBSERVED
            summary = f"Harmless verification marker reflected directly inside <script> context in parameter '{test_case.parameter}'."
        elif ctx in ("HTML_BODY_TEXT", "HTML_ATTRIBUTE"):
            severity = "MEDIUM"
            confidence = "MEDIUM"
            finding_state = FindingLifecycle.OBSERVED
            summary = f"Harmless verification marker reflected in {ctx} in parameter '{test_case.parameter}'."
        elif ctx == "JSON_VALUE":
            severity = "LOW"
            confidence = "LOW"
            finding_state = FindingLifecycle.OBSERVED
            summary = f"Verification marker reflected inside JSON response structure for parameter '{test_case.parameter}'."
        else:
            severity = "LOW"
            confidence = "LOW"
            finding_state = FindingLifecycle.CANDIDATE
            summary = f"Verification marker reflected in raw response body in parameter '{test_case.parameter}'."

        result = ValidationResult(
            test_id=test_case.test_id,
            lifecycle_state=finding_state,
            signals_observed=signals,
            evidence_summary=summary,
            confidence=confidence,
            severity=severity,
        )

        finding = Finding(
            title=f"Potential Reflected Input on {test_case.endpoint} ({test_case.parameter or 'input'})",
            summary=summary,
            affected_asset=test_case.target,
            affected_endpoint=test_case.endpoint,
            vulnerability_type="Cross-Site Scripting (Reflected)",
            severity=severity,
            confidence=confidence,
            lifecycle_state=finding_state,
            description=(
                f"Controlled input marker injected into '{test_case.parameter}' was reflected in the HTTP response "
                f"context '{ctx}'. Zero browser execution was attempted per safe testing rules."
            ),
            root_cause="User-supplied parameter reflected in server response without strict context-aware encoding.",
            prerequisites="Target endpoint accessible over HTTP/HTTPS.",
            reproduction_steps=[
                f"Send baseline request to '{test_case.endpoint}'.",
                f"Inject test marker into parameter '{test_case.parameter}'.",
                f"Observe reflection in response context '{ctx}'.",
            ],
            expected_result="Input is sanitized, escaped, or omitted from response.",
            observed_result=f"Input marker was reflected verbatim in context '{ctx}'.",
            security_impact="If untrusted JavaScript is injected and executed in victim context, session tokens or DOM data could be compromised.",
            remediation="Apply context-sensitive output encoding (HTML, JavaScript, attribute) and configure a strict Content-Security-Policy.",
            scope_reference=f"Target {test_case.target} authorized in scope",
            parameter=test_case.parameter,
            test_case_id=test_case.test_id,
            detection_method="reflected_marker",
            references=["CWE-79", "OWASP-A03:2021-Injection"],
        )

        return result, finding


class OpenRedirectValidator(BaseValidator):
    """
    Non-destructive Open Redirect Candidate Validator.
    Uses harmless external canary URL.
    Strict boundaries:
    - Inspects 3xx status codes + Location header only.
    - NEVER navigates a victim browser to external targets.
    - Disregards relative or same-origin redirects.
    """

    def __init__(self):
        super().__init__(
            validator_id="open-redirect",
            vulnerability_family=VulnerabilityFamily.OPEN_REDIRECT,
            is_available=True,
        )

    def can_test(self, endpoint: str, parameter: Optional[str] = None) -> bool:
        # Check if endpoint or parameter suggests a redirect target
        param_name = (parameter or "").lower()
        redirect_names = {"redirect", "url", "next", "return", "goto", "dest", "destination", "target", "r", "u"}
        if param_name in redirect_names:
            return True
        return bool(parameter) or "?" in endpoint

    def prepare_test_cases(
        self,
        target: str,
        endpoint: str,
        parameter: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> List[SecurityTestCase]:
        payload = PayloadRegistry.get_payload("PL-REDIR-CANARY-01")
        if not payload:
            return []

        return [
            SecurityTestCase(
                vulnerability_family=self.vulnerability_family,
                target=target,
                endpoint=endpoint,
                method="GET",
                parameter=parameter,
                payload_identifier=payload.payload_id,
                test_strategy="redirect_destination_check",
                risk_level=RiskLevel.SAFE,
                request_budget=2,
                expected_signals=["LOCATION_REDIRECT"],
                provenance=provenance,
            )
        ]

    def analyze(
        self,
        comparison: BaselineComparison,
        baseline: BaselineObservation,
        response: ControlledResponse,
        test_case: SecurityTestCase,
    ) -> Tuple[ValidationResult, Optional[Finding]]:
        if not comparison.location_header_changed or not comparison.redirect_destination:
            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=FindingLifecycle.REJECTED,
                signals_observed=["NO_REDIRECT_CHANGE"],
                evidence_summary="Location header was not altered by supplied redirect parameter.",
                confidence="LOW",
                severity="INFORMATIONAL",
            )
            return result, None

        loc = comparison.redirect_destination
        parsed_loc = urlparse(loc)
        target_parsed = urlparse(test_case.target if "://" in test_case.target else f"http://{test_case.target}")

        # Check if redirect points to an external host (not relative, not same host)
        is_external = bool(parsed_loc.netloc) and parsed_loc.netloc.lower() != target_parsed.netloc.lower()

        if is_external and "bugbounty-agent.local" in parsed_loc.netloc.lower():
            # Matches canary host!
            severity = "MEDIUM"
            confidence = "HIGH"
            finding_state = FindingLifecycle.OBSERVED
            summary = f"Endpoint redirects to arbitrary external canary destination '{loc}' via parameter '{test_case.parameter}'."

            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=finding_state,
                signals_observed=comparison.signals,
                evidence_summary=summary,
                confidence=confidence,
                severity=severity,
            )

            finding = Finding(
                title=f"Potential Open Redirect on {test_case.endpoint} ({test_case.parameter or 'parameter'})",
                summary=summary,
                affected_asset=test_case.target,
                affected_endpoint=test_case.endpoint,
                vulnerability_type="Open Redirect",
                severity=severity,
                confidence=confidence,
                lifecycle_state=finding_state,
                description=(
                    f"Parameter '{test_case.parameter}' accepts an arbitrary external URL and the server "
                    f"responds with an HTTP {response.status_code} redirect to '{loc}'."
                ),
                root_cause="User-supplied redirect URL is not validated against an allowed whitelist of destinations.",
                prerequisites="Endpoint accessible over HTTP/HTTPS.",
                reproduction_steps=[
                    f"Send request to '{test_case.endpoint}' with parameter '{test_case.parameter}' set to external canary URL.",
                    f"Observe HTTP {response.status_code} with Location header pointing to external destination.",
                ],
                expected_result="Redirect destination is restricted to local application paths or validated whitelist.",
                observed_result=f"Location header redirected to external target: {loc}",
                security_impact="Can be used in phishing campaigns to lend credibility to malicious redirect links.",
                remediation="Validate redirect destinations against a strict whitelist of approved domains or enforce relative paths.",
                scope_reference=f"Target {test_case.target} authorized in scope",
                parameter=test_case.parameter,
                test_case_id=test_case.test_id,
                detection_method="redirect_destination_check",
                references=["CWE-601", "OWASP-A01:2021-Broken Access Control"],
            )
            return result, finding

        # Not external or did not match canary
        result = ValidationResult(
            test_id=test_case.test_id,
            lifecycle_state=FindingLifecycle.REJECTED,
            signals_observed=comparison.signals,
            evidence_summary=f"Redirect was internal or did not divert to external canary ({loc}).",
            confidence="LOW",
            severity="INFORMATIONAL",
        )
        return result, None


# ---------------- Stub / Unavailable Validators ----------------


class UnavailableValidator(BaseValidator):
    """Placeholder stub declaring explicit unavailable capability status."""

    def __init__(self, validator_id: str, vulnerability_family: VulnerabilityFamily):
        super().__init__(validator_id=validator_id, vulnerability_family=vulnerability_family, is_available=False)

    def can_test(self, endpoint: str, parameter: Optional[str] = None) -> bool:
        return False

    def prepare_test_cases(
        self,
        target: str,
        endpoint: str,
        parameter: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> List[SecurityTestCase]:
        return []

    def analyze(
        self,
        comparison: BaselineComparison,
        baseline: BaselineObservation,
        response: ControlledResponse,
        test_case: SecurityTestCase,
    ) -> Tuple[ValidationResult, Optional[Finding]]:
        res = ValidationResult(
            test_id=test_case.test_id,
            lifecycle_state=FindingLifecycle.REJECTED,
            signals_observed=["CAPABILITY_UNAVAILABLE"],
            evidence_summary=f"Validator '{self.validator_id}' is not yet implemented or available.",
        )
        return res, None


class SqlInjectionValidator(UnavailableValidator):
    def __init__(self):
        super().__init__("sql-injection", VulnerabilityFamily.SQL_INJECTION)


class SsrfValidator(UnavailableValidator):
    def __init__(self):
        super().__init__("ssrf", VulnerabilityFamily.SSRF)


class CommandInjectionValidator(UnavailableValidator):
    def __init__(self):
        super().__init__("command-injection", VulnerabilityFamily.COMMAND_INJECTION)


class PathTraversalValidator(UnavailableValidator):
    def __init__(self):
        super().__init__("path-traversal", VulnerabilityFamily.PATH_TRAVERSAL)


class AuthorizationValidator(UnavailableValidator):
    def __init__(self):
        super().__init__("authorization", VulnerabilityFamily.AUTHORIZATION)
